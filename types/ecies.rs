//! ECIES (ristretto255, AES256-GCM, HMAC-SHA256)

use aes_gcm::{KeyInit as _, aead::Aead as _};
use curve25519_dalek::RistrettoPoint;
use hkdf::hmac::{self, Hmac, KeyInit as _, Mac as _};
use rand::CryptoRng;
use sha2::Sha256;

use crate::keys::{CompressedPublicKey, PublicKey, SecretKey};

pub mod error {
    use hkdf::hmac::digest::MacError;
    use thiserror::Error;

    use crate::error::NonCanonicalRistrettoPointEncoding;

    #[derive(Debug, Error)]
    pub enum Decrypt {
        #[error("AES-GCM decryption failed")]
        AesGcm(#[from] aes_gcm::Error),
        #[error("invalid MAC")]
        InvalidMac(#[from] MacError),
        #[error("invalid ephemeral public key")]
        InvalidEphemeralKey(#[from] NonCanonicalRistrettoPointEncoding),
        #[error("unable to parse encryption nonce")]
        ParseEncryptionNonce,
        #[error("unable to parse ephemeral public key")]
        ParseEphemeralKey,
        #[error("unable to parse MAC")]
        ParseMac,
        #[error("unable to parse MAC key")]
        ParseMacKey,
    }

    #[derive(Debug, Error)]
    pub enum Encrypt {
        #[error("AES-GCM encryption failed")]
        AesGcm(#[from] aes_gcm::Error),
    }
}

const ENCRYPTION_KEY_LEN: usize = 32;
const ENCRYPTION_NONCE_LEN: usize = 12;
const MAC_KEY_LEN: usize = 32;
const MAC_LEN: usize = 32;

fn diffie_hellman(
    secret_key: &SecretKey,
    their_public_key: PublicKey,
) -> RistrettoPoint {
    their_public_key.0 * secret_key
}

/// Derive (encryption key, MAC key)
fn derive_keys(
    shared_secret_bytes: [u8; 32],
    cpk: CompressedPublicKey,
) -> ([u8; ENCRYPTION_KEY_LEN], [u8; MAC_KEY_LEN]) {
    let ikm = {
        let mut ikm = [0u8; 64];
        *ikm.first_chunk_mut().unwrap() = shared_secret_bytes;
        *ikm.last_chunk_mut().unwrap() = cpk.0.to_bytes();
        ikm
    };
    let hkdf = hkdf::Hkdf::<Sha256>::new(None, &ikm);
    let key_material: [u8; ENCRYPTION_KEY_LEN + MAC_KEY_LEN] = {
        let mut key_material = [0u8; ENCRYPTION_KEY_LEN + MAC_KEY_LEN];
        hkdf.expand(b"", &mut key_material)
            .expect("Could not derive enough key material");
        key_material
    };
    let (encryption_key, key_material) =
        key_material.split_first_chunk().unwrap();
    let mac_key = key_material.as_array().unwrap();
    (*encryption_key, *mac_key)
}

/// Decrypt `ciphertext` using the `ECIES-MAC` variant
pub fn decrypt(
    recipient_secret_key: &SecretKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, error::Decrypt> {
    let (epk_bytes, ciphertext) = ciphertext
        .split_first_chunk::<32>()
        .ok_or(error::Decrypt::ParseEphemeralKey)?;
    let ephemeral_pk = PublicKey::try_from(*epk_bytes)?;
    let (nonce, ciphertext) = ciphertext
        .split_first_chunk::<ENCRYPTION_NONCE_LEN>()
        .ok_or(error::Decrypt::ParseEncryptionNonce)?;
    let (mac_bytes, ciphertext) = ciphertext
        .split_first_chunk::<MAC_LEN>()
        .ok_or(error::Decrypt::ParseMac)?;
    let shared_secret_bytes =
        diffie_hellman(recipient_secret_key, ephemeral_pk)
            .compress()
            .to_bytes();
    let (encryption_key, mac_key) =
        derive_keys(shared_secret_bytes, ephemeral_pk.compress());
    {
        let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
        mac.update(nonce);
        mac.update(ciphertext);
        let () = mac.verify(&hmac::digest::array::Array(*mac_bytes))?;
    };
    let dec = aes_gcm::Aes256Gcm::new(&encryption_key.into());
    let res = dec.decrypt(
        nonce.into(),
        aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: b"",
        },
    )?;
    Ok(res)
}

/// Decrypt `ciphertext` using the `ECIES-MAC` variant
pub fn encrypt<R>(
    mut rng: R,
    recipient_public_key: &PublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, error::Encrypt>
where
    R: CryptoRng,
{
    let ephemeral_sk = SecretKey::random(&mut rng);
    let ephemeral_pk = PublicKey::from_secret_key(&ephemeral_sk);
    let nonce = {
        let mut nonce = [0u8; ENCRYPTION_NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        nonce
    };

    let shared_secret_bytes =
        diffie_hellman(&ephemeral_sk, *recipient_public_key)
            .compress()
            .to_bytes();
    let (encryption_key, mac_key) =
        derive_keys(shared_secret_bytes, ephemeral_pk.compress());

    let enc = aes_gcm::Aes256Gcm::new(&encryption_key.into());
    let ciphertext = enc.encrypt(&nonce.into(), plaintext)?;
    let mac = {
        let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
        mac.update(&nonce);
        mac.update(&ciphertext);
        mac.finalize().into_bytes()
    };

    let mut res = Vec::new();
    res.extend_from_slice(ephemeral_pk.compress().0.as_bytes());
    res.extend_from_slice(nonce.as_slice());
    res.extend_from_slice(mac.as_slice());
    res.extend_from_slice(ciphertext.as_slice());

    Ok(res)
}

#[cfg(test)]
mod test {
    use rand::Rng as _;

    use crate::{
        ecies,
        keys::{PublicKey, SecretKey},
    };

    #[test]
    fn test_encryption_roundtrip() -> anyhow::Result<()> {
        let mut rng = rand::rng();
        let plaintext = {
            let mut plaintext = [0u8; 256];
            rng.fill_bytes(&mut plaintext);
            plaintext
        };
        let recipient_sk = SecretKey::random(&mut rng);
        let recipient_pk = PublicKey::from_secret_key(&recipient_sk);
        let ciphertext = ecies::encrypt(&mut rng, &recipient_pk, &plaintext)?;
        let decrypted = ecies::decrypt(&recipient_sk, &ciphertext)?;
        anyhow::ensure!(plaintext.as_slice() == decrypted);
        Ok(())
    }
}
