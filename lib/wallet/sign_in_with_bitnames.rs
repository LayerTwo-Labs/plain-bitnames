//! Sign in with BitNames

use std::marker::PhantomData;

use bitcoin::bip32::DerivationPath;
use borsh::{BorshDeserialize, BorshSerialize};
use crypto_box::{
    ChaChaBox,
    aead::{Aead, AeadCore, OsRng},
};
use curve25519_dalek::{
    RistrettoPoint, Scalar, ristretto::CompressedRistretto,
};
use ed25519_bip32::{XPrv, XPub};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    authorization::Signature,
    types::{BitName, EncryptionPubKey},
    wallet::{self, RoTxn, Wallet},
};

/// Derive an XPub using a derivation path
fn derive_xpub(
    xpub: XPub,
    path: &DerivationPath,
) -> Result<XPub, ed25519_bip32::DerivationError> {
    path.into_iter().try_fold(xpub, |xpub, child_number| {
        xpub.derive(ed25519_bip32::DerivationScheme::V2, (*child_number).into())
    })
}

fn hardened_derivation_path_from_bytes32(bytes: &[u8; 32]) -> DerivationPath {
    bytes
        .chunks_exact(4)
        .map(|chunk| {
            let chunk: &[u8; 4] = chunk.try_into().unwrap();
            bitcoin::bip32::ChildNumber::Hardened {
                index: u32::from_le_bytes(*chunk),
            }
        })
        .collect()
}

fn non_hardened_derivation_path_from_bytes32(
    bytes: &[u8; 32],
) -> DerivationPath {
    bytes
        .chunks_exact(4)
        .map(|chunk| {
            let chunk: &[u8; 4] = chunk.try_into().unwrap();
            bitcoin::bip32::ChildNumber::Normal {
                index: u32::from_le_bytes(*chunk),
            }
        })
        .collect()
}

fn sign_in_with_bitnames_derivation_path_prefix() -> DerivationPath {
    let path_bytes: [u8; 32] = blake3::hash(b"Sign in with BitNames").into();
    non_hardened_derivation_path_from_bytes32(&path_bytes)
}

/// Non-hardened derivation path from BitName
fn bitname_to_non_hardened_derivation_path(
    bitname: &BitName,
) -> DerivationPath {
    let bitname_bytes: &[u8; 32] = &bitname.0;
    non_hardened_derivation_path_from_bytes32(bitname_bytes)
}

fn sign_in_with_bitnames_non_hardened_derivation_path(
    bitname: &BitName,
) -> DerivationPath {
    sign_in_with_bitnames_derivation_path_prefix()
        .extend(bitname_to_non_hardened_derivation_path(bitname))
}

fn secret_from_xprv(xprv: &XPrv) -> &[u8; 32] {
    let (secret_bytes, _): (&[u8; 32], _) = xprv
        .extended_secret_key_bytes()
        .split_first_chunk()
        .unwrap();
    secret_bytes
}

fn secret_scalar_from_xprv(xprv: &XPrv) -> curve25519_dalek::Scalar {
    curve25519_dalek::Scalar::from_bytes_mod_order(*secret_from_xprv(xprv))
}

fn edwards_to_ristretto(
    point: curve25519_dalek::EdwardsPoint,
) -> RistrettoPoint {
    // SAFETY: RistrettoPoint is just a wrapper around EdwardsPoint
    unsafe { std::mem::transmute(point) }
}

fn ristretto_to_edwards(
    point: RistrettoPoint,
) -> curve25519_dalek::EdwardsPoint {
    // SAFETY: RistrettoPoint is just a wrapper around EdwardsPoint
    unsafe { std::mem::transmute(point) }
}

fn ristretto_point_from_curve25519_edwards_compressed(
    compressed_edwards: [u8; 32],
) -> anyhow::Result<RistrettoPoint> {
    curve25519_dalek::edwards::CompressedEdwardsY(compressed_edwards)
        .decompress()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to decompress edwards point (`{}`)",
                hex::encode(compressed_edwards)
            )
        })
        .map(edwards_to_ristretto)
}

fn ristretto_point_from_ed25519_xpub(
    xpub: &XPub,
) -> anyhow::Result<RistrettoPoint> {
    ristretto_point_from_curve25519_edwards_compressed(xpub.public_key())
}

fn ristretto_point_to_x25519_pk(
    point: RistrettoPoint,
) -> x25519_dalek::PublicKey {
    ristretto_to_edwards(point)
        .to_montgomery()
        .to_bytes()
        .into()
}

fn borsh_deserialize_compressed_ristretto<R>(
    reader: &mut R,
) -> borsh::io::Result<CompressedRistretto>
where
    R: borsh::io::Read,
{
    <[u8; 32] as BorshDeserialize>::deserialize_reader(reader)
        .map(CompressedRistretto)
}

fn borsh_deserialize_scalar<R>(reader: &mut R) -> borsh::io::Result<Scalar>
where
    R: borsh::io::Read,
{
    let bytes: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
    Scalar::from_canonical_bytes(bytes)
        .into_option()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Non-canonical scalar (`{}`)", hex::encode(bytes)),
            )
        })
}

fn borsh_serialize_compressed_ristretto<W>(
    compressed_point: &CompressedRistretto,
    writer: &mut W,
) -> borsh::io::Result<()>
where
    W: borsh::io::Write,
{
    borsh::BorshSerialize::serialize(compressed_point.as_bytes(), writer)
}

fn borsh_serialize_scalar<W>(
    scalar: &Scalar,
    writer: &mut W,
) -> borsh::io::Result<()>
where
    W: borsh::io::Write,
{
    borsh::BorshSerialize::serialize(scalar.as_bytes(), writer)
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct RegistrationPlaintext {
    #[borsh(
        deserialize_with = "borsh_deserialize_compressed_ristretto",
        serialize_with = "borsh_serialize_compressed_ristretto"
    )]
    authentication_cpk: CompressedRistretto,
    #[borsh(
        deserialize_with = "borsh_deserialize_compressed_ristretto",
        serialize_with = "borsh_serialize_compressed_ristretto"
    )]
    randomized_point: CompressedRistretto,
    #[borsh(
        deserialize_with = "borsh_deserialize_scalar",
        serialize_with = "borsh_serialize_scalar"
    )]
    challenge_response: Scalar,
}

#[derive(Debug, Serialize)]
pub struct Registration {
    pub bitname: BitName,
    pub ciphertext: Vec<u8>,
    pub encryption_nonce: [u8; 24],
}

impl Registration {
    /// Compute registration challenge
    fn challenge(
        siwb_cpk: &CompressedRistretto,
        authentication_cpk: &CompressedRistretto,
        randomized_point: &CompressedRistretto,
    ) -> Scalar {
        // TODO: use blake3 XOF,
        // keyed by `secret_from_xprv(siwb_encryption_xprv)`,
        // once digest 0.11.0 is available
        use sha3::{Digest as _, Sha3_512};
        let mut hasher = Sha3_512::new();
        hasher.update(siwb_cpk.as_bytes());
        hasher.update(authentication_cpk.as_bytes());
        hasher.update(randomized_point.as_bytes());
        curve25519_dalek::Scalar::from_hash(hasher)
    }

    /// Verify a registration, obtaining an authentication pubkey if successful
    fn verify_registration(
        &self,
        register_as_xpub: XPub,
        service_bitname: &BitName,
        encryption_secret: x25519_dalek::StaticSecret,
    ) -> anyhow::Result<RistrettoPoint> {
        let siwb_xpub = derive_xpub(
            register_as_xpub,
            &sign_in_with_bitnames_non_hardened_derivation_path(
                service_bitname,
            ),
        )?;
        let registration_plaintext: RegistrationPlaintext = {
            let chacha_box = crypto_box::ChaChaBox::new(
                &siwb_xpub.public_key().into(),
                &encryption_secret.to_bytes().into(),
            );
            let payload = crypto_box::aead::Payload {
                msg: self.ciphertext.as_slice(),
                aad: &self.bitname.0,
            };
            let decrypted_bytes =
                chacha_box.decrypt(&self.encryption_nonce.into(), payload)?;
            borsh::from_slice(&decrypted_bytes)?
        };
        let siwb_pk = ristretto_point_from_ed25519_xpub(&siwb_xpub)?;
        let challenge = Self::challenge(
            &siwb_pk.compress(),
            &registration_plaintext.authentication_cpk,
            &registration_plaintext.randomized_point,
        );
        let Some(authentication_pk) =
            registration_plaintext.authentication_cpk.decompress()
        else {
            anyhow::bail!("Failed to decompress authentication cpk")
        };
        let Some(randomized_point) =
            registration_plaintext.randomized_point.decompress()
        else {
            anyhow::bail!("Failed to decompress randomized point")
        };
        if siwb_pk * registration_plaintext.challenge_response
            == randomized_point + (authentication_pk * challenge)
        {
            Ok(authentication_pk)
        } else {
            Err(anyhow::anyhow!("Invalid challenge response"))
        }
    }
}

#[derive(Debug, Error)]
pub enum RegisterAsError {
    #[error(transparent)]
    BorshSerialize(#[from] borsh::io::Error),
    #[error(transparent)]
    CryptoBox(#[from] crypto_box::aead::Error),
    #[error(transparent)]
    Wallet(#[from] wallet::Error),
}

/// Register using the specified BitName and EncryptionPubKey, for the
/// service with the specified BitName and EncryptionPubKey
fn register_as(
    wallet: &Wallet,
    rotxn: &RoTxn,
    register_as_bitname: BitName,
    register_as_epk: &EncryptionPubKey,
    service_bitname: &BitName,
    service_epk: EncryptionPubKey,
) -> Result<Registration, RegisterAsError> {
    let epk_xprv =
        wallet.get_encryption_xprv_for_epk(rotxn, register_as_epk)?;
    let siwb_encryption_xprv = wallet::derive_xprv(
        epk_xprv,
        &sign_in_with_bitnames_non_hardened_derivation_path(service_bitname),
    );
    let siwb_pk_secret = secret_from_xprv(&siwb_encryption_xprv);
    // FIXME: implement
    let authentication_xprv: XPrv = todo!();
    let authentication_secret = secret_from_xprv(&authentication_xprv);
    let random_scalar = {
        // TODO: use blake3 XOF,
        // keyed by `secret_from_xprv(siwb_encryption_xprv)`,
        // once digest 0.11.0 is available
        use sha3::{Digest as _, Sha3_512};
        // `register_as_epk` and `service_bitname` also contribute to the hash
        // via `siwb_encryption_xprv`
        let mut hasher = Sha3_512::new();
        hasher.update(siwb_pk_secret);
        hasher.update(authentication_secret);
        hasher.update(register_as_bitname.0);
        hasher.update(service_epk.0.as_bytes());
        curve25519_dalek::Scalar::from_hash(hasher)
    };
    let siwb_pk_secret =
        curve25519_dalek::Scalar::from_bytes_mod_order(*siwb_pk_secret);
    let siwb_pk = curve25519_dalek::RistrettoPoint::mul_base(&siwb_pk_secret);
    let randomized_point = (siwb_pk * random_scalar).compress();
    let authentication_secret =
        curve25519_dalek::Scalar::from_bytes_mod_order(*authentication_secret);
    let authentication_cpk = (siwb_pk * authentication_secret).compress();
    let challenge = Registration::challenge(
        &siwb_pk.compress(),
        &authentication_cpk,
        &randomized_point,
    );
    let challenge_response =
        random_scalar + (challenge * authentication_secret);
    let (encryption_nonce, ciphertext) = {
        let chacha_box = crypto_box::ChaChaBox::new(
            &service_epk.into(),
            &siwb_pk_secret.into(),
        );
        let nonce = ChaChaBox::generate_nonce(&mut OsRng);
        let payload = crypto_box::aead::Payload {
            msg: borsh::to_vec(&RegistrationPlaintext {
                authentication_cpk,
                randomized_point,
                challenge_response,
            })?
            .as_slice(),
            aad: &register_as_bitname.0,
        };
        (nonce.into(), chacha_box.encrypt(&nonce, payload)?)
    };
    Ok(Registration {
        bitname: register_as_bitname,
        ciphertext,
        encryption_nonce,
    })
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct EpkRotation {
    #[borsh(
        deserialize_with = "borsh_deserialize_compressed_ristretto",
        serialize_with = "borsh_serialize_compressed_ristretto"
    )]
    authentication_cpk: CompressedRistretto,
    #[borsh(
        deserialize_with = "borsh_deserialize_compressed_ristretto",
        serialize_with = "borsh_serialize_compressed_ristretto"
    )]
    randomized_point_0: CompressedRistretto,
    #[borsh(
        deserialize_with = "borsh_deserialize_compressed_ristretto",
        serialize_with = "borsh_serialize_compressed_ristretto"
    )]
    randomized_point_1: CompressedRistretto,
    #[borsh(
        deserialize_with = "borsh_deserialize_scalar",
        serialize_with = "borsh_serialize_scalar"
    )]
    challenge_response: Scalar,
}

impl EpkRotation {
    /// Compute encryption pubkey rotation challenge
    fn challenge(
        siwb_cpk_old: &CompressedRistretto,
        authentication_cpk_old: &CompressedRistretto,
        randomized_point_0: &CompressedRistretto,
        siwb_cpk: &CompressedRistretto,
        authentication_cpk: &CompressedRistretto,
        randomized_point_1: &CompressedRistretto,
    ) -> Scalar {
        // TODO: use blake3 XOF,
        // keyed by `secret_from_xprv(siwb_encryption_xprv)`,
        // once digest 0.11.0 is available
        use sha3::{Digest as _, Sha3_512};
        let mut hasher = Sha3_512::new();
        hasher.update(siwb_cpk_old.as_bytes());
        hasher.update(authentication_cpk_old.as_bytes());
        hasher.update(randomized_point_0.as_bytes());
        hasher.update(siwb_cpk.as_bytes());
        hasher.update(authentication_cpk.as_bytes());
        hasher.update(randomized_point_1.as_bytes());
        curve25519_dalek::Scalar::from_hash(hasher)
    }

    /// Verify an EPK rotation, obtaining an authentication pubkey if successful
    fn verify(
        &self,
        siwb_xpub: &XPub,
        service_bitname: &BitName,
        register_as_xpub_old: XPub,
        authentication_pk_old: &RistrettoPoint,
    ) -> anyhow::Result<RistrettoPoint> {
        let siwb_xpub_old = derive_xpub(
            register_as_xpub_old,
            &sign_in_with_bitnames_non_hardened_derivation_path(
                service_bitname,
            ),
        )?;
        let siwb_pubkey_old =
            ristretto_point_from_ed25519_xpub(&siwb_xpub_old)?;
        let siwb_pubkey = ristretto_point_from_ed25519_xpub(siwb_xpub)?;
        let challenge = Self::challenge(
            &siwb_pubkey_old.compress(),
            &authentication_pk_old.compress(),
            &self.randomized_point_0,
            &siwb_pubkey.compress(),
            &self.authentication_cpk,
            &self.randomized_point_1,
        );
        let Some(randomized_point_0) = self.randomized_point_0.decompress()
        else {
            anyhow::bail!("Failed to decompress randomized point 0")
        };
        if siwb_pubkey_old * self.challenge_response
            != randomized_point_0 + (authentication_pk_old * challenge)
        {
            anyhow::bail!("Invalid challenge response")
        }
        let Some(authentication_pk) = self.authentication_cpk.decompress()
        else {
            anyhow::bail!("Failed to decompress authentication cpk")
        };
        let Some(randomized_point_1) = self.randomized_point_1.decompress()
        else {
            anyhow::bail!("Failed to decompress randomized point 1")
        };
        if siwb_pubkey * self.challenge_response
            == randomized_point_1 + (authentication_pk * challenge)
        {
            Ok(authentication_pk)
        } else {
            Err(anyhow::anyhow!("Invalid challenge response"))
        }
    }
}

fn rotate_epk(
    wallet: &Wallet,
    rotxn: &RoTxn,
    register_as_bitname: BitName,
    register_as_xpub: XPub,
    service_bitname: &BitName,
    authentication_pubkey_old: &RistrettoPoint,
) -> anyhow::Result<EpkRotation> {
    // FIXME: implement
    let authentication_xprv: XPrv = todo!();
    let authentication_secret = secret_from_xprv(&authentication_xprv);
    let random_scalar = {
        // TODO: use blake3 XOF,
        // keyed by `secret_from_xprv(siwb_encryption_xprv)`,
        // once digest 0.11.0 is available
        use sha3::{Digest as _, Sha3_512};
        let mut hasher = Sha3_512::new();
        hasher.update(register_as_xpub.public_key_bytes());
        hasher.update(register_as_xpub.chain_code());
        hasher.update(authentication_secret);
        hasher.update(authentication_pubkey_old.compress().as_bytes());
        curve25519_dalek::Scalar::from_hash(hasher)
    };
    let authentication_secret =
        curve25519_dalek::Scalar::from_bytes_mod_order(*authentication_secret);
    let siwb_pubkey_old =
        authentication_pubkey_old * authentication_secret.invert();
    let randomized_point_0 = (siwb_pubkey_old * random_scalar).compress();
    let siwb_xpub = derive_xpub(
        register_as_xpub,
        &sign_in_with_bitnames_non_hardened_derivation_path(service_bitname),
    )?;
    let siwb_pubkey = ristretto_point_from_ed25519_xpub(&siwb_xpub)?;
    let authentication_cpk = (siwb_pubkey * authentication_secret).compress();
    let randomized_point_1 = (siwb_pubkey * random_scalar).compress();
    let challenge = EpkRotation::challenge(
        &siwb_pubkey_old.compress(),
        &authentication_pubkey_old.compress(),
        &randomized_point_0,
        &siwb_pubkey.compress(),
        &authentication_cpk,
        &randomized_point_1,
    );
    let challenge_response =
        random_scalar + (challenge * authentication_secret);
    Ok(EpkRotation {
        authentication_cpk,
        randomized_point_0,
        randomized_point_1,
        challenge_response,
    })
}

#[derive(BorshSerialize, Debug)]
struct AuthenticationChallengePlaintextRef<'a, C> {
    challenge: &'a C,
    #[borsh(
        deserialize_with = "borsh_deserialize_compressed_ristretto",
        serialize_with = "borsh_serialize_compressed_ristretto"
    )]
    registered_authentication_cpk: &'a CompressedRistretto,
}

#[derive(BorshDeserialize, Debug)]
pub struct AuthenticationChallengePlaintext<C> {
    pub challenge: C,
    #[borsh(
        deserialize_with = "borsh_deserialize_compressed_ristretto",
        serialize_with = "borsh_serialize_compressed_ristretto"
    )]
    pub registered_authentication_cpk: CompressedRistretto,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct AuthenticationChallenge<C> {
    /// The user bitname that the sign-in is for
    pub bitname: BitName,
    pub ciphertext: Vec<u8>,
    pub encryption_nonce: [u8; 24],
    #[borsh(skip)]
    _marker: PhantomData<C>,
}

impl<C> AuthenticationChallenge<C> {
    /// Generate an authentication challenge for a user.
    /// The user's encryption xpub should be resolved via BitNames.
    pub fn new(
        user_bitname: BitName,
        user_encryption_xpub_resolved: XPub,
        authentication_pubkey: &RistrettoPoint,
        service_bitname: &BitName,
        encryption_secret: x25519_dalek::StaticSecret,
        challenge: &C,
    ) -> anyhow::Result<Self>
    where
        C: BorshDeserialize + BorshSerialize,
    {
        let siwb_xpub = derive_xpub(
            user_encryption_xpub_resolved,
            &sign_in_with_bitnames_non_hardened_derivation_path(
                service_bitname,
            ),
        )?;
        let (encryption_nonce, ciphertext) = {
            let chacha_box = crypto_box::ChaChaBox::new(
                &siwb_xpub.public_key().into(),
                &encryption_secret.to_bytes().into(),
            );
            let nonce = ChaChaBox::generate_nonce(&mut OsRng);
            let challenge_plaintext = AuthenticationChallengePlaintextRef {
                challenge,
                registered_authentication_cpk: &authentication_pubkey
                    .compress(),
            };
            let challenge_plaintext = borsh::to_vec(&challenge_plaintext)?;
            let payload = crypto_box::aead::Payload {
                msg: challenge_plaintext.as_slice(),
                aad: &user_bitname.0,
            };
            (nonce.into(), chacha_box.encrypt(&nonce, payload)?)
        };
        Ok(Self {
            bitname: user_bitname,
            ciphertext,
            encryption_nonce,
            _marker: PhantomData,
        })
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
struct AuthenticationResponsePlaintext {
    signature: Signature,
    epk_rotation: Option<EpkRotation>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticationResponse {
    pub ciphertext: Vec<u8>,
    pub encryption_nonce: [u8; 24],
}

impl AuthenticationResponse {
    /// Validate authentication response,
    /// returning the new authentication pubkey
    fn validate<C>(
        &self,
        register_as_xpub: XPub,
        register_as_xpub_old: XPub,
        mut authentication_pk: RistrettoPoint,
        challenge: C,
        service_bitname: &BitName,
        encryption_secret: x25519_dalek::StaticSecret,
    ) -> anyhow::Result<RistrettoPoint>
    where
        C: BorshSerialize,
    {
        let siwb_xpub = derive_xpub(
            register_as_xpub,
            &sign_in_with_bitnames_non_hardened_derivation_path(
                service_bitname,
            ),
        )?;
        let response_plaintext: AuthenticationResponsePlaintext = {
            let chacha_box = crypto_box::ChaChaBox::new(
                &siwb_xpub.public_key().into(),
                &encryption_secret.to_bytes().into(),
            );
            let payload = crypto_box::aead::Payload {
                msg: self.ciphertext.as_slice(),
                aad: &[],
            };
            let decrypted_bytes =
                chacha_box.decrypt(&self.encryption_nonce.into(), payload)?;
            borsh::from_slice(&decrypted_bytes)?
        };
        if let Some(epk_rotation) = response_plaintext.epk_rotation {
            authentication_pk = epk_rotation.verify(
                &siwb_xpub,
                service_bitname,
                register_as_xpub_old,
                &authentication_pk,
            )?;
        }
        // Verify signature
        {
            // x25519 DH
            let shared_secret = {
                let authentication_pk_x25519 =
                    ristretto_point_to_x25519_pk(authentication_pk);
                encryption_secret.diffie_hellman(&authentication_pk_x25519)
            };
            // Use shared secret as signing key for ed25519 signature
            let shared_signing_key = ed25519_dalek::SigningKey::from_bytes(
                &shared_secret.to_bytes(),
            );
            // TODO: use blake3 XOF,
            // keyed by `secret_from_xprv(siwb_encryption_xprv)`,
            // once digest 0.11.0 is available
            use sha3::{Digest as _, Sha3_512};
            let mut hasher = Sha3_512::new();
            hasher.update(service_bitname.0);
            borsh::to_writer(&mut hasher, &challenge)?;
            let () = shared_signing_key.verify_prehashed(
                hasher,
                None,
                &response_plaintext.signature.0,
            )?;
        }
        Ok(authentication_pk)
    }
}

/// Authenticate to a service.
/// The challenge validation function must return `Some(_)` to sign the
/// challenge, and `None` to reject it.
fn authenticate<C, F, T>(
    wallet: &Wallet,
    rotxn: &RoTxn,
    auth_as_epk: &EncryptionPubKey,
    service_bitname: &BitName,
    service_epk: EncryptionPubKey,
    challenge: &AuthenticationChallenge<C>,
    validate_challenge: F,
) -> anyhow::Result<AuthenticationResponse>
where
    C: BorshDeserialize + BorshSerialize,
    F: FnOnce(&C) -> anyhow::Result<Option<T>>,
{
    let auth_as_epk_xprv =
        wallet.get_encryption_xprv_for_epk(rotxn, auth_as_epk)?;
    let siwb_encryption_xprv = wallet::derive_xprv(
        auth_as_epk_xprv,
        &sign_in_with_bitnames_non_hardened_derivation_path(service_bitname),
    );
    let siwb_pk_secret = secret_from_xprv(&siwb_encryption_xprv);
    let siwb_pk_secret =
        curve25519_dalek::Scalar::from_bytes_mod_order(*siwb_pk_secret);
    let challenge_plaintext: AuthenticationChallengePlaintext<C> = {
        let chacha_box = crypto_box::ChaChaBox::new(
            &service_epk.into(),
            &siwb_pk_secret.into(),
        );
        let payload = crypto_box::aead::Payload {
            msg: challenge.ciphertext.as_slice(),
            aad: &challenge.bitname.0,
        };
        let decrypted_bytes =
            chacha_box.decrypt(&challenge.encryption_nonce.into(), payload)?;
        borsh::from_slice(&decrypted_bytes)?
    };
    let Some(value) = validate_challenge(&challenge_plaintext.challenge)?
    else {
        anyhow::bail!("Challenge validation was not successful")
    };
    // FIXME: implement
    let authentication_xprv: XPrv = todo!();
    // Sign challenge
    let signature = {
        let authentication_secret = secret_from_xprv(&authentication_xprv);
        // x25519 DH
        let shared_secret =
            x25519_dalek::StaticSecret::from(*authentication_secret)
                .diffie_hellman(&service_epk.0);
        // Use shared secret as signing key for ed25519 signature
        let shared_signing_key =
            ed25519_dalek::SigningKey::from_bytes(&shared_secret.to_bytes());
        // TODO: use blake3 XOF,
        // keyed by `secret_from_xprv(siwb_encryption_xprv)`,
        // once digest 0.11.0 is available
        use sha3::{Digest as _, Sha3_512};
        let mut hasher = Sha3_512::new();
        hasher.update(service_bitname.0);
        borsh::to_writer(&mut hasher, &challenge_plaintext.challenge)?;
        shared_signing_key
            .sign_prehashed(hasher, None)
            .map(Signature)?
    };
    let authentication_pubkey =
        ristretto_point_from_ed25519_xpub(&authentication_xprv.public())?;
    let epk_rotation = if challenge_plaintext.registered_authentication_cpk
        != authentication_pubkey.compress()
    {
        let Some(authentication_pubkey_old) = challenge_plaintext
            .registered_authentication_cpk
            .decompress()
        else {
            anyhow::bail!("Failed to decompress authentication cpk")
        };
        Some(rotate_epk(
            wallet,
            rotxn,
            challenge.bitname,
            auth_as_epk_xprv.public(),
            service_bitname,
            &authentication_pubkey_old,
        )?)
    } else {
        None
    };
    let (encryption_nonce, ciphertext) = {
        let chacha_box = crypto_box::ChaChaBox::new(
            &service_epk.into(),
            &siwb_pk_secret.to_bytes().into(),
        );
        let nonce = ChaChaBox::generate_nonce(&mut OsRng);
        let response_plaintext = AuthenticationResponsePlaintext {
            signature,
            epk_rotation,
        };
        let response_plaintext = borsh::to_vec(&response_plaintext)?;
        let payload = crypto_box::aead::Payload {
            msg: response_plaintext.as_slice(),
            aad: &[],
        };
        (nonce.into(), chacha_box.encrypt(&nonce, payload)?)
    };
    Ok(AuthenticationResponse {
        ciphertext,
        encryption_nonce,
    })
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{Scalar, ristretto::RistrettoPoint};
    use ed25519_bip32::{XPrv, XPub};

    /// Generate master xprv from seed entropy
    fn master_xprv(seed_entropy_bytes: &[u8]) -> anyhow::Result<XPrv> {
        use bitcoin::hashes::{Hash as _, HashEngine as _, sha256};
        let master_secret = blake3::hash(seed_entropy_bytes);
        // Derived as described in
        // https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf
        let root_chain_code: [u8; 32] = {
            let mut hasher = sha256::HashEngine::default();
            hasher.input(&[0x01]);
            hasher.input(master_secret.as_bytes());
            assert_eq!(hasher.n_bytes_hashed(), 33);
            sha256::Hash::from_engine(hasher).to_byte_array()
        };
        ed25519_bip32::XPrv::from_nonextended_noforce(
            master_secret.as_bytes(),
            &root_chain_code,
        )
        .map_err(|()| anyhow::anyhow!("Invalid master secret"))
    }

    /// Returns XPrv and XPub derived separately from master XPrv/XPub,
    /// respectively
    fn non_hardened_derivation(
        master_xprv: &XPrv,
        index: u32,
    ) -> anyhow::Result<(XPrv, XPub)> {
        use bitcoin::bip32::ChildNumber;
        use ed25519_bip32::DerivationScheme;
        let master_xpub = master_xprv.public();
        let child_idx = ChildNumber::Normal { index };
        let child_xprv =
            master_xprv.derive(DerivationScheme::V2, child_idx.into());
        // public derivation for child xpub
        let child_xpub =
            master_xpub.derive(DerivationScheme::V2, child_idx.into())?;
        Ok((child_xprv, child_xpub))
    }

    #[test]
    fn test_non_hardened_derivation() -> anyhow::Result<()> {
        let master_xprv = master_xprv(b"test non-hardened derivation")?;
        for index in (69_420..).take(16) {
            let (child_xprv, child_xpub) =
                non_hardened_derivation(&master_xprv, index)?;
            anyhow::ensure!(child_xprv.public() == child_xpub);
        }
        Ok(())
    }

    fn curve25519_scalar_from_ed25519_xprv(xprv: &XPrv) -> Scalar {
        let (secret_bytes, _): (&[u8; 32], _) = xprv
            .extended_secret_key_bytes()
            .split_first_chunk()
            .unwrap();
        curve25519_dalek::Scalar::from_bytes_mod_order(*secret_bytes)
    }

    fn ristretto_pk_from_ed25519_xprv(xprv: &XPrv) -> RistrettoPoint {
        let scalar = curve25519_scalar_from_ed25519_xprv(xprv);
        RistrettoPoint::mul_base(&scalar)
    }

    #[test]
    fn test_non_hardened_derivation_ristretto() -> anyhow::Result<()> {
        let master_xprv = master_xprv(
            b"Test non-hardened derivation Ristretto master secret",
        )?;
        for index in (69_420..).take(16) {
            let (child_xprv, child_xpub) =
                non_hardened_derivation(&master_xprv, index)?;
            let private_derived_ristretto_pk =
                super::ristretto_point_from_ed25519_xpub(&child_xprv.public())?;
            let public_derived_ristretto_pk =
                super::ristretto_point_from_ed25519_xpub(&child_xpub)?;
            anyhow::ensure!(
                private_derived_ristretto_pk == public_derived_ristretto_pk
            );
            // Check that secret still corresponds to pub key
            let pk_from_secret = ristretto_pk_from_ed25519_xprv(&child_xprv);
            anyhow::ensure!(private_derived_ristretto_pk == pk_from_secret);
        }
        Ok(())
    }
}
