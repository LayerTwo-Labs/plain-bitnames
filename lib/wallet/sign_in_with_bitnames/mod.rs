//! Sign in with BitNames

use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, AeadCore, OsRng, Payload as AeadPayload},
};
use curve25519_dalek::{
    RistrettoPoint, Scalar, ristretto::CompressedRistretto,
};
use ed25519_bip32::{XPrv, XPub};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::ToSchema;

use crate::{
    authorization::Signature,
    types::{BitName, EncryptionPubKey, serde_hexstr_human_readable},
    wallet::util::{KnownBip32Path, derive_xprv, derive_xpub},
};

pub(in crate::wallet) mod error;

#[derive(Clone, Debug, ToSchema)]
#[repr(transparent)]
#[schema(value_type = String)]
pub struct CompressedAuthenticationPubkey(pub CompressedRistretto);

impl<'de> Deserialize<'de> for CompressedAuthenticationPubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = if deserializer.is_human_readable() {
            hex::deserialize(deserializer)?
        } else {
            <[u8; 32] as Deserialize>::deserialize(deserializer)?
        };
        Ok(Self(CompressedRistretto(bytes)))
    }
}

impl Serialize for CompressedAuthenticationPubkey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            hex::serialize(self.0.as_bytes(), serializer)
        } else {
            <[u8; 32] as Serialize>::serialize(self.0.as_bytes(), serializer)
        }
    }
}

impl std::str::FromStr for CompressedAuthenticationPubkey {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = <[u8; 32] as hex::FromHex>::from_hex(s)?;
        Ok(Self(CompressedRistretto(bytes)))
    }
}

fn secret_from_xprv(xprv: &XPrv) -> &[u8; 32] {
    let (secret_bytes, _): (&[u8; 32], _) = xprv
        .extended_secret_key_bytes()
        .split_first_chunk()
        .unwrap();
    secret_bytes
}

#[cfg(test)]
fn secret_scalar_from_xprv(xprv: &XPrv) -> curve25519_dalek::Scalar {
    curve25519_dalek::Scalar::from_bytes_mod_order(*secret_from_xprv(xprv))
}

fn ristretto_from_edwards(
    point: curve25519_dalek::EdwardsPoint,
) -> RistrettoPoint {
    // SAFETY: RistrettoPoint is just a wrapper around EdwardsPoint
    unsafe { std::mem::transmute(point) }
}

fn edwards_from_ristretto(
    point: RistrettoPoint,
) -> curve25519_dalek::EdwardsPoint {
    // SAFETY: RistrettoPoint is just a wrapper around EdwardsPoint
    unsafe { std::mem::transmute(point) }
}

fn x25519_pk_from_edwards(
    point: &curve25519_dalek::EdwardsPoint,
) -> x25519_dalek::PublicKey {
    point.to_montgomery().to_bytes().into()
}

fn ristretto_point_from_curve25519_edwards_compressed(
    compressed_edwards: [u8; 32],
) -> Result<RistrettoPoint, error::DecompressEdwards> {
    curve25519_dalek::edwards::CompressedEdwardsY(compressed_edwards)
        .decompress()
        .ok_or(error::DecompressEdwards { compressed_edwards })
        .map(ristretto_from_edwards)
}

fn x25519_pk_from_curve25519_edwards_compressed(
    compressed_edwards: [u8; 32],
) -> Result<x25519_dalek::PublicKey, error::DecompressEdwards> {
    curve25519_dalek::edwards::CompressedEdwardsY(compressed_edwards)
        .decompress()
        .ok_or(error::DecompressEdwards { compressed_edwards })
        .map(|edwards| x25519_pk_from_edwards(&edwards))
}

fn ristretto_point_from_ed25519_xpub(
    xpub: &XPub,
) -> Result<RistrettoPoint, error::DecompressEdwards> {
    ristretto_point_from_curve25519_edwards_compressed(xpub.public_key())
}

fn x25519_pk_from_ed25519_xpub(
    xpub: &XPub,
) -> Result<x25519_dalek::PublicKey, error::DecompressEdwards> {
    x25519_pk_from_curve25519_edwards_compressed(xpub.public_key())
}

fn x25519_pk_from_ristretto(point: RistrettoPoint) -> x25519_dalek::PublicKey {
    let point = point.compress().decompress().unwrap();
    edwards_from_ristretto(point)
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

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct Registration {
    pub bitname: BitName,
    #[serde(with = "serde_hexstr_human_readable")]
    #[cfg_attr(feature = "clap", arg(
        long,
        value_parser = |s: &str| hex::decode(s)
    ))]
    pub ciphertext: Vec<u8>,
    #[serde(with = "serde_hexstr_human_readable")]
    #[cfg_attr(feature = "clap", arg(
        long,
        value_parser = |s: &str| <[u8; 24] as hex::FromHex>::from_hex(s)
    ))]
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
    pub(in crate::wallet) fn verify(
        &self,
        register_as_encryption_xpub: XPub,
        service_bitname: BitName,
        encryption_secret: x25519_dalek::StaticSecret,
    ) -> Result<RistrettoPoint, error::VerifyRegistration> {
        let siwb_encryption_xpub = derive_xpub(
            register_as_encryption_xpub,
            &KnownBip32Path::SiwbEncryptionFromEpk { service_bitname }.into(),
        )
        .map_err(error::VerifyRegistrationInner::DeriveSiwbEncryptionXpub)?;
        let registration_plaintext: RegistrationPlaintext = {
            let shared_secret = encryption_secret.diffie_hellman(
                &x25519_pk_from_ed25519_xpub(&siwb_encryption_xpub)?,
            );
            let cipher =
                XChaCha20Poly1305::new(&shared_secret.to_bytes().into());
            let payload = AeadPayload {
                msg: self.ciphertext.as_slice(),
                aad: &self.bitname.0,
            };
            let decrypted_bytes =
                cipher.decrypt(&self.encryption_nonce.into(), payload)?;
            borsh::from_slice(&decrypted_bytes)?
        };
        let siwb_encryption_pk =
            ristretto_point_from_ed25519_xpub(&siwb_encryption_xpub)?;
        let challenge = Self::challenge(
            &siwb_encryption_pk.compress(),
            &registration_plaintext.authentication_cpk,
            &registration_plaintext.randomized_point,
        );
        let authentication_pk = registration_plaintext
            .authentication_cpk
            .decompress()
            .ok_or(error::VerifyRegistrationInner::DecompressAuthCpk)?;
        let randomized_point = registration_plaintext
            .randomized_point
            .decompress()
            .ok_or(error::VerifyRegistrationInner::DecompressRandomizedPoint)?;
        if siwb_encryption_pk * registration_plaintext.challenge_response
            == randomized_point + (authentication_pk * challenge)
        {
            Ok(authentication_pk)
        } else {
            Err(error::VerifyRegistrationInner::InvalidChallengeResponse.into())
        }
    }
}

/// Register using the specified BitName and EncryptionPubKey, for the
/// service with the specified BitName and EncryptionPubKey
pub(in crate::wallet) fn register_as(
    register_as_bitname: BitName,
    register_as_encryption_xprv: XPrv,
    siwb_authentication_xprv: XPrv,
    service_bitname: BitName,
    service_epk: &EncryptionPubKey,
) -> Result<Registration, error::RegisterAs> {
    let siwb_encryption_xprv = derive_xprv(
        register_as_encryption_xprv,
        &KnownBip32Path::SiwbEncryptionFromEpk { service_bitname }.into(),
    );
    let siwb_pk_secret = *secret_from_xprv(&siwb_encryption_xprv);
    let siwb_authentication_secret =
        secret_from_xprv(&siwb_authentication_xprv);
    let random_scalar = {
        // TODO: use blake3 XOF,
        // keyed by `secret_from_xprv(siwb_encryption_xprv)`,
        // once digest 0.11.0 is available
        use sha3::{Digest as _, Sha3_512};
        // `register_as_epk` and `service_bitname` also contribute to the hash
        // via `siwb_encryption_xprv`
        let mut hasher = Sha3_512::new();
        hasher.update(siwb_pk_secret);
        hasher.update(siwb_authentication_secret);
        hasher.update(register_as_bitname.0);
        hasher.update(service_epk.0.as_bytes());
        curve25519_dalek::Scalar::from_hash(hasher)
    };
    let siwb_pk = {
        let siwb_pk_secret =
            curve25519_dalek::Scalar::from_bytes_mod_order(siwb_pk_secret);
        RistrettoPoint::mul_base(&siwb_pk_secret)
    };
    let randomized_point = (siwb_pk * random_scalar).compress();
    let siwb_authentication_secret =
        curve25519_dalek::Scalar::from_bytes_mod_order(
            *siwb_authentication_secret,
        );
    let siwb_authentication_cpk =
        (siwb_pk * siwb_authentication_secret).compress();
    let challenge = Registration::challenge(
        &siwb_pk.compress(),
        &siwb_authentication_cpk,
        &randomized_point,
    );
    let challenge_response =
        random_scalar + (challenge * siwb_authentication_secret);
    let (encryption_nonce, ciphertext) = {
        let shared_secret = x25519_dalek::StaticSecret::from(siwb_pk_secret)
            .diffie_hellman(&service_epk.0);
        let cipher = XChaCha20Poly1305::new(&shared_secret.to_bytes().into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let registration_plaintext = borsh::to_vec(&RegistrationPlaintext {
            authentication_cpk: siwb_authentication_cpk,
            randomized_point,
            challenge_response,
        })?;
        let payload = AeadPayload {
            msg: registration_plaintext.as_slice(),
            aad: &register_as_bitname.0,
        };
        (nonce.into(), cipher.encrypt(&nonce, payload)?)
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
        service_bitname: BitName,
        register_as_xpub_old: XPub,
        authentication_pk_old: &RistrettoPoint,
    ) -> Result<RistrettoPoint, error::VerifyEpkRotation> {
        let siwb_xpub_old = derive_xpub(
            register_as_xpub_old,
            &KnownBip32Path::SiwbEncryptionFromEpk { service_bitname }.into(),
        )
        .map_err(error::VerifyEpkRotationInner::DerivePreviousSiwbXpub)?;
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
        let randomized_point_0 = self
            .randomized_point_0
            .decompress()
            .ok_or(error::VerifyEpkRotationInner::DecompressRandomizedPoint0)?;
        if siwb_pubkey_old * self.challenge_response
            != randomized_point_0 + (authentication_pk_old * challenge)
        {
            return Err(
                error::VerifyEpkRotationInner::InvalidChallengeResponse.into(),
            );
        }
        let authentication_pk = self
            .authentication_cpk
            .decompress()
            .ok_or(error::VerifyEpkRotationInner::DecompressAuthCpk)?;
        let randomized_point_1 = self
            .randomized_point_1
            .decompress()
            .ok_or(error::VerifyEpkRotationInner::DecompressRandomizedPoint1)?;
        if siwb_pubkey * self.challenge_response
            == randomized_point_1 + (authentication_pk * challenge)
        {
            Ok(authentication_pk)
        } else {
            Err(error::VerifyEpkRotationInner::InvalidChallengeResponse.into())
        }
    }
}

fn rotate_epk(
    register_as_encryption_xpub: XPub,
    siwb_authentication_xprv: XPrv,
    service_bitname: BitName,
    authentication_pubkey_old: &RistrettoPoint,
) -> Result<EpkRotation, error::RotateEpk> {
    let siwb_authentication_secret =
        secret_from_xprv(&siwb_authentication_xprv);
    let random_scalar = {
        // TODO: use blake3 XOF,
        // keyed by `secret_from_xprv(siwb_encryption_xprv)`,
        // once digest 0.11.0 is available
        use sha3::{Digest as _, Sha3_512};
        let mut hasher = Sha3_512::new();
        hasher.update(register_as_encryption_xpub.public_key_bytes());
        hasher.update(register_as_encryption_xpub.chain_code());
        hasher.update(siwb_authentication_secret);
        hasher.update(authentication_pubkey_old.compress().as_bytes());
        curve25519_dalek::Scalar::from_hash(hasher)
    };
    let siwb_authentication_secret =
        curve25519_dalek::Scalar::from_bytes_mod_order(
            *siwb_authentication_secret,
        );
    let siwb_pubkey_old =
        authentication_pubkey_old * siwb_authentication_secret.invert();
    let randomized_point_0 = (siwb_pubkey_old * random_scalar).compress();
    let siwb_encryption_xpub = derive_xpub(
        register_as_encryption_xpub,
        &KnownBip32Path::SiwbEncryptionFromEpk { service_bitname }.into(),
    )
    .map_err(error::RotateEpkInner::DeriveSiwbEncryptionXpub)?;
    let siwb_encryption_pk =
        ristretto_point_from_ed25519_xpub(&siwb_encryption_xpub)?;
    let authentication_cpk =
        (siwb_encryption_pk * siwb_authentication_secret).compress();
    let randomized_point_1 = (siwb_encryption_pk * random_scalar).compress();
    let challenge = EpkRotation::challenge(
        &siwb_pubkey_old.compress(),
        &authentication_pubkey_old.compress(),
        &randomized_point_0,
        &siwb_encryption_pk.compress(),
        &authentication_cpk,
        &randomized_point_1,
    );
    let challenge_response =
        random_scalar + (challenge * siwb_authentication_secret);
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

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Debug,
    Deserialize,
    Serialize,
    ToSchema,
)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct AuthenticationChallenge<C> {
    /// The user bitname that the sign-in is for
    #[cfg_attr(feature = "clap", arg(long))]
    pub bitname: BitName,
    #[serde(with = "serde_hexstr_human_readable")]
    #[cfg_attr(feature = "clap", arg(
        long,
        value_parser = |s: &str| hex::decode(s)
    ))]
    pub ciphertext: Vec<u8>,
    #[serde(with = "serde_hexstr_human_readable")]
    #[cfg_attr(feature = "clap", arg(
        long,
        value_parser = |s: &str| <[u8; 24] as hex::FromHex>::from_hex(s)
    ))]
    pub encryption_nonce: [u8; 24],
    #[borsh(skip)]
    #[cfg_attr(feature = "clap", arg(skip))]
    #[serde(skip)]
    _marker: PhantomData<C>,
}

impl<C> AuthenticationChallenge<C> {
    /// Generate an authentication challenge for a user.
    /// The user's encryption xpub should be resolved via BitNames.
    pub fn new(
        user_bitname: BitName,
        user_encryption_xpub_resolved: XPub,
        authentication_pubkey: &RistrettoPoint,
        service_bitname: BitName,
        encryption_secret: x25519_dalek::StaticSecret,
        challenge: &C,
    ) -> Result<Self, error::GenerateAuthChallenge>
    where
        C: BorshDeserialize + BorshSerialize,
    {
        let siwb_xpub = derive_xpub(
            user_encryption_xpub_resolved,
            &KnownBip32Path::SiwbEncryptionFromEpk { service_bitname }.into(),
        )
        .map_err(error::GenerateAuthChallengeInner::DeriveSiwbXpub)?;
        let (encryption_nonce, ciphertext) = {
            let shared_secret = encryption_secret
                .diffie_hellman(&x25519_pk_from_ed25519_xpub(&siwb_xpub)?);
            let cipher =
                XChaCha20Poly1305::new(&shared_secret.to_bytes().into());
            let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
            let challenge_plaintext = AuthenticationChallengePlaintextRef {
                challenge,
                registered_authentication_cpk: &authentication_pubkey
                    .compress(),
            };
            let challenge_plaintext = borsh::to_vec(&challenge_plaintext)?;
            let payload = AeadPayload {
                msg: challenge_plaintext.as_slice(),
                aad: &user_bitname.0,
            };
            (nonce.into(), cipher.encrypt(&nonce, payload)?)
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

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct AuthenticationResponse {
    #[serde(with = "serde_hexstr_human_readable")]
    #[cfg_attr(feature = "clap", arg(
        long,
        value_parser = |s: &str| hex::decode(s)
    ))]
    pub ciphertext: Vec<u8>,
    #[serde(with = "serde_hexstr_human_readable")]
    #[cfg_attr(feature = "clap", arg(
        long,
        value_parser = |s: &str| <[u8; 24] as hex::FromHex>::from_hex(s)
    ))]
    pub encryption_nonce: [u8; 24],
}

impl AuthenticationResponse {
    /// Validate authentication response,
    /// returning the new authentication pubkey
    pub(in crate::wallet) fn verify<C>(
        &self,
        register_as_encryption_xpub: XPub,
        register_as_encryption_xpub_old: XPub,
        mut authentication_pk: RistrettoPoint,
        challenge: C,
        service_bitname: BitName,
        encryption_secret: x25519_dalek::StaticSecret,
    ) -> Result<RistrettoPoint, error::VerifyAuth>
    where
        C: BorshSerialize,
    {
        let siwb_encryption_xpub = derive_xpub(
            register_as_encryption_xpub,
            &KnownBip32Path::SiwbEncryptionFromEpk { service_bitname }.into(),
        )
        .map_err(error::VerifyAuthInner::DeriveSiwbEncryptionXpub)?;
        let response_plaintext: AuthenticationResponsePlaintext = {
            let shared_secret = encryption_secret.diffie_hellman(
                &x25519_pk_from_ed25519_xpub(&siwb_encryption_xpub)?,
            );
            let cipher =
                XChaCha20Poly1305::new(&shared_secret.to_bytes().into());
            let payload = AeadPayload {
                msg: self.ciphertext.as_slice(),
                aad: &[],
            };
            let decrypted_bytes = cipher
                .decrypt(&self.encryption_nonce.into(), payload)
                .map_err(error::VerifyAuthInner::DecryptCiphertext)?;
            borsh::from_slice(&decrypted_bytes)
                .map_err(error::VerifyAuthInner::DeserializePlaintext)?
        };
        if let Some(epk_rotation) = response_plaintext.epk_rotation {
            authentication_pk = epk_rotation.verify(
                &siwb_encryption_xpub,
                service_bitname,
                register_as_encryption_xpub_old,
                &authentication_pk,
            )?;
        }
        // Verify signature
        {
            // x25519 DH
            let shared_secret = {
                let authentication_pk_x25519 =
                    x25519_pk_from_ristretto(authentication_pk);
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
            borsh::to_writer(&mut hasher, &challenge)
                .map_err(error::VerifyAuthInner::SerializeChallenge)?;
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
pub(in crate::wallet) fn authenticate<C, F, E, T>(
    register_as_encryption_xprv: XPrv,
    siwb_authentication_xprv: XPrv,
    service_bitname: BitName,
    service_epk: EncryptionPubKey,
    challenge: &AuthenticationChallenge<C>,
    validate_challenge: F,
) -> Result<(AuthenticationResponse, T), error::Authenticate<E>>
where
    C: BorshDeserialize + BorshSerialize,
    E: std::error::Error,
    F: FnOnce(&C) -> Result<Option<T>, E>,
{
    let siwb_encryption_xprv = derive_xprv(
        register_as_encryption_xprv.clone(),
        &KnownBip32Path::SiwbEncryptionFromEpk { service_bitname }.into(),
    );
    let cipher = {
        let siwb_pk_secret = *secret_from_xprv(&siwb_encryption_xprv);
        let shared_secret = x25519_dalek::StaticSecret::from(siwb_pk_secret)
            .diffie_hellman(&service_epk.0);
        XChaCha20Poly1305::new(&shared_secret.to_bytes().into())
    };
    let challenge_plaintext: AuthenticationChallengePlaintext<C> = {
        let payload = AeadPayload {
            msg: challenge.ciphertext.as_slice(),
            aad: &challenge.bitname.0,
        };
        let decrypted_bytes = cipher
            .decrypt(&challenge.encryption_nonce.into(), payload)
            .map_err(error::AuthenticateInner::DecryptCiphertext)?;
        borsh::from_slice(&decrypted_bytes)
            .map_err(error::AuthenticateInner::DeserializePlaintext)?
    };
    let value = validate_challenge(&challenge_plaintext.challenge)
        .map_err(error::AuthenticateInner::ValidateChallengeFailed)?
        .ok_or(error::AuthenticateInner::ValidateChallenge)?;
    // Sign challenge
    let signature = {
        // x25519 DH
        let shared_secret = {
            let shared_secret_pk = x25519_dalek::x25519(
                *secret_from_xprv(&siwb_authentication_xprv),
                service_epk.0.to_bytes(),
            );
            x25519_dalek::StaticSecret::from(*secret_from_xprv(
                &siwb_encryption_xprv,
            ))
            .diffie_hellman(&x25519_dalek::PublicKey::from(shared_secret_pk))
        };
        // Use shared secret as signing key for ed25519 signature
        let shared_signing_key =
            ed25519_dalek::SigningKey::from_bytes(&shared_secret.to_bytes());
        // TODO: use blake3 XOF,
        // keyed by `secret_from_xprv(siwb_encryption_xprv)`,
        // once digest 0.11.0 is available
        use sha3::{Digest as _, Sha3_512};
        let mut hasher = Sha3_512::new();
        hasher.update(service_bitname.0);
        borsh::to_writer(&mut hasher, &challenge_plaintext.challenge)
            .map_err(error::AuthenticateInner::SerializeChallenge)?;
        match shared_signing_key.sign_prehashed(hasher, None) {
            Ok(signature) => Ok(Signature(signature)),
            Err(err) => Err(error::AuthenticateInner::SignChallenge(err)),
        }
    }?;
    let authentication_pubkey =
        ristretto_point_from_ed25519_xpub(&siwb_authentication_xprv.public())?;
    let epk_rotation = if challenge_plaintext.registered_authentication_cpk
        != authentication_pubkey.compress()
    {
        let authentication_pubkey_old = challenge_plaintext
            .registered_authentication_cpk
            .decompress()
            .ok_or(error::AuthenticateInner::DecompressAuthCpk)?;
        Some(rotate_epk(
            register_as_encryption_xprv.public(),
            siwb_authentication_xprv,
            service_bitname,
            &authentication_pubkey_old,
        )?)
    } else {
        None
    };
    let (encryption_nonce, ciphertext) = {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let response_plaintext = AuthenticationResponsePlaintext {
            signature,
            epk_rotation,
        };
        let response_plaintext = borsh::to_vec(&response_plaintext)
            .map_err(error::AuthenticateInner::SerializeResponse)?;
        let payload = AeadPayload {
            msg: response_plaintext.as_slice(),
            aad: &[],
        };
        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(error::AuthenticateInner::EncryptResponse)?;
        (nonce.into(), ciphertext)
    };
    let authentication_response = AuthenticationResponse {
        ciphertext,
        encryption_nonce,
    };
    Ok((authentication_response, value))
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use ed25519_bip32::{XPrv, XPub};

    use crate::{
        types::BitName,
        wallet::{
            sign_in_with_bitnames::{
                ristretto_point_from_ed25519_xpub, secret_from_xprv,
            },
            util::{KnownBip32Path, derive_xprv},
        },
    };

    /// Generate master xprv from seed entropy
    fn master_xprv(seed_entropy_bytes: &[u8]) -> XPrv {
        use bitcoin::hashes::{Hash as _, HashEngine as _, sha256};
        let mut master_secret: [u8; 32] =
            blake3::hash(seed_entropy_bytes).into();
        loop {
            // Derived as described in
            // https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf
            let root_chain_code: [u8; 32] = {
                let mut hasher = sha256::HashEngine::default();
                hasher.input(&[0x01]);
                hasher.input(&master_secret);
                assert_eq!(hasher.n_bytes_hashed(), 33);
                sha256::Hash::from_engine(hasher).to_byte_array()
            };
            match ed25519_bip32::XPrv::from_nonextended_noforce(
                &master_secret,
                &root_chain_code,
            ) {
                Ok(xprv) => return xprv,
                Err(()) => master_secret = blake3::hash(&master_secret).into(),
            }
        }
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
        let master_xprv = master_xprv(b"test non-hardened derivation");
        for index in (69_420..).take(16) {
            let (child_xprv, child_xpub) =
                non_hardened_derivation(&master_xprv, index)?;
            anyhow::ensure!(child_xprv.public() == child_xpub);
        }
        Ok(())
    }

    fn ristretto_pk_from_ed25519_xprv(xprv: &XPrv) -> RistrettoPoint {
        let scalar = super::secret_scalar_from_xprv(xprv);
        RistrettoPoint::mul_base(&scalar)
    }

    fn canonical_ristretto_pk_from_ed25519_xprv(
        xprv: &XPrv,
    ) -> Option<RistrettoPoint> {
        let point = ristretto_pk_from_ed25519_xprv(xprv);
        let edwards_point = super::edwards_from_ristretto(point);
        let canonical = point.compress().decompress().unwrap();
        let canonical_edwards = super::edwards_from_ristretto(canonical);
        if edwards_point == canonical_edwards {
            Some(point)
        } else {
            None
        }
    }

    fn x25519_pk_from_ed25519_xprv(xprv: &XPrv) -> x25519_dalek::PublicKey {
        let secret =
            x25519_dalek::StaticSecret::from(*super::secret_from_xprv(xprv));
        x25519_dalek::PublicKey::from(&secret)
    }

    #[test]
    fn test_non_hardened_derivation_ristretto() -> anyhow::Result<()> {
        let master_xprv = master_xprv(
            b"Test non-hardened derivation Ristretto master secret",
        );
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

    #[test]
    fn test_non_hardened_derivation_x25519() -> anyhow::Result<()> {
        let master_xprv =
            master_xprv(b"Test non-hardened derivation x25519 master secret");
        for index in (69_420..).take(16) {
            let (child_xprv, child_xpub) =
                non_hardened_derivation(&master_xprv, index)?;
            let private_derived_x25519_pk =
                super::x25519_pk_from_ed25519_xpub(&child_xprv.public())?;
            let public_derived_x25519_pk =
                super::x25519_pk_from_ed25519_xpub(&child_xpub)?;
            anyhow::ensure!(
                private_derived_x25519_pk == public_derived_x25519_pk
            );
            // Check that secret still corresponds to pub key
            let pk_from_secret = x25519_pk_from_ed25519_xprv(&child_xprv);
            anyhow::ensure!(private_derived_x25519_pk == pk_from_secret);
        }
        Ok(())
    }

    #[test]
    fn test_non_hardened_derivation_ristretto_x25519() -> anyhow::Result<()> {
        let master_xprv = master_xprv(
            b"Test non-hardened derivation ristretto-x25519 master secret",
        );
        for index in (69_420..).take(16) {
            let (child_xprv, child_xpub) = {
                let mut xprv = master_xprv.clone();
                'child_xkeys: loop {
                    let (child_xprv, child_xpub) =
                        non_hardened_derivation(&xprv, index)?;
                    if canonical_ristretto_pk_from_ed25519_xprv(&child_xprv)
                        .is_some()
                    {
                        break 'child_xkeys (child_xprv, child_xpub);
                    }
                    xprv = xprv.derive(ed25519_bip32::DerivationScheme::V2, 0);
                }
            };
            let private_derived_ristretto_pk =
                super::ristretto_point_from_ed25519_xpub(&child_xprv.public())?;
            let private_derived_x25519_pk =
                super::x25519_pk_from_ristretto(private_derived_ristretto_pk);
            let public_derived_ristretto_pk =
                super::ristretto_point_from_ed25519_xpub(&child_xpub)?;
            let public_derived_x25519_pk =
                super::x25519_pk_from_ristretto(public_derived_ristretto_pk);
            anyhow::ensure!(
                private_derived_x25519_pk == public_derived_x25519_pk
            );
            // Check that secret still corresponds to pub key
            let pk_from_secret = x25519_pk_from_ed25519_xprv(&child_xprv);
            anyhow::ensure!(private_derived_x25519_pk == pk_from_secret);
        }
        Ok(())
    }

    #[test]
    fn test_registration() -> anyhow::Result<()> {
        let register_as_bitname =
            BitName(blake3::hash(b"Register as BitName").into());
        let service_bitname = BitName(blake3::hash(b"Service BitName").into());
        let register_as_encryption_xprv =
            master_xprv(b"test registration (registrant, encryption)");
        let register_as_auth_xprv =
            master_xprv(b"test registration (registrant, authentication)");
        let service_xprv = master_xprv(b"test registration (service)");
        let register_as_encryption_xpub = register_as_encryption_xprv.public();
        let siwb_encryption_xpub = super::derive_xpub(
            register_as_encryption_xpub,
            &KnownBip32Path::SiwbEncryptionFromEpk { service_bitname }.into(),
        )?;
        let siwb_authentication_xprv = derive_xprv(
            register_as_auth_xprv.clone(),
            &KnownBip32Path::SiwbAuthentication {
                bitname: register_as_bitname,
                service_bitname,
                nonce: 0,
            }
            .into(),
        );
        let siwb_encryption_pk =
            ristretto_point_from_ed25519_xpub(&siwb_encryption_xpub)?;
        let siwb_authentication_pk = siwb_encryption_pk
            * super::secret_scalar_from_xprv(&siwb_authentication_xprv);
        let service_secret = *secret_from_xprv(&service_xprv);
        let service_epk =
            super::x25519_pk_from_ed25519_xpub(&service_xprv.public())?;
        let registration = super::register_as(
            register_as_bitname,
            register_as_encryption_xprv,
            siwb_authentication_xprv,
            service_bitname,
            &service_epk.into(),
        )?;
        let registered_authentication_pk = registration.verify(
            register_as_encryption_xpub,
            service_bitname,
            x25519_dalek::StaticSecret::from(service_secret),
        )?;
        anyhow::ensure!(siwb_authentication_pk == registered_authentication_pk);
        Ok(())
    }

    /// Test authentication, with EPK rotation
    #[test]
    fn test_authentication() -> anyhow::Result<()> {
        let register_as_bitname =
            BitName(blake3::hash(b"Register as BitName").into());
        let service_bitname = BitName(blake3::hash(b"Service BitName").into());
        let register_as_encryption_xprv_0 =
            master_xprv(b"test registration (registrant, encryption 0)");
        let register_as_encryption_xprv_1 =
            master_xprv(b"test registration (registrant, encryption 1)");
        let register_as_auth_xprv =
            master_xprv(b"test registration (registrant, authentication)");
        let service_xprv = {
            let mut xprv = master_xprv(b"test registration (service)");
            while canonical_ristretto_pk_from_ed25519_xprv(&xprv).is_none() {
                xprv = xprv.derive(ed25519_bip32::DerivationScheme::V2, 0);
            }
            xprv
        };
        let register_as_encryption_xpub_0 =
            register_as_encryption_xprv_0.public();
        let register_as_encryption_xpub_1 =
            register_as_encryption_xprv_1.public();
        let siwb_encryption_xprv_0 = derive_xprv(
            register_as_encryption_xprv_0,
            &KnownBip32Path::SiwbEncryptionFromEpk { service_bitname }.into(),
        );
        let siwb_encryption_xprv_1 = derive_xprv(
            register_as_encryption_xprv_1.clone(),
            &KnownBip32Path::SiwbEncryptionFromEpk { service_bitname }.into(),
        );
        let siwb_authentication_xprv = derive_xprv(
            register_as_auth_xprv.clone(),
            &KnownBip32Path::SiwbAuthentication {
                bitname: register_as_bitname,
                service_bitname,
                nonce: 0,
            }
            .into(),
        );
        let siwb_authentication_pk_0 =
            ristretto_pk_from_ed25519_xprv(&siwb_encryption_xprv_0)
                * super::secret_scalar_from_xprv(&siwb_authentication_xprv);
        let siwb_authentication_pk_1 =
            ristretto_pk_from_ed25519_xprv(&siwb_encryption_xprv_1)
                * super::secret_scalar_from_xprv(&siwb_authentication_xprv);
        let service_secret = *secret_from_xprv(&service_xprv);
        let service_epk =
            super::x25519_pk_from_ed25519_xpub(&service_xprv.public())?;
        let challenge = ();
        let authentication_challenge = super::AuthenticationChallenge::new(
            register_as_bitname,
            register_as_encryption_xpub_1,
            &siwb_authentication_pk_0,
            service_bitname,
            x25519_dalek::StaticSecret::from(service_secret),
            &challenge,
        )?;
        let (authentication_response, ()) = super::authenticate(
            register_as_encryption_xprv_1,
            siwb_authentication_xprv,
            service_bitname,
            service_epk.into(),
            &authentication_challenge,
            |_| Ok::<_, std::convert::Infallible>(Some(())),
        )?;
        let registered_authentication_pk_1 = authentication_response.verify(
            register_as_encryption_xpub_1,
            register_as_encryption_xpub_0,
            siwb_authentication_pk_0,
            challenge,
            service_bitname,
            x25519_dalek::StaticSecret::from(service_secret),
        )?;
        anyhow::ensure!(
            siwb_authentication_pk_1 == registered_authentication_pk_1
        );
        Ok(())
    }
}
