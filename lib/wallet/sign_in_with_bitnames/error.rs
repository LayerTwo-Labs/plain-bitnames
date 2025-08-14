use chacha20poly1305::aead::Error as AeadError;
use thiserror::Error;

use crate::wallet;

#[derive(Debug, Error)]
#[error(
    "Failed to decompress edwards point (`{}`)",
    hex::encode(.compressed_edwards)
)]
#[repr(transparent)]
pub(in crate::wallet::sign_in_with_bitnames) struct DecompressEdwards {
    pub compressed_edwards: [u8; 32],
}

#[derive(Debug, Error)]
pub(in crate::wallet::sign_in_with_bitnames) enum RegisterAsInner {
    #[error(transparent)]
    Aead(#[from] AeadError),
    #[error(transparent)]
    BorshSerialize(#[from] borsh::io::Error),
    #[error(transparent)]
    Wallet(#[from] wallet::Error),
}

#[derive(Debug, Error)]
#[error("SIWB registration failed")]
#[repr(transparent)]
pub struct RegisterAs(#[source] RegisterAsInner);

impl<Err> From<Err> for RegisterAs
where
    RegisterAsInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
pub(in crate::wallet::sign_in_with_bitnames) enum VerifyRegistrationInner {
    #[error("failed to decompress authentication cpk")]
    DecompressAuthCpk,
    #[error(transparent)]
    DecompressEdwards(#[from] DecompressEdwards),
    #[error("failed to decompress randomized point")]
    DecompressRandomizedPoint,
    #[error("failed to decrypt registration ciphertext")]
    DecryptCiphertext(#[from] AeadError),
    #[error("failed to derive SIWB encryption XPub")]
    DeriveSiwbEncryptionXpub(#[source] ed25519_bip32::DerivationError),
    #[error("failed to deserialize registration plaintext")]
    DeserializePlaintext(#[from] borsh::io::Error),
    #[error("invalid challenge response")]
    InvalidChallengeResponse,
}

#[derive(Debug, Error)]
#[error("failed to verify SIWB registration")]
#[repr(transparent)]
pub struct VerifyRegistration(#[source] VerifyRegistrationInner);

impl<Err> From<Err> for VerifyRegistration
where
    VerifyRegistrationInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
pub(in crate::wallet::sign_in_with_bitnames) enum VerifyEpkRotationInner {
    #[error("failed to decompress authentication cpk")]
    DecompressAuthCpk,
    #[error(transparent)]
    DecompressEdwards(#[from] DecompressEdwards),
    #[error("failed to decompress randomized point 0")]
    DecompressRandomizedPoint0,
    #[error("failed to decompress randomized point 1")]
    DecompressRandomizedPoint1,
    #[error("failed to derive previous SIWB XPub")]
    DerivePreviousSiwbXpub(#[source] ed25519_bip32::DerivationError),
    #[error("invalid challenge response")]
    InvalidChallengeResponse,
}

#[derive(Debug, Error)]
#[error("failed to verify SIWB encryption pubkey rotation")]
#[repr(transparent)]
pub struct VerifyEpkRotation(#[source] VerifyEpkRotationInner);

impl<Err> From<Err> for VerifyEpkRotation
where
    VerifyEpkRotationInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
pub(in crate::wallet::sign_in_with_bitnames) enum RotateEpkInner {
    #[error(transparent)]
    DecompressEdwards(#[from] DecompressEdwards),
    #[error("failed to derive SIWB encryption XPub")]
    DeriveSiwbEncryptionXpub(#[source] ed25519_bip32::DerivationError),
}

#[derive(Debug, Error)]
#[error("failed to generate EPK rotation proof")]
#[repr(transparent)]
pub struct RotateEpk(#[source] RotateEpkInner);

impl<Err> From<Err> for RotateEpk
where
    RotateEpkInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
pub(in crate::wallet::sign_in_with_bitnames) enum GenerateAuthChallengeInner {
    #[error(transparent)]
    DecompressEdwards(#[from] DecompressEdwards),
    #[error("failed to derive SIWB XPub")]
    DeriveSiwbXpub(#[source] ed25519_bip32::DerivationError),
    #[error("failed to encrypt challenge plaintext")]
    EncryptChallengePlaintext(#[from] AeadError),
    #[error("failed to serialize challenge plaintext")]
    SerializeChallengePlaintext(#[from] borsh::io::Error),
}

#[derive(Debug, Error)]
#[error("failed to generate authentication challenge")]
#[repr(transparent)]
pub struct GenerateAuthChallenge(#[source] GenerateAuthChallengeInner);

impl<Err> From<Err> for GenerateAuthChallenge
where
    GenerateAuthChallengeInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
pub(in crate::wallet::sign_in_with_bitnames) enum VerifyAuthInner {
    #[error(transparent)]
    DecompressEdwards(#[from] DecompressEdwards),
    #[error("failed to decrypt response ciphertext")]
    DecryptCiphertext(#[source] AeadError),
    #[error("failed to derive SIWB encryption XPub")]
    DeriveSiwbEncryptionXpub(#[source] ed25519_bip32::DerivationError),
    #[error("failed to deserialize response plaintext")]
    DeserializePlaintext(#[source] borsh::io::Error),
    #[error("failed to serialize challenge")]
    SerializeChallenge(#[source] borsh::io::Error),
    #[error(transparent)]
    VerifyEpkRotation(#[from] VerifyEpkRotation),
    #[error("failed to verify signature")]
    VerifySignature(#[from] ed25519_dalek::SignatureError),
}

#[derive(Debug, Error)]
#[error("failed to verify authentication response")]
#[repr(transparent)]
pub struct VerifyAuth(#[source] VerifyAuthInner);

impl<Err> From<Err> for VerifyAuth
where
    VerifyAuthInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
pub(in crate::wallet::sign_in_with_bitnames) enum AuthenticateInner<E> {
    #[error("failed to decompress authentication cpk")]
    DecompressAuthCpk,
    #[error(transparent)]
    DecompressEdwards(#[from] DecompressEdwards),
    #[error("failed to decrypt challenge ciphertext")]
    DecryptCiphertext(#[source] AeadError),
    #[error("failed to deserialize challenge plaintext")]
    DeserializePlaintext(#[source] borsh::io::Error),
    #[error("failed to encrypt response")]
    EncryptResponse(#[source] AeadError),
    #[error(transparent)]
    RotateEpk(#[from] RotateEpk),
    #[error("failed to serialize challenge")]
    SerializeChallenge(#[source] borsh::io::Error),
    #[error("failed to serialize response")]
    SerializeResponse(#[source] borsh::io::Error),
    #[error("failed to sign challenge")]
    SignChallenge(#[source] ed25519_dalek::SignatureError),
    #[error("failed to validate challenge")]
    ValidateChallengeFailed(#[source] E),
    #[error("challenge validation was not successful")]
    ValidateChallenge,
}

#[derive(Debug, Error)]
#[error("failed to generate authentication response")]
#[repr(transparent)]
pub struct Authenticate<E>(#[source] AuthenticateInner<E>);

impl<E, Err> From<Err> for Authenticate<E>
where
    AuthenticateInner<E>: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}
