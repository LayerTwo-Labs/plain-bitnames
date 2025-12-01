use borsh::BorshSerialize;
use libes::{auth::HmacSha256, enc::Aes256Gcm, key::X25519};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeAs, DisplayFromStr, FromInto, SerializeAs};
use thiserror::Error;
use utoipa::ToSchema;

#[derive(Debug, Error)]
enum Base58ckDecodeErrorInner<const PREFIX_LEN: usize> {
    #[error(transparent)]
    Decode(#[from] bitcoin::base58::Error),
    #[error(
        "Incorrect prefix (`{}`): expected `{}`.",
        hex::encode(.decoded),
        hex::encode(.expected),
    )]
    IncorrectPrefix {
        decoded: [u8; PREFIX_LEN],
        expected: [u8; PREFIX_LEN],
    },
    #[error(
        "Incorrect decoded byte length ({}). Expected {} bytes of data.",
        .decoded,
        .expected,
    )]
    IncorrectSize { decoded: usize, expected: usize },
}

#[derive(Debug, Error)]
#[error("Failed to decode base58ck")]
#[repr(transparent)]
pub struct Base58DecodeError<const PREFIX_LEN: usize>(
    #[source] Base58ckDecodeErrorInner<PREFIX_LEN>,
);

impl<const PREFIX_LEN: usize, E> From<E> for Base58DecodeError<PREFIX_LEN>
where
    Base58ckDecodeErrorInner<PREFIX_LEN>: From<E>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
#[error("Wrong Bech32 HRP. Expected {expected} but decoded {decoded}")]
pub struct WrongHrpError {
    expected: bech32::Hrp,
    decoded: bech32::Hrp,
}

#[derive(Debug, Error)]
pub enum Bech32mDecodeError {
    #[error(transparent)]
    Bech32m(#[from] bech32::DecodeError),
    #[error("Invalid bytes: {}", hex::encode(.bytes))]
    InvalidBytes {
        bytes: [u8; 32],
        source: Box<ed25519_dalek::SignatureError>,
    },
    #[error(transparent)]
    WrongHrp(#[from] Box<WrongHrpError>),
    #[error(
        "Wrong decoded byte length ({decoded_len}). Must decode to {expected_len} bytes of data."
    )]
    WrongSize {
        decoded_len: usize,
        expected_len: usize,
    },
    #[error("Wrong Bech32 variant. Only Bech32m is accepted.")]
    WrongVariant,
}

fn borsh_serialize_x25519_pubkey<W>(
    pk: &x25519_dalek::PublicKey,
    writer: &mut W,
) -> borsh::io::Result<()>
where
    W: borsh::io::Write,
{
    borsh::BorshSerialize::serialize(pk.as_bytes(), writer)
}

/// Wrapper around x25519 pubkeys
#[derive(BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq, ToSchema)]
#[repr(transparent)]
#[schema(value_type = String)]
pub struct EncryptionPubKey(
    #[borsh(serialize_with = "borsh_serialize_x25519_pubkey")]
    pub  x25519_dalek::PublicKey,
);

impl EncryptionPubKey {
    /// HRP for Bech32m encoding
    const BECH32M_HRP: bech32::Hrp = bech32::Hrp::parse_unchecked("bn-enc");

    /// Encode to Bech32m format
    pub fn bech32m_encode(&self) -> String {
        bech32::encode::<bech32::Bech32m>(Self::BECH32M_HRP, self.0.as_bytes())
            .expect("Bech32m Encoding should not fail")
    }

    /// Decode from Bech32m format
    pub fn bech32m_decode(s: &str) -> Result<Self, Bech32mDecodeError> {
        let (hrp, data) = bech32::decode(s)?;
        if hrp != Self::BECH32M_HRP {
            let err = WrongHrpError {
                expected: Self::BECH32M_HRP,
                decoded: hrp,
            };
            return Err(Box::new(err).into());
        }
        let bytes = match <[u8; 32]>::try_from(data) {
            Ok(bytes) => bytes,
            Err(data) => {
                return Err(Bech32mDecodeError::WrongSize {
                    decoded_len: data.len(),
                    expected_len: 32,
                });
            }
        };
        let res = Self::from(bytes);
        if s != res.bech32m_encode() {
            return Err(Bech32mDecodeError::WrongVariant);
        }
        Ok(res)
    }
}

impl std::fmt::Display for EncryptionPubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.bech32m_encode().fmt(f)
    }
}

impl<T> From<T> for EncryptionPubKey
where
    x25519_dalek::PublicKey: From<T>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl std::str::FromStr for EncryptionPubKey {
    type Err = Bech32mDecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::bech32m_decode(s)
    }
}

impl<'de> Deserialize<'de> for EncryptionPubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serde_with::IfIsHumanReadable::<
            DisplayFromStr,
            FromInto<x25519_dalek::PublicKey>,
        >::deserialize_as(deserializer)
    }
}

impl Serialize for EncryptionPubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            DisplayFromStr::serialize_as(self, serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

fn borsh_serialize_ed25519_vk<W>(
    vk: &ed25519_dalek::VerifyingKey,
    writer: &mut W,
) -> borsh::io::Result<()>
where
    W: borsh::io::Write,
{
    borsh::BorshSerialize::serialize(vk.as_bytes(), writer)
}

/// Wrapper around ed25519 pubkeys
#[derive(BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq, ToSchema)]
#[repr(transparent)]
#[schema(value_type = String)]
pub struct VerifyingKey(
    #[borsh(serialize_with = "borsh_serialize_ed25519_vk")]
    pub  ed25519_dalek::VerifyingKey,
);

impl VerifyingKey {
    /// HRP for Bech32m encoding
    const BECH32M_HRP: bech32::Hrp = bech32::Hrp::parse_unchecked("bn-svk");

    const BYTE_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

    /// Encode to Bech32m format
    pub fn bech32m_encode(&self) -> String {
        bech32::encode::<bech32::Bech32m>(Self::BECH32M_HRP, self.0.as_bytes())
            .expect("Bech32m Encoding should not fail")
    }

    /// Decode from Bech32m format
    pub fn bech32m_decode(s: &str) -> Result<Self, Bech32mDecodeError> {
        let (hrp, data) = bech32::decode(s)?;
        if hrp != Self::BECH32M_HRP {
            let err = WrongHrpError {
                expected: Self::BECH32M_HRP,
                decoded: hrp,
            };
            return Err(Box::new(err).into());
        }
        let bytes = match <[u8; 32]>::try_from(data) {
            Ok(bytes) => bytes,
            Err(data) => {
                return Err(Bech32mDecodeError::WrongSize {
                    decoded_len: data.len(),
                    expected_len: 32,
                });
            }
        };
        let res = match ed25519_dalek::VerifyingKey::from_bytes(&bytes) {
            Ok(vk) => Self(vk),
            Err(err) => {
                let err = Bech32mDecodeError::InvalidBytes {
                    bytes,
                    source: Box::new(err),
                };
                return Err(err);
            }
        };
        if s != res.bech32m_encode() {
            return Err(Bech32mDecodeError::WrongVariant);
        }
        Ok(res)
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTE_LEN] {
        self.0.to_bytes()
    }
}

impl std::fmt::Display for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.bech32m_encode().fmt(f)
    }
}

impl From<ed25519_dalek::VerifyingKey> for VerifyingKey {
    fn from(vk: ed25519_dalek::VerifyingKey) -> Self {
        Self(vk)
    }
}

impl From<VerifyingKey> for ed25519_dalek::VerifyingKey {
    fn from(vk: VerifyingKey) -> Self {
        vk.0
    }
}

impl TryFrom<&[u8; VerifyingKey::BYTE_LEN]> for VerifyingKey {
    type Error = ed25519_dalek::SignatureError;

    fn try_from(
        bytes: &[u8; VerifyingKey::BYTE_LEN],
    ) -> Result<Self, Self::Error> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes).map(Self)
    }
}

impl std::str::FromStr for VerifyingKey {
    type Err = Bech32mDecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::bech32m_decode(s)
    }
}

impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serde_with::IfIsHumanReadable::<
            DisplayFromStr,
            FromInto<ed25519_dalek::VerifyingKey>,
        >::deserialize_as(deserializer)
    }
}

impl Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_with::IfIsHumanReadable::<
            DisplayFromStr,
            FromInto<ed25519_dalek::VerifyingKey>,
        >::serialize_as(self, serializer)
    }
}

/// Wrapper around ed25519 xpubkeys
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, ToSchema)]
#[repr(transparent)]
#[schema(value_type = String)]
pub struct XVerifyingKey(pub ed25519_bip32::XPub);

impl XVerifyingKey {
    /// HRP for Bech32m encoding
    const BECH32M_HRP: bech32::Hrp = bech32::Hrp::parse_unchecked("bn-xvk");

    const BYTE_LEN: usize = ed25519_bip32::XPUB_SIZE;

    /// Byte length of Base58 prefix
    const B58_PREFIX_LEN: usize = 5;

    /// Encoded prefix
    #[allow(dead_code)]
    const B58_PREFIX: &str = "BNsXVK";

    /// Prefix encodes to "BNsXVK"
    const B58_DATA_PREFIX: [u8; Self::B58_PREFIX_LEN] =
        [0x9f, 0x48, 0x71, 0x91, 0x4b];

    /// Data to encode as b58, including prefix
    #[inline(always)]
    fn base58_data(&self) -> [u8; Self::B58_PREFIX_LEN + Self::BYTE_LEN] {
        let payload: &[u8] = self.0.as_ref();
        std::array::from_fn(|idx| {
            if idx < Self::B58_PREFIX_LEN {
                Self::B58_DATA_PREFIX[idx]
            } else {
                payload[idx - Self::B58_PREFIX_LEN]
            }
        })
    }

    /// Decode from Base58ck
    pub fn base58ck_decode(
        s: &str,
    ) -> Result<Self, Base58DecodeError<{ Self::B58_PREFIX_LEN }>> {
        let decoded = bitcoin::base58::decode_check(s)?;
        let payload = match decoded.split_first_chunk() {
            Some((&Self::B58_DATA_PREFIX, payload)) => payload,
            Some((prefix, _)) => {
                return Err(Base58ckDecodeErrorInner::IncorrectPrefix {
                    decoded: *prefix,
                    expected: Self::B58_DATA_PREFIX,
                }
                .into());
            }
            None => {
                return Err(Base58ckDecodeErrorInner::IncorrectSize {
                    decoded: decoded.len(),
                    expected: Self::B58_PREFIX_LEN + Self::BYTE_LEN,
                }
                .into());
            }
        };
        match payload.split_first_chunk() {
            Some((payload, &[])) => Ok((*payload).into()),
            Some(_) | None => Err(Base58ckDecodeErrorInner::IncorrectSize {
                decoded: decoded.len(),
                expected: Self::B58_PREFIX_LEN + Self::BYTE_LEN,
            }
            .into()),
        }
    }

    /// Encode to Base58ck
    pub fn base58ck_encode_fmt(
        &self,
        fmt: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        bitcoin::base58::encode_check_to_fmt(fmt, &self.base58_data())
    }

    /// Encode to Base58ck
    pub fn base58ck_encode(&self) -> String {
        bitcoin::base58::encode_check(&self.base58_data())
    }

    /// Encode to Bech32m format
    pub fn bech32m_encode(&self) -> String {
        bech32::encode::<bech32::Bech32m>(Self::BECH32M_HRP, self.0.as_ref())
            .expect("Bech32m Encoding should not fail")
    }

    /// Decode from Bech32m format
    pub fn bech32m_decode(s: &str) -> Result<Self, Bech32mDecodeError> {
        let (hrp, data) = bech32::decode(s)?;
        if hrp != Self::BECH32M_HRP {
            let err = WrongHrpError {
                expected: Self::BECH32M_HRP,
                decoded: hrp,
            };
            return Err(Box::new(err).into());
        }
        let bytes = match <[u8; Self::BYTE_LEN]>::try_from(data) {
            Ok(bytes) => bytes,
            Err(data) => {
                return Err(Bech32mDecodeError::WrongSize {
                    decoded_len: data.len(),
                    expected_len: Self::BYTE_LEN,
                });
            }
        };
        let res = Self(ed25519_bip32::XPub::from_bytes(bytes));
        if s != res.bech32m_encode() {
            return Err(Bech32mDecodeError::WrongVariant);
        }
        Ok(res)
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTE_LEN] {
        self.0.into()
    }
}

impl std::fmt::Display for XVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.base58ck_encode_fmt(f)
    }
}

impl From<ed25519_bip32::XPub> for XVerifyingKey {
    fn from(xpub: ed25519_bip32::XPub) -> Self {
        Self(xpub)
    }
}

impl From<XVerifyingKey> for ed25519_bip32::XPub {
    fn from(xvk: XVerifyingKey) -> Self {
        xvk.0
    }
}

impl From<[u8; XVerifyingKey::BYTE_LEN]> for XVerifyingKey {
    fn from(bytes: [u8; XVerifyingKey::BYTE_LEN]) -> Self {
        Self(ed25519_bip32::XPub::from_bytes(bytes))
    }
}

impl std::str::FromStr for XVerifyingKey {
    type Err = Base58DecodeError<{ Self::B58_PREFIX_LEN }>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::base58ck_decode(s)
    }
}

/// ECIES crypto scheme over x25519
pub type Ecies = libes::Ecies<X25519, Aes256Gcm, HmacSha256>;

#[cfg(test)]
mod tests {
    use super::XVerifyingKey;

    fn test_b58ck_roundtrip(xvk: &XVerifyingKey) -> anyhow::Result<()> {
        let encoded = xvk.base58ck_encode();
        anyhow::ensure!(encoded.starts_with(XVerifyingKey::B58_PREFIX));
        let decoded = XVerifyingKey::base58ck_decode(&encoded)?;
        anyhow::ensure!(decoded == *xvk);
        Ok(())
    }

    #[test]
    fn test_b58ck_roundtrips() -> anyhow::Result<()> {
        test_b58ck_roundtrip(&XVerifyingKey::from(
            [0; XVerifyingKey::BYTE_LEN],
        ))?;
        test_b58ck_roundtrip(&XVerifyingKey::from(
            [u8::MAX; XVerifyingKey::BYTE_LEN],
        ))
    }
}
