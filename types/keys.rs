use borsh::BorshSerialize;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use generic_array::{ArrayLength, GenericArray};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeAs, DisplayFromStr, SerializeAs};
use utoipa::ToSchema;

use crate::{error, util};

pub type SecretKey = curve25519_dalek::Scalar;

/// Wrapper around compressed ristretto255 pubkeys
#[derive(Debug)]
#[repr(transparent)]
pub struct CompressedPublicKey(pub CompressedRistretto);

impl CompressedPublicKey {
    /// HRP for Bech32m encoding
    const BECH32M_HRP: bech32::Hrp = bech32::Hrp::parse_unchecked("bn-cpk");

    /// Encode to Bech32m format
    pub fn bech32m_encode(&self) -> String {
        bech32::encode::<bech32::Bech32m>(Self::BECH32M_HRP, self.0.as_bytes())
            .expect("Bech32m Encoding should not fail")
    }
}

impl std::fmt::Display for CompressedPublicKey {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.bech32m_encode().fmt(f)
    }
}

/// Wrapper around ristretto255 pubkeys
#[derive(BorshSerialize, Clone, Copy, Debug, Eq, PartialEq, ToSchema)]
#[repr(transparent)]
#[schema(value_type = String)]
pub struct PublicKey(
    #[borsh(serialize_with = "util::borsh::serialize::ristretto_point")]
    pub  RistrettoPoint,
);

impl PublicKey {
    #[inline(always)]
    pub fn compress(&self) -> CompressedPublicKey {
        CompressedPublicKey(self.0.compress())
    }

    /// Encode to Bech32m format
    #[inline(always)]
    pub fn bech32m_encode(&self) -> String {
        self.compress().bech32m_encode()
    }

    /// Decode from Bech32m format
    pub fn bech32m_decode(s: &str) -> Result<Self, error::Bech32mDecode> {
        let (hrp, data) = bech32::decode(s)?;
        if hrp != CompressedPublicKey::BECH32M_HRP {
            let err = error::WrongHrp {
                expected: CompressedPublicKey::BECH32M_HRP,
                decoded: hrp,
            };
            return Err(Box::new(err).into());
        }
        let bytes = match <[u8; 32]>::try_from(data) {
            Ok(bytes) => bytes,
            Err(data) => {
                return Err(error::Bech32mDecode::WrongSize {
                    decoded_len: data.len(),
                    expected_len: 32,
                });
            }
        };
        let res = Self::try_from(bytes).map_err(|err| {
            error::Bech32mDecode::InvalidBytes {
                bytes,
                source: Box::new(err),
            }
        })?;
        if s != res.bech32m_encode() {
            return Err(error::Bech32mDecode::WrongVariant);
        }
        Ok(res)
    }

    #[inline(always)]
    pub fn from_secret_key(secret_key: &SecretKey) -> Self {
        Self(RistrettoPoint::mul_base(secret_key))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            DisplayFromStr::deserialize_as(deserializer)
        } else {
            let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
            Self::try_from(bytes).map_err(serde::de::Error::custom)
        }
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            DisplayFromStr::serialize_as(self, serializer)
        } else {
            Serialize::serialize(self.0.compress().as_bytes(), serializer)
        }
    }
}

impl std::fmt::Display for PublicKey {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.bech32m_encode().fmt(f)
    }
}

impl std::str::FromStr for PublicKey {
    type Err = error::Bech32mDecode;

    #[inline(always)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::bech32m_decode(s)
    }
}

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.compress().0.as_bytes());
    }
}

impl TryFrom<CompressedRistretto> for PublicKey {
    type Error = error::NonCanonicalRistrettoPointEncoding;

    fn try_from(cpk: CompressedRistretto) -> Result<Self, Self::Error> {
        match cpk.decompress() {
            Some(pubkey) => Ok(Self(pubkey)),
            None => Err(error::NonCanonicalRistrettoPointEncoding),
        }
    }
}

impl TryFrom<[u8; 32]> for PublicKey {
    type Error = error::NonCanonicalRistrettoPointEncoding;

    #[inline(always)]
    fn try_from(cpk: [u8; 32]) -> Result<Self, Self::Error> {
        Self::try_from(CompressedRistretto(cpk))
    }
}

// TODO: Remove dependency on generic-array / typenum,
// once #![feature(generic_const_exprs)] has been stabilized.
pub trait Base58Encoding: TryFrom<GenericArray<u8, Self::ByteLen>> {
    type ByteLen: ArrayLength;

    type B58PrefixLen: ArrayLength + std::ops::Add<Self::ByteLen>;

    /// Data prefix, used to ensure that the encoded string has a certain
    /// prefix
    const B58_DATA_PREFIX: GenericArray<u8, Self::B58PrefixLen>;

    /// Encoded prefix, used only for tests
    const B58_PREFIX: &str;

    fn as_bytes(&self) -> GenericArray<u8, Self::ByteLen>;
}

mod private {
    pub trait Base58EncodingExtSealed {}

    impl<T> Base58EncodingExtSealed for T where T: super::Base58Encoding {}
}

type B58ckDecodeError<T> = error::Base58ckDecode<
    <T as Base58Encoding>::B58PrefixLen,
    <T as TryFrom<GenericArray<u8, <T as Base58Encoding>::ByteLen>>>::Error,
>;

pub trait Base58EncodingExt:
    Base58Encoding + private::Base58EncodingExtSealed
{
    #[inline(always)]
    fn base58_data(
        &self,
    ) -> GenericArray<u8, typenum::Sum<Self::B58PrefixLen, Self::ByteLen>>
    where
        typenum::Sum<Self::B58PrefixLen, Self::ByteLen>: ArrayLength,
    {
        use generic_array::sequence::GenericSequence;
        use typenum::Unsigned;
        let payload: &[u8] = &self.as_bytes();
        GenericArray::generate(|idx| {
            if idx < Self::B58PrefixLen::USIZE {
                Self::B58_DATA_PREFIX[idx]
            } else {
                payload[idx - Self::B58PrefixLen::USIZE]
            }
        })
    }

    /// Decode from Base58ck
    fn base58ck_decode(s: &str) -> Result<Self, B58ckDecodeError<Self>>
    where
        typenum::Sum<Self::B58PrefixLen, Self::ByteLen>: ArrayLength
            + std::ops::Sub<Self::B58PrefixLen, Output = Self::ByteLen>,
    {
        use typenum::Unsigned;
        let decoded = bitcoin::base58::decode_check(s)?;
        let decoded: &GenericArray<
            u8,
            typenum::Sum<Self::B58PrefixLen, Self::ByteLen>,
        > = decoded.as_slice().try_into().map_err(
            |generic_array::LengthError| {
                error::base58ck_decode::Inner::IncorrectSize {
                    decoded: decoded.len(),
                    expected: Self::B58PrefixLen::USIZE + Self::ByteLen::USIZE,
                }
            },
        )?;
        let (prefix, payload) =
            generic_array::sequence::Split::split(decoded.clone());
        if prefix != Self::B58_DATA_PREFIX {
            return Err(error::base58ck_decode::Inner::IncorrectPrefix {
                decoded: prefix,
                expected: Self::B58_DATA_PREFIX,
            }
            .into());
        }
        payload
            .try_into()
            .map_err(|err| error::base58ck_decode::Inner::TryFrom(err).into())
    }

    /// Encode to Base58ck
    fn base58ck_encode_fmt(
        &self,
        fmt: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result
    where
        typenum::Sum<Self::B58PrefixLen, Self::ByteLen>: ArrayLength,
    {
        bitcoin::base58::encode_check_to_fmt(fmt, self.base58_data().as_slice())
    }

    /// Encode to Base58ck
    fn base58ck_encode(&self) -> String
    where
        typenum::Sum<Self::B58PrefixLen, Self::ByteLen>: ArrayLength,
    {
        bitcoin::base58::encode_check(self.base58_data().as_slice())
    }
}

impl<T> Base58EncodingExt for T where T: Base58Encoding {}

#[cfg(test)]
pub(crate) mod test {
    use generic_array::{ArrayLength, GenericArray};

    use crate::keys::{Base58Encoding, Base58EncodingExt};

    pub fn test_b58ck_roundtrip<T>(value: &T) -> anyhow::Result<()>
    where
        T: Base58Encoding + Eq,
        typenum::Sum<T::B58PrefixLen, T::ByteLen>:
            ArrayLength + std::ops::Sub<T::B58PrefixLen, Output = T::ByteLen>,
        <T as TryFrom<GenericArray<u8, T::ByteLen>>>::Error:
            std::fmt::Debug + std::error::Error + Send + Sync + 'static,
    {
        let encoded = value.base58ck_encode();
        anyhow::ensure!(encoded.starts_with(T::B58_PREFIX));
        let decoded = T::base58ck_decode(&encoded)?;
        anyhow::ensure!(decoded == *value);
        Ok(())
    }
}
