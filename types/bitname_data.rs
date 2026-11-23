use std::{
    net::{SocketAddrV4, SocketAddrV6},
    str::FromStr,
};

use borsh::BorshSerialize;
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeAs as _, DisplayFromStr, SerializeAs as _};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{RefOr, Schema},
};

use crate::{
    bitname_seq_id::BitNameSeqId,
    error,
    hashes::Hash,
    keys::{Base58Encoding, Base58EncodingExt as _, PublicKey},
};

const CHAINCODE_SIZE: usize = 32;
const XPK_SIZE: usize = {
    const CPK_SIZE: usize = 32;
    CPK_SIZE + CHAINCODE_SIZE
};

/// Encoding for ristretto255 xpubkeys
#[derive(BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq, ToSchema)]
pub struct XPublicKey {
    pub pubkey: PublicKey,
    pub chaincode: [u8; CHAINCODE_SIZE],
}

impl XPublicKey {
    fn as_bytes(&self) -> [u8; XPK_SIZE] {
        let Self { pubkey, chaincode } = self;
        let mut res = [0u8; XPK_SIZE];
        let (cpk_bytes, rest) = res.split_first_chunk_mut().unwrap();
        *cpk_bytes = pubkey.0.compress().to_bytes();
        let chaincode_bytes = rest.as_mut_array().unwrap();
        *chaincode_bytes = *chaincode;
        res
    }
}

impl Base58Encoding for XPublicKey {
    type B58PrefixLen = generic_array::ConstArrayLength<6>;

    type ByteLen = generic_array::ConstArrayLength<{ XPK_SIZE }>;

    const B58_PREFIX: &str = "BNsXPub";

    const B58_DATA_PREFIX: GenericArray<u8, Self::B58PrefixLen> =
        generic_array::arr![0x24, 0x16, 0x69, 0x9f, 0x0e, 0xc6];

    fn as_bytes(&self) -> GenericArray<u8, Self::ByteLen> {
        GenericArray::from_array(Self::as_bytes(self))
    }
}

impl std::fmt::Display for XPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.base58ck_encode_fmt(f)
    }
}

impl FromStr for XPublicKey {
    type Err = error::Base58ckDecode<
        <Self as Base58Encoding>::B58PrefixLen,
        error::NonCanonicalRistrettoPointEncoding,
    >;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::base58ck_decode(s)
    }
}

impl<'de> Deserialize<'de> for XPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            DisplayFromStr::deserialize_as(deserializer)
        } else {
            let bytes: [u8; XPK_SIZE] =
                serde_with::Bytes::deserialize_as(deserializer)?;
            bytes.try_into().map_err(serde::de::Error::custom)
        }
    }
}

impl Serialize for XPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            Serialize::serialize(&self.to_string(), serializer)
        } else {
            serde_with::Bytes::serialize_as(&self.as_bytes(), serializer)
        }
    }
}

impl TryFrom<[u8; 64]> for XPublicKey {
    type Error = error::NonCanonicalRistrettoPointEncoding;

    fn try_from(xpk: [u8; XPK_SIZE]) -> Result<Self, Self::Error> {
        let (cpk_bytes, rest) = xpk.split_first_chunk::<32>().unwrap();
        let pubkey = PublicKey::try_from(*cpk_bytes)?;
        let chaincode = rest.try_into().unwrap();
        Ok(Self { pubkey, chaincode })
    }
}

impl TryFrom<generic_array::ConstGenericArray<u8, XPK_SIZE>> for XPublicKey {
    type Error = error::NonCanonicalRistrettoPointEncoding;

    fn try_from(
        xpk: generic_array::ConstGenericArray<u8, XPK_SIZE>,
    ) -> Result<Self, Self::Error> {
        xpk.into_array().try_into()
    }
}

#[cfg(test)]
mod test_xpk {
    use curve25519_dalek::ristretto::RistrettoPoint;

    use crate::{
        bitname_data::XPublicKey,
        keys::{self, PublicKey},
    };

    #[test]
    fn test_b58ck_roundtrip() -> anyhow::Result<()> {
        let pubkey = {
            let uniform_bytes = {
                let mut uniform_bytes = [0u8; 64];
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"test xpk");
                hasher.finalize_xof().fill(&mut uniform_bytes);
                uniform_bytes
            };
            PublicKey(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
        };
        let chaincode = blake3::hash(b"test chaincode").into();
        let xpk = XPublicKey { pubkey, chaincode };
        keys::test::test_b58ck_roundtrip(&xpk)
    }
}

/// Bitname data that can be updated later
#[derive(
    BorshSerialize,
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    Hash,
    PartialEq,
    Serialize,
    ToSchema,
)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
#[cfg_attr(feature = "clap", group(required = false, multiple = true))]
pub struct MutableBitNameData {
    /// Commitment to arbitrary data
    #[cfg_attr(feature = "clap", arg(
        long,
        value_parser = |s: &str| <Hash as const_hex::FromHex>::from_hex(s)
    ))]
    #[schema(value_type = Option<String>)]
    pub commitment: Option<Hash>,
    /// Optional ipv4 addr
    #[cfg_attr(feature = "clap", arg(long))]
    #[schema(value_type = Option<String>)]
    pub socket_addr_v4: Option<SocketAddrV4>,
    /// Optional ipv6 addr
    #[cfg_attr(feature = "clap", arg(long))]
    #[schema(value_type = Option<String>)]
    pub socket_addr_v6: Option<SocketAddrV6>,
    /// optional minimum paymail fee, in sats
    #[cfg_attr(feature = "clap", arg(long))]
    pub paymail_fee_sats: Option<u64>,
    /// Optional extended public key
    #[cfg_attr(feature = "clap", arg(long))]
    pub xpubkey: Option<XPublicKey>,
}

/// Bitname data that can be updated later
#[derive(
    BorshSerialize,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    PartialEq,
    Serialize,
    ToSchema,
)]
pub struct BitNameData {
    pub seq_id: BitNameSeqId,
    #[serde(flatten)]
    pub mutable_data: MutableBitNameData,
}

/// delete, retain, or set a value
#[derive(BorshSerialize, Clone, Debug, Deserialize, Serialize)]
pub enum Update<T> {
    Delete,
    Retain,
    Set(T),
}

impl<T> Update<T> {
    /// Create a schema from a schema for `T`.
    fn schema(schema_t: RefOr<Schema>) -> RefOr<Schema> {
        let schema_delete = utoipa::openapi::ObjectBuilder::new()
            .schema_type(utoipa::openapi::Type::String)
            .enum_values(Some(["Delete"]));
        let schema_retain = utoipa::openapi::ObjectBuilder::new()
            .schema_type(utoipa::openapi::Type::String)
            .enum_values(Some(["Retain"]));
        let schema_set = utoipa::openapi::ObjectBuilder::new()
            .property("Set", schema_t)
            .required("Set");
        let schema = utoipa::openapi::OneOfBuilder::new()
            .item(schema_delete)
            .item(schema_retain)
            .item(schema_set)
            .build()
            .into();
        RefOr::T(schema)
    }
}

impl PartialSchema for Update<Hash> {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        Self::schema(<String as PartialSchema>::schema())
    }
}

impl ToSchema for Update<Hash> {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UpdateHash")
    }
}

impl PartialSchema for Update<SocketAddrV4> {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        Self::schema(<String as PartialSchema>::schema())
    }
}

impl ToSchema for Update<SocketAddrV4> {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UpdateSocketAddrV4")
    }
}

impl PartialSchema for Update<SocketAddrV6> {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        Self::schema(<String as PartialSchema>::schema())
    }
}

impl ToSchema for Update<SocketAddrV6> {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UpdateSocketAddrV6")
    }
}

impl PartialSchema for Update<XPublicKey> {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        Self::schema(<XPublicKey as PartialSchema>::schema())
    }
}

impl ToSchema for Update<XPublicKey> {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UpdateXPublicKey")
    }
}

impl PartialSchema for Update<u64> {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        Self::schema(<u64 as PartialSchema>::schema())
    }
}

impl ToSchema for Update<u64> {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UpdateU64")
    }
}

/// updates to the data associated with a BitName
#[derive(BorshSerialize, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct BitNameDataUpdates {
    /// commitment to arbitrary data
    #[schema(schema_with = <Update<Hash> as PartialSchema>::schema)]
    pub commitment: Update<Hash>,
    /// optional ipv4 addr
    #[schema(schema_with = <Update<SocketAddrV4> as PartialSchema>::schema)]
    pub socket_addr_v4: Update<SocketAddrV4>,
    /// optional ipv6 addr
    #[schema(schema_with = <Update<SocketAddrV6> as PartialSchema>::schema)]
    pub socket_addr_v6: Update<SocketAddrV6>,
    /// optional extended public key
    #[schema(schema_with = <Update<XPublicKey> as PartialSchema>::schema)]
    pub xpubkey: Update<XPublicKey>,
    /// optional minimum paymail fee, in sats
    #[schema(schema_with = <Update<u64> as PartialSchema>::schema)]
    pub paymail_fee_sats: Update<u64>,
}
