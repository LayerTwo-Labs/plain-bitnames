use std::str::FromStr;

use bip300301::bitcoin;
use bitcoin::hashes::Hash as _;
use borsh::{BorshDeserialize, BorshSerialize};
use hex::FromHex;
use serde::{Deserialize, Serialize};

pub type Hash = [u8; blake3::OUT_LEN];

use super::serde_hexstr_human_readable;

#[derive(
    BorshSerialize,
    Clone,
    Copy,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct BlockHash(#[serde(with = "serde_hexstr_human_readable")] pub Hash);

impl From<Hash> for BlockHash {
    fn from(other: Hash) -> Self {
        Self(other)
    }
}

impl From<BlockHash> for Hash {
    fn from(other: BlockHash) -> Self {
        other.0
    }
}

impl From<BlockHash> for Vec<u8> {
    fn from(other: BlockHash) -> Self {
        other.0.into()
    }
}

impl From<BlockHash> for bitcoin::BlockHash {
    fn from(other: BlockHash) -> Self {
        let inner: [u8; 32] = other.into();
        Self::from_byte_array(inner)
    }
}

impl FromHex for BlockHash {
    type Error = <Hash as FromHex>::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Hash::from_hex(hex).map(Self)
    }
}

impl std::fmt::Display for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for BlockHash {
    type Err = <Self as FromHex>::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl utoipa::PartialSchema for BlockHash {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        let obj = utoipa::openapi::Object::with_type(
            utoipa::openapi::SchemaType::String,
        );
        utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(obj))
    }
}

impl utoipa::ToSchema<'static> for BlockHash {
    fn schema() -> (
        &'static str,
        utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
    ) {
        ("BlockHash", <Self as utoipa::PartialSchema>::schema())
    }
}

#[derive(
    BorshSerialize,
    Clone,
    Copy,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct MerkleRoot(#[serde(with = "serde_hexstr_human_readable")] Hash);

impl From<Hash> for MerkleRoot {
    fn from(other: Hash) -> Self {
        Self(other)
    }
}

impl From<MerkleRoot> for Hash {
    fn from(other: MerkleRoot) -> Self {
        other.0
    }
}

impl std::fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl utoipa::PartialSchema for MerkleRoot {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        let obj = utoipa::openapi::Object::with_type(
            utoipa::openapi::SchemaType::String,
        );
        utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(obj))
    }
}

impl utoipa::ToSchema<'static> for MerkleRoot {
    fn schema() -> (
        &'static str,
        utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
    ) {
        ("MerkleRoot", <Self as utoipa::PartialSchema>::schema())
    }
}

#[derive(
    BorshSerialize,
    Clone,
    Copy,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Txid(#[serde(with = "serde_hexstr_human_readable")] pub Hash);

impl Txid {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<Hash> for Txid {
    fn from(other: Hash) -> Self {
        Self(other)
    }
}

impl From<Txid> for Hash {
    fn from(other: Txid) -> Self {
        other.0
    }
}

impl<'a> From<&'a Txid> for &'a Hash {
    fn from(other: &'a Txid) -> Self {
        &other.0
    }
}

impl std::fmt::Display for Txid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for Txid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for Txid {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash::from_hex(s).map(Self)
    }
}

impl utoipa::PartialSchema for Txid {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        let obj = utoipa::openapi::Object::with_type(
            utoipa::openapi::SchemaType::String,
        );
        utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(obj))
    }
}

impl utoipa::ToSchema<'static> for Txid {
    fn schema() -> (
        &'static str,
        utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
    ) {
        ("Txid", <Self as utoipa::PartialSchema>::schema())
    }
}

/// Identifier for a BitName
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct BitName(#[serde(with = "serde_hexstr_human_readable")] pub Hash);

impl std::fmt::Display for BitName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromHex for BitName {
    type Error = <Hash as FromHex>::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Hash::from_hex(hex).map(Self)
    }
}

impl utoipa::PartialSchema for BitName {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        let obj = utoipa::openapi::Object::with_type(
            utoipa::openapi::SchemaType::String,
        );
        utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(obj))
    }
}

impl utoipa::ToSchema<'static> for BitName {
    fn schema() -> (
        &'static str,
        utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
    ) {
        ("BitName", <Self as utoipa::PartialSchema>::schema())
    }
}

pub fn hash<T>(data: &T) -> Hash
where
    T: BorshSerialize,
{
    let data_serialized = borsh::to_vec(data)
        .expect("failed to serialize with borsh to compute a hash");
    blake3::hash(&data_serialized).into()
}
