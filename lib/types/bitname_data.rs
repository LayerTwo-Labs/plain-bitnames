use std::net::{Ipv4Addr, Ipv6Addr};

use borsh::BorshSerialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use utoipa::{
    openapi::{RefOr, Schema},
    PartialSchema, ToSchema,
};

use crate::{
    authorization::VerifyingKey,
    types::{BitNameSeqId, EncryptionPubKey, Hash},
};

fn hash_option_verifying_key<H>(pk: &Option<VerifyingKey>, state: &mut H)
where
    H: std::hash::Hasher,
{
    use std::hash::Hash;
    pk.map(|pk| pk.to_bytes()).hash(state)
}

fn borsh_serialize_option_verifying_key<W>(
    pk: &Option<VerifyingKey>,
    writer: &mut W,
) -> borsh::io::Result<()>
where
    W: borsh::io::Write,
{
    borsh::BorshSerialize::serialize(&pk.map(|pk| pk.to_bytes()), writer)
}

/// Bitname data that can be updated later
#[derive(
    BorshSerialize,
    Clone,
    Debug,
    Default,
    Deserialize,
    Educe,
    Eq,
    PartialEq,
    Serialize,
    ToSchema,
)]
#[educe(Hash)]
pub struct MutableBitNameData {
    /// commitment to arbitrary data
    #[schema(value_type = Option<String>)]
    pub commitment: Option<Hash>,
    /// optional ipv4 addr
    #[schema(value_type = Option<String>)]
    pub ipv4_addr: Option<Ipv4Addr>,
    /// optional ipv6 addr
    #[schema(value_type = Option<String>)]
    pub ipv6_addr: Option<Ipv6Addr>,
    /// optional pubkey used for encryption
    #[schema(value_type = Option<String>)]
    pub encryption_pubkey: Option<EncryptionPubKey>,
    /// optional pubkey used for signing messages
    #[borsh(serialize_with = "borsh_serialize_option_verifying_key")]
    #[educe(Hash(method = "hash_option_verifying_key"))]
    #[schema(value_type = Option<String>)]
    pub signing_pubkey: Option<VerifyingKey>,
    /// optional minimum paymail fee, in sats
    pub paymail_fee_sats: Option<u64>,
}

/// Bitname data that can be updated later
#[derive(
    BorshSerialize,
    Clone,
    Debug,
    Deserialize,
    Educe,
    Eq,
    PartialEq,
    Serialize,
    ToSchema,
)]
#[educe(Hash)]
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

impl PartialSchema for Update<Ipv4Addr> {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        Self::schema(<String as PartialSchema>::schema())
    }
}

impl ToSchema for Update<Ipv4Addr> {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UpdateIpv4Addr")
    }
}

impl PartialSchema for Update<Ipv6Addr> {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        Self::schema(<String as PartialSchema>::schema())
    }
}

impl ToSchema for Update<Ipv6Addr> {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UpdateIpv6Addr")
    }
}

impl PartialSchema for Update<EncryptionPubKey> {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        Self::schema(<String as PartialSchema>::schema())
    }
}

impl ToSchema for Update<EncryptionPubKey> {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UpdateEncryptionPubKey")
    }
}

impl PartialSchema for Update<VerifyingKey> {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        Self::schema(<String as PartialSchema>::schema())
    }
}

impl ToSchema for Update<VerifyingKey> {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UpdateVerifyingKey")
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

fn borsh_serialize_update_pubkey<W>(
    update: &Update<VerifyingKey>,
    writer: &mut W,
) -> borsh::io::Result<()>
where
    W: borsh::io::Write,
{
    let update = match update {
        Update::Delete => Update::Delete,
        Update::Retain => Update::Retain,
        Update::Set(value) => Update::Set(value.as_bytes()),
    };
    borsh::BorshSerialize::serialize(&update, writer)
}

/// updates to the data associated with a BitName
#[derive(BorshSerialize, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct BitNameDataUpdates {
    /// commitment to arbitrary data
    #[schema(schema_with = <Update<Hash> as PartialSchema>::schema)]
    pub commitment: Update<Hash>,
    /// optional ipv4 addr
    #[schema(schema_with = <Update<Ipv4Addr> as PartialSchema>::schema)]
    pub ipv4_addr: Update<Ipv4Addr>,
    /// optional ipv6 addr
    #[schema(schema_with = <Update<Ipv6Addr> as PartialSchema>::schema)]
    pub ipv6_addr: Update<Ipv6Addr>,
    /// optional pubkey used for encryption
    #[schema(schema_with = <Update<EncryptionPubKey> as PartialSchema>::schema)]
    pub encryption_pubkey: Update<EncryptionPubKey>,
    /// optional pubkey used for signing messages
    #[borsh(serialize_with = "borsh_serialize_update_pubkey")]
    #[schema(schema_with = <Update<VerifyingKey> as PartialSchema>::schema)]
    pub signing_pubkey: Update<VerifyingKey>,
    /// optional minimum paymail fee, in sats
    #[schema(schema_with = <Update<u64> as PartialSchema>::schema)]
    pub paymail_fee_sats: Update<u64>,
}
