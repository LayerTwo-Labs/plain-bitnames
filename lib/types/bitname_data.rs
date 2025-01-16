use std::net::{SocketAddrV4, SocketAddrV6};

use borsh::BorshSerialize;
use serde::{Deserialize, Serialize};
use utoipa::{
    openapi::{RefOr, Schema},
    PartialSchema, ToSchema,
};

use crate::types::{BitNameSeqId, EncryptionPubKey, Hash, VerifyingKey};

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
pub struct MutableBitNameData {
    /// commitment to arbitrary data
    #[schema(value_type = Option<String>)]
    pub commitment: Option<Hash>,
    /// optional ipv4 addr
    #[schema(value_type = Option<String>)]
    pub socket_addr_v4: Option<SocketAddrV4>,
    /// optional ipv6 addr
    #[schema(value_type = Option<String>)]
    pub socket_addr_v6: Option<SocketAddrV6>,
    /// optional pubkey used for encryption
    pub encryption_pubkey: Option<EncryptionPubKey>,
    /// optional pubkey used for signing messages
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
    /// optional pubkey used for encryption
    #[schema(schema_with = <Update<EncryptionPubKey> as PartialSchema>::schema)]
    pub encryption_pubkey: Update<EncryptionPubKey>,
    /// optional pubkey used for signing messages
    #[schema(schema_with = <Update<VerifyingKey> as PartialSchema>::schema)]
    pub signing_pubkey: Update<VerifyingKey>,
    /// optional minimum paymail fee, in sats
    #[schema(schema_with = <Update<u64> as PartialSchema>::schema)]
    pub paymail_fee_sats: Update<u64>,
}
