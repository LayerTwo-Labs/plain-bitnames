//! Schemas for OpenAPI

use std::marker::PhantomData;

use utoipa::{
    openapi::{self, RefOr, Schema},
    PartialSchema, ToSchema,
};

/// Utoipa does not support tuples at all, so these are represented as an
/// arbitrary json value
#[derive(Default)]
pub struct ArrayTuple<A, B>(PhantomData<A>, PhantomData<B>);

impl<A, B> PartialSchema for ArrayTuple<A, B> {
    fn schema() -> RefOr<Schema> {
        openapi::schema::ToArray::to_array(serde_json::Value::schema()).into()
    }
}

pub struct BitcoinTxid;

impl PartialSchema for BitcoinTxid {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::with_type(openapi::Type::String);
        RefOr::T(Schema::Object(obj))
    }
}

impl ToSchema for BitcoinTxid {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("bitcoin.Txid")
    }
}

pub struct OpenApi;

impl PartialSchema for OpenApi {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::new();
        RefOr::T(Schema::Object(obj))
    }
}

pub struct SocketAddr;

impl PartialSchema for SocketAddr {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::with_type(openapi::Type::String);
        RefOr::T(Schema::Object(obj))
    }
}
