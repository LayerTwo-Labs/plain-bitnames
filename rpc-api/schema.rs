//! Schemas for OpenAPI

use std::marker::PhantomData;

use utoipa::{
    PartialSchema, ToSchema,
    openapi::{self, RefOr, Schema},
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

/// Optional `T`
pub struct Optional<T>(PhantomData<T>);

impl<T> PartialSchema for Optional<T>
where
    T: PartialSchema,
{
    fn schema() -> openapi::RefOr<openapi::schema::Schema> {
        openapi::schema::OneOf::builder()
            .item(
                openapi::schema::Object::builder()
                    .schema_type(openapi::schema::Type::Null),
            )
            .item(T::schema())
            .into()
    }
}
