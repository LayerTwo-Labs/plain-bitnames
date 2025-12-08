use serde_with::{DeserializeAs, IfIsHumanReadable, SerializeAs, serde_as};

/// Serialize [`bitcoin::Amount`] as sats
struct BitcoinAmountSats;

impl<'de> DeserializeAs<'de, bitcoin::Amount> for BitcoinAmountSats {
    fn deserialize_as<D>(deserializer: D) -> Result<bitcoin::Amount, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        bitcoin::amount::serde::as_sat::deserialize(deserializer)
    }
}

impl SerializeAs<bitcoin::Amount> for BitcoinAmountSats {
    fn serialize_as<S>(
        source: &bitcoin::Amount,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        bitcoin::amount::serde::as_sat::serialize(source, serializer)
    }
}

fn borsh_serialize_bitcoin_amount<W>(
    bitcoin_amount: &bitcoin::Amount,
    writer: &mut W,
) -> borsh::io::Result<()>
where
    W: borsh::io::Write,
{
    borsh::BorshSerialize::serialize(&bitcoin_amount.to_sat(), writer)
}

#[serde_as]
#[derive(
    borsh::BorshSerialize,
    serde::Deserialize,
    serde::Serialize,
    utoipa::ToSchema,
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
)]
#[repr(transparent)]
#[schema(value_type = u64)]
#[serde(transparent)]
pub struct BitcoinContent(
    #[borsh(serialize_with = "borsh_serialize_bitcoin_amount")]
    #[serde_as(as = "IfIsHumanReadable<BitcoinAmountSats>")]
    pub bitcoin::Amount,
);

fn borsh_serialize_bitcoin_address<V, W>(
    bitcoin_address: &bitcoin::Address<V>,
    writer: &mut W,
) -> borsh::io::Result<()>
where
    V: bitcoin::address::NetworkValidation,
    W: borsh::io::Write,
{
    let spk = bitcoin_address
        .as_unchecked()
        .assume_checked_ref()
        .script_pubkey();
    borsh::BorshSerialize::serialize(spk.as_bytes(), writer)
}

mod withdrawal_content {
    use serde::{Deserialize, Serialize};

    /// Defines a WithdrawalContent struct with the specified visibility, name,
    /// derives, and attributes for each field
    macro_rules! WithdrawalContent {
        (   $vis:vis $struct_name:ident
            $(, attrs: [$($attr:meta),* $(,)?])?
            $(, value_attrs: [$($value_attr:meta),* $(,)?])?
            $(, main_fee_attrs: [$($main_fee_attr:meta),* $(,)?])?
            $(, main_address_attrs: [$($main_address_attr:meta),* $(,)?])?
            $(,)?
        ) => {
            // Generate attributes if they were provided
            $(
                $(#[$attr])*
            )?
            $vis struct $struct_name {
                // Generate attributes if they were provided
                $(
                    $(#[$value_attr])*
                )?
                pub value: bitcoin::Amount,
                // Generate attributes if they were provided
                $(
                    $(#[$main_fee_attr])*
                )?
                pub main_fee: bitcoin::Amount,
                // Generate attributes if they were provided
                $(
                    $(#[$main_address_attr])*
                )?
                pub main_address: bitcoin::Address<
                    bitcoin::address::NetworkUnchecked
                >,
            }
        }
    }

    WithdrawalContent!(DefaultRepr, attrs: [derive(Deserialize, Serialize)]);

    WithdrawalContent!(
        HumanReadableRepr,
        attrs: [
            derive(utoipa::ToSchema, Deserialize, Serialize),
            schema(as = WithdrawalOutputContent)
        ],
        value_attrs: [
            schema(value_type = u64),
            serde(rename = "value_sats"),
            serde(with = "bitcoin::amount::serde::as_sat")
        ],
        main_fee_attrs: [
            schema(value_type = u64),
            serde(rename = "main_fee_sats"),
            serde(with = "bitcoin::amount::serde::as_sat")
        ],
        main_address_attrs: [
            schema(value_type = crate::schema::BitcoinAddr),
        ],
    );

    type SerdeRepr = serde_with::IfIsHumanReadable<
        serde_with::FromInto<HumanReadableRepr>,
        serde_with::FromInto<DefaultRepr>,
    >;

    WithdrawalContent!(
        pub WithdrawalContent,
        attrs: [derive(
            borsh::BorshSerialize,
            Clone,
            Debug,
            Eq,
            PartialEq
        )],
        value_attrs: [
            borsh(serialize_with = "super::borsh_serialize_bitcoin_amount"),
        ],
        main_fee_attrs: [
            borsh(serialize_with = "super::borsh_serialize_bitcoin_amount"),
        ],
        main_address_attrs: [
            borsh(serialize_with = "super::borsh_serialize_bitcoin_address"),
        ],
    );

    impl From<WithdrawalContent> for DefaultRepr {
        fn from(withdrawal_content: WithdrawalContent) -> Self {
            Self {
                value: withdrawal_content.value,
                main_fee: withdrawal_content.main_fee,
                main_address: withdrawal_content.main_address,
            }
        }
    }

    impl From<WithdrawalContent> for HumanReadableRepr {
        fn from(withdrawal_content: WithdrawalContent) -> Self {
            Self {
                value: withdrawal_content.value,
                main_fee: withdrawal_content.main_fee,
                main_address: withdrawal_content.main_address,
            }
        }
    }

    impl From<DefaultRepr> for WithdrawalContent {
        fn from(repr: DefaultRepr) -> Self {
            Self {
                value: repr.value,
                main_fee: repr.main_fee,
                main_address: repr.main_address,
            }
        }
    }

    impl From<HumanReadableRepr> for WithdrawalContent {
        fn from(repr: HumanReadableRepr) -> Self {
            Self {
                value: repr.value,
                main_fee: repr.main_fee,
                main_address: repr.main_address,
            }
        }
    }

    impl<'de> Deserialize<'de> for WithdrawalContent {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            <SerdeRepr as serde_with::DeserializeAs<'de, _>>::deserialize_as(
                deserializer,
            )
        }
    }

    impl Serialize for WithdrawalContent {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            <SerdeRepr as serde_with::SerializeAs<_>>::serialize_as(
                self, serializer,
            )
        }
    }

    impl utoipa::PartialSchema for WithdrawalContent {
        fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
            <HumanReadableRepr as utoipa::PartialSchema>::schema()
        }
    }

    impl utoipa::ToSchema for WithdrawalContent {
        fn name() -> std::borrow::Cow<'static, str> {
            <HumanReadableRepr as utoipa::ToSchema>::name()
        }
    }

    impl crate::GetValue for WithdrawalContent {
        fn get_value(&self) -> bitcoin::Amount {
            self.value
        }
    }
}
pub use withdrawal_content::WithdrawalContent;

mod content {
    use serde::{Deserialize, Serialize};
    use utoipa::{PartialSchema, ToSchema};

    /// Defines a Content enum with the specified visibility, name,
    /// derives, and attributes for each variant
    macro_rules! Content {
        (   $vis:vis $enum_name:ident
            $(, attrs: [$($attr:meta),* $(,)?])?
            $(, bitcoin_attrs: [$($bitcoin_attr:meta),* $(,)?])?
            $(,)?
        ) => {
            // Generate attributes if they were provided
            $(
                $(#[$attr])*
            )?
            $vis enum $enum_name {
                // Generate attributes if they were provided
                $(
                    $(#[$bitcoin_attr])*
                )?
                Bitcoin(super::BitcoinContent),
                BitName,
                BitNameReservation,
                Withdrawal(super::WithdrawalContent),
            }
        }
    }

    Content!(DefaultRepr, attrs: [derive(Deserialize, Serialize)]);

    Content!(
        HumanReadableRepr,
        attrs: [
            derive(utoipa::ToSchema, Deserialize, Serialize),
            schema(as = OutputContent)
        ],
        bitcoin_attrs: [
            serde(rename = "BitcoinSats")
        ],
    );

    type SerdeRepr = serde_with::IfIsHumanReadable<
        serde_with::FromInto<HumanReadableRepr>,
        serde_with::FromInto<DefaultRepr>,
    >;

    Content!(
        pub Content,
        attrs: [derive(
            borsh::BorshSerialize,
            Clone,
            Debug,
            Eq,
            PartialEq,
        )],
    );

    impl Content {
        pub fn is_bitcoin(&self) -> bool {
            matches!(self, Self::Bitcoin(_))
        }

        /// true if the output content corresponds to a BitName
        pub fn is_bitname(&self) -> bool {
            matches!(self, Self::BitName)
        }

        /// true if the output content corresponds to a reservation
        pub fn is_reservation(&self) -> bool {
            matches!(self, Self::BitNameReservation)
        }

        pub fn is_withdrawal(&self) -> bool {
            matches!(self, Self::Withdrawal { .. })
        }
    }

    impl From<super::BitcoinContent> for Content {
        fn from(content: super::BitcoinContent) -> Self {
            Self::Bitcoin(content)
        }
    }

    impl From<DefaultRepr> for Content {
        fn from(repr: DefaultRepr) -> Self {
            match repr {
                DefaultRepr::Bitcoin(value) => Self::Bitcoin(value),
                DefaultRepr::BitName => Self::BitName,
                DefaultRepr::BitNameReservation => Self::BitNameReservation,
                DefaultRepr::Withdrawal(withdrawal) => {
                    Self::Withdrawal(withdrawal)
                }
            }
        }
    }

    impl From<HumanReadableRepr> for Content {
        fn from(repr: HumanReadableRepr) -> Self {
            match repr {
                HumanReadableRepr::Bitcoin(value) => Self::Bitcoin(value),
                HumanReadableRepr::BitName => Self::BitName,
                HumanReadableRepr::BitNameReservation => {
                    Self::BitNameReservation
                }
                HumanReadableRepr::Withdrawal(withdrawal) => {
                    Self::Withdrawal(withdrawal)
                }
            }
        }
    }

    impl From<Content> for DefaultRepr {
        fn from(content: Content) -> Self {
            match content {
                Content::Bitcoin(value) => Self::Bitcoin(value),
                Content::BitName => Self::BitName,
                Content::BitNameReservation => Self::BitNameReservation,
                Content::Withdrawal(withdrawal) => Self::Withdrawal(withdrawal),
            }
        }
    }

    impl From<Content> for HumanReadableRepr {
        fn from(content: Content) -> Self {
            match content {
                Content::Bitcoin(value) => Self::Bitcoin(value),
                Content::BitName => Self::BitName,
                Content::BitNameReservation => Self::BitNameReservation,
                Content::Withdrawal(withdrawal) => Self::Withdrawal(withdrawal),
            }
        }
    }

    impl<'de> Deserialize<'de> for Content {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            <SerdeRepr as serde_with::DeserializeAs<'de, _>>::deserialize_as(
                deserializer,
            )
        }
    }

    impl Serialize for Content {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            <SerdeRepr as serde_with::SerializeAs<_>>::serialize_as(
                self, serializer,
            )
        }
    }

    impl PartialSchema for Content {
        fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
            <HumanReadableRepr as PartialSchema>::schema()
        }
    }

    impl ToSchema for Content {
        fn name() -> std::borrow::Cow<'static, str> {
            <HumanReadableRepr as ToSchema>::name()
        }
    }

    impl crate::GetValue for Content {
        #[inline(always)]
        fn get_value(&self) -> bitcoin::Amount {
            match self {
                Self::Bitcoin(value) => value.0,
                Self::BitName | Self::BitNameReservation => {
                    bitcoin::Amount::ZERO
                }
                Self::Withdrawal(withdrawal) => withdrawal.get_value(),
            }
        }
    }
}
pub use content::Content;

mod filled {
    use serde::{Deserialize, Serialize};
    use utoipa::{PartialSchema, ToSchema};

    use super::Content;
    use crate::{BitName, Hash, Txid};

    /// Defines a Filled enum with the specified visibility, name,
    /// derives, and attributes for each variant
    macro_rules! Filled {
        (   $vis:vis $enum_name:ident
            $(, attrs: [$($attr:meta),* $(,)?])?
            $(, bitcoin_attrs: [$($bitcoin_attr:meta),* $(,)?])?
            $(, bitname_reservation_commitment_attrs:
                [$($bitname_reservation_commitment_attr:meta),* $(,)?]
            )?
            $(,)?
        ) => {
            /// Representation of Output Content that includes asset type and/or
            /// reservation commitment
            // Generate attributes if they were provided
            $(
                $(#[$attr])*
            )?
            $vis enum $enum_name {
                // Generate attributes if they were provided
                $(
                    $(#[$bitcoin_attr])*
                )?
                Bitcoin(super::BitcoinContent),
                BitcoinWithdrawal(super::WithdrawalContent),
                BitName(BitName),
                /// Reservation txid and commitment
                BitNameReservation(
                    crate::Txid,
                    $(
                        $(#[$bitname_reservation_commitment_attr])*
                    )?
                    crate::Hash
                ),
            }
        }
    }

    Filled!(DefaultRepr, attrs: [derive(Deserialize, Serialize)]);

    Filled!(
        HumanReadableRepr,
        attrs: [
            derive(utoipa::ToSchema, Deserialize, Serialize),
            schema(as = FilledOutputContent)
        ],
        bitcoin_attrs: [
            serde(rename = "BitcoinSats")
        ],
        bitname_reservation_commitment_attrs: [
            serde(with = "hex::serde")
        ]
    );

    type SerdeRepr = serde_with::IfIsHumanReadable<
        serde_with::FromInto<HumanReadableRepr>,
        serde_with::FromInto<DefaultRepr>,
    >;

    Filled!(
        pub Filled,
        attrs: [derive(
            Clone,
            Debug,
            Eq,
            PartialEq,
        )],
    );

    impl Filled {
        /// returns the BitName ID (name hash) if the filled output content
        /// corresponds to a BitName output.
        pub fn bitname(&self) -> Option<&BitName> {
            match self {
                Self::BitName(name_hash) => Some(name_hash),
                _ => None,
            }
        }

        /// true if the output content corresponds to a bitname
        pub fn is_bitname(&self) -> bool {
            matches!(self, Self::BitName(_))
        }

        /// true if the output content corresponds to a reservation
        pub fn is_reservation(&self) -> bool {
            matches!(self, Self::BitNameReservation { .. })
        }

        /// true if the output content corresponds to a withdrawal
        pub fn is_withdrawal(&self) -> bool {
            matches!(self, Self::BitcoinWithdrawal { .. })
        }

        /// returns the reservation txid and commitment if the filled output
        /// content corresponds to a BitName reservation output.
        pub fn reservation_data(&self) -> Option<(&Txid, &Hash)> {
            match self {
                Self::BitNameReservation(txid, commitment) => {
                    Some((txid, commitment))
                }
                _ => None,
            }
        }

        /// returns the reservation commitment if the filled output content
        /// corresponds to a BitName reservation output.
        pub fn reservation_commitment(&self) -> Option<&Hash> {
            self.reservation_data().map(|(_, commitment)| commitment)
        }
    }

    impl From<Filled> for Content {
        fn from(filled: Filled) -> Self {
            match filled {
                Filled::Bitcoin(value) => Content::Bitcoin(value),
                Filled::BitcoinWithdrawal(withdrawal) => {
                    Content::Withdrawal(withdrawal)
                }
                Filled::BitName(_) => Content::BitName,
                Filled::BitNameReservation { .. } => {
                    Content::BitNameReservation
                }
            }
        }
    }

    impl From<DefaultRepr> for Filled {
        fn from(repr: DefaultRepr) -> Self {
            match repr {
                DefaultRepr::Bitcoin(value) => Self::Bitcoin(value),
                DefaultRepr::BitcoinWithdrawal(withdrawal) => {
                    Self::BitcoinWithdrawal(withdrawal)
                }
                DefaultRepr::BitName(bitname) => Self::BitName(bitname),
                DefaultRepr::BitNameReservation(txid, commitment) => {
                    Self::BitNameReservation(txid, commitment)
                }
            }
        }
    }

    impl From<HumanReadableRepr> for Filled {
        fn from(repr: HumanReadableRepr) -> Self {
            match repr {
                HumanReadableRepr::Bitcoin(value) => Self::Bitcoin(value),
                HumanReadableRepr::BitcoinWithdrawal(withdrawal) => {
                    Self::BitcoinWithdrawal(withdrawal)
                }
                HumanReadableRepr::BitName(bitname) => Self::BitName(bitname),
                HumanReadableRepr::BitNameReservation(txid, commitment) => {
                    Self::BitNameReservation(txid, commitment)
                }
            }
        }
    }

    impl From<Filled> for DefaultRepr {
        fn from(content: Filled) -> Self {
            match content {
                Filled::Bitcoin(value) => Self::Bitcoin(value),
                Filled::BitcoinWithdrawal(withdrawal) => {
                    Self::BitcoinWithdrawal(withdrawal)
                }
                Filled::BitName(bitname) => Self::BitName(bitname),
                Filled::BitNameReservation(txid, commitment) => {
                    Self::BitNameReservation(txid, commitment)
                }
            }
        }
    }

    impl From<Filled> for HumanReadableRepr {
        fn from(content: Filled) -> Self {
            match content {
                Filled::Bitcoin(value) => Self::Bitcoin(value),
                Filled::BitcoinWithdrawal(withdrawal) => {
                    Self::BitcoinWithdrawal(withdrawal)
                }
                Filled::BitName(bitname) => Self::BitName(bitname),
                Filled::BitNameReservation(txid, commitment) => {
                    Self::BitNameReservation(txid, commitment)
                }
            }
        }
    }

    impl<'de> Deserialize<'de> for Filled {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            <SerdeRepr as serde_with::DeserializeAs<'de, _>>::deserialize_as(
                deserializer,
            )
        }
    }

    impl Serialize for Filled {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            <SerdeRepr as serde_with::SerializeAs<_>>::serialize_as(
                self, serializer,
            )
        }
    }

    impl PartialSchema for Filled {
        fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
            <HumanReadableRepr as PartialSchema>::schema()
        }
    }

    impl ToSchema for Filled {
        fn name() -> std::borrow::Cow<'static, str> {
            <HumanReadableRepr as ToSchema>::name()
        }
    }

    impl crate::GetValue for Filled {
        fn get_value(&self) -> bitcoin::Amount {
            Content::from(self.clone()).get_value()
        }
    }
}
pub use filled::Filled;
