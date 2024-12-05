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

fn borsh_serialize_bitcoin_amount<W>(
    bitcoin_amount: &bitcoin::Amount,
    writer: &mut W,
) -> borsh::io::Result<()>
where
    W: borsh::io::Write,
{
    borsh::BorshSerialize::serialize(&bitcoin_amount.to_sat(), writer)
}

mod content {
    use serde::{Deserialize, Serialize};
    use utoipa::{PartialSchema, ToSchema};

    /// Default representation for Serde
    #[derive(Deserialize, Serialize)]
    enum DefaultRepr {
        Bitcoin(bitcoin::Amount),
        BitName,
        BitNameReservation,
        Withdrawal {
            value: bitcoin::Amount,
            main_fee: bitcoin::Amount,
            main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        },
    }

    /// Human-readable representation for Serde
    #[derive(Deserialize, Serialize, ToSchema)]
    #[schema(as = OutputContent, description = "")]
    enum HumanReadableRepr {
        Bitcoin {
            #[serde(with = "bitcoin::amount::serde::as_sat")]
            #[serde(rename = "value_sats")]
            #[schema(value_type = u64)]
            value: bitcoin::Amount,
        },
        BitName,
        BitNameReservation,
        Withdrawal {
            #[serde(with = "bitcoin::amount::serde::as_sat")]
            #[serde(rename = "value_sats")]
            #[schema(value_type = u64)]
            value: bitcoin::Amount,
            #[serde(with = "bitcoin::amount::serde::as_sat")]
            #[serde(rename = "main_fee_sats")]
            #[schema(value_type = u64)]
            main_fee: bitcoin::Amount,
            #[schema(value_type = crate::types::schema::BitcoinAddr)]
            main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        },
    }

    type SerdeRepr = serde_with::IfIsHumanReadable<
        serde_with::FromInto<DefaultRepr>,
        serde_with::FromInto<HumanReadableRepr>,
    >;

    #[derive(borsh::BorshSerialize, Clone, Debug, Eq, PartialEq)]
    pub enum Content {
        Bitcoin(
            #[borsh(serialize_with = "super::borsh_serialize_bitcoin_amount")]
            bitcoin::Amount,
        ),
        BitName,
        BitNameReservation,
        Withdrawal {
            #[borsh(serialize_with = "super::borsh_serialize_bitcoin_amount")]
            value: bitcoin::Amount,
            #[borsh(serialize_with = "super::borsh_serialize_bitcoin_amount")]
            main_fee: bitcoin::Amount,
            #[borsh(serialize_with = "super::borsh_serialize_bitcoin_address")]
            main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        },
    }

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

    impl crate::types::GetValue for Content {
        #[inline(always)]
        fn get_value(&self) -> bitcoin::Amount {
            match self {
                Self::Bitcoin(value) => *value,
                Self::BitName | Self::BitNameReservation => {
                    bitcoin::Amount::ZERO
                }
                Self::Withdrawal { value, .. } => *value,
            }
        }
    }

    impl From<Content> for DefaultRepr {
        fn from(content: Content) -> Self {
            match content {
                Content::Bitcoin(value) => Self::Bitcoin(value),
                Content::BitName => Self::BitName,
                Content::BitNameReservation => Self::BitNameReservation,
                Content::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                } => Self::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                },
            }
        }
    }

    impl From<Content> for HumanReadableRepr {
        fn from(content: Content) -> Self {
            match content {
                Content::Bitcoin(value) => Self::Bitcoin { value },
                Content::BitName => Self::BitName,
                Content::BitNameReservation => Self::BitNameReservation,
                Content::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                } => Self::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                },
            }
        }
    }

    impl From<DefaultRepr> for Content {
        fn from(repr: DefaultRepr) -> Self {
            match repr {
                DefaultRepr::Bitcoin(value) => Self::Bitcoin(value),
                DefaultRepr::BitName => Self::BitName,
                DefaultRepr::BitNameReservation => Self::BitNameReservation,
                DefaultRepr::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                } => Self::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                },
            }
        }
    }

    impl From<HumanReadableRepr> for Content {
        fn from(repr: HumanReadableRepr) -> Self {
            match repr {
                HumanReadableRepr::Bitcoin { value } => Self::Bitcoin(value),
                HumanReadableRepr::BitName => Self::BitName,
                HumanReadableRepr::BitNameReservation => {
                    Self::BitNameReservation
                }
                HumanReadableRepr::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                } => Self::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                },
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
}
pub use content::Content;

mod filled {
    use serde::{Deserialize, Serialize};
    use utoipa::{PartialSchema, ToSchema};

    use super::Content;
    use crate::types::{BitName, Hash, Txid};

    /// Default representation for Serde
    #[derive(Deserialize, Serialize)]
    enum DefaultRepr {
        Bitcoin(bitcoin::Amount),
        BitName(BitName),
        BitNameReservation(Txid, Hash),
        Withdrawal {
            value: bitcoin::Amount,
            main_fee: bitcoin::Amount,
            main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        },
    }

    /// Human-readable representation for Serde
    #[derive(Deserialize, Serialize, ToSchema)]
    #[schema(as = FilledOutputContent, description = "")]
    enum HumanReadableRepr {
        Bitcoin {
            #[serde(with = "bitcoin::amount::serde::as_sat")]
            #[serde(rename = "value_sats")]
            #[schema(value_type = u64)]
            value: bitcoin::Amount,
        },
        BitName(BitName),
        BitNameReservation(Txid, Hash),
        Withdrawal {
            #[serde(with = "bitcoin::amount::serde::as_sat")]
            #[serde(rename = "value_sats")]
            #[schema(value_type = u64)]
            value: bitcoin::Amount,
            #[serde(with = "bitcoin::amount::serde::as_sat")]
            #[serde(rename = "main_fee_sats")]
            #[schema(value_type = u64)]
            main_fee: bitcoin::Amount,
            #[schema(value_type = crate::types::schema::BitcoinAddr)]
            main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        },
    }

    type SerdeRepr = serde_with::IfIsHumanReadable<
        serde_with::FromInto<DefaultRepr>,
        serde_with::FromInto<HumanReadableRepr>,
    >;

    /// Representation of Output Content that includes asset type and/or
    /// reservation commitment
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum Filled {
        Bitcoin(bitcoin::Amount),
        BitcoinWithdrawal {
            value: bitcoin::Amount,
            main_fee: bitcoin::Amount,
            main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        },
        BitName(BitName),
        /// Reservation txid and commitment
        BitNameReservation(Txid, Hash),
    }

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
                Filled::BitcoinWithdrawal {
                    value,
                    main_fee,
                    main_address,
                } => Content::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                },
                Filled::BitName(_) => Content::BitName,
                Filled::BitNameReservation { .. } => {
                    Content::BitNameReservation
                }
            }
        }
    }

    impl crate::types::GetValue for Filled {
        fn get_value(&self) -> bitcoin::Amount {
            Content::from(self.clone()).get_value()
        }
    }

    impl From<Filled> for DefaultRepr {
        fn from(content: Filled) -> Self {
            match content {
                Filled::Bitcoin(value) => Self::Bitcoin(value),
                Filled::BitName(bitname) => Self::BitName(bitname),
                Filled::BitNameReservation(txid, commitment) => {
                    Self::BitNameReservation(txid, commitment)
                }
                Filled::BitcoinWithdrawal {
                    value,
                    main_fee,
                    main_address,
                } => Self::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                },
            }
        }
    }

    impl From<Filled> for HumanReadableRepr {
        fn from(content: Filled) -> Self {
            match content {
                Filled::Bitcoin(value) => Self::Bitcoin { value },
                Filled::BitName(bitname) => Self::BitName(bitname),
                Filled::BitNameReservation(txid, commitment) => {
                    Self::BitNameReservation(txid, commitment)
                }
                Filled::BitcoinWithdrawal {
                    value,
                    main_fee,
                    main_address,
                } => Self::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                },
            }
        }
    }

    impl From<DefaultRepr> for Filled {
        fn from(repr: DefaultRepr) -> Self {
            match repr {
                DefaultRepr::Bitcoin(value) => Self::Bitcoin(value),
                DefaultRepr::BitName(bitname) => Self::BitName(bitname),
                DefaultRepr::BitNameReservation(txid, commitment) => {
                    Self::BitNameReservation(txid, commitment)
                }
                DefaultRepr::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                } => Self::BitcoinWithdrawal {
                    value,
                    main_fee,
                    main_address,
                },
            }
        }
    }

    impl From<HumanReadableRepr> for Filled {
        fn from(repr: HumanReadableRepr) -> Self {
            match repr {
                HumanReadableRepr::Bitcoin { value } => Self::Bitcoin(value),
                HumanReadableRepr::BitName(bitname) => Self::BitName(bitname),
                HumanReadableRepr::BitNameReservation(txid, commitment) => {
                    Self::BitNameReservation(txid, commitment)
                }
                HumanReadableRepr::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                } => Self::BitcoinWithdrawal {
                    value,
                    main_fee,
                    main_address,
                },
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
}
pub use filled::Filled;
