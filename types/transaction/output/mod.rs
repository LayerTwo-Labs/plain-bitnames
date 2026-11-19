use borsh::BorshSerialize;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    GetValue,
    address::Address,
    hashes::{BitName, Hash, Txid},
    transaction::outpoint::OutPoint,
    util,
};

mod content;
pub use content::{
    BitcoinContent, Content, Filled as FilledContent, WithdrawalContent,
};

#[derive(
    BorshSerialize,
    Clone,
    Debug,
    Deserialize,
    Eq,
    PartialEq,
    Serialize,
    ToSchema,
)]
pub struct Output {
    #[serde(with = "util::serde::display_fromstr_human_readable")]
    pub address: Address,
    pub content: Content,
    #[serde(with = "util::serde::hexstr_human_readable")]
    pub memo: Vec<u8>,
}

impl Output {
    pub fn new(address: Address, content: Content) -> Self {
        Self {
            address,
            content,
            memo: Vec::new(),
        }
    }

    /// Canonical size in bytes. The canonical encoding is used for hashing,
    /// but other encodings may be used at eg. networking, rpc levels.
    #[inline(always)]
    pub(crate) fn canonical_size(&self) -> borsh::io::Result<u64> {
        borsh::object_length(self).map(|size| size as u64)
    }

    /// true if the output content corresponds to a BitName
    pub fn is_bitname(&self) -> bool {
        self.content.is_bitname()
    }

    /// true if the output content corresponds to a reservation
    pub fn is_reservation(&self) -> bool {
        self.content.is_reservation()
    }

    /// `true` if the output content corresponds to a value output
    pub fn is_value(&self) -> bool {
        match self.content {
            Content::Bitcoin(_) | Content::Withdrawal { .. } => true,
            Content::BitName | Content::BitNameReservation => false,
        }
    }
}

impl GetValue for Output {
    #[inline(always)]
    fn get_value(&self) -> bitcoin::Amount {
        self.content.get_value()
    }
}

/// Representation of output that includes asset type
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct FilledOutput {
    #[serde(with = "util::serde::display_fromstr_human_readable")]
    pub address: Address,
    pub content: FilledContent,
    #[serde(with = "util::serde::hexstr_human_readable")]
    pub memo: Vec<u8>,
}

impl FilledOutput {
    /// construct a new filled output
    #[inline(always)]
    pub fn new(address: Address, content: FilledContent) -> Self {
        Self {
            address,
            content,
            memo: Vec::new(),
        }
    }

    /// Construct a new Bitcoin value output
    #[inline(always)]
    pub fn new_bitcoin_value(
        address: Address,
        amount: bitcoin::Amount,
    ) -> Self {
        Self::new(address, FilledContent::new_bitcoin_value(amount))
    }

    /// returns the BitName ID (name hash) if the filled output content
    /// corresponds to a BitName output.
    pub fn bitname(&self) -> Option<&BitName> {
        self.content.bitname()
    }

    /// accessor for content
    pub fn content(&self) -> &FilledContent {
        &self.content
    }

    /// true if the output content corresponds to a bitname
    pub fn is_bitname(&self) -> bool {
        self.content.is_bitname()
    }

    /// true if the output content corresponds to a reservation
    pub fn is_reservation(&self) -> bool {
        self.content.is_reservation()
    }

    /// returns the reservation txid and commitment if the filled output
    /// content corresponds to a BitName reservation output.
    pub fn reservation_data(&self) -> Option<(&Txid, &Hash)> {
        self.content.reservation_data()
    }

    /// returns the reservation commitment if the filled output content
    /// corresponds to a BitName reservation output.
    pub fn reservation_commitment(&self) -> Option<&Hash> {
        self.content.reservation_commitment()
    }
}

impl From<FilledOutput> for Output {
    fn from(filled: FilledOutput) -> Self {
        Self {
            address: filled.address,
            content: filled.content.into(),
            memo: filled.memo,
        }
    }
}

impl GetValue for FilledOutput {
    fn get_value(&self) -> bitcoin::Amount {
        self.content.get_value()
    }
}

#[derive(
    BorshSerialize,
    Clone,
    Debug,
    Deserialize,
    Eq,
    PartialEq,
    Serialize,
    ToSchema,
)]
pub struct PointedOutput<OutputKind = Output> {
    pub outpoint: OutPoint,
    pub output: OutputKind,
}
