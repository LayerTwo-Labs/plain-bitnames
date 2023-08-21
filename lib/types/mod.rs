use std::{
    cmp::Ordering,
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use blake3;
use serde::{Deserialize, Serialize};
pub use x25519_dalek::PublicKey as EncryptionPubKey;

use bip300301::bitcoin;

use crate::authorization::{Authorization, PublicKey};

mod address;
mod hashes;

pub use address::*;
pub use hashes::*;

#[derive(Hash, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutPoint {
    // Created by transactions.
    Regular { txid: Txid, vout: u32 },
    // Created by block bodies.
    Coinbase { merkle_root: MerkleRoot, vout: u32 },
    // Created by mainchain deposits.
    Deposit(bitcoin::OutPoint),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Content {
    BitName,
    BitNameReservation,
    Value(u64),
    Withdrawal {
        value: u64,
        main_fee: u64,
        main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub address: Address,
    pub content: Content,
    pub memo: Vec<u8>,
}

/*
// Replace () with a type (usually an enum) for output data specific for your sidechain.
pub type Output = types::Output<()>;
pub type Transaction = types::Transaction<()>;
pub type FilledTransaction = types::FilledTransaction<()>;
pub type AuthorizedTransaction = types::AuthorizedTransaction<Authorization, ()>;
pub type Body = types::Body<Authorization, ()>;
*/

pub type TxInputs = Vec<OutPoint>;

pub type TxOutputs = Vec<Output>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitNameData {
    /// commitment to arbitrary data
    pub commitment: Option<Hash>,
    /// optional ipv4 addr
    pub ipv4_addr: Option<Ipv4Addr>,
    /// optional ipv6 addr
    pub ipv6_addr: Option<Ipv6Addr>,
    /// optional pubkey used for encryption
    pub encryption_pubkey: Option<EncryptionPubKey>,
    /// optional pubkey used for signing messages
    pub signing_pubkey: Option<PublicKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransactionData {
    BitNameReservation {
        /// commitment to the BitName that will be registered
        commitment: Hash,
    },
    BitNameRegistration {
        /// reveal of the name hash
        name_hash: Hash,
        /// reveal of the nonce used for the BitName reservation commitment
        revealed_nonce: Hash,
        /// initial BitName data
        bitname_data: Box<BitNameData>,
    },
}

pub type TxData = TransactionData;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: TxInputs,
    pub outputs: TxOutputs,
    pub memo: Vec<u8>,
    pub data: Option<TransactionData>,
}

/// Representation of Output Content that includes asset type or
/// reservation commitment
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FilledContent {
    Bitcoin(u64),
    BitcoinWithdrawal {
        value: u64,
        main_fee: u64,
        main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
    },
    BitName(Hash),
    /// Reservation commitment
    BitNameReservation(Hash),
}

/// Representation of output that includes asset type
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FilledOutput {
    pub address: Address,
    pub content: FilledContent,
    pub memo: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilledTransaction {
    pub transaction: Transaction,
    pub spent_utxos: Vec<FilledOutput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    pub merkle_root: MerkleRoot,
    pub prev_side_hash: BlockHash,
    pub prev_main_hash: bitcoin::BlockHash,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WithdrawalBundleStatus {
    Failed,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalBundle {
    pub spent_utxos: HashMap<OutPoint, FilledOutput>,
    pub transaction: bitcoin::Transaction,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TwoWayPegData {
    pub deposits: HashMap<OutPoint, Output>,
    pub deposit_block_hash: Option<bitcoin::BlockHash>,
    pub bundle_statuses: HashMap<bitcoin::Txid, WithdrawalBundleStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedTransaction {
    pub transaction: Transaction,
    /// Authorization is called witness in Bitcoin.
    pub authorizations: Vec<Authorization>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    pub coinbase: Vec<Output>,
    pub transactions: Vec<Transaction>,
    pub authorizations: Vec<Authorization>,
}

/*
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisconnectData {
    pub spent_utxos: HashMap<types::OutPoint, Output>,
    pub deposits: Vec<types::OutPoint>,
    pub pending_bundles: Vec<bitcoin::Txid>,
    pub spent_bundles: HashMap<bitcoin::Txid, Vec<types::OutPoint>>,
    pub spent_withdrawals: HashMap<types::OutPoint, Output>,
    pub failed_withdrawals: Vec<bitcoin::Txid>,
}
*/

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct AggregatedWithdrawal {
    pub spent_utxos: HashMap<OutPoint, FilledOutput>,
    pub main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
    pub value: u64,
    pub main_fee: u64,
}

impl std::fmt::Display for OutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Regular { txid, vout } => write!(f, "regular {txid} {vout}"),
            Self::Coinbase { merkle_root, vout } => {
                write!(f, "coinbase {merkle_root} {vout}")
            }
            Self::Deposit(bitcoin::OutPoint { txid, vout }) => {
                write!(f, "deposit {txid} {vout}")
            }
        }
    }
}

impl Content {
    /// true if the output content corresponds to a BitName
    pub fn is_bitname(&self) -> bool {
        matches!(self, Self::BitName)
    }

    /// true if the output content corresponds to a reservation
    pub fn is_reservation(&self) -> bool {
        matches!(self, Self::BitNameReservation)
    }

    pub fn is_value(&self) -> bool {
        matches!(self, Self::Value(_))
    }
    pub fn is_withdrawal(&self) -> bool {
        matches!(self, Self::Withdrawal { .. })
    }
}

impl GetValue for Content {
    #[inline(always)]
    fn get_value(&self) -> u64 {
        match self {
            Self::BitName => 0,
            Self::BitNameReservation => 0,
            Self::Value(value) => *value,
            Self::Withdrawal { value, .. } => *value,
        }
    }
}

impl Output {
    pub fn new(address: Address, content: Content) -> Self {
        Self {
            address,
            content,
            memo: Vec::new(),
        }
    }

    /// true if the output content corresponds to a BitName
    pub fn is_bitname(&self) -> bool {
        self.content.is_bitname()
    }

    /// true if the output content corresponds to a reservation
    pub fn is_reservation(&self) -> bool {
        self.content.is_reservation()
    }
}

impl GetValue for Output {
    #[inline(always)]
    fn get_value(&self) -> u64 {
        self.content.get_value()
    }
}

impl TxData {
    /// true if the tx data corresponds to a reservation
    pub fn is_registration(&self) -> bool {
        matches!(self, Self::BitNameRegistration { .. })
    }

    /// true if the tx data corresponds to a reservation
    pub fn is_reservation(&self) -> bool {
        matches!(self, Self::BitNameReservation { .. })
    }
}

impl Transaction {
    pub fn new(inputs: TxInputs, outputs: TxOutputs) -> Self {
        Self {
            inputs,
            outputs,
            memo: Vec::new(),
            data: None,
        }
    }

    /// return an iterator over bitname outputs
    pub fn bitname_outputs(&self) -> impl Iterator<Item = &Output> {
        self.outputs.iter().filter(|output| output.is_bitname())
    }

    /// true if the tx data corresponds to a bitname registration
    pub fn is_registration(&self) -> bool {
        match &self.data {
            Some(tx_data) => tx_data.is_registration(),
            None => false,
        }
    }

    /// true if the tx data corresponds to a reservation
    pub fn is_reservation(&self) -> bool {
        match &self.data {
            Some(tx_data) => tx_data.is_reservation(),
            None => false,
        }
    }

    /// If the tx is a bitname registration, returns the registered name hash
    pub fn registration_name_hash(&self) -> Option<Hash> {
        match self.data {
            Some(TxData::BitNameRegistration { name_hash, .. }) => {
                Some(name_hash)
            }
            _ => None,
        }
    }

    /// If the tx is a bitname registration, returns the implied reservation
    /// commitment
    pub fn implied_reservation_commitment(&self) -> Option<Hash> {
        match self.data {
            Some(TxData::BitNameRegistration {
                name_hash,
                revealed_nonce,
                ..
            }) => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&revealed_nonce);
                hasher.update(&name_hash);
                let implied_commitment = hasher.finalize().into();
                Some(implied_commitment)
            }
            _ => None,
        }
    }

    /// return an iterator over reservation outputs
    pub fn reservation_outputs(&self) -> impl Iterator<Item = &Output> {
        self.outputs.iter().filter(|output| output.is_reservation())
    }

    pub fn txid(&self) -> Txid {
        hash(self).into()
    }

    /// If the tx is a bitname reservation, returns the reservation commitment
    pub fn reservation_commitment(&self) -> Option<Hash> {
        match self.data {
            Some(TxData::BitNameReservation { commitment }) => Some(commitment),
            _ => None,
        }
    }
}

impl FilledContent {
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
}

impl From<FilledContent> for Content {
    fn from(filled: FilledContent) -> Self {
        match filled {
            FilledContent::Bitcoin(value) => Content::Value(value),
            FilledContent::BitcoinWithdrawal {
                value,
                main_fee,
                main_address,
            } => Content::Withdrawal {
                value,
                main_fee,
                main_address,
            },
            FilledContent::BitName(_) => Content::BitName,
            FilledContent::BitNameReservation { .. } => {
                Content::BitNameReservation
            }
        }
    }
}

impl GetValue for FilledContent {
    fn get_value(&self) -> u64 {
        Content::from(self.clone()).get_value()
    }
}

impl FilledOutput {
    /// construct a new filled output
    pub fn new(address: Address, content: FilledContent) -> Self {
        Self {
            address,
            content,
            memo: Vec::new(),
        }
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
    fn get_value(&self) -> u64 {
        self.content.get_value()
    }
}

impl FilledTransaction {
    // return an iterator over BitName reservation outputs
    pub fn bitname_outputs(&self) -> impl Iterator<Item = &Output> {
        self.transaction.bitname_outputs()
    }

    /// accessor for tx data
    pub fn data(&self) -> &Option<TxData> {
        &self.transaction.data
    }

    /// If the tx is a bitname registration, returns the implied reservation
    /// commitment
    pub fn implied_reservation_commitment(&self) -> Option<Hash> {
        self.transaction.implied_reservation_commitment()
    }

    /// accessor for tx outputs
    pub fn inputs(&self) -> &TxInputs {
        &self.transaction.inputs
    }

    /// true if the tx data corresponds to a BitName registration
    pub fn is_registration(&self) -> bool {
        self.transaction.is_registration()
    }

    /// true if the tx data corresponds to a BitName reservation
    pub fn is_reservation(&self) -> bool {
        self.transaction.is_reservation()
    }

    /// accessor for tx outputs
    pub fn outputs(&self) -> &TxOutputs {
        &self.transaction.outputs
    }

    /// If the tx is a bitname registration, returns the registered name hash
    pub fn registration_name_hash(&self) -> Option<Hash> {
        self.transaction.registration_name_hash()
    }

    /// return an iterator over BitName reservation outputs
    pub fn reservation_outputs(&self) -> impl Iterator<Item = &Output> {
        self.transaction.reservation_outputs()
    }

    /// If the tx is a bitname reservation, returns the reservation commitment
    pub fn reservation_commitment(&self) -> Option<Hash> {
        self.transaction.reservation_commitment()
    }

    /// accessor for txid
    pub fn txid(&self) -> Txid {
        self.transaction.txid()
    }

    /// returns the total value spent
    pub fn spent_value(&self) -> u64 {
        self.spent_utxos.iter().map(GetValue::get_value).sum()
    }

    /// returns the total value in the outputs
    pub fn value_out(&self) -> u64 {
        self.outputs().iter().map(GetValue::get_value).sum()
    }

    /// returns the difference between the value spent and value out, if it is
    /// non-negative.
    pub fn fee(&self) -> Option<u64> {
        let spent_value = self.spent_value();
        let value_out = self.value_out();
        if spent_value < value_out {
            None
        } else {
            Some(spent_value - value_out)
        }
    }

    /// return an iterator over spent reservations
    pub fn spent_reservations(&self) -> impl Iterator<Item = &FilledOutput> {
        self.spent_utxos
            .iter()
            .filter(|filled_output| filled_output.is_reservation())
    }

    /// return an iterator over spent bitnames
    pub fn spent_bitnames(&self) -> impl Iterator<Item = &FilledOutput> {
        self.spent_utxos
            .iter()
            .filter(|filled_output| filled_output.is_bitname())
    }

    /// compute the filled content for BitName outputs
    fn filled_bitname_output_content(
        &self,
    ) -> impl Iterator<Item = FilledContent> + '_ {
        // If this tx is a BitName registration, this is the content of the
        // output corresponding to the newly created BitName, which must be
        // the final BitName output.
        let new_bitname_content: Option<FilledContent> =
            self.registration_name_hash().map(FilledContent::BitName);
        self.spent_bitnames()
            .map(FilledOutput::content)
            .cloned()
            .chain(new_bitname_content.into_iter())
    }

    /// compute the filled content for BitName reservation outputs
    fn filled_reservation_output_content(
        &self,
    ) -> impl Iterator<Item = FilledContent> + '_ {
        // If this tx is a BitName reservation, this is the content of the
        // output corresponding to the newly created BitName reservation,
        // which must be the final reservation output.
        let new_reservation_content: Option<FilledContent> = self
            .reservation_commitment()
            .map(FilledContent::BitNameReservation);
        // used to track if the reservation that should be burned as part
        // of a registration tx
        let mut reservation_to_burn: Option<Hash> =
            self.implied_reservation_commitment();
        self.spent_reservations()
            .map(FilledOutput::content)
            .cloned()
            // In the event of a registration, the first corresponding
            // reservation does not occur in the output
            .filter(move |content| {
                if let Some(implied_commitment) = reservation_to_burn {
                    if matches!(
                        content,
                        FilledContent::BitNameReservation(commitment)
                            if *commitment == implied_commitment)
                    {
                        reservation_to_burn = None;
                        false
                    } else {
                        true
                    }
                } else {
                    true
                }
            })
            .chain(new_reservation_content.into_iter())
    }

    /// compute the filled outputs.
    /// returns None if the outputs cannot be filled because the tx is invalid
    pub fn filled_outputs(&self) -> Option<Vec<FilledOutput>> {
        let mut filled_bitname_output_content =
            self.filled_bitname_output_content();
        let mut filled_reservation_output_content =
            self.filled_reservation_output_content();
        self.outputs()
            .iter()
            .map(|output| {
                let content = match output.content.clone() {
                    Content::BitName => {
                        filled_bitname_output_content.next()?.clone()
                    }
                    Content::BitNameReservation => {
                        filled_reservation_output_content.next()?.clone()
                    }
                    Content::Value(value) => FilledContent::Bitcoin(value),
                    Content::Withdrawal {
                        value,
                        main_fee,
                        main_address,
                    } => FilledContent::BitcoinWithdrawal {
                        value,
                        main_fee,
                        main_address,
                    },
                };
                Some(FilledOutput {
                    address: output.address,
                    content,
                    memo: output.memo.clone(),
                })
            })
            .collect()
    }
}

impl Header {
    pub fn hash(&self) -> BlockHash {
        hashes::hash(self).into()
    }
}

impl Body {
    pub fn new(
        authorized_transactions: Vec<AuthorizedTransaction>,
        coinbase: Vec<Output>,
    ) -> Self {
        let mut authorizations = Vec::with_capacity(
            authorized_transactions
                .iter()
                .map(|t| t.transaction.inputs.len())
                .sum(),
        );
        let mut transactions =
            Vec::with_capacity(authorized_transactions.len());
        for at in authorized_transactions.into_iter() {
            authorizations.extend(at.authorizations);
            transactions.push(at.transaction);
        }
        Self {
            coinbase,
            transactions,
            authorizations,
        }
    }

    pub fn compute_merkle_root(&self) -> MerkleRoot {
        // FIXME: Compute actual merkle root instead of just a hash.
        hash(&(&self.coinbase, &self.transactions)).into()
    }

    pub fn get_inputs(&self) -> Vec<OutPoint> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.inputs.iter())
            .copied()
            .collect()
    }

    pub fn get_outputs(&self) -> HashMap<OutPoint, Output> {
        let mut outputs = HashMap::new();
        let merkle_root = self.compute_merkle_root();
        for (vout, output) in self.coinbase.iter().enumerate() {
            let vout = vout as u32;
            let outpoint = OutPoint::Coinbase { merkle_root, vout };
            outputs.insert(outpoint, output.clone());
        }
        for transaction in &self.transactions {
            let txid = transaction.txid();
            for (vout, output) in transaction.outputs.iter().enumerate() {
                let vout = vout as u32;
                let outpoint = OutPoint::Regular { txid, vout };
                outputs.insert(outpoint, output.clone());
            }
        }
        outputs
    }

    pub fn get_coinbase_value(&self) -> u64 {
        self.coinbase.iter().map(|output| output.get_value()).sum()
    }
}

pub trait GetAddress {
    fn get_address(&self) -> Address;
}

pub trait GetValue {
    fn get_value(&self) -> u64;
}

impl GetValue for () {
    fn get_value(&self) -> u64 {
        0
    }
}

pub trait Verify {
    type Error;
    fn verify_transaction(
        transaction: &AuthorizedTransaction,
    ) -> Result<(), Self::Error>;
    fn verify_body(body: &Body) -> Result<(), Self::Error>;
}

impl Ord for AggregatedWithdrawal {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            Ordering::Equal
        } else if self.main_fee > other.main_fee
            || self.value > other.value
            || self.main_address > other.main_address
        {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }
}

impl PartialOrd for AggregatedWithdrawal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
