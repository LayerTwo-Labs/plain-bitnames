use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use bip300301::bitcoin;

use super::{
    address::Address,
    hashes::{self, Hash, MerkleRoot, Txid},
    EncryptionPubKey, GetValue,
};
use crate::authorization::{Authorization, PublicKey, Signature};

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

/// delete, retain, or set a value
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Update<T> {
    Delete,
    Retain,
    Set(T),
}

/// updates to the data associated with a BitName
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitNameDataUpdates {
    /// commitment to arbitrary data
    pub commitment: Update<Hash>,
    /// optional ipv4 addr
    pub ipv4_addr: Update<Ipv4Addr>,
    /// optional ipv6 addr
    pub ipv6_addr: Update<Ipv6Addr>,
    /// optional pubkey used for encryption
    pub encryption_pubkey: Update<EncryptionPubKey>,
    /// optional pubkey used for signing messages
    pub signing_pubkey: Update<PublicKey>,
}

/// batch icann registration tx payload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchIcannRegistrationData {
    /// plaintext names of the bitnames to be registered as ICANN domains
    pub plain_names: Vec<String>,
    /// signature over the batch icann registration tx
    pub signature: Signature,
}

#[allow(clippy::enum_variant_names)]
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
    BitNameUpdate(Box<BitNameDataUpdates>),
    BatchIcann(BatchIcannRegistrationData),
}

pub type TxData = TransactionData;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: TxInputs,
    pub outputs: TxOutputs,
    pub memo: Vec<u8>,
    pub data: Option<TransactionData>,
}

/// Representation of Output Content that includes asset type and/or
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
    /// Reservation txid and commitment
    BitNameReservation(Txid, Hash),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedTransaction {
    pub transaction: Transaction,
    /// Authorization is called witness in Bitcoin.
    pub authorizations: Vec<Authorization>,
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

    /// true if the tx data corresponds to an update
    pub fn is_update(&self) -> bool {
        matches!(self, Self::BitNameUpdate(_))
    }

    /// true if the tx data corresponds to a batch icann registration
    pub fn is_batch_icann(&self) -> bool {
        matches!(self, Self::BatchIcann(_))
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

    /// return an iterator over value outputs with index
    pub fn indexed_value_outputs(&self) -> impl Iterator<Item = (usize, &Output)> {
        self.outputs.iter().enumerate().filter(|(_, output)| output.get_value() != 0)
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

    /// true if the tx data corresponds to a regular tx
    pub fn is_regular(&self) -> bool {
        self.data.is_none()
    }

    /// true if the tx data corresponds to a reservation
    pub fn is_reservation(&self) -> bool {
        match &self.data {
            Some(tx_data) => tx_data.is_reservation(),
            None => false,
        }
    }

    /// true if the tx data corresponds to an update
    pub fn is_update(&self) -> bool {
        match &self.data {
            Some(tx_data) => tx_data.is_update(),
            None => false,
        }
    }

    /// true if the tx data corresponds to a batch icann registration
    pub fn is_batch_icann(&self) -> bool {
        match &self.data {
            Some(tx_data) => tx_data.is_batch_icann(),
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
                let implied_commitment = blake3::keyed_hash(
                    &revealed_nonce ,
                    &name_hash).into();
                Some(implied_commitment)
            }
            _ => None,
        }
    }

    /// return an iterator over reservation outputs
    pub fn reservation_outputs(&self) -> impl DoubleEndedIterator<Item = &Output> {
        self.outputs.iter().filter(|output| output.is_reservation())
    }

    pub fn txid(&self) -> Txid {
        hashes::hash(self).into()
    }

    /// If the tx is a bitname reservation, returns the reservation commitment
    pub fn reservation_commitment(&self) -> Option<Hash> {
        match self.data {
            Some(TxData::BitNameReservation { commitment }) => Some(commitment),
            _ => None,
        }
    }

    pub fn batch_icann_data(&self) -> Option<&BatchIcannRegistrationData> {
        match self.data {
            Some(TxData::BatchIcann(ref batch_icann_data)) => {
                Some(batch_icann_data)
            }
            _ => None,
        }
    }
}

impl FilledContent {
    /// returns the BitName ID (name hash) if the filled output content
    /// corresponds to a BitName output.
    pub fn bitname(&self) -> Option<&Hash> {
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

    /// returns the BitName ID (name hash) if the filled output content
    /// corresponds to a BitName output.
    pub fn bitname(&self) -> Option<&Hash> {
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

    /// true if the tx data corresponds to a regular tx
    pub fn is_regular(&self) -> bool {
        self.transaction.is_regular()
    }

    /// true if the tx data corresponds to a BitName reservation
    pub fn is_reservation(&self) -> bool {
        self.transaction.is_reservation()
    }

    /// true if the tx data corresponds to a BitName update
    pub fn is_update(&self) -> bool {
        self.transaction.is_update()
    }

    /// true if the tx data corresponds to a BitName batch icann registration
    pub fn is_batch_icann(&self) -> bool {
        self.transaction.is_batch_icann()
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

    /// If the tx is a batch icann registration, returns the batch icann
    /// registration data
    pub fn batch_icann_data(&self) -> Option<&BatchIcannRegistrationData> {
        self.transaction.batch_icann_data()
    }

    /// accessor for txid
    pub fn txid(&self) -> Txid {
        self.transaction.txid()
    }

    /// return an iterator over spent outpoints/outputs
    pub fn spent_inputs(
        &self,
    ) -> impl DoubleEndedIterator<Item = (&OutPoint, &FilledOutput)> {
        self.inputs().iter().zip(self.spent_utxos.iter())
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
    pub fn spent_reservations(
        &self,
    ) -> impl Iterator<Item = (&OutPoint, &FilledOutput)> {
        self.spent_inputs()
            .filter(|(_, filled_output)| filled_output.is_reservation())
    }

    /// return an iterator over spent bitnames
    pub fn spent_bitnames(
        &self,
    ) -> impl DoubleEndedIterator<Item = (&OutPoint, &FilledOutput)> {
        self.spent_inputs()
            .filter(|(_, filled_output)| filled_output.is_bitname())
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
            .map(|(_, filled_output)| filled_output.content())
            .cloned()
            .chain(new_bitname_content.into_iter())
    }

    /// compute the filled content for BitName reservation outputs
    /// WARNING: do not expose DoubleEndedIterator.
    fn filled_reservation_output_content(
        &self,
    ) -> impl Iterator<Item = FilledContent> + '_ {
        // If this tx is a BitName reservation, this is the content of the
        // output corresponding to the newly created BitName reservation,
        // which must be the final reservation output.
        let new_reservation_content: Option<FilledContent> =
            self.reservation_commitment().map(|commitment| {
                FilledContent::BitNameReservation(self.txid(), commitment)
            });
        // used to track if the reservation that should be burned as part
        // of a registration tx
        let mut reservation_to_burn: Option<Hash> =
            self.implied_reservation_commitment();
        self.spent_reservations()
            .map(|(_, filled_output)| filled_output.content())
            .cloned()
            // In the event of a registration, the first corresponding
            // reservation does not occur in the output
            .filter(move |content| {
                if let Some(implied_commitment) = reservation_to_burn {
                    if matches!(
                        content,
                        FilledContent::BitNameReservation(_, commitment)
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

    /// not all spent utxos require auth
    pub fn spent_utxos_requiring_auth(&self) -> Vec<FilledOutput> {
        if let Some(batch_icann_data) = self.batch_icann_data() {
            let mut bitnames = batch_icann_data
                .plain_names
                .iter()
                .map(|plain_name| {
                    Hash::from(blake3::hash(plain_name.as_bytes()))
                })
                .peekable();
            let mut spent_utxos = self.spent_utxos.clone();
            spent_utxos.retain(|output| {
                let Some(spent_bitname) = output.bitname() else {
                    return true;
                };
                let Some(bitname) = bitnames.peek() else {
                    return true;
                };
                if spent_bitname == bitname {
                    let _ = bitnames.next();
                    false
                } else {
                    true
                }
            });
            spent_utxos
        } else {
            self.spent_utxos.clone()
        }
    }
}