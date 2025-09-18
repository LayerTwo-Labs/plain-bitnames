use std::io::Cursor;

use bitcoin::amount::CheckedSum;
use borsh::{self, BorshDeserialize, BorshSerialize};
use heed::{BoxedError, BytesDecode, BytesEncode};
use serde::{Deserialize, Serialize};
use utoipa::{PartialSchema, ToSchema};

use super::{
    AmountOverflowError, GetValue,
    address::Address,
    hashes::{self, BitName, Hash, M6id, MerkleRoot, Txid},
    serde_display_fromstr_human_readable, serde_hexstr_human_readable,
};
use crate::{
    authorization::{Authorization, Signature},
    types::{BitNameDataUpdates, MutableBitNameData},
};

mod output_content;
pub use output_content::{
    BitcoinContent as BitcoinOutputContent, Content, Filled as FilledContent,
    WithdrawalContent as WithdrawalOutputContent,
};

fn borsh_serialize_bitcoin_outpoint<W>(
    block_hash: &bitcoin::OutPoint,
    writer: &mut W,
) -> borsh::io::Result<()>
where
    W: borsh::io::Write,
{
    let bitcoin::OutPoint { txid, vout } = block_hash;
    let txid_bytes: &[u8; 32] = txid.as_ref();
    borsh::BorshSerialize::serialize(&(txid_bytes, vout), writer)
}

fn borsh_deserialize_bitcoin_outpoint<R>(
    reader: &mut R,
) -> borsh::io::Result<bitcoin::OutPoint>
where
    R: borsh::io::Read,
{
    use bitcoin::hashes::Hash as _;
    let (txid_bytes, vout): ([u8; 32], u32) =
        <([u8; 32], u32) as BorshDeserialize>::deserialize_reader(reader)?;
    Ok(bitcoin::OutPoint {
        txid: bitcoin::Txid::from_byte_array(txid_bytes),
        vout,
    })
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
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
    ToSchema,
)]
pub enum OutPoint {
    // Created by transactions.
    Regular {
        txid: Txid,
        vout: u32,
    },
    // Created by block bodies.
    Coinbase {
        merkle_root: MerkleRoot,
        vout: u32,
    },
    // Created by mainchain deposits.
    #[schema(value_type = crate::types::schema::BitcoinOutPoint)]
    Deposit(
        #[borsh(
            serialize_with = "borsh_serialize_bitcoin_outpoint",
            deserialize_with = "borsh_deserialize_bitcoin_outpoint"
        )]
        bitcoin::OutPoint,
    ),
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

const OUTPOINT_KEY_SIZE: usize = 37;

/// Fixed-width key for OutPoint based on its canonical Borsh encoding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OutPointKey([u8; OUTPOINT_KEY_SIZE]);

impl OutPointKey {
    /// Get the raw key bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8; OUTPOINT_KEY_SIZE] {
        &self.0
    }

    /// Decode OutPointKey back to OutPoint
    #[inline]
    pub fn to_outpoint(&self) -> OutPoint {
        let mut cursor = Cursor::new(&self.0[..]);
        OutPoint::deserialize_reader(&mut cursor)
            .expect("OutPointKey stores canonical Borsh-serialized OutPoints")
    }

    /// Encode an OutPoint into a fixed-width key
    #[inline]
    pub fn from_outpoint(op: &OutPoint) -> Self {
        let mut key = [0u8; OUTPOINT_KEY_SIZE];
        let mut cursor = Cursor::new(&mut key[..]);
        BorshSerialize::serialize(op, &mut cursor)
            .expect("serializing OutPoint into key buffer should never fail");
        debug_assert_eq!(cursor.position() as usize, OUTPOINT_KEY_SIZE);
        Self(key)
    }
}

impl From<OutPoint> for OutPointKey {
    #[inline]
    fn from(op: OutPoint) -> Self {
        Self::from_outpoint(&op)
    }
}

impl From<&OutPoint> for OutPointKey {
    #[inline]
    fn from(op: &OutPoint) -> Self {
        Self::from_outpoint(op)
    }
}

impl From<OutPointKey> for OutPoint {
    #[inline]
    fn from(key: OutPointKey) -> Self {
        key.to_outpoint()
    }
}

impl From<&OutPointKey> for OutPoint {
    #[inline]
    fn from(key: &OutPointKey) -> Self {
        key.to_outpoint()
    }
}

impl Ord for OutPointKey {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for OutPointKey {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for OutPointKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// Database key encoding traits for direct LMDB usage
impl<'a> BytesEncode<'a> for OutPointKey {
    type EItem = OutPointKey;

    #[inline]
    fn bytes_encode(
        item: &'a Self::EItem,
    ) -> Result<std::borrow::Cow<'a, [u8]>, BoxedError> {
        Ok(std::borrow::Cow::Borrowed(item.as_ref()))
    }
}

impl<'a> BytesDecode<'a> for OutPointKey {
    type DItem = OutPointKey;

    #[inline]
    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, BoxedError> {
        if bytes.len() != OUTPOINT_KEY_SIZE {
            return Err("OutPointKey must be exactly 37 bytes".into());
        }
        let mut key = [0u8; OUTPOINT_KEY_SIZE];
        key.copy_from_slice(bytes);
        let mut cursor = Cursor::new(&key[..]);
        OutPoint::deserialize_reader(&mut cursor)
            .map_err(|err| -> BoxedError { Box::new(err) })?;
        Ok(OutPointKey(key))
    }
}

#[cfg(test)]
mod tests {
    use super::{OUTPOINT_KEY_SIZE, OutPoint, OutPointKey};

    #[test]
    fn check_outpoint_key_size() -> anyhow::Result<()> {
        use bitcoin::hashes::Hash as _;

        let variants = [
            OutPoint::Regular {
                txid: Default::default(),
                vout: u32::MAX,
            },
            OutPoint::Coinbase {
                merkle_root: Default::default(),
                vout: u32::MAX,
            },
            OutPoint::Deposit(bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([0; 32]),
                vout: u32::MAX,
            }),
        ];

        for op in variants {
            let serialized = borsh::to_vec(&op)?;
            anyhow::ensure!(
                serialized.len() == OUTPOINT_KEY_SIZE,
                "unexpected serialized size: {}",
                serialized.len()
            );

            let key = OutPointKey::from(op);
            let decoded = OutPoint::from(key);
            anyhow::ensure!(decoded == op);
        }
        Ok(())
    }
}

/// Reference to a tx input.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum InPoint {
    /// Transaction input
    Regular {
        txid: Txid,
        // index of the spend in the inputs to spend_tx
        vin: u32,
    },
    // Created by mainchain withdrawals
    Withdrawal {
        m6id: M6id,
    },
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
pub struct Output {
    #[serde(with = "serde_display_fromstr_human_readable")]
    pub address: Address,
    pub content: Content,
    #[serde(with = "serde_hexstr_human_readable")]
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

pub type TxInputs = Vec<OutPoint>;

pub type TxOutputs = Vec<Output>;

/// batch icann registration tx payload
#[derive(BorshSerialize, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct BatchIcannRegistrationData {
    /// Plaintext names of the bitnames to be registered as ICANN domains
    pub plain_names: Vec<String>,
    /// Signature over the batch icann registration tx
    #[schema(schema_with = <String as utoipa::PartialSchema>::schema)]
    pub signature: Signature,
}

#[allow(clippy::enum_variant_names)]
#[derive(BorshSerialize, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub enum TransactionData {
    BitNameReservation {
        /// commitment to the BitName that will be registered
        #[serde(with = "serde_hexstr_human_readable")]
        #[schema(value_type = String)]
        commitment: Hash,
    },
    BitNameRegistration {
        /// reveal of the name hash
        name_hash: BitName,
        /// reveal of the nonce used for the BitName reservation commitment
        #[serde(with = "serde_hexstr_human_readable")]
        #[schema(value_type = String)]
        revealed_nonce: Hash,
        /// initial BitName data
        bitname_data: Box<MutableBitNameData>,
    },
    BitNameUpdate(Box<BitNameDataUpdates>),
    BatchIcann(BatchIcannRegistrationData),
}

pub type TxData = TransactionData;

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

#[derive(
    BorshSerialize, Clone, Debug, Default, Deserialize, Serialize, ToSchema,
)]
pub struct Transaction {
    #[schema(schema_with = TxInputs::schema)]
    pub inputs: TxInputs,
    #[schema(schema_with = TxOutputs::schema)]
    pub outputs: TxOutputs,
    #[serde(with = "serde_hexstr_human_readable")]
    #[schema(value_type = String)]
    pub memo: Vec<u8>,
    pub data: Option<TransactionData>,
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

    /// Canonical size in bytes. The canonical encoding is used for hashing,
    /// But other encodings may be used at eg. networking, rpc levels.
    pub fn canonical_size(&self) -> u64 {
        (borsh::object_length(self).unwrap() / 8) as u64
    }

    /// return an iterator over value outputs with index
    pub fn indexed_value_outputs(
        &self,
    ) -> impl Iterator<Item = (usize, &Output)> {
        self.outputs
            .iter()
            .enumerate()
            .filter(|(_, output)| output.is_value())
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

    /// If the tx is a bitname registration, returns the registered BitName
    pub fn registration_name_hash(&self) -> Option<BitName> {
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
                let implied_commitment =
                    blake3::keyed_hash(&revealed_nonce, &name_hash.0).into();
                Some(implied_commitment)
            }
            _ => None,
        }
    }

    /// return an iterator over reservation outputs
    pub fn reservation_outputs(
        &self,
    ) -> impl DoubleEndedIterator<Item = &Output> {
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

/// Representation of output that includes asset type
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct FilledOutput {
    #[serde(with = "serde_display_fromstr_human_readable")]
    pub address: Address,
    pub content: FilledContent,
    #[serde(with = "serde_hexstr_human_readable")]
    pub memo: Vec<u8>,
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

/// Representation of a spent output
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpentOutput {
    pub output: FilledOutput,
    pub inpoint: InPoint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FilledTransaction {
    pub transaction: Transaction,
    pub spent_utxos: Vec<FilledOutput>,
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

    /// Calculate the fee for this transaction
    pub fn get_fee(&self) -> Result<bitcoin::Amount, super::GetFeeError> {
        let input_value = self.spent_utxos.iter().try_fold(
            bitcoin::Amount::ZERO,
            |acc, output| {
                acc.checked_add(output.content.get_value())
                    .ok_or(super::GetFeeError::AmountOverflow)
            },
        )?;

        let output_value = self.transaction.outputs.iter().try_fold(
            bitcoin::Amount::ZERO,
            |acc, output| {
                acc.checked_add(output.content.get_value())
                    .ok_or(super::GetFeeError::AmountOverflow)
            },
        )?;

        input_value
            .checked_sub(output_value)
            .ok_or(super::GetFeeError::AmountUnderflow)
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
    pub fn registration_name_hash(&self) -> Option<BitName> {
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
    pub fn spent_value(&self) -> Result<bitcoin::Amount, AmountOverflowError> {
        self.spent_utxos
            .iter()
            .map(GetValue::get_value)
            .checked_sum()
            .ok_or(AmountOverflowError)
    }

    /// returns the total value in the outputs
    pub fn value_out(&self) -> Result<bitcoin::Amount, AmountOverflowError> {
        self.outputs()
            .iter()
            .map(GetValue::get_value)
            .checked_sum()
            .ok_or(AmountOverflowError)
    }

    /// returns the difference between the value spent and value out, if it is
    /// non-negative.
    pub fn fee(&self) -> Result<Option<bitcoin::Amount>, AmountOverflowError> {
        let spent_value = self.spent_value()?;
        let value_out = self.value_out()?;
        if spent_value < value_out {
            Ok(None)
        } else {
            Ok(Some(spent_value - value_out))
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
            .chain(new_bitname_content)
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
            .cloned()
            .chain(new_reservation_content)
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
                    Content::Bitcoin(value) => FilledContent::Bitcoin(value),
                    Content::Withdrawal(withdrawal) => {
                        FilledContent::BitcoinWithdrawal(withdrawal)
                    }
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
                    let hash = blake3::hash(plain_name.as_bytes());
                    BitName(Hash::from(hash))
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

#[derive(BorshSerialize, Clone, Debug, Deserialize, Serialize)]
pub struct Authorized<T> {
    pub transaction: T,
    /// Authorizations are called witnesses in Bitcoin.
    pub authorizations: Vec<Authorization>,
}

pub type AuthorizedTransaction = Authorized<Transaction>;

impl From<Authorized<FilledTransaction>> for AuthorizedTransaction {
    fn from(tx: Authorized<FilledTransaction>) -> Self {
        Self {
            transaction: tx.transaction.transaction,
            authorizations: tx.authorizations,
        }
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
pub struct Pointed<OutputKind = Output> {
    pub outpoint: OutPoint,
    pub output: OutputKind,
}
