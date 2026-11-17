use std::borrow::Borrow;

use bitcoin::amount::CheckedSum;
use borsh::{self, BorshSerialize};
use serde::{Deserialize, Serialize};
use utoipa::{PartialSchema, ToSchema};

use crate::{
    AmountOverflowError, BitNameDataUpdates, ComputeFeeError, GetValue,
    MutableBitNameData,
    authorization::{Authorization, Signature},
    hashes::{self, BitName, Hash, M6id, Txid},
    util,
};

pub mod outpoint;
pub use outpoint::{OutPoint, OutPointKey};
pub mod output;
pub use output::{
    BitcoinContent as BitcoinOutputContent, Content as OutputContent,
    FilledContent as FilledOutputContent, FilledOutput, Output, PointedOutput,
    WithdrawalContent as WithdrawalOutputContent,
};

/// Reference to a tx input.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, ToSchema,
)]
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
        #[serde(with = "util::serde::hexstr_human_readable")]
        #[schema(value_type = String)]
        commitment: Hash,
    },
    BitNameRegistration {
        /// reveal of the name hash
        name_hash: BitName,
        /// reveal of the nonce used for the BitName reservation commitment
        #[serde(with = "util::serde::hexstr_human_readable")]
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
    #[serde(with = "util::serde::hexstr_human_readable")]
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

    /// Canonical encoding as bytes. The canonical encoding is used for hashing,
    /// but other encodings may be used at eg. networking, rpc levels.
    pub fn canonical_bytes(&self) -> borsh::io::Result<Vec<u8>> {
        borsh::to_vec(&self)
    }

    /// Canonical size in bytes. The canonical encoding is used for hashing,
    /// But other encodings may be used at eg. networking, rpc levels.
    #[inline(always)]
    pub fn canonical_size(&self) -> borsh::io::Result<u64> {
        borsh::object_length(self).map(|size| size as u64)
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

/// Representation of a spent output
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
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

    pub fn get_value_in(&self) -> Result<bitcoin::Amount, AmountOverflowError> {
        self.spent_utxos
            .iter()
            .map(GetValue::get_value)
            .checked_sum()
            .ok_or(AmountOverflowError)
    }

    pub fn get_value_out(
        &self,
    ) -> Result<bitcoin::Amount, AmountOverflowError> {
        self.transaction
            .outputs
            .iter()
            .map(GetValue::get_value)
            .checked_sum()
            .ok_or(AmountOverflowError)
    }

    /// Calculate the fee for this transaction
    pub fn get_fee(&self) -> Result<bitcoin::Amount, ComputeFeeError> {
        let value_in = self
            .get_value_in()
            .map_err(ComputeFeeError::ValueInOverflow)?;
        let value_out = self
            .get_value_out()
            .map_err(ComputeFeeError::ValueOutOverflow)?;
        value_in
            .checked_sub(value_out)
            .ok_or(ComputeFeeError::Underfunded)
    }

    /// If the tx is a bitname registration, returns the implied reservation
    /// commitment
    pub fn implied_reservation_commitment(&self) -> Option<Hash> {
        self.transaction.implied_reservation_commitment()
    }

    /// accessor for tx inputs
    pub fn inputs(&self) -> &TxInputs {
        &self.transaction.inputs
    }

    pub fn filled_inputs(
        &self,
    ) -> impl DoubleEndedIterator<Item = (&OutPoint, &FilledOutput)> {
        self.transaction.inputs.iter().zip(&self.spent_utxos)
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
    pub fn fee(&self) -> Result<bitcoin::Amount, ComputeFeeError> {
        let spent_value = self
            .spent_value()
            .map_err(ComputeFeeError::ValueInOverflow)?;
        let value_out = self
            .value_out()
            .map_err(ComputeFeeError::ValueOutOverflow)?;
        if spent_value < value_out {
            Err(ComputeFeeError::Underfunded)
        } else {
            Ok(spent_value - value_out)
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
    ) -> impl Iterator<Item = FilledOutputContent> + '_ {
        // If this tx is a BitName registration, this is the content of the
        // output corresponding to the newly created BitName, which must be
        // the final BitName output.
        let new_bitname_content: Option<FilledOutputContent> = self
            .registration_name_hash()
            .map(FilledOutputContent::BitName);
        self.spent_bitnames()
            .map(|(_, filled_output)| filled_output.content())
            .cloned()
            .chain(new_bitname_content)
    }

    /// compute the filled content for BitName reservation outputs
    /// WARNING: do not expose DoubleEndedIterator.
    fn filled_reservation_output_content(
        &self,
    ) -> impl Iterator<Item = FilledOutputContent> + '_ {
        // If this tx is a BitName reservation, this is the content of the
        // output corresponding to the newly created BitName reservation,
        // which must be the final reservation output.
        let new_reservation_content: Option<FilledOutputContent> =
            self.reservation_commitment().map(|commitment| {
                FilledOutputContent::BitNameReservation(self.txid(), commitment)
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
                        FilledOutputContent::BitNameReservation(_, commitment)
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
                    OutputContent::BitName => {
                        filled_bitname_output_content.next()?.clone()
                    }
                    OutputContent::BitNameReservation => {
                        filled_reservation_output_content.next()?.clone()
                    }
                    OutputContent::Bitcoin(value) => {
                        FilledOutputContent::Bitcoin(value)
                    }
                    OutputContent::Withdrawal(withdrawal) => {
                        FilledOutputContent::BitcoinWithdrawal(withdrawal)
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

#[derive(BorshSerialize, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Authorized<T> {
    pub transaction: T,
    /// Authorizations are called witnesses in Bitcoin.
    pub authorizations: Vec<Authorization>,
}

pub type AuthorizedTransaction = Authorized<Transaction>;

impl<T> Borrow<T> for Authorized<T> {
    fn borrow(&self) -> &T {
        &self.transaction
    }
}

impl From<Authorized<FilledTransaction>> for AuthorizedTransaction {
    fn from(tx: Authorized<FilledTransaction>) -> Self {
        Self {
            transaction: tx.transaction.transaction,
            authorizations: tx.authorizations,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        Address,
        transaction::{
            BitcoinOutputContent, FilledOutput, FilledOutputContent,
            FilledTransaction, GetValue as _, Output, OutputContent,
            Transaction, WithdrawalOutputContent,
        },
    };

    // a withdrawal output must be funded for both its payout and its mainchain
    // fee, since both leave the treasury
    #[test]
    fn withdrawal_value_includes_main_fee() {
        let value = bitcoin::Amount::from_sat(1000);
        let main_fee = bitcoin::Amount::from_sat(300);
        let main_address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .unwrap();
        let withdrawal = Output {
            address: Address::ALL_ZEROS,
            content: OutputContent::Withdrawal(WithdrawalOutputContent {
                value,
                main_fee,
                main_address,
            }),
            memo: Vec::new(),
        };
        assert_eq!(withdrawal.get_value(), value + main_fee);

        let value_output = |amount| FilledOutput {
            address: Address::ALL_ZEROS,
            content: FilledOutputContent::Bitcoin(BitcoinOutputContent(amount)),
            memo: Vec::new(),
        };
        let withdrawal_tx = |funding| FilledTransaction {
            transaction: Transaction {
                outputs: vec![withdrawal.clone()],
                ..Default::default()
            },
            spent_utxos: vec![value_output(funding)],
        };

        // inputs covering only the payout are insufficient
        assert!(withdrawal_tx(value).get_fee().is_err());
        // inputs covering payout plus mainchain fee fully fund it
        assert_eq!(
            withdrawal_tx(value + main_fee).get_fee().unwrap(),
            bitcoin::Amount::ZERO
        );
    }
}
