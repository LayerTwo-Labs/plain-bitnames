use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::HashMap};

use bip300301::bitcoin;

use crate::authorization::Authorization;

mod address;
mod hashes;

pub use blake3;
pub use bs58;
pub use serde;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub address: Address,
    pub content: Content,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Content {
    Value(u64),
    Withdrawal {
        value: u64,
        main_fee: u64,
        main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
    },
}

/*
// Replace () with a type (usually an enum) for output data specific for your sidechain.
pub type Output = types::Output<()>;
pub type Transaction = types::Transaction<()>;
pub type FilledTransaction = types::FilledTransaction<()>;
pub type AuthorizedTransaction = types::AuthorizedTransaction<Authorization, ()>;
pub type Body = types::Body<Authorization, ()>;
*/

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub merkle_root: MerkleRoot,
    pub prev_side_hash: BlockHash,
    pub prev_main_hash: bitcoin::BlockHash,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum WithdrawalBundleStatus {
    Failed,
    Confirmed,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WithdrawalBundle {
    pub spent_utxos: HashMap<OutPoint, Output>,
    pub transaction: bitcoin::Transaction,
}

#[derive(Default, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TwoWayPegData {
    pub deposits: HashMap<OutPoint, Output>,
    pub deposit_block_hash: Option<bitcoin::BlockHash>,
    pub bundle_statuses: HashMap<bitcoin::Txid, WithdrawalBundleStatus>,
}

impl Header {
    pub fn hash(&self) -> BlockHash {
        hashes::hash(self).into()
    }
}

impl Content {
    pub fn is_value(&self) -> bool {
        matches!(self, Self::Value(_))
    }
    pub fn is_withdrawal(&self) -> bool {
        matches!(self, Self::Withdrawal { .. })
    }
}

impl GetValue for Output {
    #[inline(always)]
    fn get_value(&self) -> u64 {
        self.content.get_value()
    }
}

impl GetValue for Content {
    #[inline(always)]
    fn get_value(&self) -> u64 {
        match self {
            Self::Value(value) => *value,
            Self::Withdrawal { value, .. } => *value,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<Output>,
}

impl Transaction {
    pub fn txid(&self) -> Txid {
        hash(self).into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilledTransaction {
    pub transaction: Transaction,
    pub spent_utxos: Vec<Output>,
}

impl FilledTransaction {
    pub fn get_value_in(&self) -> u64 {
        self.spent_utxos.iter().map(GetValue::get_value).sum()
    }

    pub fn get_value_out(&self) -> u64 {
        self.transaction
            .outputs
            .iter()
            .map(GetValue::get_value)
            .sum()
    }

    pub fn get_fee(&self) -> Option<u64> {
        let value_in = self.get_value_in();
        let value_out = self.get_value_out();
        if value_in < value_out {
            None
        } else {
            Some(value_in - value_out)
        }
    }
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    pub spent_utxos: HashMap<OutPoint, Output>,
    pub main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
    pub value: u64,
    pub main_fee: u64,
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
