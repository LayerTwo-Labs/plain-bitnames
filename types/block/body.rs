use std::{borrow::Borrow, cmp::Ordering, collections::HashMap};

use bitcoin::amount::CheckedSum as _;
use borsh::BorshSerialize;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    GetValue as _,
    authorization::Authorization,
    block::coinbase::Coinbase,
    error,
    hashes::{
        self, CoinbaseMerkleRoot, CoinbaseTxid, Hash, MerkleRoot, TxMerkleRoot,
    },
    transaction::{
        AuthorizedTransaction, FilledTransaction, OutPoint, Output, Transaction,
    },
    util,
};

// Marker type for merging branch commitments with
// * branch fee totals
// * branch canonical size totals
/// Hash to get a [`CbmtNode`] inner commitment for a leaf value
#[derive(BorshSerialize, Debug)]
struct CbmtLeafPreCommitment {
    #[borsh(serialize_with = "util::borsh::serialize::bitcoin_amount")]
    fee: bitcoin::Amount,
    canonical_size: u64,
    tx_merkle_root: TxMerkleRoot,
}

/// Hash to get a [`CbmtNode`] inner commitment for an internal node
#[derive(BorshSerialize, Debug)]
struct CbmtNodePreCommitment {
    /// left child inner commitment
    left_commitment: Hash,
    /// Sum of child tx fees
    #[borsh(serialize_with = "util::borsh::serialize::bitcoin_amount")]
    fees: bitcoin::Amount,
    /// Sum of canonical sizes of child txs
    canonical_size: u64,
    /// right child inner commitment
    right_commitment: Hash,
}

// Internal node of a CBMT
#[derive(BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
struct CbmtNode {
    // Commitment to child nodes or leaf value
    commitment: Hash,
    // Sum of fees for child nodes or leaf value
    #[borsh(serialize_with = "util::borsh::serialize::bitcoin_amount")]
    fees: bitcoin::Amount,
    // Sum of canonical tx sizes for child nodes or leaf value
    canonical_size: u64,
    // CBT index, see https://github.com/nervosnetwork/merkle-tree/blob/5d1898263e7167560fdaa62f09e8d52991a1c712/README.md#tree-struct
    // This is required so that `CbmtNode` can be `Ord` correctly
    index: usize,
}

impl PartialOrd for CbmtNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CbmtNode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.index.cmp(&other.index)
    }
}

// Marker type for merging branch commitments with
// * branch fee totals
// * branch canonical size totals
struct MergeFeeSizeTotal;

impl merkle_cbt::merkle_tree::Merge for MergeFeeSizeTotal {
    type Item = CbmtNode;

    fn merge(lnode: &Self::Item, rnode: &Self::Item) -> Self::Item {
        let fees = lnode.fees + rnode.fees;
        let canonical_size = lnode.canonical_size + rnode.canonical_size;
        // see https://github.com/nervosnetwork/merkle-tree/blob/5d1898263e7167560fdaa62f09e8d52991a1c712/README.md#tree-struct
        assert_eq!(lnode.index + 1, rnode.index);
        let index = (lnode.index - 1) / 2;
        let commitment =
            hashes::hash_with_scratch_buffer(&CbmtNodePreCommitment {
                left_commitment: lnode.commitment,
                fees,
                canonical_size,
                right_commitment: rnode.commitment,
            });
        Self::Item {
            commitment,
            fees,
            canonical_size,
            index,
        }
    }
}

// Complete binary merkle tree with annotated fee and canonical size totals
type CbmtWithFeeTotal = merkle_cbt::CBMT<CbmtNode, MergeFeeSizeTotal>;

#[derive(BorshSerialize, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Body {
    pub coinbase: Coinbase,
    pub transactions: Vec<Transaction>,
    pub authorizations: Vec<Authorization>,
}

impl Body {
    pub fn new(
        authorized_transactions: Vec<AuthorizedTransaction>,
        coinbase: Coinbase,
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

    /// Size limit in bytes
    pub const MAX_SIZE: usize = 8 * 1024 * 1024;

    pub fn authorized_transactions(&self) -> Vec<AuthorizedTransaction> {
        let mut authorizations_iter = self.authorizations.iter();
        self.transactions
            .iter()
            .map(|tx| {
                let mut authorizations = Vec::with_capacity(tx.inputs.len());
                for _ in 0..tx.inputs.len() {
                    let auth = authorizations_iter.next().unwrap();
                    authorizations.push(auth.clone());
                }
                AuthorizedTransaction {
                    transaction: tx.clone(),
                    authorizations,
                }
            })
            .collect()
    }

    pub fn compute_merkle_root<FilledTx>(
        coinbase: &Coinbase,
        txs: &[FilledTx],
    ) -> Result<MerkleRoot, error::ComputeMerkleRoot>
    where
        FilledTx: Borrow<FilledTransaction> + Sync,
    {
        let CbmtNode {
            commitment: txs_commitment,
            ..
        } = {
            let n_txs = txs.len();

            // Pre-allocate Vec for direct indexing by parallel threads
            let mut leaves = vec![CbmtNode::default(); n_txs];

            // Use Rayon to compute leaves in parallel across all CPU cores
            use rayon::iter::{
                IndexedParallelIterator, IntoParallelRefIterator,
                ParallelIterator,
            };
            let results: Result<Vec<_>, error::ComputeMerkleRoot> =
                txs.par_iter()
                    .enumerate()
                    .map(|(idx, tx)| {
                        let tx = tx.borrow();
                        let fees = tx.get_fee().map_err(|err| {
                            error::compute_merkle_root::Inner::TxFee {
                                txid: tx.transaction.txid(),
                                source: err,
                            }
                        })?;
                        let canonical_size = tx.transaction.canonical_size()
                        .map_err(|err|
                            error::compute_merkle_root::Inner::TxCanonicalSize {
                                txid: tx.transaction.txid(),
                                source: err,
                            })?;
                        let tx_merkle_root = tx
                            .transaction
                            .compute_merkle_root()
                            .map_err(|err| {
                            error::compute_merkle_root::Inner::TxMerkleRoot {
                                txid: tx.transaction.txid(),
                                source: err,
                            }
                        })?;
                        let leaf_pre_commitment = CbmtLeafPreCommitment {
                            fee: fees,
                            canonical_size,
                            tx_merkle_root,
                        };
                        let node = CbmtNode {
                            commitment: hashes::hash_with_scratch_buffer(
                                &leaf_pre_commitment,
                            ),
                            fees,
                            canonical_size,
                            // see https://github.com/nervosnetwork/merkle-tree/blob/5d1898263e7167560fdaa62f09e8d52991a1c712/README.md#tree-struct
                            index: (idx + n_txs) - 1,
                        };
                        Ok((idx, node))
                    })
                    .collect();

            // Fill the pre-allocated vector with computed nodes
            for (idx, node) in results? {
                leaves[idx] = node;
            }

            // Replace tree-based CBMT with parallel levelized approach for better performance
            if n_txs >= 1000 {
                // Use optimized parallel level merging for large transaction sets
                Self::compute_merkle_root_levelized_parallel(leaves)
            } else {
                // Use original CBMT for smaller sets
                CbmtWithFeeTotal::build_merkle_root(leaves.as_slice())
            }
        };
        let coinbase_commitment = coinbase
            .compute_merkle_root()
            .map_err(error::compute_merkle_root::Inner::CoinbaseMerkleRoot)?;
        // Borsh encoding for hashing
        #[derive(BorshSerialize)]
        struct HashComponents {
            coinbase_commitment: CoinbaseMerkleRoot,
            txs_commitment: Hash,
        }
        let root = hashes::hash_with_scratch_buffer(&HashComponents {
            coinbase_commitment,
            txs_commitment,
        })
        .into();
        Ok(root)
    }

    /// Optimized level-by-level parallel merkle tree construction
    /// Processes each level of the tree in parallel for maximum performance
    fn compute_merkle_root_levelized_parallel(
        mut current_level: Vec<CbmtNode>,
    ) -> CbmtNode {
        use rayon::prelude::*;

        while current_level.len() > 1 {
            // Handle odd number of nodes by duplicating the last node (standard merkle tree approach)
            if current_level.len() % 2 == 1 {
                let last_node = current_level.last().unwrap().clone();
                current_level.push(last_node);
            }

            // Process pairs of nodes in parallel across all CPU cores
            current_level = current_level
                .par_chunks_exact(2)
                .enumerate()
                .map(|(parent_idx, pair)| {
                    let lnode = &pair[0];
                    let rnode = &pair[1];

                    // Compute parent node using the same merge logic as MergeFeeSizeTotal
                    let fees = lnode.fees + rnode.fees;
                    let canonical_size =
                        lnode.canonical_size + rnode.canonical_size;

                    let commitment = hashes::hash_with_scratch_buffer(
                        &CbmtNodePreCommitment {
                            left_commitment: lnode.commitment,
                            fees,
                            canonical_size,
                            right_commitment: rnode.commitment,
                        },
                    );

                    CbmtNode {
                        commitment,
                        fees,
                        canonical_size,
                        index: parent_idx,
                    }
                })
                .collect();
        }

        // Return the root node
        current_level
            .into_iter()
            .next()
            .expect("Tree should have exactly one root")
    }

    pub fn get_inputs(&self) -> Vec<OutPoint> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.inputs.iter())
            .copied()
            .collect()
    }

    pub fn get_outputs(
        coinbase_txid: CoinbaseTxid,
        coinbase: &Coinbase,
        txs: &[FilledTransaction],
    ) -> HashMap<OutPoint, Output> {
        let mut res = HashMap::new();
        for (vout, output) in coinbase.outputs.iter().enumerate() {
            let vout = vout as u32;
            let outpoint = OutPoint::Coinbase {
                txid: coinbase_txid,
                vout,
            };
            res.insert(outpoint, output.clone());
        }
        for transaction in txs {
            let txid = transaction.txid();
            for (vout, output) in transaction.outputs().iter().enumerate() {
                let vout = vout as u32;
                let outpoint = OutPoint::Regular { txid, vout };
                res.insert(outpoint, output.clone());
            }
        }
        res
    }

    pub fn get_coinbase_value(
        &self,
    ) -> Result<bitcoin::Amount, error::AmountOverflow> {
        self.coinbase
            .outputs
            .iter()
            .map(|output| output.get_value())
            .checked_sum()
            .ok_or(error::AmountOverflow)
    }
}
