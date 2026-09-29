use borsh::BorshSerialize;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    block::coinbase::Coinbase,
    hashes::{self, BlockHash, CoinbaseTxid, MerkleRoot},
    schema, util,
};

#[derive(
    BorshSerialize,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    PartialEq,
    Serialize,
    ToSchema,
)]
pub struct Header {
    pub merkle_root: MerkleRoot,
    pub prev_side_hash: Option<BlockHash>,
    #[borsh(serialize_with = "util::borsh::serialize::bitcoin_block_hash")]
    #[schema(value_type = schema::BitcoinBlockHash)]
    pub prev_main_hash: bitcoin::BlockHash,
}

impl Header {
    pub fn compute_coinbase_txid(&self) -> CoinbaseTxid {
        let Self {
            merkle_root,
            prev_side_hash,
            prev_main_hash,
        } = self;
        Coinbase::compute_txid(
            merkle_root,
            prev_main_hash,
            prev_side_hash.as_ref(),
        )
    }

    pub fn hash(&self) -> BlockHash {
        hashes::hash(self).into()
    }
}
