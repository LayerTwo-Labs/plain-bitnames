#![feature(impl_trait_in_assoc_type)]
#![feature(let_chains)]
#![feature(trait_alias)]
#![feature(try_find)]

pub mod archive;
pub mod authorization;
pub mod mempool;
pub mod miner;
pub mod net;
pub mod node;
pub mod state;
pub mod types;
pub mod util;
pub mod wallet;

/// Format `b58_dest` with the proper `s{sidechain_number}_` prefix and a
/// checksum postfix for calling createsidechaindeposit on mainchain.
pub fn format_deposit_address(dest: types::Address) -> String {
    format!("s{}_{}", types::THIS_SIDECHAIN, dest.to_base58ck())
}
