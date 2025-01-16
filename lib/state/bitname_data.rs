use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::{
    state::rollback::{RollBack, TxidStamped},
    types::{
        BitNameDataUpdates, BitNameSeqId, EncryptionPubKey, Hash, Txid, Update,
        VerifyingKey,
    },
};

/// Representation of BitName data that supports rollbacks.
/// The most recent datum is the element at the back of the vector.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BitNameData {
    pub seq_id: BitNameSeqId,
    /// commitment to arbitrary data
    pub(in crate::state) commitment: RollBack<TxidStamped<Option<Hash>>>,
    /// set if the plain bitname is known to be an ICANN domain
    pub(in crate::state) is_icann: bool,
    /// optional ipv4 addr
    pub(in crate::state) ipv4_addr: RollBack<TxidStamped<Option<Ipv4Addr>>>,
    /// optional ipv6 addr
    pub(in crate::state) ipv6_addr: RollBack<TxidStamped<Option<Ipv6Addr>>>,
    /// optional pubkey used for encryption
    pub(in crate::state) encryption_pubkey:
        RollBack<TxidStamped<Option<EncryptionPubKey>>>,
    /// optional pubkey used for signing messages
    pub(in crate::state) signing_pubkey:
        RollBack<TxidStamped<Option<VerifyingKey>>>,
    /// optional minimum paymail fee, in sats
    pub(in crate::state) paymail_fee_sats: RollBack<TxidStamped<Option<u64>>>,
}

impl BitNameData {
    // initialize from BitName data provided during a registration
    pub(in crate::state) fn init(
        bitname_data: crate::types::MutableBitNameData,
        txid: Txid,
        height: u32,
        seq_id: BitNameSeqId,
    ) -> Self {
        Self {
            seq_id,
            commitment: RollBack::<TxidStamped<_>>::new(
                bitname_data.commitment,
                txid,
                height,
            ),
            is_icann: false,
            ipv4_addr: RollBack::<TxidStamped<_>>::new(
                bitname_data.ipv4_addr,
                txid,
                height,
            ),
            ipv6_addr: RollBack::<TxidStamped<_>>::new(
                bitname_data.ipv6_addr,
                txid,
                height,
            ),
            encryption_pubkey: RollBack::<TxidStamped<_>>::new(
                bitname_data.encryption_pubkey,
                txid,
                height,
            ),
            signing_pubkey: RollBack::<TxidStamped<_>>::new(
                bitname_data.signing_pubkey,
                txid,
                height,
            ),
            paymail_fee_sats: RollBack::<TxidStamped<_>>::new(
                bitname_data.paymail_fee_sats,
                txid,
                height,
            ),
        }
    }

    // apply bitname data updates
    pub(in crate::state) fn apply_updates(
        &mut self,
        updates: BitNameDataUpdates,
        txid: Txid,
        height: u32,
    ) {
        let Self {
            seq_id: _,
            ref mut commitment,
            is_icann: _,
            ref mut ipv4_addr,
            ref mut ipv6_addr,
            ref mut encryption_pubkey,
            ref mut signing_pubkey,
            ref mut paymail_fee_sats,
        } = self;

        // apply an update to a single data field
        fn apply_field_update<T>(
            data_field: &mut RollBack<TxidStamped<Option<T>>>,
            update: Update<T>,
            txid: Txid,
            height: u32,
        ) {
            match update {
                Update::Delete => data_field.push(None, txid, height),
                Update::Retain => (),
                Update::Set(value) => {
                    data_field.push(Some(value), txid, height)
                }
            }
        }
        apply_field_update(commitment, updates.commitment, txid, height);
        apply_field_update(ipv4_addr, updates.ipv4_addr, txid, height);
        apply_field_update(ipv6_addr, updates.ipv6_addr, txid, height);
        apply_field_update(
            encryption_pubkey,
            updates.encryption_pubkey,
            txid,
            height,
        );
        apply_field_update(
            signing_pubkey,
            updates.signing_pubkey,
            txid,
            height,
        );
        apply_field_update(
            paymail_fee_sats,
            updates.paymail_fee_sats,
            txid,
            height,
        );
    }

    // revert bitname data updates
    pub(in crate::state) fn revert_updates(
        &mut self,
        updates: BitNameDataUpdates,
        txid: Txid,
        height: u32,
    ) {
        // apply an update to a single data field
        fn revert_field_update<T>(
            data_field: &mut RollBack<TxidStamped<Option<T>>>,
            update: Update<T>,
            txid: Txid,
            height: u32,
        ) where
            T: std::fmt::Debug + Eq,
        {
            match update {
                Update::Delete => {
                    let popped = data_field.pop();
                    assert!(popped.is_some());
                    let popped = popped.unwrap();
                    assert!(popped.data.is_none());
                    assert_eq!(popped.txid, txid);
                    assert_eq!(popped.height, height)
                }
                Update::Retain => (),
                Update::Set(value) => {
                    let popped = data_field.pop();
                    assert!(popped.is_some());
                    let popped = popped.unwrap();
                    assert!(popped.data.is_some());
                    assert_eq!(popped.data.unwrap(), value);
                    assert_eq!(popped.txid, txid);
                    assert_eq!(popped.height, height)
                }
            }
        }

        let Self {
            seq_id: _,
            ref mut commitment,
            is_icann: _,
            ref mut ipv4_addr,
            ref mut ipv6_addr,
            ref mut encryption_pubkey,
            ref mut signing_pubkey,
            ref mut paymail_fee_sats,
        } = self;
        revert_field_update(
            paymail_fee_sats,
            updates.paymail_fee_sats,
            txid,
            height,
        );
        revert_field_update(
            signing_pubkey,
            updates.signing_pubkey,
            txid,
            height,
        );
        revert_field_update(
            encryption_pubkey,
            updates.encryption_pubkey,
            txid,
            height,
        );
        revert_field_update(ipv6_addr, updates.ipv6_addr, txid, height);
        revert_field_update(ipv4_addr, updates.ipv4_addr, txid, height);
        revert_field_update(commitment, updates.commitment, txid, height);
    }

    /** Returns the Bitname data as it was, at the specified block height.
     *  If a value was updated several times in the block, returns the
     *  last value seen in the block.
     *  Returns `None` if the data did not exist at the specified block
     *  height. */
    pub fn at_block_height(
        &self,
        height: u32,
    ) -> Option<crate::types::BitNameData> {
        let mutable_data = crate::types::MutableBitNameData {
            commitment: self.commitment.at_block_height(height)?.data,
            ipv4_addr: self.ipv4_addr.at_block_height(height)?.data,
            ipv6_addr: self.ipv6_addr.at_block_height(height)?.data,
            encryption_pubkey: self
                .encryption_pubkey
                .at_block_height(height)?
                .data,
            signing_pubkey: self.signing_pubkey.at_block_height(height)?.data,
            paymail_fee_sats: self
                .paymail_fee_sats
                .at_block_height(height)?
                .data,
        };
        Some(crate::types::BitNameData {
            seq_id: self.seq_id,
            mutable_data,
        })
    }

    /// get the current bitname data
    pub fn current(&self) -> crate::types::BitNameData {
        let mutable_data = crate::types::MutableBitNameData {
            commitment: self.commitment.latest().data,
            ipv4_addr: self.ipv4_addr.latest().data,
            ipv6_addr: self.ipv6_addr.latest().data,
            encryption_pubkey: self.encryption_pubkey.latest().data,
            signing_pubkey: self.signing_pubkey.latest().data,
            paymail_fee_sats: self.paymail_fee_sats.latest().data,
        };
        crate::types::BitNameData {
            seq_id: self.seq_id,
            mutable_data,
        }
    }
}
