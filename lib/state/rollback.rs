use std::collections::HashMap;

use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};

use crate::types::Txid;

/// Data of type `T` paired with block height at which it was last updated
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(in crate::state) struct HeightStamped<T> {
    pub value: T,
    pub height: u32,
}

/// Data of type `T` paired with
/// * the txid at which it was last updated
/// * block height at which it was last updated
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(in crate::state) struct TxidStamped<T> {
    pub data: T,
    pub txid: Txid,
    pub height: u32,
}

/// Wrapper struct for fields that support rollbacks
#[derive(Clone, Debug, Deserialize, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub(in crate::state) struct RollBack<T>(pub NonEmpty<T>);

impl<T> RollBack<HeightStamped<T>> {
    pub fn new(value: T, height: u32) -> Self {
        let height_stamped = HeightStamped { value, height };
        Self(NonEmpty::new(height_stamped))
    }

    /// Pop the most recent value
    pub fn pop(mut self) -> (Option<Self>, HeightStamped<T>) {
        if let Some(value) = self.0.pop() {
            (Some(self), value)
        } else {
            (None, self.0.head)
        }
    }

    /// Attempt to push a value as the new most recent.
    /// Returns the value if the operation fails.
    pub fn push(&mut self, value: T, height: u32) -> Result<(), T> {
        if self.0.last().height > height {
            return Err(value);
        }
        let height_stamped = HeightStamped { value, height };
        self.0.push(height_stamped);
        Ok(())
    }

    /// Returns the earliest value
    #[allow(dead_code)]
    pub fn earliest(&self) -> &HeightStamped<T> {
        self.0.first()
    }

    /// Iterate values, earliest to latest
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &HeightStamped<T>> {
        self.0.iter()
    }

    /// Returns the most recent value
    pub fn latest(&self) -> &HeightStamped<T> {
        self.0.last()
    }
}

impl<T> RollBack<TxidStamped<T>> {
    pub fn new(value: T, txid: Txid, height: u32) -> Self {
        let txid_stamped = TxidStamped {
            data: value,
            txid,
            height,
        };
        Self(NonEmpty::new(txid_stamped))
    }

    /// push a value as the new most recent
    pub fn push(&mut self, value: T, txid: Txid, height: u32) {
        let txid_stamped = TxidStamped {
            data: value,
            txid,
            height,
        };
        self.0.push(txid_stamped)
    }

    /// pop the most recent value
    pub fn pop(&mut self) -> Option<TxidStamped<T>> {
        self.0.pop()
    }

    /** Returns the value as it was, at the specified block height.
     *  If a value was updated several times in the block, returns the
     *  last value seen in the block. */
    pub fn at_block_height(&self, height: u32) -> Option<&TxidStamped<T>> {
        self.0
            .iter()
            .rev()
            .find(|txid_stamped| txid_stamped.height <= height)
    }

    /// Returns the value as it was after the transaction at `tx_index` in a
    /// block. This avoids applying a later update from the same block.
    pub fn at_block_position(
        &self,
        height: u32,
        tx_index: u32,
        tx_indexes: &HashMap<Txid, u32>,
    ) -> Option<&TxidStamped<T>> {
        self.0.iter().rev().find(|txid_stamped| {
            txid_stamped.height < height
                || (txid_stamped.height == height
                    && tx_indexes
                        .get(&txid_stamped.txid)
                        .is_some_and(|update_index| *update_index <= tx_index))
        })
    }

    /// returns the most recent value, along with it's txid
    pub fn latest(&self) -> &TxidStamped<T> {
        self.0.last()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_position_excludes_later_update_in_same_block() {
        let first_txid = Txid([1; 32]);
        let later_txid = Txid([2; 32]);
        let mut history = RollBack::<TxidStamped<i32>>::new(10, first_txid, 7);
        history.push(20, later_txid, 7);
        let tx_indexes = HashMap::from([(first_txid, 1), (later_txid, 3)]);

        assert_eq!(
            history.at_block_position(7, 2, &tx_indexes).unwrap().data,
            10
        );
        assert_eq!(
            history.at_block_position(7, 3, &tx_indexes).unwrap().data,
            20
        );
    }
}
