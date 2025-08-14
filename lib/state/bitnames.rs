//! Functions and types related to BitNames

use std::net::{SocketAddrV4, SocketAddrV6};

use heed::types::SerdeBincode;
use serde::{Deserialize, Serialize};
use sneed::{DatabaseUnique, RoDatabaseUnique, RoTxn, RwTxn, db, env};

use crate::{
    state::{
        error::BitName as Error,
        rollback::{RollBack, TxidStamped},
    },
    types::{
        BatchIcannRegistrationData, BitName, BitNameDataUpdates, BitNameSeqId,
        FilledTransaction, Hash, Txid, Update, VerifyingKey,
        bitname_data::EncryptionPubKey,
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
    pub(in crate::state) socket_addr_v4:
        RollBack<TxidStamped<Option<SocketAddrV4>>>,
    /// optional ipv6 addr
    pub(in crate::state) socket_addr_v6:
        RollBack<TxidStamped<Option<SocketAddrV6>>>,
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
            socket_addr_v4: RollBack::<TxidStamped<_>>::new(
                bitname_data.socket_addr_v4,
                txid,
                height,
            ),
            socket_addr_v6: RollBack::<TxidStamped<_>>::new(
                bitname_data.socket_addr_v6,
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
            commitment,
            is_icann: _,
            socket_addr_v4,
            socket_addr_v6,
            encryption_pubkey,
            signing_pubkey,
            paymail_fee_sats,
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
        apply_field_update(
            socket_addr_v4,
            updates.socket_addr_v4,
            txid,
            height,
        );
        apply_field_update(
            socket_addr_v6,
            updates.socket_addr_v6,
            txid,
            height,
        );
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
            commitment,
            is_icann: _,
            socket_addr_v4,
            socket_addr_v6,
            encryption_pubkey,
            signing_pubkey,
            paymail_fee_sats,
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
        revert_field_update(
            socket_addr_v4,
            updates.socket_addr_v4,
            txid,
            height,
        );
        revert_field_update(
            socket_addr_v6,
            updates.socket_addr_v6,
            txid,
            height,
        );
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
            socket_addr_v4: self.socket_addr_v4.at_block_height(height)?.data,
            socket_addr_v6: self.socket_addr_v6.at_block_height(height)?.data,
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
            socket_addr_v4: self.socket_addr_v4.latest().data,
            socket_addr_v6: self.socket_addr_v6.latest().data,
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

/// BitName databases
#[derive(Clone)]
pub struct Dbs {
    /// Associates bitname IDs (name hashes) with bitname data
    bitnames: DatabaseUnique<SerdeBincode<BitName>, SerdeBincode<BitNameData>>,
    /// Associates tx hashes with bitname reservation commitments
    reservations: DatabaseUnique<SerdeBincode<Txid>, SerdeBincode<Hash>>,
    /// Associates BitName sequence numbers with BitName IDs (name hashes)
    seq_to_bitname: DatabaseUnique<BitNameSeqId, SerdeBincode<BitName>>,
}

impl Dbs {
    pub const NUM_DBS: u32 = 3;

    /// Create / Open DBs. Does not commit the RwTxn.
    pub(in crate::state) fn new(
        env: &sneed::Env,
        rwtxn: &mut RwTxn,
    ) -> Result<Self, env::error::CreateDb> {
        let bitnames = DatabaseUnique::create(env, rwtxn, "bitnames")?;
        let reservations =
            DatabaseUnique::create(env, rwtxn, "bitname_reservations")?;
        let seq_to_bitname =
            DatabaseUnique::create(env, rwtxn, "bitname_seq_to_bitname")?;
        Ok(Self {
            bitnames,
            reservations,
            seq_to_bitname,
        })
    }

    pub fn bitnames(
        &self,
    ) -> &RoDatabaseUnique<SerdeBincode<BitName>, SerdeBincode<BitNameData>>
    {
        &self.bitnames
    }

    pub fn seq_to_bitname(
        &self,
    ) -> &RoDatabaseUnique<BitNameSeqId, SerdeBincode<BitName>> {
        &self.seq_to_bitname
    }

    /// The sequence number of the last registered BitName.
    /// Returns `None` if no BitNames have been registered.
    pub(in crate::state) fn last_seq(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<BitNameSeqId>, db::error::Last> {
        match self.seq_to_bitname.last(rotxn)? {
            Some((seq, _)) => Ok(Some(seq)),
            None => Ok(None),
        }
    }

    /// The sequence number that the next registered BitName will take.
    pub(in crate::state) fn next_seq(
        &self,
        rotxn: &RoTxn,
    ) -> Result<BitNameSeqId, db::error::Last> {
        match self.last_seq(rotxn)? {
            Some(seq) => Ok(seq.next()),
            None => Ok(BitNameSeqId::new(0)),
        }
    }

    /// Return the Bitname data, if it exists
    pub fn try_get_bitname(
        &self,
        rotxn: &RoTxn,
        bitname: &BitName,
    ) -> Result<Option<BitNameData>, db::error::TryGet> {
        self.bitnames.try_get(rotxn, bitname)
    }

    /// Return the Bitname data. Returns an error if it does not exist.
    pub fn get_bitname(
        &self,
        rotxn: &RoTxn,
        bitname: &BitName,
    ) -> Result<BitNameData, Error> {
        self.try_get_bitname(rotxn, bitname)?
            .ok_or(Error::Missing { bitname: *bitname })
    }

    /// Resolve bitname data at the specified block height, if it exists.
    pub fn try_get_bitname_data_at_block_height(
        &self,
        rotxn: &RoTxn,
        bitname: &BitName,
        height: u32,
    ) -> Result<Option<crate::types::BitNameData>, db::error::TryGet> {
        let res = self
            .bitnames
            .try_get(rotxn, bitname)?
            .and_then(|bitname_data| bitname_data.at_block_height(height));
        Ok(res)
    }

    /** Resolve bitname data at the specified block height.
     * Returns an error if it does not exist. */
    pub fn get_bitname_data_at_block_height(
        &self,
        rotxn: &RoTxn,
        bitname: &BitName,
        height: u32,
    ) -> Result<crate::types::BitNameData, Error> {
        self.get_bitname(rotxn, bitname)?
            .at_block_height(height)
            .ok_or(Error::MissingData {
                bitname: *bitname,
                block_height: height,
            })
    }

    /// resolve current bitname data, if it exists
    pub fn try_get_current_bitname_data(
        &self,
        rotxn: &RoTxn,
        bitname: &BitName,
    ) -> Result<Option<crate::types::BitNameData>, Error> {
        let res = self
            .bitnames
            .try_get(rotxn, bitname)?
            .map(|bitname_data| bitname_data.current());
        Ok(res)
    }

    /// Resolve current bitname data. Returns an error if it does not exist.
    pub fn get_current_bitname_data(
        &self,
        rotxn: &RoTxn,
        bitname: &BitName,
    ) -> Result<crate::types::BitNameData, Error> {
        self.try_get_current_bitname_data(rotxn, bitname)?
            .ok_or(Error::Missing { bitname: *bitname })
    }

    /// Delete a BitName reservation.
    /// Returns `true` if a BitName reservation was deleted.
    pub(in crate::state) fn delete_reservation(
        &self,
        rwtxn: &mut RwTxn,
        txid: &Txid,
    ) -> Result<bool, db::error::Delete> {
        self.reservations.delete(rwtxn, txid)
    }

    /// Store a BitName reservation
    pub(in crate::state) fn put_reservation(
        &self,
        rwtxn: &mut RwTxn,
        txid: &Txid,
        commitment: &Hash,
    ) -> Result<(), db::error::Put> {
        self.reservations.put(rwtxn, txid, commitment)
    }

    /// Apply BitName updates
    pub(in crate::state) fn apply_updates(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        bitname_updates: BitNameDataUpdates,
        height: u32,
    ) -> Result<(), Error> {
        /* The updated BitName is the BitName that corresponds to the last
         * bitname output, or equivalently, the BitName corresponding to the
         * last BitName input */
        let updated_bitname = filled_tx
            .spent_bitnames()
            .next_back()
            .ok_or(Error::NoBitNamesToUpdate)?
            .1
            .bitname()
            .expect("should only contain BitName outputs");
        let mut bitname_data = self
            .bitnames
            .try_get(rwtxn, updated_bitname)?
            .ok_or(Error::Missing {
            bitname: *updated_bitname,
        })?;
        bitname_data.apply_updates(bitname_updates, filled_tx.txid(), height);
        self.bitnames.put(rwtxn, updated_bitname, &bitname_data)?;
        Ok(())
    }

    /// Revert BitName updates
    pub(in crate::state) fn revert_updates(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        bitname_updates: BitNameDataUpdates,
        height: u32,
    ) -> Result<(), Error> {
        /* The updated BitName is the BitName that corresponds to the last
         * bitname output, or equivalently, the BitName corresponding to the
         * last BitName input */
        let updated_bitname = filled_tx
            .spent_bitnames()
            .next_back()
            .ok_or(Error::NoBitNamesToUpdate)?
            .1
            .bitname()
            .expect("should only contain BitName outputs");
        let mut bitname_data = self
            .bitnames
            .try_get(rwtxn, updated_bitname)?
            .ok_or(Error::Missing {
            bitname: *updated_bitname,
        })?;
        bitname_data.revert_updates(bitname_updates, filled_tx.txid(), height);
        self.bitnames.put(rwtxn, updated_bitname, &bitname_data)?;
        Ok(())
    }

    /// Apply BitName registration
    pub(in crate::state) fn apply_registration(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        bitname: BitName,
        bitname_data: &crate::types::MutableBitNameData,
        height: u32,
    ) -> Result<(), Error> {
        // Find the reservation to burn
        let implied_commitment =
            filled_tx.implied_reservation_commitment().expect(
                "A BitName registration tx should have an implied commitment",
            );
        let burned_reservation_txid =
            filled_tx.spent_reservations().find_map(|(_, filled_output)| {
                let (txid, commitment) = filled_output.reservation_data()
                    .expect("A spent reservation should correspond to a commitment");
                if *commitment == implied_commitment {
                    Some(txid)
                } else {
                    None
                }
            }).expect("A BitName registration tx should correspond to a burned reservation");
        if !self.reservations.delete(rwtxn, burned_reservation_txid)? {
            return Err(Error::MissingReservation {
                txid: *burned_reservation_txid,
            });
        }
        let seq = self.next_seq(rwtxn)?;
        self.seq_to_bitname.put(rwtxn, &seq, &bitname)?;
        let bitname_data = BitNameData::init(
            bitname_data.clone(),
            filled_tx.txid(),
            height,
            seq,
        );
        self.bitnames.put(rwtxn, &bitname, &bitname_data)?;
        Ok(())
    }

    /// Revert BitName registration
    pub(in crate::state) fn revert_registration(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        bitname: BitName,
    ) -> Result<(), Error> {
        let Some(BitNameData { seq_id, .. }) =
            self.bitnames.try_get(rwtxn, &bitname)?
        else {
            return Err(Error::Missing { bitname });
        };
        if !self.bitnames.delete(rwtxn, &bitname)? {
            return Err(Error::Missing { bitname });
        }
        let (_last_seq_id, latest_registered_bitname) = self
            .seq_to_bitname
            .last(rwtxn)?
            .expect("A registered bitname should have a seq id");
        assert_eq!(latest_registered_bitname, bitname);
        if !self.seq_to_bitname.delete(rwtxn, &seq_id)? {
            return Err(Error::Missing { bitname });
        }
        // Find the reservation to restore
        let implied_commitment =
            filled_tx.implied_reservation_commitment().expect(
                "A BitName registration tx should have an implied commitment",
            );
        let burned_reservation_txid =
            filled_tx.spent_reservations().find_map(|(_, filled_output)| {
                let (txid, commitment) = filled_output.reservation_data()
                    .expect("A spent reservation should correspond to a commitment");
                if *commitment == implied_commitment {
                    Some(txid)
                } else {
                    None
                }
            }).expect("A BitName registration tx should correspond to a burned reservation");
        self.reservations.put(
            rwtxn,
            burned_reservation_txid,
            &implied_commitment,
        )?;
        Ok(())
    }

    /// Apply batch ICANN registration
    pub(in crate::state) fn apply_batch_icann(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        batch_icann_data: &BatchIcannRegistrationData,
    ) -> Result<(), Error> {
        let name_hashes = batch_icann_data.plain_names.iter().map(|name| {
            let hash = blake3::hash(name.as_bytes());
            BitName(Hash::from(hash))
        });
        let mut spent_bitnames = filled_tx.spent_bitnames();
        for name_hash in name_hashes {
            // search for the bitname to be registered as an ICANN domain
            // exists in the inputs
            let found_bitname = spent_bitnames.any(|(_, outpoint)| {
                let bitname = outpoint.bitname()
                    .expect("spent bitname input should correspond to a known name hash");
                *bitname == name_hash
            });
            if found_bitname {
                let mut bitname_data = self
                    .bitnames
                    .try_get(rwtxn, &name_hash)?
                    .ok_or(Error::Missing { bitname: name_hash })?;
                if bitname_data.is_icann {
                    return Err(Error::AlreadyIcann { bitname: name_hash });
                }
                bitname_data.is_icann = true;
                self.bitnames.put(rwtxn, &name_hash, &bitname_data)?;
            } else {
                return Err(Error::MissingBitNameInput { bitname: name_hash });
            }
        }
        Ok(())
    }

    /// Revert batch ICANN registration
    pub(in crate::state) fn revert_batch_icann(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        batch_icann_data: &BatchIcannRegistrationData,
    ) -> Result<(), Error> {
        let name_hashes = batch_icann_data.plain_names.iter().map(|name| {
            let hash = blake3::hash(name.as_bytes());
            BitName(Hash::from(hash))
        });
        let mut spent_bitnames = filled_tx.spent_bitnames();
        for name_hash in name_hashes.into_iter().rev() {
            // search for the bitname to be registered as an ICANN domain
            // exists in the inputs
            let found_bitname = spent_bitnames.any(|(_, outpoint)| {
                let bitname = outpoint.bitname()
                    .expect("spent bitname input should correspond to a known name hash");
                *bitname == name_hash
            });
            if found_bitname {
                let mut bitname_data = self
                    .bitnames
                    .try_get(rwtxn, &name_hash)?
                    .ok_or(Error::Missing { bitname: name_hash })?;
                assert!(!bitname_data.is_icann);
                bitname_data.is_icann = false;
                self.bitnames.put(rwtxn, &name_hash, &bitname_data)?;
            } else {
                return Err(Error::MissingBitNameInput { bitname: name_hash });
            }
        }
        Ok(())
    }
}
