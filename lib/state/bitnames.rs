//! Functions and types related to BitNames

use std::net::{SocketAddrV4, SocketAddrV6};

use fallible_iterator::FallibleIterator;
use heed::{BoxedError, BytesDecode, BytesEncode, types::SerdeBincode};
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use sneed::{DatabaseUnique, RoDatabaseUnique, RoTxn, RwTxn, db, env};

use crate::{
    state::{
        error::BitName as Error,
        rollback::{RollBack, TxidStamped},
    },
    types::{
        BatchIcannRegistrationData, BitName, BitNameDataUpdates, BitNameSeqId,
        BlockHash, FilledOutput, FilledTransaction, Hash, MutableBitNameData,
        OutPoint, OutPointKey, Txid, Update, bitname_data::XPublicKey,
        state::BitNameReservationPosition,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(in crate::state) struct BitNameReservation {
    pub commitment: Hash,
    pub heights: BitNameReservationPosition,
}

/// Representation of BitName data that supports rollbacks.
/// The most recent datum is the element at the back of the vector.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BitNameData {
    pub seq_id: BitNameSeqId,
    /// Heights of the reservation used by the latest registration.
    pub(in crate::state) reservation_heights:
        RollBack<TxidStamped<BitNameReservationPosition>>,
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
    /// optional minimum paymail fee, in sats
    pub(in crate::state) paymail_fee_sats: RollBack<TxidStamped<Option<u64>>>,
    /// optional extended public key
    pub(in crate::state) xpubkey: RollBack<TxidStamped<Option<XPublicKey>>>,
}

impl BitNameData {
    // initialize from BitName data provided during a registration
    pub(in crate::state) fn init(
        bitname_data: MutableBitNameData,
        txid: Txid,
        height: u32,
        seq_id: BitNameSeqId,
        reservation_heights: BitNameReservationPosition,
    ) -> Self {
        Self {
            seq_id,
            reservation_heights: RollBack::<TxidStamped<_>>::new(
                reservation_heights,
                txid,
                height,
            ),
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
            paymail_fee_sats: RollBack::<TxidStamped<_>>::new(
                bitname_data.paymail_fee_sats,
                txid,
                height,
            ),
            xpubkey: RollBack::<TxidStamped<_>>::new(
                bitname_data.xpubkey,
                txid,
                height,
            ),
        }
    }

    fn registration_updates(data: MutableBitNameData) -> BitNameDataUpdates {
        fn set_optional<T>(value: Option<T>) -> Update<T> {
            match value {
                Some(value) => Update::Set(value),
                None => Update::Delete,
            }
        }
        BitNameDataUpdates {
            commitment: set_optional(data.commitment),
            socket_addr_v4: set_optional(data.socket_addr_v4),
            socket_addr_v6: set_optional(data.socket_addr_v6),
            paymail_fee_sats: set_optional(data.paymail_fee_sats),
            xpubkey: set_optional(data.xpubkey),
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
            reservation_heights: _,
            commitment,
            is_icann: _,
            socket_addr_v4,
            socket_addr_v6,
            paymail_fee_sats,
            xpubkey,
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
            paymail_fee_sats,
            updates.paymail_fee_sats,
            txid,
            height,
        );
        apply_field_update(xpubkey, updates.xpubkey, txid, height);
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
            reservation_heights: _,
            commitment,
            is_icann: _,
            socket_addr_v4,
            socket_addr_v6,
            paymail_fee_sats,
            xpubkey,
        } = self;
        revert_field_update(xpubkey, updates.xpubkey, txid, height);
        revert_field_update(
            paymail_fee_sats,
            updates.paymail_fee_sats,
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

    fn apply_registration(
        &mut self,
        data: MutableBitNameData,
        txid: Txid,
        height: u32,
        reservation_heights: BitNameReservationPosition,
    ) {
        self.reservation_heights
            .push(reservation_heights, txid, height);
        let () =
            self.apply_updates(Self::registration_updates(data), txid, height);
    }

    fn revert_registration(
        &mut self,
        data: MutableBitNameData,
        txid: Txid,
        height: u32,
    ) {
        let popped = self
            .reservation_heights
            .pop()
            .expect("a replaced registration should have reservation metadata");
        assert_eq!(popped.txid, txid);
        assert_eq!(popped.height, height);
        let () =
            self.revert_updates(Self::registration_updates(data), txid, height);
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
            paymail_fee_sats: self
                .paymail_fee_sats
                .at_block_height(height)?
                .data,
            xpubkey: self.xpubkey.at_block_height(height)?.data,
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
            paymail_fee_sats: self.paymail_fee_sats.latest().data,
            xpubkey: self.xpubkey.latest().data,
        };
        crate::types::BitNameData {
            seq_id: self.seq_id,
            mutable_data,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(in crate::state) struct PrunedBitNameReservation {
    pub outpoint: OutPoint,
    pub output: FilledOutput,
    pub heights: BitNameReservationPosition,
}

struct U32OutPointCodec;

impl U32OutPointCodec {
    const ENCODED_SIZE: usize =
        std::mem::size_of::<u32>() + std::mem::size_of::<OutPointKey>();
}

impl<'a> BytesEncode<'a> for U32OutPointCodec {
    type EItem = (u32, OutPoint);

    fn bytes_encode(
        item: &'a Self::EItem,
    ) -> Result<std::borrow::Cow<'a, [u8]>, BoxedError> {
        let (u32, outpoint) = item;
        let mut bytes = Vec::with_capacity(Self::ENCODED_SIZE);
        bytes.extend_from_slice(&u32.to_be_bytes());
        bytes.extend_from_slice(OutPointKey::from(outpoint).as_bytes());
        Ok(std::borrow::Cow::Owned(bytes))
    }
}

impl<'a> BytesDecode<'a> for U32OutPointCodec {
    type DItem = (u32, OutPoint);

    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, BoxedError> {
        if bytes.len() != Self::ENCODED_SIZE {
            return Err("invalid DB key size".into());
        }
        let (u32_bytes, bytes) = bytes.split_first_chunk().unwrap();
        let u32 = u32::from_be_bytes(*u32_bytes);
        let outpoint =
            <OutPointKey as BytesDecode>::bytes_decode(bytes)?.into();
        Ok((u32, outpoint))
    }
}

/// BitName databases
#[derive(Clone)]
pub struct Dbs {
    /// Associates bitname IDs (name hashes) with bitname data
    bitnames: DatabaseUnique<SerdeBincode<BitName>, SerdeBincode<BitNameData>>,
    /// Associates BitNames with their current registration outpoints.
    bitname_outpoints:
        DatabaseUnique<SerdeBincode<BitName>, SerdeBincode<OutPoint>>,
    /// BitName reservations pruned in each sidechain block, for rollback.
    pruned_reservations: DatabaseUnique<
        SerdeBincode<BlockHash>,
        SerdeBincode<NonEmpty<PrunedBitNameReservation>>,
    >,
    /// Incumbent outpoints replaced by registration challenges, keyed by the
    /// challenging registration txid.
    replaced_registrations:
        DatabaseUnique<SerdeBincode<Txid>, SerdeBincode<OutPoint>>,
    /// Indexes current reservation outpoints by creation mainchain height.
    reservation_outpoints_by_initial_mainchain_height:
        DatabaseUnique<U32OutPointCodec, SerdeBincode<()>>,
    /// Associates reservation tx hashes with their commitments and heights
    reservations:
        DatabaseUnique<SerdeBincode<Txid>, SerdeBincode<BitNameReservation>>,
    /// Associates BitName sequence numbers with BitName IDs (name hashes)
    seq_to_bitname: DatabaseUnique<BitNameSeqId, SerdeBincode<BitName>>,
}

impl Dbs {
    pub const NUM_DBS: u32 = 7;

    /// Create / Open DBs. Does not commit the RwTxn.
    pub(in crate::state) fn new<Tls>(
        env: &sneed::Env<Tls>,
        rwtxn: &mut RwTxn,
    ) -> Result<Self, env::error::CreateDb> {
        let bitname_outpoints =
            DatabaseUnique::create(env, rwtxn, "bitname_outpoints")?;
        let bitnames = DatabaseUnique::create(env, rwtxn, "bitnames")?;
        let pruned_reservations =
            DatabaseUnique::create(env, rwtxn, "pruned_bitname_reservations")?;
        let replaced_registrations = DatabaseUnique::create(
            env,
            rwtxn,
            "bitname_replaced_registrations",
        )?;
        let reservation_outpoints_by_initial_mainchain_height =
            DatabaseUnique::create(
                env,
                rwtxn,
                "bitname_reservation_outpoints_by_initial_mainchain_height",
            )?;
        let reservations =
            DatabaseUnique::create(env, rwtxn, "bitname_reservations")?;
        let seq_to_bitname =
            DatabaseUnique::create(env, rwtxn, "bitname_seq_to_bitname")?;
        Ok(Self {
            bitname_outpoints,
            bitnames,
            pruned_reservations,
            replaced_registrations,
            reservation_outpoints_by_initial_mainchain_height,
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

    pub(in crate::state) fn try_get_bitname_outpoint(
        &self,
        rotxn: &RoTxn,
        bitname: &BitName,
    ) -> Result<Option<OutPoint>, db::error::TryGet> {
        self.bitname_outpoints.try_get(rotxn, bitname)
    }

    pub(in crate::state) fn put_bitname_outpoint(
        &self,
        rwtxn: &mut RwTxn,
        outpoint: &OutPoint,
        output: &FilledOutput,
    ) -> Result<(), Error> {
        let Some(bitname) = output.bitname() else {
            return Ok(());
        };
        self.bitname_outpoints.put(rwtxn, bitname, outpoint)?;
        Ok(())
    }

    pub(in crate::state) fn delete_bitname_outpoint(
        &self,
        rwtxn: &mut RwTxn,
        outpoint: &OutPoint,
        output: &FilledOutput,
    ) -> Result<(), Error> {
        let Some(bitname) = output.bitname() else {
            return Ok(());
        };
        let current_outpoint = self
            .bitname_outpoints
            .try_get(rwtxn, bitname)?
            .ok_or(Error::MissingRegistrationUtxo { bitname: *bitname })?;
        if current_outpoint != *outpoint {
            return Err(Error::MissingRegistrationUtxo { bitname: *bitname });
        }
        if !self.bitname_outpoints.delete(rwtxn, bitname)? {
            return Err(Error::MissingRegistrationUtxo { bitname: *bitname });
        }
        Ok(())
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

    pub(in crate::state) fn reservation_outpoints_through_initial_mainchain_height<
        'txn,
    >(
        &'txn self,
        rotxn: &'txn RoTxn,
        initial_mainchain_height: u32,
    ) -> Result<
        impl FallibleIterator<Item = OutPoint, Error = db::error::IterItem> + 'txn,
        db::error::RangeInit,
    > {
        // All reservation outpoints are regular outpoints, so the greatest
        // regular outpoint is an inclusive upper bound for this height.
        let max_outpoint = OutPoint::Regular {
            txid: Txid([u8::MAX; 32]),
            vout: u32::MAX,
        };
        let range = ..=(initial_mainchain_height, max_outpoint);
        let outpoints = self
            .reservation_outpoints_by_initial_mainchain_height
            .range(rotxn, &range)?
            .map(|((_, outpoint), ())| Ok(outpoint));
        Ok(outpoints)
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

    pub(in crate::state) fn get_reservation(
        &self,
        rotxn: &RoTxn,
        txid: &Txid,
    ) -> Result<BitNameReservation, Error> {
        self.reservations
            .try_get(rotxn, txid)?
            .ok_or(Error::MissingReservation { txid: *txid })
    }

    /// Return the sidechain and mainchain heights of a reservation.
    pub fn try_get_reservation_heights(
        &self,
        rotxn: &RoTxn,
        txid: &Txid,
    ) -> Result<Option<BitNameReservationPosition>, db::error::TryGet> {
        let heights = self
            .reservations
            .try_get(rotxn, txid)?
            .map(|reservation| reservation.heights);
        Ok(heights)
    }

    pub(in crate::state) fn put_reservation_outpoint_at_initial_height(
        &self,
        rwtxn: &mut RwTxn,
        outpoint: &OutPoint,
        output: &FilledOutput,
    ) -> Result<(), Error> {
        let Some((reservation_txid, _)) = output.reservation_data() else {
            return Ok(());
        };
        let Some(position) =
            self.try_get_reservation_heights(rwtxn, reservation_txid)?
        else {
            return Err(Error::MissingReservation {
                txid: *reservation_txid,
            });
        };
        self.reservation_outpoints_by_initial_mainchain_height.put(
            rwtxn,
            &(position.mainchain, *outpoint),
            &(),
        )?;
        Ok(())
    }

    pub(in crate::state) fn delete_reservation_outpoint_at_initial_height(
        &self,
        rwtxn: &mut RwTxn,
        outpoint: &OutPoint,
        output: &FilledOutput,
    ) -> Result<(), Error> {
        let Some((reservation_txid, _)) = output.reservation_data() else {
            return Ok(());
        };
        let Some(position) =
            self.try_get_reservation_heights(rwtxn, reservation_txid)?
        else {
            return Err(Error::MissingReservation {
                txid: *reservation_txid,
            });
        };
        if !self
            .reservation_outpoints_by_initial_mainchain_height
            .delete(rwtxn, &(position.mainchain, *outpoint))?
        {
            return Err(Error::MissingReservation {
                txid: *reservation_txid,
            });
        }
        Ok(())
    }

    /// Store a BitName reservation
    pub(in crate::state) fn put_reservation(
        &self,
        rwtxn: &mut RwTxn,
        txid: &Txid,
        commitment: &Hash,
        heights: BitNameReservationPosition,
    ) -> Result<(), db::error::Put> {
        let reservation = BitNameReservation {
            commitment: *commitment,
            heights,
        };
        self.reservations.put(rwtxn, txid, &reservation)
    }

    /// Store pruned reservations for a block
    pub(in crate::state) fn put_pruned_reservations(
        &self,
        rwtxn: &mut RwTxn,
        block_hash: &BlockHash,
        reservations: NonEmpty<PrunedBitNameReservation>,
    ) -> Result<(), Error> {
        for reservation in &reservations {
            self.delete_reservation_outpoint_at_initial_height(
                rwtxn,
                &reservation.outpoint,
                &reservation.output,
            )?;
            let (reservation_txid, _) = reservation
                .output
                .reservation_data()
                .expect("pruned outputs should be reservations");
            if !self.delete_reservation(rwtxn, reservation_txid)? {
                return Err(Error::MissingReservation {
                    txid: *reservation_txid,
                });
            }
        }
        self.pruned_reservations
            .put(rwtxn, block_hash, &reservations)?;
        Ok(())
    }

    pub(in crate::state) fn restore_pruned_reservations(
        &self,
        rwtxn: &mut RwTxn,
        block_hash: &BlockHash,
    ) -> Result<Option<NonEmpty<PrunedBitNameReservation>>, Error> {
        let Some(pruned) =
            self.pruned_reservations.try_get(rwtxn, block_hash)?
        else {
            return Ok(None);
        };
        for reservation in pruned.iter().rev() {
            let (reservation_txid, commitment) = reservation
                .output
                .reservation_data()
                .expect("pruned outputs should be reservations");
            let () = self.put_reservation(
                rwtxn,
                reservation_txid,
                commitment,
                reservation.heights,
            )?;
            self.put_reservation_outpoint_at_initial_height(
                rwtxn,
                &reservation.outpoint,
                &reservation.output,
            )?;
        }
        self.pruned_reservations.delete(rwtxn, block_hash)?;
        Ok(Some(pruned))
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
        bitname_data: &MutableBitNameData,
        height: u32,
        replaced_outpoint: Option<OutPoint>,
    ) -> Result<(), Error> {
        // Find the reservation to burn: the spent reservation whose commitment
        // equals keyed_hash(revealed_nonce, name_hash). This is enforced by
        // `validate_bitnames`; returning an error here rather than panicking
        // guards against any unvalidated connection path.
        let implied_commitment = filled_tx
            .implied_reservation_commitment()
            .ok_or(Error::NoReservationForRegistration { bitname })?;
        let burned_reservation_txid = filled_tx
            .spent_reservations()
            .find_map(|(_, filled_output)| {
                let (txid, commitment) = filled_output.reservation_data()?;
                if *commitment == implied_commitment {
                    Some(txid)
                } else {
                    None
                }
            })
            .ok_or(Error::NoReservationForRegistration { bitname })?;
        let reservation = self
            .reservations
            .try_get(rwtxn, burned_reservation_txid)?
            .ok_or(Error::MissingReservation {
                txid: *burned_reservation_txid,
            })?;
        if !self.reservations.delete(rwtxn, burned_reservation_txid)? {
            return Err(Error::MissingReservation {
                txid: *burned_reservation_txid,
            });
        }
        if let Some(mut current_data) =
            self.bitnames.try_get(rwtxn, &bitname)?
        {
            let replaced_outpoint = replaced_outpoint
                .ok_or(Error::MissingRegistrationUtxo { bitname })?;
            self.replaced_registrations.put(
                rwtxn,
                &filled_tx.txid(),
                &replaced_outpoint,
            )?;
            let () = current_data.apply_registration(
                bitname_data.clone(),
                filled_tx.txid(),
                height,
                reservation.heights,
            );
            self.bitnames.put(rwtxn, &bitname, &current_data)?;
        } else {
            if replaced_outpoint.is_some() {
                return Err(Error::Missing { bitname });
            }
            let seq = self.next_seq(rwtxn)?;
            self.seq_to_bitname.put(rwtxn, &seq, &bitname)?;
            let bitname_data = BitNameData::init(
                bitname_data.clone(),
                filled_tx.txid(),
                height,
                seq,
                reservation.heights,
            );
            self.bitnames.put(rwtxn, &bitname, &bitname_data)?;
        }
        Ok(())
    }

    /// Revert BitName registration. Returns the incumbent outpoint whose STXO
    /// must be removed and whose UTXO must be restored, if this was a challenge.
    pub(in crate::state) fn revert_registration(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        bitname: BitName,
        registration_data: &MutableBitNameData,
        height: u32,
    ) -> Result<Option<OutPoint>, Error> {
        let Some(mut current_data) = self.bitnames.try_get(rwtxn, &bitname)?
        else {
            return Err(Error::Missing { bitname });
        };
        let reservation_heights =
            current_data.reservation_heights.latest().data;
        let replaced_outpoint = self
            .replaced_registrations
            .try_get(rwtxn, &filled_tx.txid())?;
        if replaced_outpoint.is_some() {
            let () = current_data.revert_registration(
                registration_data.clone(),
                filled_tx.txid(),
                height,
            );
            self.bitnames.put(rwtxn, &bitname, &current_data)?;
            if !self
                .replaced_registrations
                .delete(rwtxn, &filled_tx.txid())?
            {
                return Err(Error::MissingRegistrationUtxo { bitname });
            }
        } else {
            let seq_id = current_data.seq_id;
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
        let reservation = BitNameReservation {
            commitment: implied_commitment,
            heights: reservation_heights,
        };
        self.reservations
            .put(rwtxn, burned_reservation_txid, &reservation)?;
        Ok(replaced_outpoint)
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
