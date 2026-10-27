//! Utility types and functions for this crate

/// Borsh encoding and decoding
pub(crate) mod borsh {
    pub mod deserialize {
        use bitcoin::hashes::Hash as _;
        use borsh::BorshDeserialize;

        pub fn bitcoin_outpoint<R>(
            reader: &mut R,
        ) -> borsh::io::Result<bitcoin::OutPoint>
        where
            R: borsh::io::Read,
        {
            use bitcoin::hashes::Hash as _;
            let (txid_bytes, vout): ([u8; 32], u32) =
                <([u8; 32], u32) as BorshDeserialize>::deserialize_reader(
                    reader,
                )?;
            Ok(bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array(txid_bytes),
                vout,
            })
        }

        pub fn bitcoin_txid<R>(
            reader: &mut R,
        ) -> borsh::io::Result<bitcoin::Txid>
        where
            R: borsh::io::Read,
        {
            let txid_bytes =
                <[u8; 32] as BorshDeserialize>::deserialize_reader(reader)?;
            Ok(bitcoin::Txid::from_byte_array(txid_bytes))
        }
    }

    pub mod serialize {
        use borsh::BorshSerialize;

        use frost_ristretto255::VerifyingKey;

        pub fn bitcoin_address<V, W>(
            bitcoin_address: &bitcoin::Address<V>,
            writer: &mut W,
        ) -> borsh::io::Result<()>
        where
            V: bitcoin::address::NetworkValidation,
            W: borsh::io::Write,
        {
            let spk = bitcoin_address
                .as_unchecked()
                .assume_checked_ref()
                .script_pubkey();
            BorshSerialize::serialize(spk.as_bytes(), writer)
        }

        pub fn bitcoin_amount<W>(
            amount: &bitcoin::Amount,
            writer: &mut W,
        ) -> borsh::io::Result<()>
        where
            W: borsh::io::Write,
        {
            amount.to_sat().serialize(writer)
        }

        pub fn bitcoin_block_hash<W>(
            block_hash: &bitcoin::BlockHash,
            writer: &mut W,
        ) -> borsh::io::Result<()>
        where
            W: borsh::io::Write,
        {
            let bytes: &[u8; 32] = block_hash.as_ref();
            BorshSerialize::serialize(bytes, writer)
        }

        pub fn bitcoin_outpoint<W>(
            block_hash: &bitcoin::OutPoint,
            writer: &mut W,
        ) -> borsh::io::Result<()>
        where
            W: borsh::io::Write,
        {
            let bitcoin::OutPoint { txid, vout } = block_hash;
            let txid_bytes: &[u8; 32] = txid.as_ref();
            BorshSerialize::serialize(&(txid_bytes, vout), writer)
        }

        pub fn bitcoin_txid<W>(
            txid: &bitcoin::Txid,
            writer: &mut W,
        ) -> borsh::io::Result<()>
        where
            W: borsh::io::Write,
        {
            let bytes: &[u8; 32] = txid.as_ref();
            BorshSerialize::serialize(bytes, writer)
        }

        #[inline(always)]
        pub fn compressed_ristretto_point<W>(
            compressed: &curve25519_dalek::ristretto::CompressedRistretto,
            writer: &mut W,
        ) -> borsh::io::Result<()>
        where
            W: borsh::io::Write,
        {
            borsh::BorshSerialize::serialize(compressed.as_bytes(), writer)
        }

        #[inline(always)]
        pub fn ristretto_point<W>(
            point: &curve25519_dalek::RistrettoPoint,
            writer: &mut W,
        ) -> borsh::io::Result<()>
        where
            W: borsh::io::Write,
        {
            compressed_ristretto_point(&point.compress(), writer)
        }

        pub fn verifying_key<W>(
            vk: &VerifyingKey,
            writer: &mut W,
        ) -> borsh::io::Result<()>
        where
            W: borsh::io::Write,
        {
            ristretto_point(&vk.to_element(), writer)
        }
    }
}

/// Serde adapters
pub(crate) mod serde {
    use serde::{Deserializer, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    /// (de)serialize as Display/FromStr for human-readable forms like json,
    /// and default serialization for non human-readable forms like bincode
    pub mod display_fromstr_human_readable {
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use serde_with::{DeserializeAs, DisplayFromStr, SerializeAs};
        use std::{fmt::Display, str::FromStr};

        pub fn serialize<S, T>(
            data: T,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            T: Serialize + Display,
        {
            if serializer.is_human_readable() {
                DisplayFromStr::serialize_as(&data, serializer)
            } else {
                data.serialize(serializer)
            }
        }

        pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where
            D: Deserializer<'de>,
            T: Deserialize<'de> + FromStr,
            <T as FromStr>::Err: Display,
        {
            if deserializer.is_human_readable() {
                DisplayFromStr::deserialize_as(deserializer)
            } else {
                T::deserialize(deserializer)
            }
        }
    }

    /// (de)serialize as hex strings for human-readable forms like json,
    /// and default serialization for non human-readable formats like bincode
    pub mod hexstr_human_readable {
        use const_hex::{FromHex, ToHexExt};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S, T>(
            data: T,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            T: Serialize + ToHexExt,
        {
            if serializer.is_human_readable() {
                data.encode_hex().serialize(serializer)
            } else {
                data.serialize(serializer)
            }
        }

        pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where
            D: Deserializer<'de>,
            T: Deserialize<'de> + FromHex,
            <T as FromHex>::Error: std::fmt::Display,
        {
            if deserializer.is_human_readable() {
                const_hex::serde::deserialize(deserializer)
            } else {
                T::deserialize(deserializer)
            }
        }
    }

    /// Serialize [`bitcoin::Amount`] as sats
    pub struct BitcoinAmountSats;

    impl<'de> DeserializeAs<'de, bitcoin::Amount> for BitcoinAmountSats {
        fn deserialize_as<D>(
            deserializer: D,
        ) -> Result<bitcoin::Amount, D::Error>
        where
            D: Deserializer<'de>,
        {
            bitcoin::amount::serde::as_sat::deserialize(deserializer)
        }
    }

    impl SerializeAs<bitcoin::Amount> for BitcoinAmountSats {
        fn serialize_as<S>(
            source: &bitcoin::Amount,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            bitcoin::amount::serde::as_sat::serialize(source, serializer)
        }
    }
}
