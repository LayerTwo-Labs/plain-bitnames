use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Bitcoin amount overflow")]
pub struct AmountOverflow;

#[derive(Debug, Error)]
#[error("Bitcoin amount underflow")]
pub struct AmountUnderflow;

#[derive(Debug, Error)]
#[error("Non-canonical Ristretto point encoding")]
pub struct NonCanonicalRistrettoPointEncoding;

pub mod signature {
    use thiserror::Error;

    use crate::error::NonCanonicalRistrettoPointEncoding;

    #[derive(Debug, Error)]
    pub enum FromBytes {
        #[error(transparent)]
        R(#[from] NonCanonicalRistrettoPointEncoding),
        #[error("Non-canonical Ristretto scalar encoding")]
        Z,
    }

    #[derive(Debug, Error)]
    pub enum FromHex {
        #[error(transparent)]
        FromBytes(FromBytes),
        #[error(transparent)]
        Hex(#[from] const_hex::FromHexError),
    }

    impl<E> From<E> for FromHex
    where
        FromBytes: From<E>,
    {
        fn from(err: E) -> Self {
            Self::FromBytes(err.into())
        }
    }
}

#[derive(Debug, Error)]
pub enum Authorization {
    #[error("borsh serialization error")]
    BorshSerialize(#[from] borsh::io::Error),
    #[error("not enough authorizations")]
    NotEnoughAuthorizations,
    #[error("signature verification error")]
    SignatureVerification(#[from] frost_ristretto255::Error),
    #[error("too many authorizations")]
    TooManyAuthorizations,
    #[error(
        "wrong key for address: address = {address},
             hash(verifying_key) = {hash_verifying_key}"
    )]
    WrongKeyForAddress {
        address: crate::Address,
        hash_verifying_key: crate::Address,
    },
}

#[derive(Debug, Error)]
pub enum ComputeFee {
    #[error("underfunded (value in < value out)")]
    Underfunded,
    #[error("value in overflow")]
    ValueInOverflow(#[source] AmountOverflow),
    #[error("value out overflow")]
    ValueOutOverflow(#[source] AmountOverflow),
}

pub mod compute_merkle_root {
    use thiserror::Error;

    use crate::{error::ComputeFee, hashes::Txid};

    #[derive(Debug, Error)]
    pub(crate) enum Inner {
        #[error("failed to compute merkle root for coinbase tx")]
        CoinbaseMerkleRoot(
            #[source] crate::transaction::outputs::error::ComputeMerkleRoot,
        ),
        #[error("failed to compute canonical size for tx ({txid})")]
        TxCanonicalSize {
            txid: Txid,
            source: borsh::io::Error,
        },
        #[error("failed to compute fee for tx ({txid})")]
        TxFee { txid: Txid, source: ComputeFee },
        #[error("failed to compute merkle root for tx ({txid})")]
        TxMerkleRoot {
            txid: Txid,
            source: crate::transaction::outputs::error::ComputeMerkleRoot,
        },
    }

    #[derive(Debug, Error)]
    #[error("failed to compute merkle root")]
    #[repr(transparent)]
    pub struct Error(#[source] Box<Inner>);

    impl From<Inner> for Error {
        fn from(err: Inner) -> Self {
            Self(Box::new(err))
        }
    }
}
pub use compute_merkle_root::Error as ComputeMerkleRoot;

pub mod withdrawal_bundle {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub(crate) enum Inner {
        #[error(
            "bundle too heavy: weight `{weight}` > max weight `{max_weight}`"
        )]
        BundleTooHeavy { weight: u64, max_weight: u64 },
    }

    #[derive(Debug, Error)]
    #[error("Withdrawal bundle error")]
    #[repr(transparent)]
    pub struct Error(#[from] Inner);
}
pub use withdrawal_bundle::Error as WithdrawalBundle;

#[derive(Debug, Error)]
pub enum ParseAddress {
    #[error("bs58 error")]
    Bs58(#[from] bitcoin::base58::InvalidCharacterError),
    #[error("wrong address length {0} != 20")]
    WrongLength(usize),
}

#[derive(Debug, Error)]
pub enum ParseBitNameSeqId {
    #[error("Empty segment; cannot start with `-` char")]
    EmptySegmentStart,
    #[error("Empty segment; cannot end with `-` char")]
    EmptySegmentEnd,
    #[error("Empty segment; cannot contain sequential `-` chars")]
    EmptySegment,
    #[error("Invalid char; must contain only ASCII digits and `-`: `{char}`")]
    InvalidChar { char: char },
    #[error(
        "Invalid segment; must contain exactly 4 ASCII digits: `{invalid_segment}`"
    )]
    InvalidSegment { invalid_segment: String },
    #[error(
        "Value overflow: BitName seq ID encodes a number greater than u32::MAX"
    )]
    Overflow,
    #[error("Too few segments; 2 or 3 segments required")]
    TooFewSegments,
    #[error("Too many segments; 2 or 3 segments required")]
    TooManySegments,
}

pub mod base58ck_decode {
    use educe::Educe;
    use generic_array::{ArrayLength, GenericArray};
    use thiserror::Error;

    #[derive(Educe, Error)]
    #[educe(Debug(bound(TryFromError: std::fmt::Debug)))]
    pub(crate) enum Inner<PrefixLen, TryFromError>
    where
        PrefixLen: ArrayLength,
    {
        #[error(transparent)]
        Decode(#[from] bitcoin::base58::Error),
        #[error(
            "Incorrect prefix (`{}`): expected `{}`.",
            const_hex::encode(.decoded),
            const_hex::encode(.expected),
        )]
        IncorrectPrefix {
            decoded: GenericArray<u8, PrefixLen>,
            expected: GenericArray<u8, PrefixLen>,
        },
        #[error(
            "Incorrect decoded byte length ({}). Expected {} bytes of data.",
            .decoded,
            .expected,
        )]
        IncorrectSize { decoded: usize, expected: usize },
        #[error(transparent)]
        TryFrom(TryFromError),
    }

    #[derive(Educe, Error)]
    #[educe(Debug(bound(
        Inner<PrefixLen, TryFromError>: std::fmt::Debug
    )))]
    #[error("Failed to decode base58ck")]
    #[repr(transparent)]
    pub struct Error<PrefixLen, TryFromError>(
        #[source] Inner<PrefixLen, TryFromError>,
    )
    where
        PrefixLen: ArrayLength;

    impl<PrefixLen, TryFromError, E> From<E> for Error<PrefixLen, TryFromError>
    where
        PrefixLen: ArrayLength,
        Inner<PrefixLen, TryFromError>: From<E>,
    {
        fn from(err: E) -> Self {
            Self(err.into())
        }
    }
}
pub use base58ck_decode::Error as Base58ckDecode;

#[derive(Debug, Error)]
#[error("Wrong Bech32 HRP. Expected {expected} but decoded {decoded}")]
pub struct WrongHrp {
    pub(crate) expected: bech32::Hrp,
    pub(crate) decoded: bech32::Hrp,
}

#[derive(Debug, Error)]
pub enum Bech32mDecode {
    #[error(transparent)]
    Bech32m(#[from] bech32::DecodeError),
    #[error("Invalid bytes (`{}`)", const_hex::encode(.bytes))]
    InvalidBytes {
        bytes: [u8; 32],
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error(transparent)]
    WrongHrp(#[from] Box<WrongHrp>),
    #[error(
        "Wrong decoded byte length ({decoded_len}). Must decode to {expected_len} bytes of data."
    )]
    WrongSize {
        decoded_len: usize,
        expected_len: usize,
    },
    #[error("Wrong Bech32 variant. Only Bech32m is accepted.")]
    WrongVariant,
}

#[derive(Debug, Error)]
pub enum ParsePeerAddress {
    #[error("missing port")]
    MissingPort,
    #[error(transparent)]
    Parse(#[from] url::ParseError),
}
