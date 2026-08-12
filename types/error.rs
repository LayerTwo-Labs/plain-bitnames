use thiserror::Error;

#[derive(Debug, Error)]
#[error("Bitcoin amount overflow")]
pub struct AmountOverflow;

#[derive(Debug, Error)]
#[error("Bitcoin amount underflow")]
pub struct AmountUnderflow;

#[derive(Debug, Error)]
pub enum ComputeFee {
    #[error("underfunded (value in < value out)")]
    Underfunded,
    #[error("value in overflow")]
    ValueInOverflow(#[source] AmountOverflow),
    #[error("value out overflow")]
    ValueOutOverflow(#[source] AmountOverflow),
}

#[derive(Debug, Error)]
pub enum GetFee {
    #[error(transparent)]
    AmountOverflow(#[from] AmountOverflow),
    #[error(transparent)]
    AmountUnderflow(#[from] AmountUnderflow),
}

#[derive(Debug, Error)]
pub enum ComputeMerkleRoot {
    #[error("failed to compute fee for tx ({txid})")]
    FeeComputation {
        txid: crate::Txid,
        #[source]
        source: GetFee,
    },
}

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

#[derive(Debug, thiserror::Error)]
pub enum Authorization {
    #[error("borsh serialization error")]
    BorshSerialize(#[from] borsh::io::Error),
    #[error("ed25519 error")]
    Ed25519(#[from] ed25519_dalek::SignatureError),
    #[error("not enough authorizations")]
    NotEnoughAuthorizations,
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
        source: Box<ed25519_dalek::SignatureError>,
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
