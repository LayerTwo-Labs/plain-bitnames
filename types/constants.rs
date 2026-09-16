use std::sync::LazyLock;

use hex_literal::hex;

use crate::authorization::VerifyingKey;

/// authorized pubkey that can make batch icann registration txs
const BATCH_ICANN_VERIFYING_KEY_BYTES: [u8; 32] =
    // FIXME: choose a real key
    hex!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    );

pub static BATCH_ICANN_VERIFYING_KEY: LazyLock<VerifyingKey> =
    LazyLock::new(|| {
        let compressed = curve25519_dalek::ristretto::CompressedRistretto(
            BATCH_ICANN_VERIFYING_KEY_BYTES,
        );
        let decompressed =
            compressed.decompress().expect("invalid batch ICANN pubkey");
        VerifyingKey::new(decompressed)
    });
