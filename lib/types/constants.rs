use std::sync::LazyLock;

use ed25519_dalek::PUBLIC_KEY_LENGTH;
use hex_literal::hex;

use crate::types::VerifyingKey;

/// authorized pubkey that can make batch icann registration txs
const BATCH_ICANN_VERIFYING_KEY_BYTES: [u8; PUBLIC_KEY_LENGTH] =
    // FIXME: choose a real key
    hex!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    );

pub static BATCH_ICANN_VERIFYING_KEY: LazyLock<VerifyingKey> =
    LazyLock::new(|| {
        VerifyingKey::try_from(&BATCH_ICANN_VERIFYING_KEY_BYTES)
            .expect("invalid batch ICANN pubkey")
    });
