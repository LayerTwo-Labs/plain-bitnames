use ed25519_dalek::PUBLIC_KEY_LENGTH;
use hex_literal::hex;
use lazy_static::lazy_static;

use crate::authorization::VerifyingKey;

/// authorized pubkey that can make batch icann registration txs
const BATCH_ICANN_VERIFYING_KEY_BYTES: [u8; PUBLIC_KEY_LENGTH] =
    // FIXME: choose a real key
    hex!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    );

lazy_static! {
    pub static ref BATCH_ICANN_VERIFYING_KEY: VerifyingKey =
        VerifyingKey::from_bytes(&BATCH_ICANN_VERIFYING_KEY_BYTES)
            .expect("invalid batch ICANN pubkey");
}
