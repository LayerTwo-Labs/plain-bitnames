use std::sync::LazyLock;

use ed25519_dalek::PUBLIC_KEY_LENGTH;
use hex_literal::hex;

use crate::{BlockHash, VerifyingKey};

/// Drivenet blocks mined with the historical withdrawal accounting rule.
///
/// These blocks predate the rule that includes the mainchain fee in a
/// withdrawal output's sidechain value. Restricting compatibility to this
/// exact set preserves history without weakening validation for new blocks.
pub const LEGACY_WITHDRAWAL_ACCOUNTING_BLOCKS: [BlockHash; 2] = [
    BlockHash(hex!(
        "f9a7a9117bec4ed6c4fffbf3b651b60f9459a5fc881f267b271778874ad55d0f"
    )),
    BlockHash(hex!(
        "208e6bb567efd46d073bab68d9cff041279faada60c7f27a011a56bd1f7f86b7"
    )),
];

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
