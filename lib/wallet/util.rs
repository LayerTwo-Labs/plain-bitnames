//! Utility functions and types

use bitcoin::bip32::{ChildNumber, DerivationPath};
use ed25519_bip32::{XPrv, XPub};

/// Compute a derivation path from 8 bytes, without setting the hardened bit
const fn child_indexes_from_bytes8(bytes: [u8; 8]) -> [u32; 3] {
    let [b0, b1, b2, b3, b4, b5, b6, b7] = bytes;

    let c0 = u32::from_le_bytes([b0, b1, b2, b3 & 0b0111_1111]);
    let c1 = u32::from_le_bytes([
        (b3 >> 7) | (b4 << 1),
        (b4 >> 7) | (b5 << 1),
        (b5 >> 7) | (b6 << 1),
        (b6 >> 7) | ((b7 << 1) & 0b0111_1111),
    ]);
    let c2 = u32::from_le_bytes([b7 >> 6, 0, 0, 0]);
    [c0, c1, c2]
}

/// Compute a derivation path from 32 bytes, without setting the hardened bit
const fn child_indexes_from_bytes32(bytes: &[u8; 32]) -> [u32; 9] {
    const fn const_min_usize(left: usize, right: usize) -> usize {
        if left <= right { left } else { right }
    }

    let mut res = [0u32; 9];
    let mut idx = 0usize;
    while idx < 32 {
        let byte = bytes[idx];
        let bit_start = idx * 8; // Starting bit position for this byte
        let u32_idx_lo = bit_start / 31; // First u32 that will receive bits
        let bit_offset_lo = bit_start % 31; // Bit position within that u32

        // How many bits can fit in the current u32?
        let bits_in_current = const_min_usize(8, 31 - bit_offset_lo);

        if u32_idx_lo < 9 {
            // Place the lower bits in the current u32
            let mask = (1u32 << bits_in_current) - 1;
            let bits_to_place = (byte as u32) & mask;
            res[u32_idx_lo] |= bits_to_place << bit_offset_lo;

            // If we have remaining bits, place them in the next u32
            let remaining_bits = 8 - bits_in_current;
            if remaining_bits > 0 && u32_idx_lo + 1 < 9 {
                let remaining_byte_bits = (byte as u32) >> bits_in_current;
                res[u32_idx_lo + 1] |= remaining_byte_bits;
            }
        }
        idx += 1;
    }
    res
}

#[allow(dead_code)]
pub const fn derivation_path_from_bytes8(
    bytes: [u8; 8],
    hardened: bool,
) -> [ChildNumber; 3] {
    // Hardened
    const fn ch(index: u32) -> ChildNumber {
        ChildNumber::Hardened { index }
    }
    // Normal
    const fn cn(index: u32) -> ChildNumber {
        ChildNumber::Normal { index }
    }
    let [c0, c1, c2] = child_indexes_from_bytes8(bytes);
    if hardened {
        [ch(c0), ch(c1), ch(c2)]
    } else {
        [cn(c0), cn(c1), cn(c2)]
    }
}

#[allow(dead_code)]
pub const fn derivation_path_from_bytes32(
    bytes: &[u8; 32],
    hardened: bool,
) -> [ChildNumber; 9] {
    // Hardened
    const fn ch(index: u32) -> ChildNumber {
        ChildNumber::Hardened { index }
    }
    // Normal
    const fn cn(index: u32) -> ChildNumber {
        ChildNumber::Normal { index }
    }
    let [c0, c1, c2, c3, c4, c5, c6, c7, c8] =
        child_indexes_from_bytes32(bytes);
    if hardened {
        [
            ch(c0),
            ch(c1),
            ch(c2),
            ch(c3),
            ch(c4),
            ch(c5),
            ch(c6),
            ch(c7),
            ch(c8),
        ]
    } else {
        [
            cn(c0),
            cn(c1),
            cn(c2),
            cn(c3),
            cn(c4),
            cn(c5),
            cn(c6),
            cn(c7),
            cn(c8),
        ]
    }
}

/// Known BIP32 derivation paths.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum KnownBip32Path {
    Encryption { index: u32 },
    MessageSigning { index: u32 },
    TxSigning { index: u32 },
}

impl KnownBip32Path {
    pub const MASTER_ENCRYPTION: [ChildNumber; 1] =
        [ChildNumber::Hardened { index: 1 }];
    pub const MASTER_MESSAGE_SIGNING: [ChildNumber; 1] =
        [ChildNumber::Hardened { index: 2 }];
    pub const MASTER_TX_SIGNING: [ChildNumber; 1] =
        [ChildNumber::Hardened { index: 0 }];

    const fn encryption(index: u32) -> [ChildNumber; 2] {
        let [prefix] = Self::MASTER_ENCRYPTION;
        [prefix, ChildNumber::Normal { index }]
    }

    const fn message_signing(index: u32) -> [ChildNumber; 2] {
        let [prefix] = Self::MASTER_MESSAGE_SIGNING;
        [prefix, ChildNumber::Normal { index }]
    }

    const fn tx_signing(index: u32) -> [ChildNumber; 2] {
        let [prefix] = Self::MASTER_TX_SIGNING;
        [prefix, ChildNumber::Normal { index }]
    }

    pub fn derivation_path(&self) -> Vec<ChildNumber> {
        match self {
            Self::Encryption { index } => Self::encryption(*index).to_vec(),
            Self::MessageSigning { index } => {
                Self::message_signing(*index).to_vec()
            }
            Self::TxSigning { index } => Self::tx_signing(*index).to_vec(),
        }
    }
}

impl From<KnownBip32Path> for DerivationPath {
    fn from(path: KnownBip32Path) -> Self {
        path.derivation_path().into()
    }
}

/// Derive an XPrv using a derivation path
pub fn derive_xprv(xprv: XPrv, path: &DerivationPath) -> XPrv {
    path.into_iter().fold(xprv, |xprv, child_number| {
        xprv.derive(ed25519_bip32::DerivationScheme::V2, (*child_number).into())
    })
}

/// Derive an XPub using a derivation path
#[allow(dead_code)]
pub fn derive_xpub(
    xpub: XPub,
    path: &DerivationPath,
) -> Result<XPub, ed25519_bip32::DerivationError> {
    path.into_iter().try_fold(xpub, |xpub, child_number| {
        xpub.derive(ed25519_bip32::DerivationScheme::V2, (*child_number).into())
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_child_indexes_from_bytes8() -> anyhow::Result<()> {
        let bytes8 = [0, 1, 2, 0xcc, 4, 5, 6, 0xaa];
        let child_indexes = super::child_indexes_from_bytes8(bytes8);
        let expected_child_indexes = [0x4c020100, 0x540c0a09, 0x00000002];
        anyhow::ensure!(child_indexes == expected_child_indexes);
        Ok(())
    }

    #[test]
    fn test_child_indexes_from_bytes32() -> anyhow::Result<()> {
        let bytes32 = (0..32).collect::<Vec<u8>>().as_slice().try_into()?;
        let child_indexes = super::child_indexes_from_bytes32(&bytes32);
        let expected_child_indexes = [
            0x03020100, 0x0e0c0a08, 0x2c282420, 0x78706860, 0x31211100,
            0x62c2a282, 0x46864605, 0x0f0e8e0d, 0x0000001f,
        ];
        anyhow::ensure!(child_indexes == expected_child_indexes);
        Ok(())
    }
}
