use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{Address, BitName, BitNameData, BlockHash, FilledOutput, OutPoint};

/// The current on-chain owner and mutable data for a BitName.
///
/// BitName ownership is represented by a zero-value BitName UTXO. The address
/// on that output, rather than a field in [`BitNameData`], is the address to
/// which paymail should be sent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct BitNameResolution {
    pub bitname: BitName,
    pub outpoint: OutPoint,
    pub address: Address,
    pub data: BitNameData,
}

/// A BitName that owned the mailbox output address when it was confirmed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct PaymailRecipient {
    pub bitname: BitName,
    /// Advertised minimum paymail fee at confirmation time. `None` means the
    /// BitName was not accepting paid introductions at that time.
    pub required_fee_sats: Option<u64>,
    pub data: BitNameData,
}

/// A JSON-safe mailbox entry.
///
/// Unlike the legacy `HashMap<OutPoint, FilledOutput>` response, this type does
/// not encode an enum as a JSON object key. It also identifies the exact
/// BitName records that owned the output address at confirmation time. Entries
/// below the advertised fee are intentionally included so callers can apply a
/// local accepted-contact policy for low-value follow-up messages.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct PaymailEntry {
    pub outpoint: OutPoint,
    pub output: FilledOutput,
    pub value_sats: u64,
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub tx_index: u32,
    pub recipients: Vec<PaymailRecipient>,
}

impl PaymailEntry {
    /// Whether this output paid at least the advertised fee for any attributed
    /// recipient. Typed mailbox consumers deliberately receive entries for
    /// which this is false so they can apply local accepted-contact policy.
    pub fn meets_advertised_fee(&self) -> bool {
        self.recipients.iter().any(|recipient| {
            recipient
                .required_fee_sats
                .is_some_and(|required_fee| self.value_sats >= required_fee)
        })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Amount;

    use crate::{
        Address, BitName, BitNameData, BitNameSeqId, BlockHash, FilledOutput,
        FilledOutputContent, MutableBitNameData, OutPoint, PaymailEntry,
        PaymailRecipient, Txid,
    };

    fn underpaid_entry() -> PaymailEntry {
        let bitname = BitName([1; 32]);
        let data = BitNameData {
            seq_id: BitNameSeqId::new(0),
            mutable_data: MutableBitNameData {
                paymail_fee_sats: Some(1_000),
                ..Default::default()
            },
        };
        PaymailEntry {
            outpoint: OutPoint::Regular {
                txid: Txid([2; 32]),
                vout: 0,
            },
            output: FilledOutput {
                address: Address([3; 20]),
                content: FilledOutputContent::new_bitcoin_value(
                    Amount::from_sat(1),
                ),
                memo: vec![0xaa, 0xbb],
            },
            value_sats: 1,
            block_hash: BlockHash([4; 32]),
            block_height: 5,
            tx_index: 6,
            recipients: vec![PaymailRecipient {
                bitname,
                required_fee_sats: Some(1_000),
                data,
            }],
        }
    }

    #[test]
    fn underpaid_entry_remains_json_safe_and_attributed() {
        let entry = underpaid_entry();
        assert!(!entry.meets_advertised_fee());

        let json = serde_json::to_value([entry]).unwrap();
        let entry = &json[0];
        assert_eq!(entry["value_sats"], 1);
        assert_eq!(entry["output"]["memo"], "aabb");
        assert_eq!(entry["recipients"][0]["required_fee_sats"], 1_000);
        assert_eq!(entry["recipients"][0]["bitname"], hex::encode([1; 32]));
        assert!(entry["outpoint"].get("Regular").is_some());
    }

    #[test]
    fn advertised_fee_is_a_separate_legacy_policy() {
        let mut entry = underpaid_entry();
        entry.value_sats = 1_000;
        assert!(entry.meets_advertised_fee());
    }
}
