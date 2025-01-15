use borsh::BorshSerialize;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::{openapi, PartialSchema, ToSchema};

#[derive(Debug, Error)]
pub enum ParseBitNameSeqIdError {
    #[error("Empty segment; cannot start with `-` char")]
    EmptySegmentStart,
    #[error("Empty segment; cannot end with `-` char")]
    EmptySegmentEnd,
    #[error("Empty segment; cannot contain sequential `-` chars")]
    EmptySegment,
    #[error("Invalid char; must contain only ASCII digits and `-`: `{char}`")]
    InvalidChar { char: char },
    #[error("Invalid segment; must contain exactly 4 ASCII digits: `{invalid_segment}`")]
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

/// Sequential IDs for BitNames.
/// Has a special 'human-readable' representation, used in Display, and
/// human-readable serialization.
#[derive(
    BorshSerialize, Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
#[repr(transparent)]
pub struct BitNameSeqId(u32);

impl BitNameSeqId {
    /// Used for the 'human-readable' representation
    const DISPLAY_OFFSET: u32 = 23071990;

    pub fn new(seq_id: u32) -> Self {
        Self(seq_id)
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl std::fmt::Display for BitNameSeqId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let first_4_digit_component: u32 = self.0 / 1_0000_0000;
        // last 8 digits with offset applied
        let last_8_digit_component: u32 =
            ((self.0 % 1_0000_0000) + Self::DISPLAY_OFFSET) % 1_0000_0000;
        let reordered_ascii: [[u8; 4]; 2] = {
            let last_8_digits: String = format!("{last_8_digit_component:08}");
            let last_8_digits: &[u8] = last_8_digits.as_bytes();
            assert_eq!(last_8_digits.len(), 8);
            let mut reordered: [[u8; 4]; 2] = [[b'0'; 4]; 2];
            reordered[0][0] = last_8_digits[4];
            reordered[0][1] = last_8_digits[3];
            reordered[0][2] = last_8_digits[1];
            reordered[0][3] = last_8_digits[6];
            reordered[1][0] = last_8_digits[2];
            reordered[1][1] = last_8_digits[7];
            reordered[1][2] = last_8_digits[0];
            reordered[1][3] = last_8_digits[5];
            reordered
        };
        if first_4_digit_component > 0 {
            write!(
                f,
                "{first_4_digit_component:04}-{}-{}",
                String::from_utf8_lossy(&reordered_ascii[0]),
                String::from_utf8_lossy(&reordered_ascii[1]),
            )
        } else {
            write!(
                f,
                "{}-{}",
                String::from_utf8_lossy(&reordered_ascii[0]),
                String::from_utf8_lossy(&reordered_ascii[1]),
            )
        }
    }
}

impl std::str::FromStr for BitNameSeqId {
    type Err = ParseBitNameSeqIdError;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        // parse an ASCII segment
        fn parse_segment(s: &str) -> Result<[u8; 4], ParseBitNameSeqIdError> {
            if s.starts_with('-') {
                return Err(ParseBitNameSeqIdError::EmptySegment);
            };
            if !s.chars().all(|c| c.is_ascii_digit()) {
                return Err(ParseBitNameSeqIdError::InvalidSegment {
                    invalid_segment: s.to_owned(),
                });
            };
            s.as_bytes().try_into().map_err(|_err| {
                ParseBitNameSeqIdError::InvalidSegment {
                    invalid_segment: s.to_owned(),
                }
            })
        }
        fn last_8_digit_component(s0: &[u8; 4], s1: &[u8; 4]) -> u32 {
            let mut last_8_digits_ascii: [u8; 8] = [b'0'; 8];
            last_8_digits_ascii[0] = s1[2];
            last_8_digits_ascii[1] = s0[2];
            last_8_digits_ascii[2] = s1[0];
            last_8_digits_ascii[3] = s0[1];
            last_8_digits_ascii[4] = s0[0];
            last_8_digits_ascii[5] = s1[3];
            last_8_digits_ascii[6] = s0[3];
            last_8_digits_ascii[7] = s1[1];
            let last_8_digits_offset: u32 =
                String::from_utf8_lossy(&last_8_digits_ascii)
                    .parse()
                    .unwrap();
            // subtract offset
            if last_8_digits_offset >= BitNameSeqId::DISPLAY_OFFSET {
                last_8_digits_offset - BitNameSeqId::DISPLAY_OFFSET
            } else {
                1_0000_0000
                    - (BitNameSeqId::DISPLAY_OFFSET - last_8_digits_offset)
            }
        }
        if let Some(invalid_char) =
            s.chars().find(|c| !(c.is_ascii_digit() || *c == '-'))
        {
            return Err(Self::Err::InvalidChar { char: invalid_char });
        };
        if s.starts_with('-') {
            return Err(Self::Err::EmptySegmentStart);
        };
        if s.ends_with('-') {
            return Err(Self::Err::EmptySegmentEnd);
        };
        let mut segments = Vec::new();
        while let Some((segment, rest)) = s.split_once('-') {
            segments.push(parse_segment(segment)?);
            if segments.len() > 2 {
                return Err(Self::Err::TooManySegments);
            }
            s = rest;
        }
        // push final segment
        segments.push(parse_segment(s)?);
        match segments.as_slice() {
            [] | [_] => Err(Self::Err::TooFewSegments),
            [s0, s1] => Ok(Self(last_8_digit_component(s0, s1))),
            [s0, s1, s2] => {
                let first_4_digits: u32 =
                    String::from_utf8_lossy(s0).parse().unwrap();
                Ok(Self(
                    first_4_digits
                        .checked_mul(1_0000_0000)
                        .ok_or(Self::Err::Overflow)?
                        + last_8_digit_component(s1, s2),
                ))
            }
            _ => Err(Self::Err::TooManySegments),
        }
    }
}

impl<'de> Deserialize<'de> for BitNameSeqId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        if deserializer.is_human_readable() {
            let s = <&'de str as Deserialize<'de>>::deserialize(deserializer)?;
            s.parse().map_err(D::Error::custom)
        } else {
            <u32 as Deserialize<'de>>::deserialize(deserializer).map(Self)
        }
    }
}

impl Serialize for BitNameSeqId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            Serialize::serialize(&self.to_string(), serializer)
        } else {
            Serialize::serialize(&self.0, serializer)
        }
    }
}

/// Decode from big-endian
impl<'a> heed::BytesDecode<'a> for BitNameSeqId {
    type DItem = Self;

    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, heed::BoxedError> {
        <heed::types::U32<heed::byteorder::BE> as heed::BytesDecode>::bytes_decode(bytes)
        .map(Self)
    }
}

/// Encode as big-endian
impl<'a> heed::BytesEncode<'a> for BitNameSeqId {
    type EItem = Self;

    fn bytes_encode(
        item: &'a Self::EItem,
    ) -> Result<std::borrow::Cow<'a, [u8]>, heed::BoxedError> {
        <heed::types::U32<heed::byteorder::BE> as heed::BytesEncode>::bytes_encode(&item.0)
    }
}

impl PartialSchema for BitNameSeqId {
    fn schema() -> openapi::RefOr<openapi::schema::Schema> {
        let obj = utoipa::openapi::Object::with_type(openapi::Type::String);
        openapi::RefOr::T(openapi::Schema::Object(obj))
    }
}

impl ToSchema for BitNameSeqId {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("BitNameSeqId")
    }
}

#[cfg(test)]
mod test {
    use super::BitNameSeqId;

    // Test roundtrip display/parse of BitName IDs
    #[test]
    fn parse_display_bitname_ids() {
        [
            (0, "1739-0029"),
            (1, "1739-0129"),
            (24, "2731-0420"),
            (76928008, "9999-9899"),
            (76928009, "9999-9999"),
            (76928013, "0000-0300"),
            (1_0000_0000, "0001-1739-0029"),
        ]
        .into_iter()
        .for_each(|(seq, expected_str)| {
            let seq = BitNameSeqId(seq);
            let human_readable_repr = seq.to_string();
            assert_eq!(human_readable_repr, expected_str);
            assert_eq!(
                human_readable_repr.parse::<BitNameSeqId>().unwrap(),
                seq
            )
        })
    }
}
