use std::str::FromStr;

use borsh::BorshSerialize;
use const_hex::FromHex;
use rayon::{
    iter::{IntoParallelRefIterator as _, ParallelIterator as _},
    slice::ParallelSlice as _,
};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeAs, SerializeAs};
use utoipa::ToSchema;

pub use frost_ristretto255::rand_core;

use crate::{
    Address, AuthorizedTransaction, Body, GetAddress, Transaction, error,
    util::borsh::serialize as borsh_serialize,
};

pub type Error = error::Authorization;
pub type SigningKey = frost_ristretto255::SigningKey;
pub type VerifyingKey = frost_ristretto255::VerifyingKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ToSchema)]
#[repr(transparent)]
#[schema(value_type = String)]
pub struct Signature(pub frost_ristretto255::Signature);

impl Signature {
    fn as_bytes(&self) -> [u8; 64] {
        let mut res = [0u8; 64];
        let (r_bytes, rest) = res.split_first_chunk_mut().unwrap();
        *r_bytes = self.0.R().compress().to_bytes();
        let z_bytes = rest.as_mut_array().unwrap();
        *z_bytes = self.0.z().to_bytes();
        res
    }
}

impl BorshSerialize for Signature {
    fn serialize<W>(&self, writer: &mut W) -> borsh::io::Result<()>
    where
        W: borsh::io::Write,
    {
        borsh::BorshSerialize::serialize(&self.as_bytes(), writer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            const_hex::serde::no_prefix::deserialize(deserializer)
        } else {
            let bytes: [u8; 64] =
                serde_with::Bytes::deserialize_as(deserializer)?;
            Self::try_from(bytes).map_err(serde::de::Error::custom)
        }
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const_hex::display(self.as_bytes()).fmt(f)
    }
}

impl FromHex for Signature {
    type Error = error::signature::FromHex;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes: [u8; 64] = FromHex::from_hex(hex)?;
        let res = Self::try_from(bytes)?;
        Ok(res)
    }
}

impl FromStr for Signature {
    type Err = error::signature::FromHex;

    #[inline(always)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.as_bytes();
        if serializer.is_human_readable() {
            const_hex::serde::no_prefix::serialize(bytes, serializer)
        } else {
            serde_with::Bytes::serialize_as(&bytes, serializer)
        }
    }
}

impl TryFrom<[u8; 64]> for Signature {
    type Error = error::signature::FromBytes;

    fn try_from(bytes: [u8; 64]) -> Result<Self, Self::Error> {
        let (r_bytes, rest) = bytes.split_first_chunk().unwrap();
        let r = curve25519_dalek::ristretto::CompressedRistretto(*r_bytes)
            .decompress()
            .ok_or(error::NonCanonicalRistrettoPointEncoding)?;
        let z_bytes = rest.as_array().unwrap();
        let z = curve25519_dalek::Scalar::from_canonical_bytes(*z_bytes)
            .into_option()
            .ok_or(Self::Error::Z)?;
        Ok(Self(frost_ristretto255::Signature::new(r, z)))
    }
}

pub fn get_address(verifying_key: VerifyingKey) -> Address {
    let mut hasher = blake3::Hasher::new();
    let mut reader = hasher
        .update(verifying_key.to_element().compress().as_bytes())
        .finalize_xof();
    let mut output: [u8; 20] = [0; 20];
    reader.fill(&mut output);
    Address(output)
}

/// Domain seperation tag for signing messages
#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "lower"))]
#[repr(u8)]
#[serde(rename_all = "lowercase")]
pub enum Dst {
    Transaction = 0,
    /// Arbitrary, non-protocol messages
    Arbitrary = u8::MAX,
}

#[derive(
    BorshSerialize,
    Debug,
    Clone,
    Deserialize,
    Eq,
    PartialEq,
    Serialize,
    ToSchema,
)]
pub struct Authorization {
    #[borsh(serialize_with = "borsh_serialize::verifying_key")]
    #[schema(value_type = String)]
    pub verifying_key: VerifyingKey,
    pub signature: Signature,
}

impl GetAddress for Authorization {
    fn get_address(&self) -> Address {
        get_address(self.verifying_key)
    }
}

/// Derives a CSPRNG seed for a single batch verification.
struct BatchVerifier {
    hasher: blake3::Hasher,
    inner: frost_core::batch::Verifier<frost_ristretto255::Ristretto255Sha512>,
    /// Item counter, added as a suffix to the hasher before verification
    items: usize,
}

impl BatchVerifier {
    pub fn queue_item<Msg>(
        mut self,
        verifying_key: VerifyingKey,
        signature: Signature,
        msg: Msg,
    ) -> Result<Self, frost_ristretto255::Error>
    where
        Msg: AsRef<[u8]>,
    {
        let Self {
            inner,
            items,
            hasher,
        } = &mut self;
        let msg_bytes = msg.as_ref();
        // Borsh encoding for hashing
        #[derive(BorshSerialize)]
        struct HashComponents<'a> {
            #[borsh(serialize_with = "borsh_serialize::verifying_key")]
            verifying_key: &'a VerifyingKey,
            signature: &'a Signature,
            msg_bytes: &'a [u8],
        }
        borsh::to_writer(
            hasher,
            &HashComponents {
                verifying_key: &verifying_key,
                signature: &signature,
                msg_bytes,
            },
        )
        .expect("failed to serialize with borsh to compute a hash");
        *items += 1;
        inner.queue(frost_core::batch::Item::new(
            verifying_key,
            signature.0,
            msg_bytes,
        )?);
        Ok(self)
    }

    /// Performs batch verification, returning `Ok(_)` if all signatures were
    /// valid and the batch was non-empty, and `Err(_)` otherwise.
    pub fn verify(self) -> Result<(), frost_ristretto255::Error> {
        let Self {
            hasher,
            inner,
            items,
        } = self;
        let rng = {
            // move hasher so that it can be dropped early automatically
            let mut hasher = hasher;
            borsh::to_writer(&mut hasher, &items)
                .expect("failed to serialize with borsh to compute a hash");
            <rand::rngs::ChaCha20Rng as rand::SeedableRng>::from_seed(
                hasher.finalize().into(),
            )
        };
        inner.verify(rng)
    }
}

/// Required for batched verification.
/// It should be safe to re-use the same batch verification context for
/// several batched verifications.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct BatchVerificationContext {
    mac_key: [u8; blake3::KEY_LEN],
}

impl BatchVerificationContext {
    pub fn new<R>(rng: &mut R) -> Self
    where
        R: rand_core::CryptoRng,
    {
        let mut mac_key = [0; blake3::KEY_LEN];
        rng.fill_bytes(&mut mac_key);
        Self { mac_key }
    }

    /// Construct a new batch verifier
    fn verifier(&self) -> BatchVerifier {
        let Self { mac_key } = self;
        BatchVerifier {
            hasher: blake3::Hasher::new_keyed(mac_key),
            inner: frost_core::batch::Verifier::new(),
            items: 0,
        }
    }
}

/// Canonical message to sign a tx
fn tx_msg_canonical(tx: &Transaction) -> borsh::io::Result<Vec<u8>> {
    let mut buf = vec![Dst::Transaction as u8];
    borsh::to_writer(&mut buf, tx)?;
    Ok(buf)
}

pub fn verify_authorized_transaction(
    ctxt: &BatchVerificationContext,
    transaction: &AuthorizedTransaction,
) -> Result<(), Error> {
    let verifications_required = &transaction.transaction.inputs.len();
    match transaction.authorizations.len().cmp(verifications_required) {
        std::cmp::Ordering::Less => return Err(Error::NotEnoughAuthorizations),
        std::cmp::Ordering::Equal => (),
        std::cmp::Ordering::Greater => {
            return Err(Error::TooManyAuthorizations);
        }
    }
    if *verifications_required == 0 {
        return Ok(());
    }
    let mut batch_verifier = ctxt.verifier();
    let tx_msg_canonical = tx_msg_canonical(&transaction.transaction)?;
    for auth in &transaction.authorizations {
        let Authorization {
            verifying_key,
            signature,
        } = auth;
        batch_verifier = batch_verifier.queue_item(
            *verifying_key,
            *signature,
            &tx_msg_canonical,
        )?;
    }
    let () = batch_verifier.verify()?;
    Ok(())
}

pub fn verify_authorizations(
    ctxt: &BatchVerificationContext,
    body: &Body,
) -> Result<(), Error> {
    let verifications_required =
        body.transactions.par_iter().map(|tx| tx.inputs.len()).sum();
    match body.authorizations.len().cmp(&verifications_required) {
        std::cmp::Ordering::Less => return Err(Error::NotEnoughAuthorizations),
        std::cmp::Ordering::Equal => (),
        std::cmp::Ordering::Greater => {
            return Err(Error::TooManyAuthorizations);
        }
    }
    if verifications_required == 0 {
        return Ok(());
    }
    // pairs of serialized txs, and the number of inputs
    let serialized_transactions_inputs: Vec<(Vec<u8>, usize)> = body
        .transactions
        .par_iter()
        .map(|tx| Ok((tx_msg_canonical(tx)?, tx.inputs.len())))
        .collect::<Result<_, Error>>()?;
    let messages =
        serialized_transactions_inputs
            .iter()
            .flat_map(|(tx, n_inputs)| {
                std::iter::repeat_n(tx.as_slice(), *n_inputs)
            });
    let pairs = body.authorizations.iter().zip(messages).collect::<Vec<_>>();
    assert_eq!(pairs.len(), body.authorizations.len());
    const CHUNK_SIZE: usize = 1 << 14;
    pairs.par_chunks(CHUNK_SIZE).try_for_each(|chunk| {
        let mut batch_verifier = ctxt.verifier();
        for (auth, msg) in chunk {
            let Authorization {
                verifying_key,
                signature,
            } = auth;
            batch_verifier =
                batch_verifier.queue_item(*verifying_key, *signature, msg)?;
        }
        batch_verifier.verify()
    })?;
    Ok(())
}

/// Sign a message with DST prefix
pub fn sign<R>(
    rng: R,
    signing_key: &SigningKey,
    dst: Dst,
    msg: &[u8],
) -> Signature
where
    R: rand_core::CryptoRng,
{
    let msg_buf = [&[dst as u8], msg].concat();
    Signature(signing_key.sign(rng, &msg_buf))
}

/// Verify a message with DST prefix
pub fn verify(
    signature: &Signature,
    verifying_key: &VerifyingKey,
    dst: Dst,
    msg: &[u8],
) -> bool {
    let msg_buf = [&[dst as u8], msg].concat();
    verifying_key.verify(&msg_buf, &signature.0).is_ok()
}

pub fn sign_tx<R>(
    rng: R,
    signing_key: &SigningKey,
    transaction: &Transaction,
) -> Result<Signature, Error>
where
    R: rand_core::CryptoRng,
{
    let tx_msg_canonical = tx_msg_canonical(transaction)?;
    let sig = signing_key.sign(rng, &tx_msg_canonical);
    Ok(Signature(sig))
}

pub fn authorize<R>(
    mut rng: R,
    addresses_signing_keys: &[(Address, &SigningKey)],
    transaction: Transaction,
) -> Result<AuthorizedTransaction, Error>
where
    R: rand_core::CryptoRng,
{
    let mut authorizations: Vec<Authorization> =
        Vec::with_capacity(addresses_signing_keys.len());
    let tx_msg_canonical = tx_msg_canonical(&transaction)?;
    for (address, signing_key) in addresses_signing_keys {
        let verifying_key = VerifyingKey::from(*signing_key);
        let hash_verifying_key = get_address(verifying_key);
        if *address != hash_verifying_key {
            return Err(Error::WrongKeyForAddress {
                address: *address,
                hash_verifying_key,
            });
        }
        let signature =
            Signature(signing_key.sign(&mut rng, &tx_msg_canonical));
        let authorization = Authorization {
            verifying_key,
            signature,
        };
        authorizations.push(authorization);
    }
    Ok(AuthorizedTransaction {
        authorizations,
        transaction,
    })
}
