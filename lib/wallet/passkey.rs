//! CTAP 2.0 implementation
///
/// Public keys are identified by their compressed representation, encoded in
/// base64url form without padding.

use async_trait::async_trait;
use passkey::{
    authenticator::{
        CredentialStore, DiscoverabilitySupport, StoreInfo, UserCheck,
        UserValidationMethod
    }, 
    types::{
        ctap2::U2FError, encoding::try_from_base64url, webauthn::{
            AuthenticatorTransport,
            PublicKeyCredentialDescriptor,
            PublicKeyCredentialType,
        }
    }
};

use crate::{types::VerifyingKey, wallet::Wallet};

#[async_trait]
impl CredentialStore for Wallet {
    type PasskeyItem = passkey::types::Passkey;

     async fn find_credentials(
            &self,
            ids: Option<&[PublicKeyCredentialDescriptor]>,
            rp_id: &str,
        ) -> Result<Vec<Self::PasskeyItem>, passkey::types::ctap2::StatusCode> {
        let mut res = Vec::new();
        let rotxn = self.env.read_txn().map_err(|err| {
            tracing::error!("{:#}", anyhow::Error::from(err));
            U2FError::Other
        })?;
        for PublicKeyCredentialDescriptor { ty, id, transports } in ids.into_iter().flatten() {
            match ty {
                PublicKeyCredentialType::PublicKey => (),
                PublicKeyCredentialType::Unknown => {
                    // Ignore unknown credential types
                    continue
                }
            }
            if let Some(transports) = transports &&
                !transports.contains(&AuthenticatorTransport::Internal) {
                continue;
            }
            let Ok(vk_bytes): Result<[u8; VerifyingKey::BYTE_LEN], _> =
                id.as_slice().try_into() else {
                continue;
            };
            let Ok(vk) = VerifyingKey::try_from(&vk_bytes) else {
                continue;
            };
            let Some(sk) = self.try_get_message_signing_key_for_vk(&rotxn, &vk)
                .map_err(|err| {
                    tracing::error!("{:#}", anyhow::Error::from(err));
                    U2FError::Other
                })? else {
                continue;
            };
            let passkey_item = Self::PasskeyItem {
                key: coset::CoseKey {
                    kty: coset::KeyType::Assigned(coset::iana::KeyType::OKP),
                    key_id: vk_bytes.to_vec(),
                    alg: Some(coset::Algorithm::Assigned(coset::iana::Algorithm::EdDSA)),
                    key_ops: [
                        coset::iana::KeyOperation::Sign,
                        coset::iana::KeyOperation::Verify,    
                    ].into_iter().map(coset::KeyOperation::Assigned).collect(),
                    base_iv: Vec::new(),
                    params: Vec::new()
                },
                credential_id: todo!(),
                rp_id: rp_id.to_owned(),
                user_handle: None,
                // FIXME: should this be used?
                counter: None,
                extensions: Default::default(),
            };
            res.push(passkey_item);
        }
        Ok(res)
    }

    async fn save_credential(
        &mut self,
        _cred: passkey::types::Passkey,
        _user: passkey::types::ctap2::make_credential::PublicKeyCredentialUserEntity,
        _rp: passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity,
        _options: passkey::types::ctap2::get_assertion::Options,
    ) -> Result<(), passkey::types::ctap2::StatusCode> {
        Err(passkey::types::ctap2::Ctap2Error::InvalidSubcommand.into())
    }

    async fn update_credential(&mut self, _cred: passkey::types::Passkey)
        -> Result<(), passkey::types::ctap2::StatusCode> {
        Err(passkey::types::ctap2::Ctap2Error::InvalidSubcommand.into())
    }

    async fn get_info(&self) -> passkey::authenticator::StoreInfo {
        passkey::authenticator::StoreInfo {
            discoverability: DiscoverabilitySupport::OnlyNonDiscoverable,
        }
    }
}

#[async_trait]
impl UserValidationMethod for Wallet {
    type PasskeyItem = <Self as CredentialStore>::PasskeyItem;

    async fn check_user<'a>(
        &self,
        _credential: Option<&'a Self::PasskeyItem>,
        _presence: bool,
        _verification: bool,
    ) -> Result<UserCheck, passkey::types::ctap2::Ctap2Error> {
        Ok(UserCheck { presence: false, verification: false })
    }

    fn is_presence_enabled(&self) -> bool {
        false
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        None
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn non_hardened_derivation() -> anyhow::Result<()> {
        use bitcoin::{
            bip32::ChildNumber,
            hashes::{sha256, Hash as _, HashEngine as _},
        };
        use ed25519_bip32::DerivationScheme;
        let master_secret = blake3::hash(b"test non-hardened derivation");
        // Derived as described in
        // https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf
        let root_chain_code: [u8; 32] = {
            let mut hasher = sha256::HashEngine::default();
            hasher.input(&[0x01]);
            hasher.input(master_secret.as_bytes());
            assert_eq!(hasher.n_bytes_hashed(), 33);
            sha256::Hash::from_engine(hasher).to_byte_array()
        };
        let master_xprv = ed25519_bip32::XPrv::from_nonextended_noforce(
            master_secret.as_bytes(), &root_chain_code).map_err(|()|
            anyhow::anyhow!("Invalid master secret")
        )?;
        let master_xpub = master_xprv.public();
        let child_idx = ChildNumber::Normal { index: 69_420 };
        let child_xprv =
            master_xprv.derive(DerivationScheme::V2, child_idx.into());
        // public derivation for child xpub
        let child_xpub = master_xpub.derive(DerivationScheme::V2, child_idx.into())?;
        anyhow::ensure!(child_xprv.public() == child_xpub);
        Ok(())
    }
}