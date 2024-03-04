use eframe::egui;

use libes::key::conversion::PublicKeyFrom;
use plain_bitnames::types::EncryptionPubKey;

use super::util::{borsh_deserialize_hex, Ecies, InnerResponseExt, UiExt};
use crate::app::App;

#[derive(Debug)]
pub struct EncryptMessage {
    // pubkey or BitName
    receiver_input: String,
    // none if not yet set, otherwise result of parsing/resolving receiver pubkey
    receiver_pubkey: Option<anyhow::Result<EncryptionPubKey>>,
    plaintext: String,
    // none if not yet computed, otherwise result of attempting to encrypt
    ciphertext: Option<anyhow::Result<String>>,
}

impl EncryptMessage {
    pub fn new() -> Self {
        Self {
            receiver_input: String::new(),
            receiver_pubkey: None,
            plaintext: String::new(),
            ciphertext: None,
        }
    }

    fn show_error(ui: &mut egui::Ui, error: &anyhow::Error) {
        ui.monospace_selectable_singleline(false, "Error: ");
        ui.horizontal_wrapped(|ui| {
            ui.monospace_selectable_multiline(format!("{error:#}"));
        });
    }

    pub fn show(&mut self, app: &mut App, ui: &mut egui::Ui) {
        ui.heading("Encrypt Message");
        let receiver_input_response = ui
            .horizontal(|ui| {
                ui.monospace(
                    "Receiver's BitName or Encryption Pubkey (Bech32m): ",
                ) | ui.add(egui::TextEdit::singleline(&mut self.receiver_input))
            })
            .join();
        if receiver_input_response.changed() {
            let receiver_pubkey: anyhow::Result<EncryptionPubKey> = {
                if let Ok(bitname) = borsh_deserialize_hex(&self.receiver_input)
                {
                    app.node
                        .get_current_bitname_data(&bitname)
                        .map_err(anyhow::Error::from)
                        .and_then(|bitname_data| {
                            bitname_data.encryption_pubkey.ok_or(
                                anyhow::anyhow!(
                                "No encryption pubkey exists for this BitName"
                        ),
                            )
                        })
                } else {
                    EncryptionPubKey::bech32m_decode(&self.receiver_input)
                        .map_err(|_| {
                            anyhow::anyhow!(
                                "Failed to parse BitName or Encryption Pubkey"
                            )
                        })
                }
            };
            self.receiver_pubkey = Some(receiver_pubkey);
        }
        let plaintext_response = ui
            .horizontal_wrapped(|ui| {
                ui.monospace("Plaintext message:\n")
                    | ui.add(egui::TextEdit::multiline(&mut self.plaintext))
            })
            .join();
        let receiver_pubkey = match &self.receiver_pubkey {
            None => {
                return;
            }
            Some(Err(err)) => {
                self.ciphertext = None;
                Self::show_error(ui, err);
                return;
            }
            Some(Ok(receiver_pubkey)) => receiver_pubkey,
        };
        // regenerate ciphertext if possible
        if receiver_input_response.changed() || plaintext_response.changed() {
            let receiver_pubkey =
                libes::key::X25519::pk_from(receiver_pubkey.0);
            self.ciphertext = Some(
                // MUST instantiate a new ecies instance, even if only the
                // plaintext has changed. This is to prevent re-use of
                // ephemeral public keys & shared secrets.
                Ecies::new(receiver_pubkey)
                    .encrypt(self.plaintext.as_bytes())
                    .map(hex::encode)
                    .map_err(|err| anyhow::anyhow!("{err:?}")),
            );
        }
        let ciphertext = match &self.ciphertext {
            None => {
                return;
            }
            Some(Err(err)) => {
                Self::show_error(ui, err);
                return;
            }
            Some(Ok(ciphertext)) => ciphertext,
        };
        // show ciphertext if possible
        let _resp = ui.horizontal_wrapped(|ui| {
            ui.monospace_selectable_multiline(format!(
                "Encrypted message: \n{ciphertext}"
            ));
            if ui.button("📋").on_hover_text("Click to copy").clicked() {
                ui.output_mut(|po| po.copied_text = ciphertext.clone());
            };
        });
    }
}
