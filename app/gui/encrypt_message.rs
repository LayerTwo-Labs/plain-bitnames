use ecies_ed25519::PublicKey as EncryptionPubKey;
use eframe::egui;
use hex::FromHex;

use super::util::InnerResponseExt;
use crate::app::App;

#[derive(Debug)]
pub struct EncryptMessage {
    receiver_pubkey_string: String,
    // none if not yet set, otherwise result of parsing receiver pubkey
    receiver_pubkey: Option<anyhow::Result<EncryptionPubKey>>,
    plaintext: String,
    // none if not yet computed, otherwise result of attempting to encrypt
    ciphertext: Option<anyhow::Result<String>>,
    csprng: rand::rngs::ThreadRng,
}

impl EncryptMessage {
    pub fn new() -> Self {
        Self {
            receiver_pubkey_string: String::new(),
            receiver_pubkey: None,
            plaintext: String::new(),
            ciphertext: None,
            csprng: rand::thread_rng(),
        }
    }

    fn show_error(ui: &mut egui::Ui, error: &anyhow::Error) {
        ui.horizontal_wrapped(|ui| {
            ui.monospace("Error: ");
            ui.code(format!("{error}"));
        });
    }

    pub fn show(&mut self, _app: &mut App, ui: &mut egui::Ui) {
        ui.heading("Encrypt Message");
        let receiver_pubkey_response = ui
            .horizontal(|ui| {
                ui.monospace("Receiver's Encryption Pubkey:       ")
                    | ui.add(egui::TextEdit::singleline(
                        &mut self.receiver_pubkey_string,
                    ))
            })
            .join();
        if receiver_pubkey_response.changed() {
            self.receiver_pubkey = Some(
                <[u8; 32]>::from_hex(&self.receiver_pubkey_string)
                    .map_err(anyhow::Error::new)
                    .and_then(|bytes| {
                        EncryptionPubKey::from_bytes(&bytes)
                            .map_err(anyhow::Error::new)
                    }),
            );
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
        if receiver_pubkey_response.changed() || plaintext_response.changed() {
            self.ciphertext = Some(
                ecies_ed25519::encrypt(
                    receiver_pubkey,
                    self.plaintext.as_bytes(),
                    &mut self.csprng,
                )
                .map(hex::encode)
                .map_err(anyhow::Error::new),
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
            ui.monospace(format!("Encrypted message: \n{ciphertext}"));
            if ui.button("📋").on_hover_text("Click to copy").clicked() {
                ui.output_mut(|po| po.copied_text = ciphertext.clone());
            };
        });
    }
}
