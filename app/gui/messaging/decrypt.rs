use std::str::FromStr;

use eframe::egui;

use plain_bitnames::types::{bitname_data::XPublicKey, keys::PublicKey};

use crate::{
    app::App,
    gui::util::{InnerResponseExt, UiExt, borsh_deserialize_hex},
};

#[derive(Debug)]
pub struct DecryptMessage {
    // Encryption pubkey or BitName
    receiver_input: String,
    // none if not yet set, otherwise result of parsing/resolving receiver xpubkey
    receiver_pubkey: Option<anyhow::Result<PublicKey>>,
    ciphertext: String,
    // none if not yet computed, otherwise result of attempting to decrypt
    plaintext_bytes: Option<anyhow::Result<Vec<u8>>>,
}

impl DecryptMessage {
    pub fn new() -> Self {
        Self {
            receiver_input: String::new(),
            receiver_pubkey: None,
            ciphertext: String::new(),
            plaintext_bytes: None,
        }
    }

    fn show_error(ui: &mut egui::Ui, error: &anyhow::Error) {
        ui.monospace_selectable_singleline(false, "Error: ");
        ui.horizontal_wrapped(|ui| {
            ui.monospace_selectable_multiline(format!("{error:#}"));
        });
    }

    pub fn show(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        let Some(app) = app else {
            return;
        };
        ui.monospace("Receiver's BitName or Encryption Pubkey (Bech32m): ");
        let receiver_input_response =
            ui.add(egui::TextEdit::singleline(&mut self.receiver_input));
        if receiver_input_response.changed() {
            let receiver_xpubkey: anyhow::Result<XPublicKey> = {
                if let Ok(bitname) = borsh_deserialize_hex(&self.receiver_input)
                {
                    app.node
                        .get_current_bitname_data(&bitname)
                        .map_err(anyhow::Error::from)
                        .and_then(|bitname_data| {
                            bitname_data.mutable_data.xpubkey.ok_or(
                                anyhow::anyhow!(
                                    "No xpubkey exists for this BitName"
                                ),
                            )
                        })
                } else {
                    XPublicKey::from_str(&self.receiver_input).map_err(|_| {
                        anyhow::anyhow!("Failed to parse BitName or XPubkey")
                    })
                }
            };
            let receiver_pubkey = receiver_xpubkey.map(|xpk| xpk.pubkey);
            self.receiver_pubkey = Some(receiver_pubkey);
        }
        let ciphertext_response = egui::Panel::left("ciphertext message")
            .exact_size(ui.available_width() / 2.)
            .resizable(false)
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.monospace("Ciphertext message (hex):");
                    ui.add(egui::TextEdit::multiline(&mut self.ciphertext))
                })
                .join()
            })
            .join();
        let receiver_pubkey = match &self.receiver_pubkey {
            None => {
                return;
            }
            Some(Err(err)) => {
                self.plaintext_bytes = None;
                Self::show_error(ui, err);
                return;
            }
            Some(Ok(receiver_pubkey)) => receiver_pubkey,
        };
        // regenerate plaintext if possible
        if receiver_input_response.changed() || ciphertext_response.changed() {
            let ciphertext_bytes = match const_hex::decode(&self.ciphertext) {
                Ok(ciphertext_bytes) => ciphertext_bytes,
                Err(err) => {
                    Self::show_error(ui, &anyhow::Error::from(err));
                    return;
                }
            };
            self.plaintext_bytes = Some(
                app.wallet
                    .decrypt_msg(receiver_pubkey, &ciphertext_bytes)
                    .map_err(anyhow::Error::from),
            );
        }
        let plaintext_bytes = match &self.plaintext_bytes {
            None => {
                return;
            }
            Some(Err(err)) => {
                Self::show_error(ui, err);
                return;
            }
            Some(Ok(plaintext_bytes)) => plaintext_bytes,
        };
        // show plaintext if possible
        egui::CentralPanel::default().show(ui, |ui| {
            let plaintext_hex = const_hex::encode(plaintext_bytes);
            ui.vertical_centered(|ui| {
                ui.monospace("Decrypted message:");
                ui.monospace_selectable_multiline(plaintext_hex.as_str());
                if ui.button("📋").on_hover_text("Click to copy").clicked() {
                    ui.output_mut(|po| {
                        po.commands.push(egui::OutputCommand::CopyText(
                            plaintext_hex.clone(),
                        ))
                    });
                };
                // show UTF8-decoded plaintext if possible
                if let Ok(plaintext) = str::from_utf8(plaintext_bytes) {
                    ui.monospace("Decrypted message (UTF-8):");
                    ui.monospace_selectable_multiline(plaintext);
                    if ui.button("📋").on_hover_text("Click to copy").clicked()
                    {
                        ui.output_mut(|po| {
                            po.commands.push(egui::OutputCommand::CopyText(
                                plaintext.to_owned(),
                            ))
                        });
                    };
                }
            });
        });
    }
}
