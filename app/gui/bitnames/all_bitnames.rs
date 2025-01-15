use std::collections::BTreeMap;

use eframe::egui;
use hex::FromHex;
use plain_bitnames::types::{hashes::BitName, BitNameData, MutableBitNameData};

use crate::{
    app::App,
    gui::util::{InnerResponseExt, UiExt},
};

#[derive(Debug, Default)]
pub(super) struct AllBitNames {
    query: String,
}

fn show_bitname_data(
    ui: &mut egui::Ui,
    bitname_data: &BitNameData,
) -> egui::Response {
    let BitNameData {
        seq_id,
        mutable_data,
    } = bitname_data;
    let MutableBitNameData {
        commitment,
        ipv4_addr,
        ipv6_addr,
        encryption_pubkey,
        signing_pubkey,
        paymail_fee_sats,
    } = mutable_data;
    let commitment = commitment.map_or("Not set".to_owned(), hex::encode);
    let ipv4_addr = ipv4_addr
        .map_or("Not set".to_owned(), |ipv4_addr| ipv4_addr.to_string());
    let ipv6_addr = ipv6_addr
        .map_or("Not set".to_owned(), |ipv6_addr| ipv6_addr.to_string());
    let encryption_pubkey = encryption_pubkey
        .map_or("Not set".to_owned(), |epk| hex::encode(epk.0.as_bytes()));
    let signing_pubkey = signing_pubkey
        .map_or("Not set".to_owned(), |pk| hex::encode(pk.as_bytes()));
    let paymail_fee_sats = paymail_fee_sats
        .map_or("Not set".to_owned(), |paymail_fee| paymail_fee.to_string());
    ui.horizontal(|ui| {
        ui.monospace_selectable_singleline(false, format!("Seq ID: {seq_id}"))
    })
    .join()
        | ui.horizontal(|ui| {
            ui.monospace_selectable_singleline(
                true,
                format!("Commitment: {commitment}"),
            )
        })
        .join()
        | ui.horizontal(|ui| {
            ui.monospace_selectable_singleline(
                false,
                format!("IPv4 Address: {ipv4_addr}"),
            )
        })
        .join()
        | ui.horizontal(|ui| {
            ui.monospace_selectable_singleline(
                false,
                format!("IPv6 Address: {ipv6_addr}"),
            )
        })
        .join()
        | ui.horizontal(|ui| {
            ui.monospace_selectable_singleline(
                true,
                format!("Encryption Pubkey: {encryption_pubkey}"),
            )
        })
        .join()
        | ui.horizontal(|ui| {
            ui.monospace_selectable_singleline(
                true,
                format!("Signing Pubkey: {signing_pubkey}"),
            )
        })
        .join()
        | ui.horizontal(|ui| {
            ui.monospace_selectable_singleline(
                false,
                format!("Paymail fee: {paymail_fee_sats}"),
            )
        })
        .join()
}

fn show_bitname_with_data(
    ui: &mut egui::Ui,
    bitname_id: &BitName,
    bitname_data: &BitNameData,
) -> egui::Response {
    ui.horizontal(|ui| {
        ui.monospace_selectable_singleline(
            true,
            format!("BitName ID: {}", hex::encode(bitname_id.0)),
        )
    })
    .join()
        | show_bitname_data(ui, bitname_data)
}

impl AllBitNames {
    pub fn show(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        egui::CentralPanel::default().show_inside(ui, |ui| {
            let Some(app) = app else {
                return;
            };
            match app.node.bitnames() {
                Err(node_err) => {
                    ui.monospace_selectable_multiline(node_err.to_string());
                }
                Ok(bitnames) => {
                    let bitnames = BTreeMap::from_iter(bitnames);
                    ui.horizontal(|ui| {
                        let query_edit =
                            egui::TextEdit::singleline(&mut self.query)
                                .hint_text("Search")
                                .desired_width(150.);
                        ui.add(query_edit);
                    });
                    if self.query.is_empty() {
                        bitnames.into_iter().for_each(
                            |(bitname_id, bitname_data)| {
                                show_bitname_with_data(
                                    ui,
                                    &bitname_id,
                                    &bitname_data,
                                );
                            },
                        )
                    } else {
                        let name_hash =
                            blake3::hash(self.query.as_bytes()).into();
                        let name_hash_pattern = BitName(name_hash);
                        if let Some(bitname_data) =
                            bitnames.get(&name_hash_pattern)
                        {
                            show_bitname_with_data(
                                ui,
                                &name_hash_pattern,
                                bitname_data,
                            );
                        };
                        if let Ok(bitname_id_pattern) =
                            BitName::from_hex(&self.query)
                        {
                            if let Some(bitname_data) =
                                bitnames.get(&bitname_id_pattern)
                            {
                                show_bitname_with_data(
                                    ui,
                                    &bitname_id_pattern,
                                    bitname_data,
                                );
                            }
                        }
                    }
                }
            }
        });
    }
}
