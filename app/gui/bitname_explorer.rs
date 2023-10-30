use eframe::egui::{self, Response};

use plain_bitnames::{node, types::BitNameData};

use super::util::{InnerResponseExt, UiExt};
use crate::app::App;

/// result of the last bitname lookup query
#[derive(Debug)]
struct LastQueryResult(Result<Option<BitNameData>, node::Error>);

#[derive(Debug, Default)]
pub struct BitnameExplorer {
    plaintext_name: String,
    last_query_result: Option<LastQueryResult>,
}

impl BitnameExplorer {
    fn show_bitname_data(
        ui: &mut egui::Ui,
        bitname_data: &BitNameData,
    ) -> Response {
        let BitNameData {
            commitment,
            ipv4_addr,
            ipv6_addr,
            encryption_pubkey,
            signing_pubkey,
            paymail_fee,
        } = bitname_data;
        let commitment = commitment.map_or("Not set".to_owned(), hex::encode);
        let ipv4_addr = ipv4_addr
            .map_or("Not set".to_owned(), |ipv4_addr| ipv4_addr.to_string());
        let ipv6_addr = ipv6_addr
            .map_or("Not set".to_owned(), |ipv6_addr| ipv6_addr.to_string());
        let encryption_pubkey = encryption_pubkey
            .map_or("Not set".to_owned(), |epk| hex::encode(epk.0.as_bytes()));
        let signing_pubkey = signing_pubkey
            .map_or("Not set".to_owned(), |pk| hex::encode(pk.as_bytes()));
        let paymail_fee = paymail_fee
            .map_or("Not set".to_owned(), |paymail_fee| {
                paymail_fee.to_string()
            });
        ui.horizontal(|ui| {
            ui.monospace_selectable_singleline(format!(
                "Commitment: {commitment}"
            ))
        })
        .join()
            | ui.horizontal(|ui| {
                ui.monospace_selectable_singleline(format!(
                    "IPv4 Address: {ipv4_addr}"
                ))
            })
            .join()
            | ui.horizontal(|ui| {
                ui.monospace_selectable_singleline(format!(
                    "IPv6 Address: {ipv6_addr}"
                ))
            })
            .join()
            | ui.horizontal(|ui| {
                ui.monospace_selectable_singleline(format!(
                    "Encryption Pubkey: {encryption_pubkey}"
                ))
            })
            .join()
            | ui.horizontal(|ui| {
                ui.monospace_selectable_singleline(format!(
                    "Signing Pubkey: {signing_pubkey}"
                ))
            })
            .join()
            | ui.horizontal(|ui| {
                ui.monospace_selectable_singleline(format!(
                    "Paymail fee: {paymail_fee}"
                ))
            })
            .join()
    }

    pub fn show(&mut self, app: &mut App, ui: &mut egui::Ui) {
        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.heading("BitName Explorer");
            let text_resp =  ui.horizontal(|ui| {
                ui.monospace("Plaintext BitName:       ")
                | ui.add(egui::TextEdit::singleline(&mut self.plaintext_name))
            }).join();
            let refresh_button = ui.button("Refresh");
            // resolve bitname if changed or refresh button clicked
            if text_resp.changed() || refresh_button.clicked() {
                let bitname = blake3::hash(self.plaintext_name.as_bytes()).into();
                let last_query_result = app.node.get_current_bitname_data(&bitname);
                self.last_query_result = Some(LastQueryResult(last_query_result));
            }
            if let Some(LastQueryResult(last_query_result)) = &self.last_query_result {
                match last_query_result {
                    Err(err) => {
                        ui.horizontal(|ui| {
                            ui.monospace(format!("Error encountered when resolving bitname: {err}"))
                        });
                    }
                    Ok(None) => {
                        ui.horizontal(|ui| {
                            ui.monospace("No BitName data found")
                        });
                    }
                    Ok(Some(bitname_data)) => {
                        let _resp: Response = Self::show_bitname_data(ui, bitname_data);
                    }
                }
            }
        });
    }
}
