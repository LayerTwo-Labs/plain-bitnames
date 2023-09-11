use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
};

use eframe::egui::{self, InnerResponse, Response};

use plain_bitnames::{
    authorization::PublicKey,
    bip300301::bitcoin,
    types::{BitNameData, EncryptionPubKey, Transaction, Txid},
    wallet,
};

use crate::app::App;

#[derive(Clone, Debug, Default, PartialEq)]
pub enum TxType {
    #[default]
    Regular,
    BitNameRegistration {
        plaintext_name: String,
        bitname_data: Box<BitNameData>,
    },
    BitNameReservation {
        plaintext_name: String,
    },
}

#[derive(Debug, Default)]
pub struct TxCreator {
    pub value_in: u64,
    pub value_out: u64,
    pub tx_type: TxType,
    // if the base tx has changed, need to recompute final tx
    base_txid: Txid,
    final_tx: Option<Result<Transaction, wallet::Error>>,
}

impl std::fmt::Display for TxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Regular => write!(f, "regular"),
            Self::BitNameRegistration { .. } => write!(f, "register bitname"),
            Self::BitNameReservation { .. } => write!(f, "reserve bitname"),
        }
    }
}

// BitwiseOr for inner response option
fn bitwise_or_inner_resp_option(
    inner_resp: InnerResponse<Option<Response>>,
) -> Response {
    match inner_resp.inner {
        Some(inner) => inner_resp.response | inner,
        None => inner_resp.response,
    }
}

// BitwiseOr for inner response
fn bitwise_or_inner_resp(inner_resp: InnerResponse<Response>) -> Response {
    inner_resp.response | inner_resp.inner
}

impl TxCreator {
    // set tx data for the current transaction
    fn set_tx_data(
        &self,
        app: &mut App,
        mut tx: Transaction,
    ) -> Result<Transaction, wallet::Error> {
        match &self.tx_type {
            TxType::Regular => Ok(tx),
            TxType::BitNameRegistration {
                plaintext_name,
                bitname_data,
            } => {
                let () = app.wallet.register_bitname(
                    &mut tx,
                    plaintext_name,
                    Cow::Borrowed(bitname_data.as_ref()),
                )?;
                Ok(tx)
            }
            TxType::BitNameReservation { plaintext_name } => {
                let () = app.wallet.reserve_bitname(&mut tx, plaintext_name)?;
                Ok(tx)
            }
        }
    }

    // show setter for a single optional field, with default value
    fn show_option_field_default<T>(
        ui: &mut egui::Ui,
        name: &str,
        default: T,
        option_field: &mut Option<T>,
    ) -> Response
    where
        T: PartialEq,
    {
        let option_dropdown = egui::ComboBox::from_id_source(name)
            .selected_text(if option_field.is_some() {
                "set"
            } else {
                "do not set"
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(option_field, Some(default), "set")
                    | ui.selectable_value(option_field, None, "do not set")
            });
        bitwise_or_inner_resp_option(option_dropdown)
    }

    fn show_bitname_options(
        ui: &mut egui::Ui,
        bitname_data: &mut BitNameData,
    ) -> Response {
        let commitment_resp = ui.horizontal(|ui| {
            ui.monospace("Commitment:       ")
                | Self::show_option_field_default(
                    ui,
                    "bitname_data_commitment",
                    Default::default(),
                    &mut bitname_data.commitment,
                )
        });
        let ipv4_resp = ui.horizontal(|ui| {
            ui.monospace("IPv4 Address:       ")
                | Self::show_option_field_default(
                    ui,
                    "bitname_data_ipv4",
                    Ipv4Addr::UNSPECIFIED,
                    &mut bitname_data.ipv4_addr,
                )
        });
        let ipv6_resp = ui.horizontal(|ui| {
            ui.monospace("IPv6 Address:       ")
                | Self::show_option_field_default(
                    ui,
                    "bitname_data_ipv6",
                    Ipv6Addr::UNSPECIFIED,
                    &mut bitname_data.ipv6_addr,
                )
        });
        let encryption_pubkey_resp = ui.horizontal(|ui| {
            let default_pubkey =
                EncryptionPubKey::from(<[u8; 32] as Default>::default());
            ui.monospace("Encryption PubKey:       ")
                | Self::show_option_field_default(
                    ui,
                    "bitname_data_encryption_pubkey",
                    default_pubkey,
                    &mut bitname_data.encryption_pubkey,
                )
        });
        let signing_pubkey_resp = ui.horizontal(|ui| {
            let default_pubkey =
                PublicKey::from_bytes(&<[u8; 32] as Default>::default())
                    .unwrap();
            ui.monospace("Signing PubKey:       ")
                | Self::show_option_field_default(
                    ui,
                    "bitname_data_signing_pubkey",
                    default_pubkey,
                    &mut bitname_data.signing_pubkey,
                )
        });
        bitwise_or_inner_resp(commitment_resp)
            | bitwise_or_inner_resp(ipv4_resp)
            | bitwise_or_inner_resp(ipv6_resp)
            | bitwise_or_inner_resp(encryption_pubkey_resp)
            | bitwise_or_inner_resp(signing_pubkey_resp)
    }

    pub fn show(
        &mut self,
        app: &mut App,
        ui: &mut egui::Ui,
        base_tx: &mut Transaction,
    ) -> anyhow::Result<()> {
        let tx_type_dropdown = ui.horizontal(|ui| {
            let combobox = egui::ComboBox::from_id_source("tx_type")
                .selected_text(format!("{}", self.tx_type))
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.tx_type,
                        TxType::Regular,
                        "regular",
                    ) | ui.selectable_value(
                        &mut self.tx_type,
                        TxType::BitNameRegistration {
                            plaintext_name: String::new(),
                            bitname_data: Box::default(),
                        },
                        "register bitname",
                    ) | ui.selectable_value(
                        &mut self.tx_type,
                        TxType::BitNameReservation {
                            plaintext_name: String::new(),
                        },
                        "reserve bitname",
                    )
                });
            bitwise_or_inner_resp_option(combobox) | ui.heading("Transaction")
        });
        let tx_data_ui = match &mut self.tx_type {
            TxType::Regular => None,
            TxType::BitNameRegistration {
                plaintext_name,
                bitname_data,
            } => {
                let plaintext_name_resp = ui.horizontal(|ui| {
                    ui.monospace("Plaintext Name:       ")
                        | ui.add(egui::TextEdit::singleline(plaintext_name))
                });
                let bitname_options_resp =
                    Self::show_bitname_options(ui, bitname_data.as_mut());
                let resp = bitwise_or_inner_resp(plaintext_name_resp)
                    | bitname_options_resp;
                Some(resp)
            }
            TxType::BitNameReservation { plaintext_name } => {
                let inner_resp = ui.horizontal(|ui| {
                    ui.monospace("Plaintext Name:       ")
                        | ui.add(egui::TextEdit::singleline(plaintext_name))
                });
                Some(bitwise_or_inner_resp(inner_resp))
            }
        };
        let tx_data_changed = tx_data_ui.is_some_and(|resp| resp.changed());
        // if base txid has changed, store the new txid
        let base_txid = base_tx.txid();
        let base_txid_changed = base_txid != self.base_txid;
        if base_txid_changed {
            self.base_txid = base_txid;
        }
        // (re)compute final tx if:
        // * the tx type, tx data, or base txid has changed
        // * final tx not yet set
        let refresh_final_tx = bitwise_or_inner_resp(tx_type_dropdown)
            .changed()
            || tx_data_changed
            || base_txid_changed
            || self.final_tx.is_none();
        if refresh_final_tx {
            self.final_tx = Some(self.set_tx_data(app, base_tx.clone()));
        }
        let final_tx = match &self.final_tx {
            None => panic!("impossible! final tx should have been set"),
            Some(Ok(final_tx)) => final_tx,
            Some(Err(wallet_err)) => {
                ui.monospace(format!("{wallet_err}"));
                return Ok(());
            }
        };
        let txid = &format!("{}", final_tx.txid())[0..8];
        ui.monospace(format!("txid: {txid}"));
        if self.value_in >= self.value_out {
            let fee = self.value_in - self.value_out;
            let fee = bitcoin::Amount::from_sat(fee);
            ui.monospace(format!("fee:  {fee}"));
            if ui.button("sign and send").clicked() {
                let () = app.sign_and_send(final_tx.clone())?;
                *base_tx = Transaction::default();
                self.final_tx = None;
            }
        } else {
            ui.label("Not Enough Value In");
        }
        Ok(())
    }
}
