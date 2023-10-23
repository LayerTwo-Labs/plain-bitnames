use eframe::egui;

use plain_bitnames::{
    bip300301::bitcoin,
    types::{self, Output, OutputContent, Transaction},
};

use crate::{app::App, gui::util::InnerResponseExt};

#[derive(Debug, Eq, PartialEq)]
enum UtxoType {
    Regular,
    Withdrawal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoEncoding {
    Base16,
    Plaintext,
}

// optional warning when decoding
type MemoEncoded = (Vec<u8>, Option<String>);

#[derive(Debug)]
pub struct UtxoCreator {
    utxo_type: UtxoType,
    value: String,
    address: String,
    main_address: String,
    main_fee: String,
    // None corresponds to no memo
    memo_encoding: Option<MemoEncoding>,
    // None corresponds to no memo
    memo_user_input: Option<String>,
    // None corresponds to no memo
    memo_encoded: Option<Result<MemoEncoded, hex::FromHexError>>,
}

impl std::fmt::Display for UtxoType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Regular => write!(f, "regular"),
            Self::Withdrawal => write!(f, "withdrawal"),
        }
    }
}

impl std::fmt::Display for MemoEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoEncoding::Base16 => write!(f, "hex"),
            MemoEncoding::Plaintext => write!(f, "plaintext"),
        }
    }
}

impl Default for UtxoCreator {
    fn default() -> Self {
        Self {
            value: "".into(),
            address: "".into(),
            main_address: "".into(),
            main_fee: "".into(),
            utxo_type: UtxoType::Regular,
            memo_encoding: None,
            memo_user_input: None,
            memo_encoded: None,
        }
    }
}

impl UtxoCreator {
    fn try_encode_memo(
        memo_encoding: MemoEncoding,
        memo_user_input: &str,
    ) -> Result<MemoEncoded, hex::FromHexError> {
        // try to decode as hex
        let decoded_hex = hex::decode(memo_user_input);
        if memo_user_input.is_empty() {
            return Ok((Vec::new(), None));
        }
        match (memo_encoding, decoded_hex) {
            (MemoEncoding::Base16, Ok(hex)) => Ok((hex, None)),
            (MemoEncoding::Base16, Err(err)) => Err(err),
            (MemoEncoding::Plaintext, Ok(hex)) => {
                let warning = "This looks like hex data. Are you sure that you want to decode it as ASCII?";
                Ok((hex, Some(warning.to_owned())))
            }
            (MemoEncoding::Plaintext, Err(_)) => {
                Ok((memo_user_input.as_bytes().to_owned(), None))
            }
        }
    }

    pub fn show(
        &mut self,
        app: &mut App,
        ui: &mut egui::Ui,
        tx: &mut Transaction,
    ) {
        ui.horizontal(|ui| {
            ui.heading("Create");
            egui::ComboBox::from_id_source("utxo_type")
                .selected_text(format!("{}", self.utxo_type))
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.utxo_type,
                        UtxoType::Regular,
                        "regular",
                    );
                    ui.selectable_value(
                        &mut self.utxo_type,
                        UtxoType::Withdrawal,
                        "withdrawal",
                    );
                });
            ui.heading("UTXO");
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.monospace("Value:       ");
            ui.add(egui::TextEdit::singleline(&mut self.value));
            ui.monospace("BTC");
        });
        ui.horizontal(|ui| {
            ui.monospace("Address:     ");
            ui.add(egui::TextEdit::singleline(&mut self.address));
            if ui.button("generate").clicked() {
                self.address = app
                    .wallet
                    .get_new_address()
                    .map(|address| format!("{address}"))
                    .unwrap_or("".into());
            }
        });
        let memo_encoding_changed = ui
            .horizontal(|ui| {
                ui.monospace("Memo:     ");
                egui::ComboBox::from_id_source("memo_encoding")
                    .selected_text(match self.memo_encoding {
                        Some(MemoEncoding::Base16) => "hex",
                        Some(MemoEncoding::Plaintext) => "plaintext",
                        None => "no memo",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.memo_encoding,
                            Some(MemoEncoding::Base16),
                            "hex",
                        ) | ui.selectable_value(
                            &mut self.memo_encoding,
                            Some(MemoEncoding::Plaintext),
                            "plaintext",
                        ) | ui.selectable_value(
                            &mut self.memo_encoding,
                            None,
                            "no_memo",
                        )
                    })
                    .join()
            })
            .join()
            .changed();
        // (un)initialize memo
        if memo_encoding_changed {
            match self.memo_encoding {
                None => self.memo_user_input = None,
                Some(_) if self.memo_user_input.is_none() => {
                    self.memo_user_input = Some(String::new())
                }
                Some(_) => (),
            };
            self.memo_encoded = None;
        }
        if let Some(memo_user_input) = self.memo_user_input.as_mut() {
            let memo_user_input_changed = ui
                .horizontal(|ui| {
                    ui.add(egui::TextEdit::multiline(memo_user_input))
                })
                .join()
                .changed();
            if memo_encoding_changed || memo_user_input_changed {
                let memo_encoding = self
                    .memo_encoding
                    .as_ref()
                    .expect("impossible: memo encoding should be set");
                self.memo_encoded = Some(Self::try_encode_memo(
                    *memo_encoding,
                    memo_user_input,
                ));
            }
        }
        match &self.memo_encoded {
            Some(Err(err)) => {
                ui.horizontal(|ui| ui.monospace(format!("Error: {err}")));
            }
            Some(Ok((_, Some(warning)))) => {
                ui.horizontal(|ui| ui.monospace(format!("Warning: {warning}")));
            }
            _ => (),
        };
        if self.utxo_type == UtxoType::Withdrawal {
            ui.horizontal(|ui| {
                ui.monospace("Main Address:");
                ui.add(egui::TextEdit::singleline(&mut self.main_address));
                if ui.button("generate").clicked() {
                    let main_address = app.get_new_main_address().unwrap();
                    self.main_address = format!("{main_address}");
                }
            });
            ui.horizontal(|ui| {
                ui.monospace("Main Fee:    ");
                ui.add(egui::TextEdit::singleline(&mut self.main_fee));
                ui.monospace("BTC");
            });
        }
        ui.horizontal(|ui| {
            match self.utxo_type {
                UtxoType::Regular => {
                    let address: Option<types::Address> =
                        self.address.parse().ok();
                    let value: Option<bitcoin::Amount> =
                        bitcoin::Amount::from_str_in(
                            &self.value,
                            bitcoin::Denomination::Bitcoin,
                        )
                        .ok();
                    if ui
                        .add_enabled(
                            address.is_some() && value.is_some(),
                            egui::Button::new("create"),
                        )
                        .clicked()
                    {
                        let memo = self
                            .memo_encoded
                            .clone()
                            .map(|memo_encoded| {
                                memo_encoded
                                    .expect("decoding error displayed elswhere")
                                    .0
                            })
                            .unwrap_or_default();
                        let utxo = Output {
                            address: address.expect("should not happen"),
                            content: OutputContent::Value(
                                value.expect("should not happen").to_sat(),
                            ),
                            memo,
                        };
                        tx.outputs.push(utxo);
                    }
                }
                UtxoType::Withdrawal => {
                    let value: Option<bitcoin::Amount> =
                        bitcoin::Amount::from_str_in(
                            &self.value,
                            bitcoin::Denomination::Bitcoin,
                        )
                        .ok();
                    let address: Option<types::Address> =
                        self.address.parse().ok();
                    let main_address: Option<
                        bitcoin::Address<bitcoin::address::NetworkUnchecked>,
                    > = self.main_address.parse().ok();
                    let main_fee: Option<bitcoin::Amount> =
                        bitcoin::Amount::from_str_in(
                            &self.main_fee,
                            bitcoin::Denomination::Bitcoin,
                        )
                        .ok();
                    if ui
                        .add_enabled(
                            value.is_some()
                                && address.is_some()
                                && main_address.is_some()
                                && main_fee.is_some(),
                            egui::Button::new("create"),
                        )
                        .clicked()
                    {
                        let utxo = Output {
                            address: address.expect("invalid address"),
                            content: OutputContent::Withdrawal {
                                value: value.expect("invalid value").to_sat(),
                                main_address: main_address
                                    .expect("invalid main_address"),
                                main_fee: main_fee
                                    .expect("invalid main_fee")
                                    .to_sat(),
                            },
                            memo: Vec::new(),
                        };
                        tx.outputs.push(utxo);
                    }
                }
            }
            let num_addresses = app.wallet.get_num_addresses().unwrap();
            ui.label(format!("{num_addresses} addresses generated"));
        });
    }
}
