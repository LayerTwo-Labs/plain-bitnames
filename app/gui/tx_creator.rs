

use eframe::egui;

use plain_bitnames::bip300301::bitcoin;

use crate::app::App;

#[derive(Debug, Default, PartialEq)]
pub enum TxType {
    #[default]
    Regular,
    BitNameReservation { plaintext_name: String }
}

#[derive(Debug, Default)]
pub struct TxCreator {
    pub value_in: u64,
    pub value_out: u64,
    pub tx_type: TxType,
}

impl std::fmt::Display for TxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Regular => write!(f, "regular"),
            Self::BitNameReservation { .. }=> write!(f, "reserve bitname"),
        }
    }
}

impl TxCreator {
    // set tx data for the current transaction
    fn set_tx_data(&self, app: &mut App) -> anyhow::Result<()> {
        match &self.tx_type {
            TxType::Regular => {
                let () = app.wallet.regularize(&mut app.transaction);
            },
            TxType::BitNameReservation { plaintext_name } => {
                let () = app.wallet.reserve_bitname(&mut app.transaction, &plaintext_name)?;
            }
        }
        Ok(())
    }

    pub fn show(&mut self, app: &mut App, ui: &mut egui::Ui) -> anyhow::Result<()> {
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_source("tx_type")
                .selected_text(format!("{}", self.tx_type))
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.tx_type,
                        TxType::Regular,
                        "regular",
                    );
                    ui.selectable_value(
                        &mut self.tx_type,
                        TxType::BitNameReservation { plaintext_name: String::new() },
                        "reserve bitname",
                    );
                });
            ui.heading("Transaction");
        });
        match &mut self.tx_type {
            TxType::Regular => (),
            TxType::BitNameReservation { plaintext_name } => {
                ui.horizontal(|ui| {
                    ui.monospace("Plaintext Name:       ");
                    ui.add(egui::TextEdit::singleline(plaintext_name));
                });
            }
        }
        let () = self.set_tx_data(app)?;
        let txid =
            &format!("{}", app.transaction.txid())
                [0..8];
        ui.monospace(format!("txid: {txid}"));
        if self.value_in >= self.value_out {
            let fee = self.value_in - self.value_out;
            let fee = bitcoin::Amount::from_sat(fee);
            ui.monospace(format!("fee:  {fee}"));
            if ui.button("sign and send").clicked() {
                app.sign_and_send().unwrap_or(());
            }
        } else {
            ui.label("Not Enough Value In");
        }
        Ok(())
    }
}