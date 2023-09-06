use eframe::egui::{self, InnerResponse, Response};

use plain_bitnames::{
    bip300301::bitcoin,
    types::{Transaction, Txid},
};

use crate::app::App;

#[derive(Clone, Debug, Default, PartialEq)]
pub enum TxType {
    #[default]
    Regular,
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
    final_tx: Option<Transaction>,
}

impl std::fmt::Display for TxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Regular => write!(f, "regular"),
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
    ) -> anyhow::Result<Transaction> {
        match &self.tx_type {
            TxType::Regular => Ok(tx),
            TxType::BitNameReservation { plaintext_name } => {
                let () = app.wallet.reserve_bitname(&mut tx, plaintext_name)?;
                Ok(tx)
            }
        }
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
            self.final_tx = Some(self.set_tx_data(app, base_tx.clone())?);
        }
        let final_tx = self
            .final_tx
            .as_ref()
            .expect("impossible! final tx should have been set");
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
