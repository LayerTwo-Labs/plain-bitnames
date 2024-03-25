use std::borrow::Cow;

use bip300301::bitcoin;
use eframe::egui;
use plain_bitnames::types::BitNameData;

use crate::{
    app::App,
    gui::{coins::tx_creator, util::UiExt},
};

fn reserve_bitname(
    app: &App,
    plaintext_name: &str,
    fee: bitcoin::Amount,
) -> anyhow::Result<()> {
    let mut tx = app.wallet.create_regular_transaction(fee.to_sat())?;
    let () = app.wallet.reserve_bitname(&mut tx, plaintext_name)?;
    app.sign_and_send(tx).map_err(anyhow::Error::from)
}

fn register_bitname(
    app: &App,
    plaintext_name: &str,
    bitname_data: Cow<BitNameData>,
    fee: bitcoin::Amount,
) -> anyhow::Result<()> {
    let mut tx = app.wallet.create_regular_transaction(fee.to_sat())?;
    let () =
        app.wallet
            .register_bitname(&mut tx, plaintext_name, bitname_data)?;
    app.sign_and_send(tx).map_err(anyhow::Error::from)
}

#[derive(Debug, Default)]
struct Reserve {
    plaintext_name: String,
    fee: String,
}

impl Reserve {
    pub fn show(&mut self, app: &App, ui: &mut egui::Ui) {
        ui.add_sized((250., 10.), |ui: &mut egui::Ui| {
            ui.horizontal(|ui| {
                let plaintext_name_edit =
                    egui::TextEdit::singleline(&mut self.plaintext_name)
                        .hint_text("Plaintext Name")
                        .desired_width(150.);
                ui.add(plaintext_name_edit);
            })
            .response
        });
        ui.add_sized((110., 10.), |ui: &mut egui::Ui| {
            ui.horizontal(|ui| {
                let fee_edit = egui::TextEdit::singleline(&mut self.fee)
                    .hint_text("fee")
                    .desired_width(80.);
                ui.add(fee_edit);
                ui.label("BTC");
            })
            .response
        });
        let fee = bitcoin::Amount::from_str_in(
            &self.fee,
            bitcoin::Denomination::Bitcoin,
        );
        if ui
            .add_enabled(
                !self.plaintext_name.is_empty() && fee.is_ok(),
                egui::Button::new("Reserve"),
            )
            .clicked()
        {
            if let Err(err) = reserve_bitname(
                app,
                &self.plaintext_name,
                fee.expect("should not happen"),
            ) {
                tracing::error!("{err:#}");
            } else {
                *self = Self::default();
            }
        }
    }
}

#[derive(Debug, Default)]
struct Register {
    plaintext_name: String,
    fee: String,
    bitname_data: tx_creator::TrySetBitNameData,
}

impl Register {
    pub fn show(&mut self, app: &App, ui: &mut egui::Ui) {
        ui.add_sized((250., 10.), |ui: &mut egui::Ui| {
            ui.horizontal(|ui| {
                let plaintext_name_edit =
                    egui::TextEdit::singleline(&mut self.plaintext_name)
                        .hint_text("Plaintext Name")
                        .desired_width(150.);
                ui.add(plaintext_name_edit);
            })
            .response
        });
        ui.add_sized((110., 10.), |ui: &mut egui::Ui| {
            ui.horizontal(|ui| {
                let fee_edit = egui::TextEdit::singleline(&mut self.fee)
                    .hint_text("fee")
                    .desired_width(80.);
                ui.add(fee_edit);
                ui.label("BTC");
            })
            .response
        });
        let fee = bitcoin::Amount::from_str_in(
            &self.fee,
            bitcoin::Denomination::Bitcoin,
        );
        tx_creator::TxCreator::show_bitname_options(ui, &mut self.bitname_data);
        let bitname_data: Result<BitNameData, _> =
            self.bitname_data.clone().try_into();
        if let Err(err) = &bitname_data {
            ui.monospace_selectable_multiline(err.clone());
        }
        if ui
            .add_enabled(
                !self.plaintext_name.is_empty()
                    && fee.is_ok()
                    && bitname_data.is_ok(),
                egui::Button::new("Register"),
            )
            .clicked()
        {
            if let Err(err) = register_bitname(
                app,
                &self.plaintext_name,
                Cow::Borrowed(&bitname_data.expect("should not happen")),
                fee.expect("should not happen"),
            ) {
                tracing::error!("{err:#}");
            } else {
                *self = Self::default();
            }
        }
    }
}

#[derive(Default)]
pub(super) struct ReserveRegister {
    reserve: Reserve,
    register: Register,
}

impl ReserveRegister {
    pub fn show(&mut self, app: &App, ui: &mut egui::Ui) {
        egui::SidePanel::left("reserve")
            .exact_width(ui.available_width() / 2.)
            .resizable(false)
            .show_inside(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading("Reserve");
                    self.reserve.show(app, ui);
                })
            });
        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("Register");
                self.register.show(app, ui);
            })
        });
    }
}
