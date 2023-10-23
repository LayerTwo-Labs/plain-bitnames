use eframe::egui;

use crate::app::App;

mod my_bitnames;
mod tx_builder;
mod tx_creator;
mod utxo_creator;
mod utxo_selector;

use my_bitnames::MyBitnames;
use tx_builder::TxBuilder;

#[derive(Debug, Default, Eq, PartialEq)]
enum Tab {
    #[default]
    TransactionBuilder,
    MyBitnames,
}

#[derive(Default)]
pub struct Coins {
    tab: Tab,
    tx_builder: TxBuilder,
    my_bitnames: MyBitnames,
}

impl Coins {
    pub fn show(
        &mut self,
        app: &mut App,
        ui: &mut egui::Ui,
    ) -> anyhow::Result<()> {
        egui::TopBottomPanel::top("coins_tabs").show(ui.ctx(), |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(
                    &mut self.tab,
                    Tab::TransactionBuilder,
                    "transaction builder",
                );
                ui.selectable_value(
                    &mut self.tab,
                    Tab::MyBitnames,
                    "my bitnames",
                );
            });
        });
        egui::CentralPanel::default().show(ui.ctx(), |ui| match self.tab {
            Tab::TransactionBuilder => {
                let () = self.tx_builder.show(app, ui).unwrap();
            }
            Tab::MyBitnames => {
                self.my_bitnames.show(app, ui);
            }
        });
        Ok(())
    }
}
