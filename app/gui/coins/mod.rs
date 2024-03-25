use eframe::egui;
use strum::{EnumIter, IntoEnumIterator};

use crate::app::App;

mod my_bitnames;
mod transfer_receive;
mod tx_builder;
pub(super) mod tx_creator;
mod utxo_creator;
mod utxo_selector;

use my_bitnames::MyBitnames;
use transfer_receive::TransferReceive;
use tx_builder::TxBuilder;

#[derive(Default, EnumIter, Eq, PartialEq, strum::Display)]
enum Tab {
    #[default]
    #[strum(to_string = "Transfer & Receive")]
    TransferReceive,
    #[strum(to_string = "Transaction Builder")]
    TransactionBuilder,
    #[strum(to_string = "My BitNames")]
    MyBitnames,
}

pub struct Coins {
    my_bitnames: MyBitnames,
    tab: Tab,
    transfer_receive: TransferReceive,
    tx_builder: TxBuilder,
}

impl Coins {
    pub fn new(app: &App) -> Self {
        Self {
            my_bitnames: MyBitnames,
            tab: Tab::default(),
            transfer_receive: TransferReceive::new(app),
            tx_builder: TxBuilder::default(),
        }
    }

    pub fn show(
        &mut self,
        app: &mut App,
        ui: &mut egui::Ui,
    ) -> anyhow::Result<()> {
        egui::TopBottomPanel::top("coins_tabs").show(ui.ctx(), |ui| {
            ui.horizontal(|ui| {
                Tab::iter().for_each(|tab_variant| {
                    let tab_name = tab_variant.to_string();
                    ui.selectable_value(&mut self.tab, tab_variant, tab_name);
                })
            });
        });
        egui::CentralPanel::default().show(ui.ctx(), |ui| match self.tab {
            Tab::TransferReceive => {
                let () = self.transfer_receive.show(app, ui);
            }
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
