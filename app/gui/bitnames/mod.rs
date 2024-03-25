use eframe::egui;
use strum::{EnumIter, IntoEnumIterator};

use crate::app::App;

mod all_bitnames;
mod reserve_register;

use all_bitnames::AllBitNames;
use reserve_register::ReserveRegister;

#[derive(Default, EnumIter, Eq, PartialEq, strum::Display)]
enum Tab {
    #[default]
    #[strum(to_string = "All BitNames")]
    AllBitNames,
    #[strum(to_string = "Reserve & Register")]
    ReserveRegister,
}

#[derive(Default)]
pub struct BitNames {
    all_bitnames: AllBitNames,
    reserve_register: ReserveRegister,
    tab: Tab,
}

impl BitNames {
    pub fn show(&mut self, app: &mut App, ui: &mut egui::Ui) {
        egui::TopBottomPanel::top("bitnames_tabs").show(ui.ctx(), |ui| {
            ui.horizontal(|ui| {
                Tab::iter().for_each(|tab_variant| {
                    let tab_name = tab_variant.to_string();
                    ui.selectable_value(&mut self.tab, tab_variant, tab_name);
                })
            });
        });
        egui::CentralPanel::default().show(ui.ctx(), |ui| match self.tab {
            Tab::AllBitNames => {
                let () = self.all_bitnames.show(app, ui);
            }
            Tab::ReserveRegister => {
                let () = self.reserve_register.show(app, ui);
            }
        });
    }
}
