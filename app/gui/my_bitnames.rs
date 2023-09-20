use eframe::egui;

use plain_bitnames::types::FilledOutput;

use crate::app::App;

#[derive(Debug, Default)]
pub struct MyBitnames;

impl MyBitnames {
    pub fn show(&mut self, app: &mut App, ui: &mut egui::Ui) {
        let mut bitname_reservations: Vec<_> = app
            .utxos
            .values()
            .filter_map(FilledOutput::reservation_data)
            .collect();
        bitname_reservations.sort_by_key(|(txid, _)| *txid);
        let mut bitnames: Vec<_> = app
            .utxos
            .values()
            .filter_map(FilledOutput::bitname)
            .collect();
        bitnames.sort();
        let _reservations_response =
            egui::SidePanel::left("My BitName Reservations")
                .exact_width(250.)
                .resizable(false)
                .show_inside(ui, |ui| {
                    ui.heading("BitName Reservations");
                    egui::Grid::new("My BitName Reservations")
                        .striped(true)
                        .show(ui, |ui| {
                            for (txid, commitment) in bitname_reservations {
                                let txid = hex::encode(txid.0);
                                let commitment = hex::encode(commitment);
                                ui.monospace(format!("txid: {txid}"));
                                ui.monospace(format!(
                                    "commitment: {commitment}"
                                ));
                                ui.end_row()
                            }
                        });
                });
        let _bitnames_response = egui::SidePanel::left("My BitNames")
            .exact_width(250.)
            .resizable(false)
            .show_inside(ui, |ui| {
                ui.heading("BitNames");
                egui::Grid::new("My BitNames").striped(true).show(ui, |ui| {
                    for bitname in bitnames {
                        ui.monospace(hex::encode(bitname));
                        ui.end_row()
                    }
                });
            });
    }
}
