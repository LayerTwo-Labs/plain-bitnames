use eframe::egui;
use itertools::{Either, Itertools};

use plain_bitnames::types::FilledOutput;

use crate::app::App;

#[derive(Debug, Default)]
pub struct MyBitnames;

impl MyBitnames {
    pub fn show(&mut self, app: &mut App, ui: &mut egui::Ui) {
        // all bitname reservations
        let bitname_reservations = app
            .utxos
            .values()
            .filter_map(FilledOutput::reservation_data);
        // split into bitnames for which the names are known or unknown
        let (
            mut known_name_bitname_reservations,
            mut unknown_name_bitname_reservations,
        ): (Vec<_>, Vec<_>) =
            bitname_reservations.partition_map(|(txid, commitment)| {
                let plain_bitname = app
                    .wallet
                    .get_bitname_reservation_plaintext(commitment)
                    .expect("failed to retrieve bitname reservation data");
                match plain_bitname {
                    Some(plain_bitname) => {
                        Either::Left((*txid, *commitment, plain_bitname))
                    }
                    None => Either::Right((*txid, *commitment)),
                }
            });
        // sort name-known bitname reservations by plain name
        known_name_bitname_reservations.sort_by(
            |(_, _, plain_name_l), (_, _, plain_name_r)| {
                plain_name_l.cmp(plain_name_r)
            },
        );
        // sort name-unknown bitname reservations by txid
        unknown_name_bitname_reservations.sort_by_key(|(txid, _)| *txid);
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
                            for (txid, commitment, plaintext_name) in
                                known_name_bitname_reservations
                            {
                                let txid = hex::encode(txid.0);
                                let commitment = hex::encode(commitment);
                                ui.monospace(format!(
                                    "plaintext name: {plaintext_name}"
                                ));
                                ui.monospace(format!("txid: {txid}"));
                                ui.monospace(format!(
                                    "commitment: {commitment}"
                                ));
                                ui.end_row()
                            }
                            for (txid, commitment) in
                                unknown_name_bitname_reservations
                            {
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
