use eframe::egui;
use itertools::{Either, Itertools};

use plain_bitnames::types::{BitName, FilledOutput, Hash, Txid};

use crate::{app::App, gui::util::UiExt};

type KnownNameReservation = (Txid, Hash, String);
type UnknownNameReservation = (Txid, Hash);

#[derive(Debug, Default)]
pub struct MyBitnames;

impl MyBitnames {
    /// Returns BitName reservations with known and unknown names
    fn get_bitname_reservations(
        app: &App,
    ) -> (Vec<KnownNameReservation>, Vec<UnknownNameReservation>) {
        let utxos_read = app.utxos.read();
        // all bitname reservations
        let bitname_reservations = utxos_read
            .values()
            .filter_map(FilledOutput::reservation_data);
        // split into bitname reservations for which the names are known,
        // or unknown
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
        (
            known_name_bitname_reservations,
            unknown_name_bitname_reservations,
        )
    }

    pub fn show_reservations(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        let (
            known_name_bitname_reservations,
            unknown_name_bitname_reservations,
        ) = app.map(Self::get_bitname_reservations).unwrap_or_default();
        let _response = egui::SidePanel::left("My BitName Reservations")
            .exact_width(350.)
            .resizable(false)
            .show_inside(ui, move |ui| {
                ui.heading("BitName Reservations");
                egui::Grid::new("My BitName Reservations")
                    .num_columns(1)
                    .striped(true)
                    .show(ui, |ui| {
                        for (txid, commitment, plaintext_name) in
                            known_name_bitname_reservations
                        {
                            let txid = hex::encode(txid.0);
                            let commitment = hex::encode(commitment);
                            ui.vertical(|ui| {
                                ui.monospace_selectable_singleline(
                                    true,
                                    format!("plaintext name: {plaintext_name}"),
                                );
                                ui.monospace_selectable_singleline(
                                    true,
                                    format!("txid: {txid}"),
                                );
                                ui.monospace_selectable_singleline(
                                    true,
                                    format!("commitment: {commitment}"),
                                );
                            });
                            ui.end_row()
                        }
                        for (txid, commitment) in
                            unknown_name_bitname_reservations
                        {
                            let txid = hex::encode(txid.0);
                            let commitment = hex::encode(commitment);
                            ui.vertical(|ui| {
                                ui.monospace_selectable_singleline(
                                    true,
                                    format!("txid: {txid}"),
                                );
                                ui.monospace_selectable_singleline(
                                    true,
                                    format!("commitment: {commitment}"),
                                );
                            });
                            ui.end_row()
                        }
                    });
            });
    }

    /// Returns BitNames with known and unknown names
    fn get_bitnames(app: &App) -> (Vec<(BitName, String)>, Vec<BitName>) {
        let utxos_read = app.utxos.read();
        // all owned bitnames
        let bitnames = utxos_read.values().filter_map(FilledOutput::bitname);
        // split into bitnames for which the names are known or unknown
        let (mut known_name_bitnames, mut unknown_name_bitnames): (
            Vec<_>,
            Vec<_>,
        ) = bitnames.partition_map(|bitname| {
            let plain_bitname = app
                .wallet
                .get_bitname_plaintext(bitname)
                .expect("failed to retrieve bitname data");
            match plain_bitname {
                Some(plain_bitname) => Either::Left((*bitname, plain_bitname)),
                None => Either::Right(*bitname),
            }
        });
        // sort name-known bitnames by plain name
        known_name_bitnames.sort_by(|(_, plain_name_l), (_, plain_name_r)| {
            plain_name_l.cmp(plain_name_r)
        });
        // sort name-unknown bitnames by bitname value
        unknown_name_bitnames.sort();
        (known_name_bitnames, unknown_name_bitnames)
    }

    pub fn show_bitnames(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        let (known_name_bitnames, unknown_name_bitnames) =
            app.map(Self::get_bitnames).unwrap_or_default();
        egui::SidePanel::left("My BitNames")
            .exact_width(350.)
            .resizable(false)
            .show_inside(ui, |ui| {
                ui.heading("BitNames");
                egui::Grid::new("My BitNames")
                    .striped(true)
                    .num_columns(1)
                    .show(ui, |ui| {
                        for (bitname, plaintext_name) in known_name_bitnames {
                            ui.vertical(|ui| {
                                ui.monospace_selectable_singleline(
                                    true,
                                    format!("plaintext name: {plaintext_name}"),
                                );
                                ui.monospace_selectable_singleline(
                                    true,
                                    format!(
                                        "bitname: {}",
                                        hex::encode(bitname.0)
                                    ),
                                );
                            });
                            ui.end_row()
                        }
                        for bitname in unknown_name_bitnames {
                            ui.monospace_selectable_singleline(
                                true,
                                format!("bitname: {}", hex::encode(bitname.0)),
                            );
                            ui.end_row()
                        }
                    });
            });
    }

    pub fn show(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        let _reservations_response = self.show_reservations(app, ui);
        let _bitnames_response = self.show_bitnames(app, ui);
    }
}
