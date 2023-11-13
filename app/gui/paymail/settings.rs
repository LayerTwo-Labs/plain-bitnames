use std::collections::HashSet;

use eframe::egui;
use hex::FromHex;
use plain_bitnames::types::Hash;

#[derive(Debug, Default)]
struct BitnameInboxesState {
    add_bitname_buffer: String,
    err_msg: Option<String>,
}

#[derive(Debug, Default, Eq, PartialEq)]
enum Tab {
    #[default]
    BitnameInboxes,
}

#[derive(Debug, Default)]
pub struct Settings {
    pub bitname_inboxes: HashSet<Hash>,
    bitname_inboxes_state: BitnameInboxesState,
    tab: Tab,
}

impl Settings {
    fn show_bitname_inboxes(&mut self, ui: &mut egui::Ui) {
        let state = &mut self.bitname_inboxes_state;
        ui.heading("Bitname Inboxes");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut state.add_bitname_buffer);
            if ui.button("Add Bitname Inbox").clicked() {
                match Hash::from_hex(&state.add_bitname_buffer) {
                    Ok(bitname) => {
                        self.bitname_inboxes.insert(bitname);
                        state.err_msg = None;
                        state.add_bitname_buffer.clear();
                    }
                    Err(err) => {
                        state.err_msg = Some(err.to_string());
                    }
                }
            };
        });
        if let Some(err_msg) = &state.err_msg {
            ui.monospace(format!("Error decoding bitname: {err_msg}"));
        }
        egui::Grid::new("bitname inboxes").show(ui, |ui| {
            self.bitname_inboxes.retain(|bitname| {
                ui.monospace(hex::encode(bitname));
                let button = ui.button("Remove");
                ui.end_row();
                !button.clicked()
            })
        });
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {
        egui::SidePanel::left("Inbox")
            //.exact_width(250.)
            .show_inside(ui, |ui| {
                ui.vertical(|ui| {
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::BitnameInboxes,
                        "Bitname Inboxes",
                    );
                });
            });
        egui::CentralPanel::default().show(ui.ctx(), |ui| match self.tab {
            Tab::BitnameInboxes => {
                self.show_bitname_inboxes(ui);
            }
        });
    }
}
