use eframe::egui::{self};

use crate::{
    app::App,
    gui::util::{InnerResponseExt, UiExt},
};

#[derive(Debug, Default)]
pub struct BitNameExplorer;

impl BitNameExplorer {
    pub fn show(&mut self, app: &mut App, ui: &mut egui::Ui) {
        let bitnames = app.node.bitnames();
        egui::CentralPanel::default().show_inside(ui, |ui| match bitnames {
            Err(node_err) => {
                let resp =
                    ui.monospace_selectable_multiline(node_err.to_string());
                Some(resp)
            }
            Ok(bitnames) => bitnames
                .into_iter()
                .map(|(bitname_id, bitname_data)| {
                    {
                        ui.horizontal(|ui| {
                            ui.monospace_selectable_singleline(format!(
                                "BitName ID: {}",
                                hex::encode(bitname_id.0)
                            )) | crate::gui::bitname_explorer::show_bitname_data(
                                ui,
                                &bitname_data,
                            )
                        })
                    }
                    .join()
                })
                .reduce(|resp0, resp1| resp0 | resp1),
        });
    }
}
