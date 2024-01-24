use eframe::egui;

use crate::app::App;

mod bitname_explorer;
mod block_explorer;
mod mempool_explorer;

use bitname_explorer::BitNameExplorer;
use block_explorer::BlockExplorer;
use mempool_explorer::MemPoolExplorer;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Default, Eq, PartialEq)]
enum Tab {
    BitNameExplorer,
    #[default]
    BlockExplorer,
    MemPoolExplorer,
}

pub struct Activity {
    tab: Tab,
    bitname_explorer: BitNameExplorer,
    block_explorer: BlockExplorer,
    mempool_explorer: MemPoolExplorer,
}

impl Activity {
    pub fn new(app: &App) -> Self {
        let height = app.node.get_height().unwrap_or(0);
        Self {
            tab: Default::default(),
            bitname_explorer: BitNameExplorer,
            block_explorer: BlockExplorer::new(height),
            mempool_explorer: Default::default(),
        }
    }

    pub fn show(&mut self, app: &mut App, ui: &mut egui::Ui) {
        egui::TopBottomPanel::top("coins_tabs").show(ui.ctx(), |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(
                    &mut self.tab,
                    Tab::BlockExplorer,
                    "block explorer",
                );
                ui.selectable_value(
                    &mut self.tab,
                    Tab::MemPoolExplorer,
                    "mempool explorer",
                );
                ui.selectable_value(
                    &mut self.tab,
                    Tab::BitNameExplorer,
                    "bitname explorer",
                );
            });
        });
        egui::CentralPanel::default().show(ui.ctx(), |ui| match self.tab {
            Tab::BitNameExplorer => {
                self.bitname_explorer.show(app, ui);
            }
            Tab::BlockExplorer => {
                self.block_explorer.show(app, ui);
            }
            Tab::MemPoolExplorer => {
                self.mempool_explorer.show(app, ui);
            }
        });
    }
}
