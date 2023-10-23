use eframe::egui;

use crate::app::App;

mod block_explorer;
mod mempool_explorer;

use block_explorer::BlockExplorer;
use mempool_explorer::MemPoolExplorer;

#[derive(Debug, Default, Eq, PartialEq)]
enum Tab {
    #[default]
    BlockExplorer,
    MemPoolExplorer,
}

pub struct Activity {
    tab: Tab,
    block_explorer: BlockExplorer,
    mempool_explorer: MemPoolExplorer,
}

impl Activity {
    pub fn new(app: &App) -> Self {
        let height = app.node.get_height().unwrap_or(0);
        Self {
            tab: Default::default(),
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
            });
        });
        egui::CentralPanel::default().show(ui.ctx(), |ui| match self.tab {
            Tab::BlockExplorer => {
                self.block_explorer.show(app, ui);
            }
            Tab::MemPoolExplorer => {
                self.mempool_explorer.show(app, ui);
            }
        });
    }
}
