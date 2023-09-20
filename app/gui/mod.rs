use eframe::egui::{self, Color32};

use crate::app::App;

mod bitname_explorer;
mod block_explorer;
mod deposit;
mod mempool_explorer;
mod miner;
mod my_bitnames;
mod seed;
mod tx_builder;
mod tx_creator;
mod util;
mod utxo_creator;
mod utxo_selector;

use bitname_explorer::BitnameExplorer;
use block_explorer::BlockExplorer;
use deposit::Deposit;
use mempool_explorer::MemPoolExplorer;
use miner::Miner;
use my_bitnames::MyBitnames;
use seed::SetSeed;
use tx_builder::TxBuilder;

pub struct EguiApp {
    app: App,
    set_seed: SetSeed,
    miner: Miner,
    deposit: Deposit,
    tab: Tab,
    tx_builder: TxBuilder,
    mempool_explorer: MemPoolExplorer,
    block_explorer: BlockExplorer,
    bitname_explorer: BitnameExplorer,
    my_bitnames: MyBitnames,
}

#[derive(Eq, PartialEq)]
enum Tab {
    TransactionBuilder,
    MemPoolExplorer,
    BlockExplorer,
    BitnameExplorer,
    MyBitnames,
}

impl EguiApp {
    pub fn new(app: App, cc: &eframe::CreationContext<'_>) -> Self {
        // Customize egui here with cc.egui_ctx.set_fonts and cc.egui_ctx.set_visuals.
        // Restore app state using cc.storage (requires the "persistence" feature).
        // Use the cc.gl (a glow::Context) to create graphics shaders and buffers that you can use
        // for e.g. egui::PaintCallback.
        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals.panel_fill = Color32::from_rgb(0, 0, 0x33);
        style.visuals.extreme_bg_color = Color32::from_gray(0x3c);
        style.visuals.widgets.noninteractive.bg_stroke.color = Color32::YELLOW;

        cc.egui_ctx.set_style(style);

        let height = app.node.get_height().unwrap_or(0);
        Self {
            app,
            set_seed: SetSeed::default(),
            miner: Miner,
            deposit: Deposit::default(),
            tx_builder: TxBuilder::default(),
            mempool_explorer: MemPoolExplorer::default(),
            block_explorer: BlockExplorer::new(height),
            bitname_explorer: BitnameExplorer::default(),
            tab: Tab::TransactionBuilder,
            my_bitnames: MyBitnames,
        }
    }
}

impl eframe::App for EguiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.app.wallet.has_seed().unwrap_or(false) {
            egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::TransactionBuilder,
                        "transaction builder",
                    );
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::MemPoolExplorer,
                        "mempool explorer",
                    );
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::BlockExplorer,
                        "block explorer",
                    );
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::BitnameExplorer,
                        "bitname explorer",
                    );
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::MyBitnames,
                        "my bitnames",
                    );
                });
            });
            egui::TopBottomPanel::bottom("util").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    self.miner.show(&mut self.app, ui);
                    ui.separator();
                    self.deposit.show(&mut self.app, ui);
                });
            });
            egui::CentralPanel::default().show(ctx, |ui| match self.tab {
                Tab::TransactionBuilder => {
                    let () = self.tx_builder.show(&mut self.app, ui).unwrap();
                }
                Tab::MemPoolExplorer => {
                    self.mempool_explorer.show(&mut self.app, ui);
                }
                Tab::BlockExplorer => {
                    self.block_explorer.show(&mut self.app, ui);
                }
                Tab::BitnameExplorer => {
                    self.bitname_explorer.show(&mut self.app, ui);
                }
                Tab::MyBitnames => {
                    self.my_bitnames.show(&mut self.app, ui);
                }
            });
        } else {
            egui::CentralPanel::default().show(ctx, |_ui| {
                egui::Window::new("Set Seed").show(ctx, |ui| {
                    self.set_seed.show(&self.app, ui);
                });
            });
        }
    }
}
