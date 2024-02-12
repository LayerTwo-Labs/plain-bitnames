use eframe::egui::{self, Color32};

use crate::app::App;

mod activity;
mod bitname_explorer;
mod coins;
mod deposit;
mod encrypt_message;
mod miner;
mod paymail;
mod seed;
mod util;

use activity::Activity;
use bitname_explorer::BitnameExplorer;
use coins::Coins;
use deposit::Deposit;
use encrypt_message::EncryptMessage;
use miner::Miner;
use paymail::Paymail;
use seed::SetSeed;

pub struct EguiApp {
    app: App,
    set_seed: SetSeed,
    miner: Miner,
    deposit: Deposit,
    tab: Tab,
    activity: Activity,
    coins: Coins,
    bitname_explorer: BitnameExplorer,
    paymail: Paymail,
    encrypt_message: EncryptMessage,
}

#[derive(Eq, PartialEq)]
enum Tab {
    Coins,
    BitnameExplorer,
    Paymail,
    EncryptMessage,
    Activity,
}

impl EguiApp {
    pub fn new(app: App, cc: &eframe::CreationContext<'_>) -> Self {
        // Customize egui here with cc.egui_ctx.set_fonts and cc.egui_ctx.set_visuals.
        // Restore app state using cc.storage (requires the "persistence" feature).
        // Use the cc.gl (a glow::Context) to create graphics shaders and buffers that you can use
        // for e.g. egui::PaintCallback.
        let mut style = (*cc.egui_ctx.style()).clone();
        // Palette found using https://coolors.co/005c80-a0a0a0-0d0630-c1ff9b-ce1483
        // Default blue, eg. selected buttons
        const _LAPIS_LAZULI: Color32 = Color32::from_rgb(0x0D, 0x5c, 0x80);
        // Default grey, eg. grid lines
        const _CADET_GREY: Color32 = Color32::from_rgb(0xa0, 0xa0, 0xa0);
        const _VIOLET: Color32 = Color32::from_rgb(0x0D, 0x06, 0x30);
        const LIGHT_GREEN: Color32 = Color32::from_rgb(0xc1, 0xff, 0x9b);
        const _RED_VIOLET: Color32 = Color32::from_rgb(0xce, 0x14, 0x83);
        // Accent color
        const ACCENT: Color32 = LIGHT_GREEN;
        // Grid color / accent color
        style.visuals.widgets.noninteractive.bg_stroke.color = ACCENT;

        cc.egui_ctx.set_style(style);

        let activity = Activity::new(&app);
        Self {
            app,
            set_seed: SetSeed::default(),
            miner: Miner,
            deposit: Deposit::default(),
            bitname_explorer: BitnameExplorer::default(),
            tab: Tab::Coins,
            activity,
            coins: Coins::default(),
            encrypt_message: EncryptMessage::new(),
            paymail: Paymail::default(),
        }
    }
}

impl eframe::App for EguiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.app.wallet.has_seed().unwrap_or(false) {
            egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.tab, Tab::Coins, "coins");
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::BitnameExplorer,
                        "lookup",
                    );
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::Paymail,
                        "my paymail",
                    );
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::EncryptMessage,
                        "messaging",
                    );
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::Activity,
                        "activity",
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
                Tab::Coins => {
                    let () = self.coins.show(&mut self.app, ui).unwrap();
                }
                Tab::BitnameExplorer => {
                    self.bitname_explorer.show(&mut self.app, ui);
                }
                Tab::Paymail => self.paymail.show(&mut self.app, ui).unwrap(),
                Tab::EncryptMessage => {
                    self.encrypt_message.show(&mut self.app, ui);
                }
                Tab::Activity => {
                    self.activity.show(&mut self.app, ui);
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
