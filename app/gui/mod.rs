use std::{net::SocketAddr, task::Poll};

use eframe::egui::{self, Color32, RichText};
use plain_bitnames::{util::Watchable, wallet::Wallet};
use strum::{EnumIter, IntoEnumIterator};

use crate::{app::App, line_buffer::LineBuffer, util::PromiseStream};

mod activity;
mod bitnames;
mod coins;
mod console_logs;
mod encrypt_message;
mod fonts;
mod miner;
mod parent_chain;
mod paymail;
mod seed;
mod util;

use activity::Activity;
use bitnames::BitNames;
use coins::Coins;
use console_logs::ConsoleLogs;
use encrypt_message::EncryptMessage;
use fonts::FONT_DEFINITIONS;
use miner::Miner;
use parent_chain::ParentChain;
use paymail::Paymail;
use seed::SetSeed;
use util::{show_btc_amount_from_sats, UiExt, BITCOIN_LOGO_FA, BITCOIN_ORANGE};

struct BottomPanel {
    wallet_updated: PromiseStream<<Wallet as Watchable<()>>::WatchStream>,
    /// None if uninitialized
    /// Some(None) if failed to initialize
    balance_sats: Option<Option<u64>>,
}

impl BottomPanel {
    /// MUST be run from within a tokio runtime
    fn new(wallet: &Wallet) -> Self {
        let wallet_updated = PromiseStream::from(wallet.watch());
        Self {
            wallet_updated,
            balance_sats: None,
        }
    }

    /// Updates values
    fn update(&mut self, app: &App) {
        self.balance_sats = match app.wallet.get_balance() {
            Ok(balance) => Some(Some(balance)),
            Err(err) => {
                let err = anyhow::Error::from(err);
                tracing::error!("Failed to update balance: {err:#}");
                Some(None)
            }
        }
    }

    fn show_balance(&self, ui: &mut egui::Ui) {
        match self.balance_sats {
            Some(Some(balance_sats)) => {
                ui.monospace(
                    RichText::new(BITCOIN_LOGO_FA.to_string())
                        .color(BITCOIN_ORANGE),
                );
                ui.monospace_selectable_singleline(
                    false,
                    format!(
                        "Balance: {}",
                        show_btc_amount_from_sats(balance_sats)
                    ),
                );
            }
            Some(None) => {
                ui.monospace_selectable_singleline(
                    false,
                    "Balance error, check logs",
                );
            }
            None => {
                ui.monospace_selectable_singleline(false, "Loading balance");
            }
        }
    }

    fn show(&mut self, app: &App, miner: &mut Miner, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let rt_guard = app.runtime.enter();
            match self.wallet_updated.poll_next() {
                Some(Poll::Ready(())) => {
                    self.update(app);
                }
                Some(Poll::Pending) | None => (),
            }
            drop(rt_guard);
            self.show_balance(ui);
            // Fill center space,
            // see https://github.com/emilk/egui/discussions/3908#discussioncomment-8270353

            // this frame target width
            // == this frame initial max rect width - last frame others width
            let id_cal_target_size = egui::Id::new("cal_target_size");
            let this_init_max_width = ui.max_rect().width();
            let last_others_width = ui.data(|data| {
                data.get_temp(id_cal_target_size)
                    .unwrap_or(this_init_max_width)
            });
            // this is the total available space for expandable widgets, you can divide
            // it up if you have multiple widgets to expand, even with different ratios.
            let this_target_width = this_init_max_width - last_others_width;

            ui.add_space(this_target_width);
            ui.separator();
            miner.show(app, ui);
            // this frame others width
            // == this frame final min rect width - this frame target width
            ui.data_mut(|data| {
                data.insert_temp(
                    id_cal_target_size,
                    ui.min_rect().width() - this_target_width,
                )
            });
        });
    }
}

pub struct EguiApp {
    activity: Activity,
    app: App,
    bitnames: BitNames,
    bottom_panel: BottomPanel,
    coins: Coins,
    console_logs: ConsoleLogs,
    encrypt_message: EncryptMessage,
    miner: Miner,
    parent_chain: ParentChain,
    paymail: Paymail,
    set_seed: SetSeed,
    tab: Tab,
}

#[derive(Default, EnumIter, Eq, PartialEq, strum::Display)]
enum Tab {
    #[default]
    #[strum(to_string = "Parent Chain")]
    ParentChain,
    #[strum(to_string = "Coins")]
    Coins,
    #[strum(to_string = "BitNames")]
    BitNames,
    #[strum(to_string = "My Paymail")]
    Paymail,
    #[strum(to_string = "Messaging")]
    EncryptMessage,
    #[strum(to_string = "Activity")]
    Activity,
    #[strum(to_string = "Console / Logs")]
    ConsoleLogs,
}

impl EguiApp {
    pub fn new(
        app: App,
        cc: &eframe::CreationContext<'_>,
        logs_capture: LineBuffer,
        rpc_addr: SocketAddr,
    ) -> Self {
        // Customize egui here with cc.egui_ctx.set_fonts and cc.egui_ctx.set_visuals.
        // Restore app state using cc.storage (requires the "persistence" feature).
        // Use the cc.gl (a glow::Context) to create graphics shaders and buffers that you can use
        // for e.g. egui::PaintCallback.
        cc.egui_ctx.set_fonts(FONT_DEFINITIONS.clone());
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
        let rt_guard = app.runtime.enter();
        let bottom_panel = BottomPanel::new(&app.wallet);
        drop(rt_guard);
        let coins = Coins::new(&app);
        let console_logs = ConsoleLogs::new(logs_capture, rpc_addr);
        let parent_chain = ParentChain::new(&app);
        Self {
            activity,
            app,
            bitnames: BitNames::default(),
            bottom_panel,
            coins,
            console_logs,
            encrypt_message: EncryptMessage::new(),
            miner: Miner::default(),
            parent_chain,
            paymail: Paymail::default(),
            set_seed: SetSeed::default(),
            tab: Tab::default(),
        }
    }
}

impl eframe::App for EguiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.app.wallet.has_seed().unwrap_or(false) {
            egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    Tab::iter().for_each(|tab_variant| {
                        let tab_name = tab_variant.to_string();
                        ui.selectable_value(
                            &mut self.tab,
                            tab_variant,
                            tab_name,
                        );
                    })
                });
            });
            egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
                self.bottom_panel.show(&self.app, &mut self.miner, ui)
            });
            egui::CentralPanel::default().show(ctx, |ui| match self.tab {
                Tab::ParentChain => {
                    self.parent_chain.show(&mut self.app, ui);
                }
                Tab::Coins => {
                    let () = self.coins.show(&mut self.app, ui).unwrap();
                }
                Tab::BitNames => {
                    self.bitnames.show(&mut self.app, ui);
                }
                Tab::Paymail => self.paymail.show(&mut self.app, ui).unwrap(),
                Tab::EncryptMessage => {
                    self.encrypt_message.show(&mut self.app, ui);
                }
                Tab::Activity => {
                    self.activity.show(&mut self.app, ui);
                }
                Tab::ConsoleLogs => {
                    self.console_logs.show(&self.app, ui);
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
