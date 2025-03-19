use eframe::egui;

use crate::{app::App, gui::util::UiExt};

mod decrypt;
mod encrypt;

use decrypt::DecryptMessage;
use encrypt::EncryptMessage;

#[derive(Default, Eq, PartialEq, strum::Display)]
enum Tab {
    #[strum(to_string = "Decrypt")]
    Decrypt,
    #[default]
    #[strum(to_string = "Encrypt")]
    Encrypt,
}

impl Tab {
    fn bool_repr(&self) -> bool {
        match self {
            Self::Encrypt => false,
            Self::Decrypt => true,
        }
    }

    fn from_bool_repr(b: bool) -> Self {
        if b { Self::Decrypt } else { Self::Encrypt }
    }
}

pub struct Messaging {
    decrypt: DecryptMessage,
    encrypt: EncryptMessage,
    tab: Tab,
}

impl Messaging {
    pub fn new() -> Self {
        Self {
            decrypt: DecryptMessage::new(),
            encrypt: EncryptMessage::new(),
            tab: Tab::default(),
        }
    }

    pub fn show(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        egui::CentralPanel::default().show(ui.ctx(), |ui| {
            ui.vertical_centered(|ui| {
                ui.add_sized((250., 10.), |ui: &mut egui::Ui| {
                    //ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(Tab::from_bool_repr(false).to_string());
                        let mut tab_repr: bool = self.tab.bool_repr();
                        ui.toggle_switch(&mut tab_repr);
                        self.tab = Tab::from_bool_repr(tab_repr);
                        ui.label(Tab::from_bool_repr(true).to_string());
                    })
                    .response
                });
                match self.tab {
                    Tab::Decrypt => {
                        self.decrypt.show(app, ui);
                    }
                    Tab::Encrypt => {
                        self.encrypt.show(app, ui);
                    }
                }
            })
        });
    }
}
