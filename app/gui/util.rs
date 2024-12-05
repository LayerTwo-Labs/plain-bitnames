use std::borrow::Borrow;

use borsh::BorshDeserialize;
use eframe::egui::{self, Color32, InnerResponse, Response, Ui};
use libes::{auth::HmacSha256, enc::Aes256Gcm, key::X25519};

/// ecies crypto scheme over x25519
pub type Ecies = libes::Ecies<X25519, Aes256Gcm, HmacSha256>;

/// Bitcoin Orange Color
pub const BITCOIN_ORANGE: Color32 = Color32::from_rgb(0xf7, 0x93, 0x1a);

/// Unicode BTC symbol (U+20BF)
pub const BTC_UNICODE: char = '\u{20bf}';

/// Font-Awesome Bitcoin Logo symbol (U+F10F)
/// Note that this symbol is wider than other glyphs, often taking up as much
/// space as 3 chars.
pub const BITCOIN_LOGO_FA: char = '\u{f10f}';

/// Show a [`bitcoin::Amount`]
pub fn show_btc_amount(amount: bitcoin::Amount) -> String {
    format!(
        "{BTC_UNICODE}{}",
        amount.to_string_in(bitcoin::Denomination::Bitcoin)
    )
}

// extension for InnerResponse<Response> and InnerResponse<Option<Response>>
pub trait InnerResponseExt {
    fn join(self) -> Response;
}

/// extension trait for egui::Ui
pub trait UiExt {
    fn monospace_selectable_singleline<Text>(
        &mut self,
        clip_text: bool,
        text: Text,
    ) -> Response
    where
        Text: Borrow<str>;

    fn monospace_selectable_multiline<Text>(&mut self, text: Text) -> Response
    where
        Text: Borrow<str>;
}

impl InnerResponseExt for InnerResponse<Response> {
    fn join(self) -> Response {
        self.response | self.inner
    }
}

impl InnerResponseExt for InnerResponse<Option<Response>> {
    fn join(self) -> Response {
        match self.inner {
            Some(inner) => self.response | inner,
            None => self.response,
        }
    }
}

impl UiExt for Ui {
    fn monospace_selectable_singleline<Text>(
        &mut self,
        clip_text: bool,
        text: Text,
    ) -> Response
    where
        Text: Borrow<str>,
    {
        use egui::{TextEdit, TextStyle, Widget};
        let mut text: &str = text.borrow();
        TextEdit::singleline(&mut text)
            .font(TextStyle::Monospace)
            .clip_text(clip_text)
            .ui(self)
    }

    fn monospace_selectable_multiline<Text>(&mut self, text: Text) -> Response
    where
        Text: Borrow<str>,
    {
        use egui::{TextEdit, TextStyle, Widget};
        let mut text: &str = text.borrow();
        TextEdit::multiline(&mut text)
            .font(TextStyle::Monospace)
            .ui(self)
    }
}

pub fn borsh_deserialize_hex<T>(hex: impl AsRef<[u8]>) -> anyhow::Result<T>
where
    T: BorshDeserialize,
{
    match hex::decode(hex) {
        Ok(bytes) => borsh::BorshDeserialize::try_from_slice(&bytes)
            .map_err(anyhow::Error::new),
        Err(err) => Err(anyhow::Error::new(err)),
    }
}
