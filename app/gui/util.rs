use std::borrow::Borrow;

use borsh::BorshDeserialize;
use eframe::egui::{self, Color32, InnerResponse, Response, Ui};

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

/// iOS-style toggle switch
// Adapted from
// https://github.com/emilk/egui/blob/525d435a8475d56a6ea0ed35f41a363b622f2fce/crates/egui_demo_lib/src/demo/toggle_switch.rs
pub fn toggle_ui(ui: &mut egui::Ui, on: &mut bool) -> Response {
    let desired_size = ui.spacing().interact_size.y * egui::vec2(2.0, 1.0);

    let (rect, mut response) =
        ui.allocate_exact_size(desired_size, egui::Sense::click());

    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }

    // Attach some meta-data to the response which can be used by screen readers:
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::Checkbox,
            ui.is_enabled(),
            *on,
            "",
        )
    });

    if ui.is_rect_visible(rect) {
        let how_on = ui.ctx().animate_bool_responsive(response.id, *on);
        let visuals = ui.style().interact_selectable(&response, *on);
        let rect = rect.expand(visuals.expansion);
        let radius = 0.5 * rect.height();
        ui.painter().rect(
            rect,
            radius,
            visuals.bg_fill,
            visuals.bg_stroke,
            egui::StrokeKind::Inside,
        );
        // Paint the circle, animating it from left to right with `how_on`:
        let circle_x = egui::lerp(
            (rect.left() + radius)..=(rect.right() - radius),
            how_on,
        );
        let center = egui::pos2(circle_x, rect.center().y);
        ui.painter().circle(
            center,
            0.75 * radius,
            visuals.bg_fill,
            visuals.fg_stroke,
        );
    }
    response
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

    fn toggle_switch(&mut self, on: &mut bool) -> Response;
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

    fn toggle_switch(&mut self, on: &mut bool) -> Response {
        toggle_ui(self, on)
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
