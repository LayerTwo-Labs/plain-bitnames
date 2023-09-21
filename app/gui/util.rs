use eframe::egui::{InnerResponse, Response};
use libes::{self, auth::HmacSha256, enc::Aes256Gcm, key::X25519};

/// ecies crypto scheme over x25519
pub type Ecies = libes::Ecies<X25519, Aes256Gcm, HmacSha256>;

// extension for InnerResponse<Response> and InnerResponse<Option<Response>>
pub trait InnerResponseExt {
    fn join(self) -> Response;
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
