use eframe::egui::{InnerResponse, Response};

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
