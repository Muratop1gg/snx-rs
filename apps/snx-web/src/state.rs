use crate::prompt::WebPrompt;

/// Состояние приложения. Хранит только `WebPrompt`, потому что
/// `ServiceController` теперь создаётся на лету в каждом запросе.
#[derive(Clone)]
pub struct AppState {
    pub prompt: WebPrompt,
    pub token: String,
}

impl AppState {
    pub fn new(token: String) -> Self {
        Self {
            prompt: WebPrompt::new(),
            token,
        }
    }
}
