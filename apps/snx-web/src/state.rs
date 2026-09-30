use crate::prompt::WebPrompt;

/// Состояние приложения. Хранит только `WebPrompt`, потому что
/// `ServiceController` теперь создаётся на лету в каждом запросе.
#[derive(Clone)]
pub struct AppState {
    pub prompt: WebPrompt,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            prompt: WebPrompt::new(),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}