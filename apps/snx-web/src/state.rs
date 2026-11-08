use crate::auth::AuthSettings;
use crate::prompt::WebPrompt;
use crate::proxy::ProxyManager;

/// Состояние приложения. `ServiceController` создаётся на лету в каждом запросе.
pub struct AppState {
    pub prompt: WebPrompt,
    pub auth: AuthSettings,
    pub proxy: ProxyManager,
}

impl AppState {
    pub fn new(auth: AuthSettings, proxy: ProxyManager) -> Self {
        Self {
            prompt: WebPrompt::new(),
            auth,
            proxy,
        }
    }
}
