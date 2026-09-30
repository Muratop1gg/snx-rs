use tokio::sync::Mutex;

use snxcore::controller::ServiceController;

use crate::browser::WebBrowser;
use crate::prompt::WebPrompt;

pub struct AppState {
    pub controller: Mutex<ServiceController<WebBrowser, WebPrompt>>,
    pub prompt: WebPrompt,
}

impl AppState {
    pub fn new() -> Self {
        let prompt = WebPrompt::new();
        let browser = WebBrowser::new(prompt.clone());
        Self {
            controller: Mutex::new(ServiceController::new(prompt.clone(), browser)),
            prompt,
        }
    }
}