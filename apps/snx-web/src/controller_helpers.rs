use snxcore::controller::ServiceController;

use crate::browser::WebBrowser;
use crate::prompt::WebPrompt;

/// Создать `ServiceController`, разделяющий `WebPrompt` с `AppState`.
///
/// `WebPrompt` внутри — `Arc<Mutex<Shared>>`, поэтому все клоны видят
/// один и тот же pending-запрос. Это позволяет `POST /api/challenge`
/// отвечать на MFA из любого контроллера.
pub fn make_controller(prompt: &WebPrompt) -> ServiceController<WebBrowser, WebPrompt> {
    let browser = WebBrowser::new(prompt.clone());
    ServiceController::new(prompt.clone(), browser)
}