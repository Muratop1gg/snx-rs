pub use snxcore::browser::SystemBrowser;

use crate::prompt::WebPrompt;

pub type WebBrowser = SystemBrowser<WebPrompt>;