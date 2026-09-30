use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::anyhow;
use snxcore::model::{PromptInfo, params::NotificationLevel};
use snxcore::prompt::{NotificationCategory, SecurePrompt};
use tokio::sync::oneshot;

/// Сколько ждать ответа пользователя на MFA-запрос.
const CHALLENGE_TIMEOUT: Duration = Duration::from_secs(120);

/// Один активный MFA-запрос.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingChallenge {
    pub header: String,
    pub prompt: String,
    pub default_entry: Option<String>,
    pub secure: bool,
}

#[derive(Default)]
struct Shared {
    pending: Option<PendingChallenge>,
    reply_tx: Option<oneshot::Sender<String>>,
}

/// `SecurePrompt` для веб-UI.
///
/// Когда `snxcore` хочет спросить что-то у пользователя (MFA-код, пароль
/// из второго фактора, имя пользователя), `get_secure_input`/`get_plain_input`
/// складывают запрос в `Shared::pending` и ждут ответа через oneshot.
///
/// Ответ приходит из HTTP-хендлера `POST /api/challenge`, который берёт
/// `WebPrompt::shared()` и вызывает `submit()`.
#[derive(Clone, Default)]
pub struct WebPrompt {
    shared: Arc<Mutex<Shared>>,
}

impl WebPrompt {
    pub fn new() -> Self {
        Self::default()
    }

    /// Вернуть текущий активный запрос (если есть) — для `GET /api/status`.
    pub fn pending(&self) -> Option<PendingChallenge> {
        self.shared.lock().unwrap().pending.clone()
    }

    /// Ответить на текущий запрос. Возвращает `false`, если нечего отвечать.
    pub fn submit(&self, answer: String) -> bool {
        let mut s = self.shared.lock().unwrap();
        let Some(tx) = s.reply_tx.take() else {
            return false;
        };
        s.pending = None;
        tx.send(answer).is_ok()
    }

    /// Отменить текущий запрос (пользователь нажал «Cancel»).
    pub fn cancel(&self) {
        let mut s = self.shared.lock().unwrap();
        if let Some(tx) = s.reply_tx.take() {
            // Пустая строка = отмена. snxcore сам сгенерирует ошибку.
            let _ = tx.send(String::new());
        }
        s.pending = None;
    }

    async fn ask(&self, prompt: PromptInfo, secure: bool) -> anyhow::Result<String> {
        let (tx, rx) = oneshot::channel::<String>();

        {
            let mut s = self.shared.lock().unwrap();
            if s.pending.is_some() {
                return Err(anyhow!("Уже есть активный запрос ввода"));
            }
            s.pending = Some(PendingChallenge {
                header: prompt.header.clone(),
                prompt: prompt.prompt.clone(),
                default_entry: prompt.default_entry.clone(),
                secure,
            });
            s.reply_tx = Some(tx);
        }

        // Ждём ответа с таймаутом.
        let result = tokio::time::timeout(CHALLENGE_TIMEOUT, rx).await;

        // Что бы ни случилось — снимаем pending, чтобы следующий запрос прошёл.
        {
            let mut s = self.shared.lock().unwrap();
            s.pending = None;
            s.reply_tx = None;
        }

        match result {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(_)) => Err(anyhow!("Запрос ввода отменён")),
            Err(_) => Err(anyhow!("Таймаут ожидания ввода ({} сек)", CHALLENGE_TIMEOUT.as_secs())),
        }
    }
}

impl SecurePrompt for WebPrompt {
    async fn get_secure_input(&self, prompt: PromptInfo) -> anyhow::Result<String> {
        self.ask(prompt, true).await
    }

    async fn get_plain_input(&self, prompt: PromptInfo) -> anyhow::Result<String> {
        self.ask(prompt, false).await
    }

    async fn show_notification(
        &self,
        summary: &str,
        message: &str,
        category: NotificationCategory,
        _level: NotificationLevel,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "[{:?}] {}: {}",
            category,
            summary,
            message
        );
        Ok(())
    }
}