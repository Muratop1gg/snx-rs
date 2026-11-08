use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Extension, Request},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::Sha256;

use crate::config::{credentials_match, WebConfig};
use crate::state::AppState;

pub const COOKIE_NAME: &str = "snx_session";
const SESSION_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
const LOGIN_FAILURE_DELAY: Duration = Duration::from_secs(1);

pub struct AuthSettings {
    user: String,
    password: SecretString,
    session_secret: SecretString,
}

impl AuthSettings {
    pub fn from_config(config: &WebConfig) -> Self {
        Self {
            user: config.web_user.clone(),
            password: config.web_password.clone(),
            session_secret: config.session_secret.clone(),
        }
    }

    // Пароль входит в подпись, чтобы его смена отзывала все выданные сессии.
    fn session_mac(&self, expires: u64) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.session_secret.expose_secret().as_bytes())
            .expect("HMAC accepts keys of any length");
        mac.update(self.user.as_bytes());
        mac.update(&[0]);
        mac.update(self.password.expose_secret().as_bytes());
        mac.update(&[0]);
        mac.update(&expires.to_be_bytes());
        mac
    }

    fn issue_session(&self, now: u64) -> String {
        let expires = now + SESSION_LIFETIME_SECS;
        let signature = self.session_mac(expires).finalize().into_bytes();
        format!("{expires}.{}", hex::encode(signature))
    }

    fn session_is_valid(&self, session: &str, now: u64) -> bool {
        let Some((expires, signature)) = session.split_once('.') else {
            return false;
        };
        let (Ok(expires), Ok(signature)) = (expires.parse::<u64>(), hex::decode(signature)) else {
            return false;
        };
        expires > now && self.session_mac(expires).verify_slice(&signature).is_ok()
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn is_authed(req: &Request, auth: &AuthSettings) -> bool {
    let Some(cookie_str) = req.headers().get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    cookie_str
        .split(';')
        .filter_map(|part| part.trim().strip_prefix(COOKIE_NAME)?.strip_prefix('='))
        .any(|value| auth.session_is_valid(value, unix_now()))
}

/// Middleware: пускает дальше только с валидной cookie.
pub async fn require_auth(
    Extension(state): Extension<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path();

    // Публичные пути.
    if path == "/login" || path == "/login-submit" || path == "/logout" {
        return next.run(req).await;
    }

    if is_authed(&req, &state.auth) {
        return next.run(req).await;
    }

    if path.starts_with("/api/") {
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

// ---------- Форма логина ----------

pub async fn login_page() -> Html<&'static str> {
    Html(LOGIN_HTML)
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub user: String,
    pub password: String,
}

pub async fn login_submit(
    Extension(state): Extension<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    let auth = &state.auth;
    if !credentials_match(&form.user, &form.password, &auth.user, &auth.password) {
        tracing::warn!("web login failed");
        tokio::time::sleep(LOGIN_FAILURE_DELAY).await;
        return (StatusCode::UNAUTHORIZED, Html(LOGIN_HTML_ERR)).into_response();
    }

    let cookie = format!(
        "{COOKIE_NAME}={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_LIFETIME_SECS}",
        auth.issue_session(unix_now())
    );

    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

pub async fn logout() -> Response {
    let cookie = format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    let mut resp = Redirect::to("/login").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

const LOGIN_HTML: &str = r#"<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SNX-RS — вход</title>
<style>
  body { font-family: system-ui, sans-serif; background: #f4f5f7; margin: 0; }
  .wrap { max-width: 360px; margin: 15vh auto; padding: 1.5rem 1.75rem; background: #fff;
          border: 1px solid #e5e7eb; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  h1 { font-size: 1.1rem; margin: 0 0 1rem; color: #6b7280; text-transform: uppercase;
       letter-spacing: .04em; }
  input { display: block; width: 100%; padding: .55rem .7rem; font: inherit;
          border: 1px solid #e5e7eb; border-radius: 6px; box-sizing: border-box; }
  input:focus { outline: 2px solid #2563eb; border-color: #2563eb; }
  button { margin-top: .75rem; width: 100%; padding: .55rem; font: inherit; cursor: pointer;
           background: #2563eb; color: #fff; border: 0; border-radius: 6px; }
  button:hover { background: #1d4ed8; }
</style>
</head>
<body>
  <form class="wrap" method="POST" action="/login-submit">
    <h1>SNX-RS</h1>
    <input type="text" name="user" placeholder="Логин" autocomplete="username" autofocus required>
    <input type="password" name="password" placeholder="Пароль" autocomplete="current-password" required style="margin-top:.5rem">
    <button type="submit">Войти</button>
  </form>
</body>
</html>"#;

const LOGIN_HTML_ERR: &str = r#"<!doctype html>
<html lang="ru">
<head><meta charset="utf-8"><title>SNX-RS — вход</title></head>
<body style="font-family:system-ui;background:#f4f5f7;text-align:center;padding:15vh 0;">
  <div style="display:inline-block;background:#fff;padding:2rem;border-radius:10px;
              border:1px solid #e5e7eb;">
    <p style="color:#dc2626;margin:0 0 1rem;">Неверный логин или пароль</p>
    <a href="/login">Попробовать снова</a>
  </div>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(password: &str) -> AuthSettings {
        AuthSettings {
            user: "admin".into(),
            password: SecretString::from(password),
            session_secret: SecretString::from("secret"),
        }
    }

    #[test]
    fn session_survives_reload_of_same_settings() {
        let session = settings("pw").issue_session(1000);
        assert!(settings("pw").session_is_valid(&session, 1001));
    }

    #[test]
    fn session_expires() {
        let auth = settings("pw");
        let session = auth.issue_session(1000);
        assert!(!auth.session_is_valid(&session, 1000 + SESSION_LIFETIME_SECS));
    }

    #[test]
    fn password_change_revokes_session() {
        let session = settings("old").issue_session(1000);
        assert!(!settings("new").session_is_valid(&session, 1001));
    }

    #[test]
    fn extended_expiry_is_rejected() {
        let auth = settings("pw");
        let session = auth.issue_session(1000);
        let (_, signature) = session.split_once('.').unwrap();
        assert!(!auth.session_is_valid(&format!("99999999999.{signature}"), 1001));
        assert!(!auth.session_is_valid("garbage", 1001));
    }
}
