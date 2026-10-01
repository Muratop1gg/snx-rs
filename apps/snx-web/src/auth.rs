use std::sync::Arc;

use axum::{
    extract::{Extension, Request},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use rand::Rng;
use serde::Deserialize;

use crate::state::AppState;

pub const COOKIE_NAME: &str = "snx_token";

/// Сгенерировать случайный токен, если не задан через env.
pub fn resolve_token() -> String {
    if let Ok(t) = std::env::var("SNX_WEB_TOKEN") {
        if !t.trim().is_empty() {
            return t;
        }
    }
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.r#gen();
    hex::encode(bytes)
}

/// Проверить, что запрос авторизован (есть валидная cookie).
pub fn is_authed(req: &Request, token: &str) -> bool {
    let Some(cookie_header) = req.headers().get(header::COOKIE) else {
        return false;
    };
    let Ok(cookie_str) = cookie_header.to_str() else {
        return false;
    };
    for part in cookie_str.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{COOKIE_NAME}=")) {
            return value == token;
        }
    }
    false
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

    if is_authed(&req, &state.token) {
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
    pub token: String,
}

pub async fn login_submit(
    Extension(state): Extension<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    if form.token != state.token {
        return (StatusCode::UNAUTHORIZED, Html(LOGIN_HTML_ERR)).into_response();
    }

    // Устанавливаем cookie на 30 дней.
    let cookie = format!(
        "{COOKIE_NAME}={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000",
        state.token
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
    <input type="password" name="token" placeholder="Токен доступа" autofocus required>
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
    <p style="color:#dc2626;margin:0 0 1rem;">Неверный токен</p>
    <a href="/login">Попробовать снова</a>
  </div>
</body>
</html>"#;