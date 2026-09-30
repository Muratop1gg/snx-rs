mod api;
mod auth;
mod browser;
mod controller_helpers;
mod prompt;
mod state;

use std::sync::Arc;

use axum::{body::Body, http::{header, StatusCode, Uri}, middleware, response::{IntoResponse, Response}, routing::{delete, get, post, put}, Router, Extension};
use include_dir::{include_dir, Dir};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::state::AppState;

static STATIC_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/static");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let token = auth::resolve_token();
    tracing::info!("snx-web access token: {token}");

    let state = Arc::new(AppState::new(token));

    // Публичные роуты (без auth).
    let public_routes = Router::new()
        .route("/login", get(auth::login_page))
        .route("/login-submit", post(auth::login_submit))
        .route("/logout", post(auth::logout));

    // Приватные API-роуты.
    let api_routes = Router::new()
        .route("/status", get(api::status))
        .route("/profiles", get(api::list_profiles))
        .route("/profiles", post(api::create_profile))
        .route("/profiles/:id", put(api::update_profile))
        .route("/profiles/:id", delete(api::delete_profile))
        .route("/connect", post(api::connect))
        .route("/disconnect", post(api::disconnect))
        .route("/reconnect", post(api::reconnect))
        .route("/challenge", post(api::challenge))
        .route("/challenge/cancel", post(api::cancel_challenge))
        .route("/fetch-info", post(api::fetch_info))
        .with_state(state.clone());

    let app = Router::new()
        .merge(public_routes)
        .nest("/api", api_routes)
        .fallback(static_handler)
        .layer(middleware::from_fn(auth::require_auth))  // применяется позже
        .layer(Extension(state.clone()))                 // применяется раньше → доступен middleware
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!("snx-web listening on http://0.0.0.0:8080");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match STATIC_DIR.get_file(path) {
        Some(file) => {
            let mime = mime_guess_from_path(path);
            let body = Body::from(file.contents().to_vec());
            Response::builder()
                .header(header::CONTENT_TYPE, mime)
                .body(body)
                .unwrap()
        }
        None => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

fn mime_guess_from_path(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else {
        "application/octet-stream"
    }
}