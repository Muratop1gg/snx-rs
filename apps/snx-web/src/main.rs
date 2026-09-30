mod api;
mod browser;
mod prompt;
mod state;
mod controller_helpers;

use axum::{
    body::Body,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
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

    let state = AppState::new();

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
        .with_state(state);

    let app = Router::new()
        .nest("/api", api_routes)
        .fallback(static_handler)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    tracing::info!("snx-web listening on http://127.0.0.1:8080");
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