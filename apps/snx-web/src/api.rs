use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    Json,
};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{json, Value};
use snxcore::{
    controller::ServiceCommand,
    model::{
        params::{TunnelParams, TunnelType},
        proto::GatewayInformation,
        ConnectionStatus,
    },
    platform::{Keychain, Platform, PlatformAccess},
    profiles::ConnectionProfilesStore,
    tunnel::{connector::CheckPointConnectorFactory, TunnelConnectorFactory},
};
use uuid::Uuid;

use crate::controller_helpers::make_controller;
use crate::state::AppState;

// ---------- Статус ----------

pub async fn status(State(state): State<AppState>) -> Json<Value> {
    let params = ConnectionProfilesStore::instance().get_connected();
    let prompt = state.prompt.clone();

    // Отдельный контроллер на каждый status-запрос. `make_controller`
    // создаёт новое pipe-соединение — это дешево и не блокирует
    // параллельные запросы.
    let result = tokio::time::timeout(Duration::from_secs(3), async move {
        let mut ctrl = make_controller(&prompt);
        ctrl.command(ServiceCommand::Status, params).await
    })
        .await;

    let pending = state.prompt.pending();

    match result {
        Ok(Ok(status)) => Json(json!({
            "ok": true,
            "status": status_to_json(&status),
            "pending": pending,
        })),
        Ok(Err(e)) => Json(json!({
            "ok": false,
            "error": e.to_string(),
            "pending": pending,
        })),
        Err(_) => Json(json!({
            "ok": false,
            "error": "timeout",
            "pending": pending,
            "status": { "kind": "connecting" },
        })),
    }
}

// ---------- Профили ----------

pub async fn list_profiles() -> Json<Value> {
    let profiles = ConnectionProfilesStore::instance().all();
    let items: Vec<Value> = profiles
        .iter()
        .map(|p| {
            json!({
                "id": p.profile_id.to_string(),
                "name": p.profile_name,
                "server": p.server_name,
                "user": p.user_name,
                "tunnel_type": format!("{:?}", p.tunnel_type),
                "login_type": p.login_type,
                "keychain": p.keychain,
                "default_route": p.default_route,
                "no_dns": p.no_dns,
                "ignore_server_cert": p.ignore_server_cert,
            })
        })
        .collect();
    Json(json!({ "ok": true, "profiles": items }))
}

#[derive(Deserialize)]
pub struct ProfileInput {
    pub name: String,
    pub server: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_tunnel_type")]
    pub tunnel_type: String,
    #[serde(default)]
    pub keychain: bool,
    #[serde(default)]
    pub default_route: bool,
    #[serde(default)]
    pub no_dns: bool,
    #[serde(default)]
    pub ignore_server_cert: bool,
    #[serde(default)]
    pub login_type: String,
}

fn default_tunnel_type() -> String {
    "IPsec".to_string()
}

fn tunnel_type_from_str(s: &str) -> TunnelType {
    match s.to_ascii_lowercase().as_str() {
        "ssl" => TunnelType::SSL,
        _ => TunnelType::IPsec,
    }
}

pub async fn create_profile(Json(req): Json<ProfileInput>) -> Json<Value> {
    if req.name.trim().is_empty() {
        return Json(json!({ "ok": false, "error": "Имя профиля обязательно" }));
    }
    if req.server.trim().is_empty() {
        return Json(json!({ "ok": false, "error": "Адрес сервера обязателен" }));
    }

    let profile_id = Uuid::new_v4();
    let params = Arc::new(TunnelParams {
        profile_name: req.name.trim().to_string(),
        profile_id,
        server_name: req.server.trim().to_string(),
        user_name: req.user,
        password: SecretString::from(req.password),
        tunnel_type: tunnel_type_from_str(&req.tunnel_type),
        login_type: req.login_type,
        ignore_server_cert: req.ignore_server_cert,
        keychain: req.keychain,
        default_route: req.default_route,
        no_dns: req.no_dns,
        config_file: TunnelParams::default_config_dir().join(format!("{profile_id}.conf")),
        ..Default::default()
    });

    ConnectionProfilesStore::instance().save(params);

    Json(json!({ "ok": true, "id": profile_id.to_string() }))
}

pub async fn update_profile(
    Path(id): Path<String>,
    Json(req): Json<ProfileInput>,
) -> Json<Value> {
    let Ok(uuid) = id.parse::<Uuid>() else {
        return Json(json!({ "ok": false, "error": "Некорректный UUID" }));
    };

    let store = ConnectionProfilesStore::instance();
    let Some(existing) = store.get(uuid) else {
        return Json(json!({ "ok": false, "error": "Профиль не найден" }));
    };

    let mut params = (*existing).clone();
    params.profile_name = req.name;
    params.server_name = req.server;
    params.user_name = req.user;
    params.password = SecretString::from(req.password);
    params.tunnel_type = tunnel_type_from_str(&req.tunnel_type);
    params.login_type = req.login_type;
    params.keychain = req.keychain;
    params.ignore_server_cert = req.ignore_server_cert;
    params.default_route = req.default_route;
    params.no_dns = req.no_dns;

    store.save(Arc::new(params));

    Json(json!({ "ok": true }))
}

pub async fn delete_profile(Path(id): Path<String>) -> Json<Value> {
    let Ok(uuid) = id.parse::<Uuid>() else {
        return Json(json!({ "ok": false, "error": "Некорректный UUID" }));
    };

    if uuid == snxcore::model::params::DEFAULT_PROFILE_UUID {
        return Json(json!({
            "ok": false,
            "error": "Профиль по умолчанию нельзя удалить"
        }));
    }

    let store = ConnectionProfilesStore::instance();
    if store.get(uuid).is_none() {
        return Json(json!({ "ok": false, "error": "Профиль не найден" }));
    }

    store.remove(uuid);
    let _ = Platform::get().new_keychain().delete_password(uuid).await;

    Json(json!({ "ok": true }))
}

// ---------- Connect / Disconnect / Reconnect ----------

#[derive(Deserialize)]
pub struct ConnectReq {
    pub profile: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub mfa_code: Option<String>,
}

pub async fn connect(
    State(state): State<AppState>,
    Json(req): Json<ConnectReq>,
) -> Json<Value> {
    let store = ConnectionProfilesStore::instance();
    let Some(base) = store.find_by_name_or_uuid(&req.profile) else {
        return Json(json!({ "ok": false, "error": "Профиль не найден" }));
    };

    let mut params = (*base).clone();

    // Если login_type пустой — сходим к серверу и выясним.
    if params.login_type.is_empty() {
        let connector = CheckPointConnectorFactory::default()
            .new_gateway_connector(Arc::new(params.clone()));
        match connector.get_gateway_information().await {
            Ok(info) => {
                let login_type = info
                    .login_options_data
                    .as_ref()
                    .and_then(|d| d.login_options_list.values().find(|o| o.show_realm != 0))
                    .map(|o| o.id.clone());

                match login_type {
                    Some(lt) => {
                        params.login_type = lt;
                        store.save(Arc::new(params.clone()));
                    }
                    None => {
                        return Json(json!({
                            "ok": false,
                            "error": "Сервер не вернул ни одной login-опции"
                        }));
                    }
                }
            }
            Err(e) => {
                return Json(json!({
                    "ok": false,
                    "error": format!("Не удалось получить информацию о сервере: {e}")
                }));
            }
        }
    }

    if let Some(pw) = req.password {
        params.password = SecretString::from(pw);
    }
    if req.mfa_code.is_some() {
        params.mfa_code = req.mfa_code;
    }

    let params = Arc::new(params);
    store.set_connected(params.profile_id);

    // Запускаем коннект в фоне. HTTP-ответ вернётся сразу,
    // а фронт будет поллить /api/status и увидит pending (MFA).
    let prompt = state.prompt.clone();
    tokio::spawn(async move {
        let mut ctrl = make_controller(&prompt);
        match ctrl.command(ServiceCommand::Connect, params).await {
            Ok(s) => tracing::info!("connect finished: {:?}", s),
            Err(e) => tracing::warn!("connect failed: {e}"),
        }
    });

    Json(json!({ "ok": true, "accepted": true }))
}

pub async fn disconnect(State(state): State<AppState>) -> Json<Value> {
    let params = ConnectionProfilesStore::instance().get_connected();
    let prompt = state.prompt.clone();

    let mut ctrl = make_controller(&prompt);
    let result = ctrl.command(ServiceCommand::Disconnect, params).await;

    match result {
        Ok(status) => Json(json!({ "ok": true, "status": status_to_json(&status) })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

pub async fn reconnect(State(state): State<AppState>) -> Json<Value> {
    let params = ConnectionProfilesStore::instance().get_connected();
    let prompt = state.prompt.clone();

    let mut ctrl = make_controller(&prompt);
    let result = ctrl.command(ServiceCommand::Reconnect, params).await;

    match result {
        Ok(status) => Json(json!({ "ok": true, "status": status_to_json(&status) })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

// ---------- MFA ----------

#[derive(Deserialize)]
pub struct ChallengeReq {
    pub answer: String,
}

pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeReq>,
) -> Json<Value> {
    if state.prompt.submit(req.answer) {
        Json(json!({ "ok": true }))
    } else {
        Json(json!({ "ok": false, "error": "Нет активного запроса" }))
    }
}

pub async fn cancel_challenge(State(state): State<AppState>) -> Json<Value> {
    state.prompt.cancel();
    Json(json!({ "ok": true }))
}

// ---------- Fetch info ----------

#[derive(Deserialize)]
pub struct FetchInfoReq {
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub ignore_server_cert: bool,
}

pub async fn fetch_info(Json(req): Json<FetchInfoReq>) -> Json<Value> {
    let params: Arc<TunnelParams> = if let Some(name) = req.profile.as_deref() {
        match ConnectionProfilesStore::instance().find_by_name_or_uuid(name) {
            Some(p) => p,
            None => return Json(json!({ "ok": false, "error": "Профиль не найден" })),
        }
    } else if let Some(server) = req.server {
        Arc::new(TunnelParams {
            server_name: server,
            ignore_server_cert: req.ignore_server_cert,
            ..Default::default()
        })
    } else {
        return Json(json!({ "ok": false, "error": "Нужен profile или server" }));
    };

    let connector = CheckPointConnectorFactory::default().new_gateway_connector(params);
    let info: GatewayInformation = match connector.get_gateway_information().await {
        Ok(info) => info,
        Err(e) => {
            return Json(json!({ "ok": false, "error": e.to_string() }));
        }
    };

    let mut options: Vec<Value> = Vec::new();
    if let Some(data) = &info.login_options_data {
        for option in data.login_options_list.values() {
            if option.show_realm == 0 {
                continue;
            }
            let factors: Vec<String> = option
                .factors
                .values()
                .map(|f| f.factor_type.clone())
                .collect();
            options.push(json!({
                "id": option.id,
                "name": option.display_name,
                "factors": factors,
            }));
        }
    }

    if options.is_empty() {
        options.push(json!({
            "id": "vpn_unspecified",
            "name": "Default",
            "factors": [],
        }));
    }

    Json(json!({ "ok": true, "options": options }))
}

// ---------- Утилиты ----------

fn status_to_json(s: &ConnectionStatus) -> Value {
    match s {
        ConnectionStatus::Disconnected => json!({ "kind": "disconnected" }),
        ConnectionStatus::Connecting => json!({ "kind": "connecting" }),
        ConnectionStatus::Connected(info) => json!({
            "kind": "connected",
            "server": info.server_name,
            "user": info.username,
            "ip": info.ip_address.to_string(),
            "since": info.since.map(|d| d.to_rfc3339()),
            "profile": info.profile_name,
            "profile_id": info.profile_id.to_string(),
        }),
        ConnectionStatus::Mfa(mfa) => json!({
            "kind": "mfa",
            "mfa_type": format!("{:?}", mfa.mfa_type),
            "prompt": mfa.prompt,
        }),
    }
}