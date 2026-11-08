use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream, lookup_host},
    sync::Mutex,
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};

use crate::config::{ProxySettings, credentials_match, save_proxy};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const AUTH_FAILURE_DELAY: Duration = Duration::from_secs(1);
const MAX_CONNECTIONS: usize = 1024;
const MAX_HTTP_HEAD: usize = 16 * 1024;

const SOCKS_VERSION: u8 = 5;
const TLS_HANDSHAKE_RECORD: u8 = 0x16;
const SOCKS_USER_PASS_AUTH: u8 = 2;
const SOCKS_NO_ACCEPTABLE_AUTH: u8 = 0xff;

const SOCKS_SUCCEEDED: u8 = 0;
const SOCKS_NOT_ALLOWED: u8 = 2;
const SOCKS_HOST_UNREACHABLE: u8 = 4;
const SOCKS_COMMAND_NOT_SUPPORTED: u8 = 7;
const SOCKS_ADDRESS_NOT_SUPPORTED: u8 = 8;

const HTTP_AUTH_REQUIRED: &str = "HTTP/1.1 407 Proxy Authentication Required\r\n\
    Proxy-Authenticate: Basic realm=\"snx-rs\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const HTTP_ESTABLISHED: &str = "HTTP/1.1 200 Connection established\r\n\r\n";
const HTTP_BAD_REQUEST: &str = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const HTTP_FORBIDDEN: &str = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const HTTP_BAD_GATEWAY: &str = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

#[derive(Deserialize)]
pub struct ProxyUpdate {
    pub enabled: bool,
    pub listen: String,
    pub user: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Serialize)]
pub struct ProxyStatus {
    enabled: bool,
    running: bool,
    listen: String,
    user: String,
    has_password: bool,
    active_connections: usize,
    error: Option<String>,
}

struct Running {
    settings: ProxySettings,
    task: Option<JoinHandle<()>>,
    error: Option<String>,
}

pub struct ProxyManager {
    config_path: PathBuf,
    tls: TlsAcceptor,
    active: Arc<AtomicUsize>,
    state: Mutex<Running>,
}

struct Listener {
    user: String,
    password: SecretString,
    tls: TlsAcceptor,
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ProxyManager {
    pub fn new(config_path: PathBuf, settings: ProxySettings, tls: Arc<ServerConfig>) -> Self {
        // ALPN веб-сервера предлагает h2, а прокси говорит только на HTTP/1.1.
        let mut tls = (*tls).clone();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];

        Self {
            config_path,
            tls: TlsAcceptor::from(Arc::new(tls)),
            active: Arc::new(AtomicUsize::new(0)),
            state: Mutex::new(Running {
                settings,
                task: None,
                error: None,
            }),
        }
    }

    pub async fn start_configured(&self) {
        let mut state = self.state.lock().await;
        if !state.settings.enabled {
            return;
        }
        match self.spawn(&state.settings).await {
            Ok(task) => state.task = Some(task),
            Err(e) => {
                tracing::error!("proxy failed to start: {e:#}");
                state.error = Some(format!("{e:#}"));
            }
        }
    }

    pub async fn status(&self) -> ProxyStatus {
        let state = self.state.lock().await;
        ProxyStatus {
            enabled: state.settings.enabled,
            running: state.task.is_some(),
            listen: state.settings.listen.to_string(),
            user: state.settings.user.clone(),
            has_password: !state.settings.password.expose_secret().is_empty(),
            active_connections: self.active.load(Ordering::Relaxed),
            error: state.error.clone(),
        }
    }

    pub async fn update(&self, update: ProxyUpdate) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        let settings = resolve_update(update, &state.settings)?;

        stop(&mut state.task).await;
        match self.apply(&settings).await {
            Ok(task) => {
                state.task = task;
                state.settings = settings;
                state.error = None;
                Ok(())
            }
            Err(e) => {
                if state.settings.enabled {
                    match self.spawn(&state.settings).await {
                        Ok(task) => state.task = Some(task),
                        Err(restore) => state.error = Some(format!("{restore:#}")),
                    }
                }
                Err(e)
            }
        }
    }

    async fn apply(&self, settings: &ProxySettings) -> anyhow::Result<Option<JoinHandle<()>>> {
        let mut task = if settings.enabled {
            Some(self.spawn(settings).await?)
        } else {
            None
        };
        if let Err(e) = save_proxy(&self.config_path, settings) {
            stop(&mut task).await;
            return Err(e);
        }
        Ok(task)
    }

    async fn spawn(&self, settings: &ProxySettings) -> anyhow::Result<JoinHandle<()>> {
        if settings.user.is_empty() || settings.password.expose_secret().is_empty() {
            bail!("proxy-user and proxy-password are required");
        }
        let socket = TcpListener::bind(settings.listen)
            .await
            .with_context(|| format!("cannot listen on {}", settings.listen))?;
        tracing::info!("proxy listening on {}", settings.listen);

        let listener = Arc::new(Listener {
            user: settings.user.clone(),
            password: settings.password.clone(),
            tls: self.tls.clone(),
        });
        Ok(tokio::spawn(accept_loop(socket, listener, self.active.clone())))
    }
}

fn resolve_update(update: ProxyUpdate, current: &ProxySettings) -> anyhow::Result<ProxySettings> {
    let listen = update
        .listen
        .trim()
        .parse()
        .map_err(|_| anyhow!("Некорректный адрес, нужен формат IP:порт"))?;
    let password = if update.password.is_empty() {
        current.password.clone()
    } else {
        SecretString::from(update.password)
    };
    let user = update.user.trim().to_owned();
    if update.enabled && (user.is_empty() || password.expose_secret().is_empty()) {
        bail!("Для включения прокси нужны логин и пароль");
    }
    Ok(ProxySettings {
        enabled: update.enabled,
        listen,
        user,
        password,
    })
}

async fn stop(task: &mut Option<JoinHandle<()>>) {
    if let Some(task) = task.take() {
        task.abort();
        let _ = task.await;
    }
}

// JoinSet принадлежит этой задаче: её отмена закрывает слушающий сокет и все соединения.
async fn accept_loop(socket: TcpListener, listener: Arc<Listener>, active: Arc<AtomicUsize>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = socket.accept() => match accepted {
                Ok((stream, peer)) => {
                    if active.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
                        active.fetch_sub(1, Ordering::Relaxed);
                        tracing::warn!("proxy connection limit reached, dropping {peer}");
                        continue;
                    }
                    let guard = ActiveGuard(active.clone());
                    let listener = listener.clone();
                    connections.spawn(async move {
                        let _guard = guard;
                        if let Err(e) = handle_connection(stream, peer, &listener).await {
                            tracing::debug!("proxy connection from {peer}: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("proxy accept failed: {e}");
                    sleep(Duration::from_millis(100)).await;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn handle_connection(mut stream: TcpStream, peer: SocketAddr, listener: &Listener) -> anyhow::Result<()> {
    let _ = stream.set_nodelay(true);

    let mut first = [0u8; 1];
    if timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first)).await?? == 0 {
        return Ok(());
    }

    match first[0] {
        SOCKS_VERSION => {
            let mut upstream = timeout(HANDSHAKE_TIMEOUT, socks5_negotiate(&mut stream, peer, listener)).await??;
            relay(&mut stream, &mut upstream).await
        }
        TLS_HANDSHAKE_RECORD => {
            let mut stream = timeout(HANDSHAKE_TIMEOUT, listener.tls.accept(stream)).await??;
            let mut upstream = timeout(HANDSHAKE_TIMEOUT, http_negotiate(&mut stream, peer, listener)).await??;
            relay(&mut stream, &mut upstream).await
        }
        _ => {
            let mut upstream = timeout(HANDSHAKE_TIMEOUT, http_negotiate(&mut stream, peer, listener)).await??;
            relay(&mut stream, &mut upstream).await
        }
    }
}

async fn relay<S>(client: &mut S, upstream: &mut TcpStream) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional(client, upstream).await?;
    Ok(())
}

enum ConnectError {
    Forbidden,
    Failed,
}

// Прокси открыт для сети, поэтому клиенты не должны получать доступ к сервисам самого хоста.
fn is_allowed_target(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    !ip.is_loopback() && !ip.is_unspecified()
}

async fn connect_target(host: &str, port: u16) -> Result<TcpStream, ConnectError> {
    let addrs: Vec<SocketAddr> = timeout(CONNECT_TIMEOUT, lookup_host((host, port)))
        .await
        .map_err(|_| ConnectError::Failed)?
        .map_err(|_| ConnectError::Failed)?
        .collect();

    let allowed: Vec<SocketAddr> = addrs.iter().copied().filter(|a| is_allowed_target(a.ip())).collect();
    if allowed.is_empty() && !addrs.is_empty() {
        return Err(ConnectError::Forbidden);
    }

    for addr in allowed {
        if let Ok(Ok(stream)) = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            let _ = stream.set_nodelay(true);
            return Ok(stream);
        }
    }
    Err(ConnectError::Failed)
}

async fn socks5_negotiate<S>(stream: &mut S, peer: SocketAddr, listener: &Listener) -> anyhow::Result<TcpStream>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    let mut methods = vec![0u8; header[1] as usize];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&SOCKS_USER_PASS_AUTH) {
        stream.write_all(&[SOCKS_VERSION, SOCKS_NO_ACCEPTABLE_AUTH]).await?;
        bail!("client does not offer username/password auth");
    }
    stream.write_all(&[SOCKS_VERSION, SOCKS_USER_PASS_AUTH]).await?;

    let auth_version = stream.read_u8().await?;
    let user = read_socks_string(stream).await?;
    let password = read_socks_string(stream).await?;
    if auth_version != 1 || !credentials_match(&user, &password, &listener.user, &listener.password) {
        tracing::warn!("proxy authentication failed from {peer}");
        sleep(AUTH_FAILURE_DELAY).await;
        stream.write_all(&[1, 1]).await?;
        bail!("authentication failed");
    }
    stream.write_all(&[1, 0]).await?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    let [_, command, _, address_type] = request;

    let host = match address_type {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            Ipv4Addr::from(ip).to_string()
        }
        3 => read_socks_string(stream).await?,
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            Ipv6Addr::from(ip).to_string()
        }
        _ => {
            socks5_reply(stream, SOCKS_ADDRESS_NOT_SUPPORTED).await?;
            bail!("unsupported address type {address_type}");
        }
    };
    let port = stream.read_u16().await?;

    if command != 1 {
        socks5_reply(stream, SOCKS_COMMAND_NOT_SUPPORTED).await?;
        bail!("unsupported command {command}");
    }

    match connect_target(&host, port).await {
        Ok(upstream) => {
            socks5_reply(stream, SOCKS_SUCCEEDED).await?;
            Ok(upstream)
        }
        Err(ConnectError::Forbidden) => {
            socks5_reply(stream, SOCKS_NOT_ALLOWED).await?;
            bail!("target {host}:{port} is not allowed");
        }
        Err(ConnectError::Failed) => {
            socks5_reply(stream, SOCKS_HOST_UNREACHABLE).await?;
            bail!("cannot connect to {host}:{port}");
        }
    }
}

async fn read_socks_string<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<String> {
    let len = stream.read_u8().await?;
    let mut bytes = vec![0u8; len as usize];
    stream.read_exact(&mut bytes).await?;
    Ok(String::from_utf8(bytes)?)
}

async fn socks5_reply<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> anyhow::Result<()> {
    stream.write_all(&[SOCKS_VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

async fn read_http_head<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<(String, Vec<u8>)> {
    const END: &[u8] = b"\r\n\r\n";
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(position) = buffer.windows(END.len()).position(|w| w == END) {
            let rest = buffer.split_off(position + END.len());
            return Ok((String::from_utf8(buffer)?, rest));
        }
        if buffer.len() > MAX_HTTP_HEAD {
            bail!("request head too large");
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            bail!("connection closed during request head");
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

fn basic_credentials(value: &str) -> Option<(String, String)> {
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).ok()?;
    let (user, password) = String::from_utf8(decoded)
        .ok()?
        .split_once(':')
        .map(|(u, p)| (u.to_owned(), p.to_owned()))?;
    Some((user, password))
}

fn split_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse().ok()?,
            None if tail.is_empty() => default_port,
            None => return None,
        };
        return Some((host.to_owned(), port));
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (authority, default_port),
    };
    (!host.is_empty()).then(|| (host.to_owned(), port))
}

fn split_absolute_url(url: &str) -> Option<(&str, String)> {
    let scheme = url.get(..7)?;
    if !scheme.eq_ignore_ascii_case("http://") {
        return None;
    }
    let rest = &url[7..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    let path = path.split('#').next().unwrap_or_default();
    let path = match path.chars().next() {
        Some('/') => path.to_owned(),
        _ => format!("/{path}"),
    };
    Some((authority, path))
}

// Каждый запрос идёт в отдельном соединении с целевым сервером: без Connection: close
// следующий запрос клиента мог бы уйти на прежний хост мимо проверки адреса.
fn rewrite_request_head(head: &str, method: &str, path: &str, version: &str) -> String {
    const HOP_BY_HOP: [&str; 4] = ["proxy-authorization", "proxy-connection", "connection", "keep-alive"];

    let mut rewritten = format!("{method} {path} {version}\r\n");
    for line in head.lines().skip(1).filter(|line| !line.is_empty()) {
        let name = line.split(':').next().unwrap_or_default().trim();
        if !HOP_BY_HOP.iter().any(|hop| name.eq_ignore_ascii_case(hop)) {
            rewritten.push_str(line.trim_end_matches('\r'));
            rewritten.push_str("\r\n");
        }
    }
    rewritten.push_str("Connection: close\r\n\r\n");
    rewritten
}

async fn http_negotiate<S>(stream: &mut S, peer: SocketAddr, listener: &Listener) -> anyhow::Result<TcpStream>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (head, rest) = read_http_head(stream).await?;

    let authorization = header_value(&head, "proxy-authorization");
    let authenticated = authorization
        .and_then(basic_credentials)
        .is_some_and(|(user, password)| credentials_match(&user, &password, &listener.user, &listener.password));
    if !authenticated {
        if authorization.is_some() {
            tracing::warn!("proxy authentication failed from {peer}");
            sleep(AUTH_FAILURE_DELAY).await;
        }
        stream.write_all(HTTP_AUTH_REQUIRED.as_bytes()).await?;
        stream.shutdown().await?;
        bail!("authentication required");
    }

    let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        stream.write_all(HTTP_BAD_REQUEST.as_bytes()).await?;
        bail!("malformed request line");
    };

    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    let parsed = if is_connect {
        split_authority(target, 443).map(|authority| (authority, String::new()))
    } else {
        split_absolute_url(target).and_then(|(authority, path)| Some((split_authority(authority, 80)?, path)))
    };
    let Some(((host, port), path)) = parsed else {
        stream.write_all(HTTP_BAD_REQUEST.as_bytes()).await?;
        bail!("unsupported request target");
    };

    let mut upstream = match connect_target(&host, port).await {
        Ok(upstream) => upstream,
        Err(error) => {
            let response = match error {
                ConnectError::Forbidden => HTTP_FORBIDDEN,
                ConnectError::Failed => HTTP_BAD_GATEWAY,
            };
            stream.write_all(response.as_bytes()).await?;
            stream.shutdown().await?;
            bail!("cannot connect to {host}:{port}");
        }
    };

    if is_connect {
        stream.write_all(HTTP_ESTABLISHED.as_bytes()).await?;
    } else {
        upstream
            .write_all(rewrite_request_head(&head, method, &path, version).as_bytes())
            .await?;
    }
    upstream.write_all(&rest).await?;
    Ok(upstream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_forms() {
        assert_eq!(split_authority("host", 443), Some(("host".into(), 443)));
        assert_eq!(split_authority("host:8080", 443), Some(("host".into(), 8080)));
        assert_eq!(split_authority("[::1]:8080", 443), Some(("::1".into(), 8080)));
        assert_eq!(split_authority("[fe80::1]", 80), Some(("fe80::1".into(), 80)));
        assert_eq!(split_authority("host:bad", 80), None);
    }

    #[test]
    fn absolute_url_forms() {
        assert_eq!(split_absolute_url("http://a/b?c"), Some(("a", "/b?c".to_owned())));
        assert_eq!(split_absolute_url("HTTP://a:81"), Some(("a:81", "/".to_owned())));
        assert_eq!(split_absolute_url("http://a?x=1"), Some(("a", "/?x=1".to_owned())));
        assert_eq!(split_absolute_url("https://a/"), None);
        assert_eq!(split_absolute_url("/relative"), None);
    }

    #[test]
    fn basic_auth_allows_colon_in_password() {
        // "user:pa:ss"
        assert_eq!(
            basic_credentials("Basic dXNlcjpwYTpzcw=="),
            Some(("user".to_owned(), "pa:ss".to_owned()))
        );
        assert_eq!(basic_credentials("Bearer abc"), None);
    }

    #[test]
    fn rewrite_strips_proxy_headers() {
        let head =
            "GET http://a/ HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic x\r\nConnection: keep-alive\r\n\r\n";
        assert_eq!(
            rewrite_request_head(head, "GET", "/", "HTTP/1.1"),
            "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn loopback_targets_are_denied() {
        assert!(!is_allowed_target("127.0.0.1".parse().unwrap()));
        assert!(!is_allowed_target("::1".parse().unwrap()));
        assert!(!is_allowed_target("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_allowed_target("0.0.0.0".parse().unwrap()));
        assert!(is_allowed_target("10.1.2.3".parse().unwrap()));
    }
}
