use std::{
    collections::HashMap,
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::Context;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use snxcore::model::params::TunnelParams;
use subtle::ConstantTimeEq;

const DEFAULT_WEB_USER: &str = "admin";
const DEFAULT_PROXY_LISTEN: &str = "0.0.0.0:1080";

#[derive(Clone)]
pub struct ProxySettings {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub user: String,
    pub password: SecretString,
}

pub struct WebConfig {
    pub path: PathBuf,
    pub web_user: String,
    pub web_password: SecretString,
    pub session_secret: SecretString,
    pub proxy: ProxySettings,
}

pub fn config_path() -> PathBuf {
    std::env::var_os("SNX_WEB_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| TunnelParams::default_config_dir().join("snx-web.conf"))
}

// Значения сравниваются по хешам, чтобы время сравнения не зависело от их длины и содержимого.
pub fn credentials_match(user: &str, password: &str, expected_user: &str, expected_password: &SecretString) -> bool {
    let user_ok = Sha256::digest(user).ct_eq(&Sha256::digest(expected_user));
    let password_ok = Sha256::digest(password).ct_eq(&Sha256::digest(expected_password.expose_secret()));
    (user_ok & password_ok).into()
}

fn random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn parse(contents: &str) -> HashMap<String, String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

fn merge(contents: &str, updates: &[(&str, String)]) -> String {
    let mut remaining: Vec<_> = updates.iter().collect();
    let mut lines = Vec::new();
    for line in contents.lines() {
        let key = line.split_once('=').map(|(key, _)| key.trim());
        match remaining
            .iter()
            .position(|(name, _)| !line.trim_start().starts_with('#') && Some(*name) == key)
        {
            Some(index) => {
                let (name, value) = remaining.remove(index);
                lines.push(format!("{name}={value}"));
            }
            None => lines.push(line.to_owned()),
        }
    }
    lines.extend(remaining.iter().map(|(name, value)| format!("{name}={value}")));
    lines.join("\n") + "\n"
}

fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let tmp = path.with_extension("conf.tmp");
    let _ = fs::remove_file(&tmp);

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);

    let mut file = options
        .open(&tmp)
        .with_context(|| format!("cannot create {}", tmp.display()))?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}

fn update_file(path: &Path, updates: &[(&str, String)]) -> anyhow::Result<()> {
    let contents = read_optional(path)?;
    write_private(path, &merge(&contents, updates))
}

fn read_optional(path: &Path) -> anyhow::Result<String> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

impl WebConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let values = parse(&read_optional(path)?);
        let value = |key: &str| values.get(key).filter(|v| !v.is_empty()).cloned();

        let mut generated = Vec::new();
        let web_user = value("web-user").unwrap_or_else(|| {
            generated.push(("web-user", DEFAULT_WEB_USER.to_owned()));
            DEFAULT_WEB_USER.to_owned()
        });
        let web_password = value("web-password").unwrap_or_else(|| {
            let password = random_hex(12);
            generated.push(("web-password", password.clone()));
            tracing::warn!("generated web UI password, see web-password in {}", path.display());
            password
        });
        let session_secret = value("session-secret").unwrap_or_else(|| {
            let secret = random_hex(32);
            generated.push(("session-secret", secret.clone()));
            secret
        });

        let listen = value("proxy-listen").unwrap_or_else(|| DEFAULT_PROXY_LISTEN.to_owned());
        let proxy = ProxySettings {
            enabled: value("proxy-enabled").is_some_and(|v| v == "true"),
            listen: listen
                .parse()
                .with_context(|| format!("invalid proxy-listen: {listen}"))?,
            user: value("proxy-user").unwrap_or_default(),
            password: SecretString::from(value("proxy-password").unwrap_or_default()),
        };

        if !generated.is_empty() {
            update_file(path, &generated)?;
        }

        Ok(Self {
            path: path.to_owned(),
            web_user,
            web_password: SecretString::from(web_password),
            session_secret: SecretString::from(session_secret),
            proxy,
        })
    }
}

pub fn save_proxy(path: &Path, proxy: &ProxySettings) -> anyhow::Result<()> {
    update_file(
        path,
        &[
            ("proxy-enabled", proxy.enabled.to_string()),
            ("proxy-listen", proxy.listen.to_string()),
            ("proxy-user", proxy.user.clone()),
            ("proxy-password", proxy.password.expose_secret().to_owned()),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_keeps_comments_and_unknown_keys() {
        let merged = merge(
            "# note\nother=1\nproxy-user=a\n",
            &[("proxy-user", "b".into()), ("new", "c".into())],
        );
        assert_eq!(merged, "# note\nother=1\nproxy-user=b\nnew=c\n");
    }

    #[test]
    fn password_with_equals_sign_is_preserved() {
        assert_eq!(parse("web-password=a=b")["web-password"], "a=b");
    }

    #[test]
    fn credentials_compare_both_fields() {
        let password = SecretString::from("pw");
        assert!(credentials_match("u", "pw", "u", &password));
        assert!(!credentials_match("x", "pw", "u", &password));
        assert!(!credentials_match("u", "x", "u", &password));
    }
}
