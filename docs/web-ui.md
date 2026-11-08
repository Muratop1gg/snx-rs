# Web UI

`snx-web` serves the management interface on `https://<host>:8443` and talks to the `snx-rs` service running in command mode.

## Configuration

Settings are stored in `snx-web.conf` in the snx-rs configuration directory. Set the `SNX_WEB_CONFIG` environment variable to use another path. The file is created on first start with permissions `0600`, including a generated `web-password`. Restart `snx-web` after editing it by hand.

| Option           | Description                                                         | Default        |
|------------------|---------------------------------------------------------------------|----------------|
| `web-user`       | Web UI login                                                        | `admin`        |
| `web-password`   | Web UI password. Changing it signs out all browsers                 | generated      |
| `session-secret` | Key that signs browser sessions. Changing it signs out all browsers | generated      |
| `proxy-enabled`  | Start the proxy together with `snx-web`                             | `false`        |
| `proxy-listen`   | Proxy address and port                                              | `0.0.0.0:1080` |
| `proxy-user`     | Proxy login                                                         |                |
| `proxy-password` | Proxy password                                                      |                |

## Proxy

The proxy lets other devices reach the Check Point network through the computer running the tunnel. One port accepts SOCKS5, HTTP and HTTPS (TLS to the proxy) clients, always with a login and password. Enable it in the web interface or in the configuration file.

```bash
curl -x socks5h://user:password@host:1080 http://intranet.example/
curl -x http://user:password@host:1080 https://intranet.example/
curl --proxy-insecure -x https://user:password@host:1080 https://intranet.example/
```

Use `socks5h` so names are resolved on the proxy host, where the VPN DNS is configured. Only TCP is supported; SOCKS5 UDP ASSOCIATE and BIND are rejected.

SOCKS5 and plain HTTP send the proxy password unencrypted, so prefer HTTPS on untrusted networks. The HTTPS mode uses the web UI certificate. The proxy refuses connections to the loopback addresses of its own host.
