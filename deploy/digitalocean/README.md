# DigitalOcean deployment (singapore-vps)

Deployed at `https://zcode-proxy.internal.getyokedapp.com` on
`singapore-vps` (sgp1, 157.245.158.183), live path 2026-11-07 from commit
`0b31cc6`.

## Topology

```
internet → nginx-sni (host :443, SNI split, PROXY protocol, default → haproxy)
         → haproxy (TLS termination, *.internal.getyokedapp.com wildcard cert,
                    Host-header routing, X-Forwarded-For reset)
         → zcode-proxy container, published on 172.17.0.1:8687 (bridge gateway only)
```

No public port is opened for the app; the DO firewall's existing 443 rule is
the only exposure, and the app port is not bound on the public interface.

## Files on the droplet (/opt/zcode-proxy)

- `Dockerfile.runtime` — alpine:3.20 + chromium, non-root uid 10001; expects a
  prebuilt linux/amd64 binary named `zcode-proxy` in the same directory.
- `docker-compose.yml` — hardened service definition (mem/pids caps,
  no-new-privileges, Secure cookie).
- `config/config.json` — must set `listen_addr: 0.0.0.0:8687` (the app
  default 127.0.0.1 binds loopback inside the container and breaks the
  published port).
- `data/` — SQLite DB, auto-generated `vault.key`, `initial_admin_password`
  (0600, first start only). `chown -R 10001:10001 data` before first start.

## Update procedure

From the repo root:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o /tmp/zcode-proxy-do-staging/zcode-proxy .

ssh root@157.245.158.183 'mkdir -p /opt/zcode-proxy'
scp /tmp/zcode-proxy-do-staging/zcode-proxy root@157.245.158.183:/opt/zcode-proxy/zcode-proxy
scp deploy/digitalocean/Dockerfile.runtime deploy/digitalocean/docker-compose.yml \
    deploy/digitalocean/config.json root@157.245.158.183:/opt/zcode-proxy/

ssh root@157.245.158.183 'cd /opt/zcode-proxy \
  && docker compose build --pull \
  && docker compose up -d \
  && docker ps --filter name=zcode-proxy --format "{{.Status}}"'
```

The Go build is deliberately done on the workstation, not the droplet: the
box has 2GB RAM and a full Go toolchain build risks OOM against the
co-hosted services.

## Security posture

- Container: unprivileged uid 10001, `no-new-privileges`, mem cap 1g,
  pids cap 256, port bound to the bridge gateway only.
- TLS at haproxy with the wildcard cert; session cookie forced Secure via
  `ZCODE_COOKIE_SECURE=1`.
- Secrets: `ZCODE_WEB_PASS`/vault/credential secrets are all unset; the
  bootstrap admin password is a generated 20-char value persisted to
  `data/initial_admin_password` (0600), and the vault key is generated into
  `data/vault.key`. Nothing secret lives in the image or in compose.
- Admin panel and `/v1/*` API are both behind the app's own auth (admin
  password with step-up lockout; gateway keys for relay calls).
- sshd on the droplet is key-only (`passwordauthentication no`).
- Chromium inside the container is used by captcha.go, which passes
  `no-sandbox` itself (captcha.go:603), so no privileged sandbox is needed.

## HAProxy vhost

`/root/haproxy/haproxy.cfg` on the droplet carries `is_zcode` ACL +
`backend zcode` (→ 172.17.0.1:8687, 600s server timeout for SSE, XFF reset)
and `!is_zcode` was added to the fallthrough redirect. After edits:
`docker exec haproxy haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg` then
`docker kill -s HUP haproxy`.

## DNS

`zcode-proxy.internal.getyokedapp.com` A record → 157.245.158.183
(DNS-only, no Cloudflare proxy, matching the other internal vhosts),
created via the Cloudflare API token already used by certbot-wildcard /
cloudflare-ddns on the droplet.
