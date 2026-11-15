# Rust data-plane image (side-by-side trial; the Go container stays the
# system of record). Build context = this directory staged on the droplet
# per deploy/digitalocean/README.md.
#
# The binary is cross-compiled on the workstation (2GB droplet cannot build):
#   CGO_ENABLED=0 GOOS=... is the Go recipe; for Rust:
#   cargo build --release --target x86_64-unknown-linux-musl
#   (musl target: rustup target add x86_64-unknown-linux-musl)
# then scp rust/zcode-proxy/target/x86_64-unknown-linux-musl/release/zcode-proxy-rs
# to /opt/zcode-proxy/zcode-proxy-rs alongside this file.
FROM alpine:3.20

RUN adduser -D -u 10001 app && mkdir -p /home/app && chown app:app /home/app \
    && apk add --no-cache ca-certificates

# Captcha solving needs chromium when wired (CaptchaSolver seam); the
# fail-closed NoopSolver runs without it.
# RUN apk add --no-cache chromium

COPY zcode-proxy-rs /usr/local/bin/zcode-proxy-rs
RUN chmod +x /usr/local/bin/zcode-proxy-rs

ENV HOME=/home/app \
    ZCODE_RS_BIND=0.0.0.0:8787 \
    ZCODE_RS_DB=/app/data/zcode-rs.db
USER app
WORKDIR /app
EXPOSE 8787
CMD ["zcode-proxy-rs"]
