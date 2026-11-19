#!/usr/bin/env python3
"""TLS HTTP CONNECT proxy for the egress tunnel regression tests.

Stdlib only. Serves TLS with the given leaf certificate, enforces optional
Basic proxy auth, records every request head (CONNECT or otherwise) plus
handshake outcomes as JSON lines into the log file, and blindly tunnels
accepted CONNECT requests. Test helper, never production code.

Usage:
  https_proxy.py --port P --cert C --key K --log L [--require-auth 'Basic ...']
"""

import argparse
import json
import socket
import ssl
import threading


def write_log(path, record):
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def read_request_head(tls):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = tls.recv(4096)
        if not chunk:
            return None
        data += chunk
        if len(data) > 65536:
            return None
    return data.split(b"\r\n\r\n", 1)[0].decode("latin1")


def parse_head(head):
    lines = head.split("\r\n")
    parts = lines[0].split(" ") if lines else []
    method = parts[0] if len(parts) > 0 else ""
    target = parts[1] if len(parts) > 1 else ""
    auth = ""
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "proxy-authorization":
            auth = value.strip()
    return method, target, auth


def pump(source, sink):
    try:
        while True:
            chunk = source.recv(8192)
            if not chunk:
                break
            sink.sendall(chunk)
    except OSError:
        pass


def handle(conn, args):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls = context.wrap_socket(conn, server_side=True)
    except Exception as exc:  # noqa: BLE001 - record every handshake failure
        write_log(args.log, {"event": "tls_handshake_failed",
                             "error": type(exc).__name__})
        conn.close()
        return
    write_log(args.log, {"event": "tls_handshake_ok"})
    head = read_request_head(tls)
    if head is None:
        tls.close()
        return
    method, target, auth = parse_head(head)
    write_log(args.log, {"event": "request", "method": method,
                         "target": target, "auth": auth})
    if method != "CONNECT":
        tls.sendall(b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n")
        tls.close()
        return
    if args.require_auth and auth != args.require_auth:
        tls.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"proxy-authenticate: Basic\r\ncontent-length: 0\r\n\r\n")
        tls.close()
        return
    host, _, port = target.partition(":")
    try:
        upstream = socket.create_connection((host, int(port)), timeout=10)
    except OSError:
        tls.sendall(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
        tls.close()
        return
    tls.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    relay = threading.Thread(target=pump, args=(tls, upstream), daemon=True)
    relay.start()
    pump(upstream, tls)
    relay.join(timeout=30)
    upstream.close()
    tls.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--require-auth", default=None)
    args = parser.parse_args()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", args.port))
    server.listen(16)
    print("READY", flush=True)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn, args), daemon=True).start()


if __name__ == "__main__":
    main()
