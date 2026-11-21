#!/usr/bin/env python3
"""MerlinAI relay: carries XP25 guests' builder requests to the MerlinAI Builder.

NT 5.1 cannot speak the TLS a remote builder needs, so the guest talks plain
HTTP to this relay on its own host's isolated bridge, and the relay forwards
to the builder URL: plain HTTP on a private network, or HTTPS with full
certificate and host-name verification for a builder elsewhere.

The relay holds no credentials and decides nothing. Requests and replies are
authenticated end to end with XP25-MERLIN1 (HMAC over method, path,
installation, challenge, nonce and body hash, and over every reply), so the
relay can neither forge nor alter them unnoticed. It only limits what it
forwards: GET/POST below /merlin/v1/ (never the builder's agent paths),
bounded bodies, the X-Merlin-* and Content-Type headers, one request per
connection, and optionally a list of client addresses.

usage: merlin_relay.py --listen 10.25.0.1:8740 --builder http://192.168.122.50:8740
                       [--client 10.25.0.27 ...] [--ca-file FILE] [--max-body 9437184]"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

FORWARD_HEADERS = ('X-Merlin-Installation', 'X-Merlin-Challenge', 'X-Merlin-Nonce', 'X-Merlin-Signature', 'Content-Type')
REPLY_HEADERS = ('X-Merlin-Signature', 'Content-Type')


class Relay(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'MerlinAI-Relay/1'
    sys_version = ''

    def log_message(self, fmt, *args):
        pass

    def audit(self, **record):
        record.update(time=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), client=self.client_address[0])
        print(json.dumps(record, sort_keys=True), flush=True)

    def send_plain(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def relay(self, method):
        cfg = self.server.cfg
        if cfg.clients and self.client_address[0] not in cfg.clients:
            self.audit(event='refused', reason='client not allowed')
            return self.send_plain(403, {'error': 'client_not_allowed'})
        path = self.path
        if not path.startswith('/merlin/v1/') or path.startswith('/merlin/v1/agent/') or '..' in path or len(path) > 200 or \
                any(ord(c) <= 32 or ord(c) >= 127 for c in path):
            self.audit(event='refused', reason='path', path=path[:80])
            return self.send_plain(404, {'error': 'not_relayed'})
        body = b''
        if method == 'POST':
            length = self.headers.get('Content-Length', '')
            if not length.isdigit() or int(length) > cfg.max_body:
                self.audit(event='refused', reason='body size', path=path[:80])
                return self.send_plain(413, {'error': 'request_too_large'})
            body = self.rfile.read(int(length))
        headers = {h: self.headers[h] for h in FORWARD_HEADERS if self.headers.get(h)}
        request = urllib.request.Request(cfg.builder + path, data=body if method == 'POST' else None, method=method, headers=headers)
        started = time.time()
        try:
            with cfg.opener.open(request, timeout=cfg.timeout) as r:
                status, reply_headers, data = r.status, r.headers, r.read(cfg.max_reply + 1)
        except urllib.error.HTTPError as e:
            status, reply_headers, data = e.code, e.headers, e.read(cfg.max_reply + 1)
        except (urllib.error.URLError, OSError, ssl.SSLError) as e:
            self.audit(event='builder_unreachable', path=path[:80], error=str(e)[:200])
            return self.send_plain(502, {'error': 'builder_unreachable'})
        if len(data) > cfg.max_reply:
            self.audit(event='reply_too_large', path=path[:80])
            return self.send_plain(502, {'error': 'reply_too_large'})
        self.send_response(status)
        for h in REPLY_HEADERS:
            if reply_headers.get(h):
                self.send_header(h, reply_headers[h])
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True
        self.audit(event='relayed', method=method, path=path[:80], status=status, request_bytes=len(body), reply_bytes=len(data),
                   ms=int((time.time() - started) * 1000), installation=headers.get('X-Merlin-Installation', ''))

    def do_GET(self):
        self.relay('GET')

    def do_POST(self):
        self.relay('POST')


class Config:
    def __init__(self, args):
        self.builder = args.builder.rstrip('/')
        scheme = self.builder.split(':', 1)[0]
        if scheme == 'https':
            context = ssl.create_default_context(cafile=args.ca_file)          # verification and host names on
            handlers = [urllib.request.HTTPSHandler(context=context)]
        elif scheme == 'http':
            host = self.builder.split('/')[2].rsplit(':', 1)[0].strip('[]')
            try:
                address = ipaddress.ip_address(socket.gethostbyname(host))
            except (OSError, ValueError):
                raise SystemExit('cannot resolve the builder host')
            if not address.is_private:
                raise SystemExit('plain HTTP is only allowed to a builder on a private network; use https://')
            handlers = []
        else:
            raise SystemExit('the builder URL must be http:// or https://')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), *handlers)
        self.clients = set(args.client or [])
        self.max_body, self.max_reply, self.timeout = args.max_body, 4 * 1024 * 1024 + 4096, 180


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--listen', required=True)
    parser.add_argument('--builder', required=True)
    parser.add_argument('--client', action='append')
    parser.add_argument('--ca-file')
    parser.add_argument('--max-body', type=int, default=9 * 1024 * 1024)
    parser.add_argument('--freebind', action='store_true', help='bind the bridge address before it exists (boot)')
    args = parser.parse_args()
    host, _, port = args.listen.rpartition(':')

    class Server(ThreadingHTTPServer):
        daemon_threads = True

        def server_bind(self):
            if args.freebind and hasattr(socket, 'IP_FREEBIND'):
                self.socket.setsockopt(socket.SOL_IP, socket.IP_FREEBIND, 1)
            super().server_bind()
    server = Server((host, int(port)), Relay)
    server.cfg = Config(args)
    print(json.dumps({'event': 'listening', 'listen': args.listen, 'builder': server.cfg.builder}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
