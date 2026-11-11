#!/usr/bin/env python3
"""XP25 companion gateway: lets Windows XP25 reach the OpenAI API without
running TLS 1.2 on NT 5.1.

The gateway runs on a current, trusted machine. It holds the OpenAI API key,
connects upstream with full TLS certificate and hostname validation (Python's
default SSL context; never disabled), and accepts requests from XP25 only
when they are authenticated:

  1. GET  /xp25/v1/challenge  -> {"challenge": <32 random bytes, hex>}; single use, 60 s.
  2. POST /xp25/v1/responses or /xp25/v1/chat/completions with headers
       X-XP25-Client, X-XP25-Challenge, X-XP25-Nonce, X-XP25-Content-SHA256,
       X-XP25-Signature = HMAC-SHA256(secret,
           "XP25-GW1\\nPOST\\n<path>\\n<challenge>\\n<nonce>\\n<sha256(body) hex>")
  3. Every reply carries X-XP25-Response-Signature = HMAC-SHA256(secret,
           "XP25-GW1-RESPONSE\\n<nonce>\\n<status>\\n<sha256(body) hex>")
     and XP25 discards replies whose signature does not verify.

The link between XP25 and the gateway is authenticated and integrity
protected but not encrypted; place the gateway on a trusted network segment.
Request bodies are forwarded with "store": false and are not logged.
Standard library only.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import urllib.error
import urllib.request

REQUEST_LABEL = 'XP25-GW1'
RESPONSE_LABEL = 'XP25-GW1-RESPONSE'
ROUTES = {'/xp25/v1/responses': '/v1/responses', '/xp25/v1/chat/completions': '/v1/chat/completions'}
HEX = re.compile(r'^[0-9a-f]+$')


def sign_request(secret, method, path, challenge, nonce, body):
    message = '\n'.join((REQUEST_LABEL, method, path, challenge, nonce, hashlib.sha256(body).hexdigest()))
    return hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()


def sign_response(secret, nonce, status, body):
    message = '\n'.join((RESPONSE_LABEL, nonce, str(status), hashlib.sha256(body).hexdigest()))
    return hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()


class Gateway:
    def __init__(self, clients, upstream, api_key, insecure_loopback, max_body, log_path, timeout):
        self.clients = clients
        self.upstream = upstream.rstrip('/')
        self.api_key = api_key
        self.max_body = max_body
        self.timeout = timeout
        self.log_path = log_path
        self.challenges = {}
        self.lock = threading.Lock()
        parts = urlsplit(self.upstream)
        if parts.scheme == 'https':
            self.context = ssl.create_default_context()   # certificate + hostname validation on
        elif parts.scheme == 'http' and insecure_loopback and parts.hostname in ('127.0.0.1', 'localhost', '::1'):
            self.context = None                           # local test double only
        else:
            raise SystemExit('upstream must be https:// (plain http is only allowed to loopback for tests)')

    def log(self, **record):
        record['time'] = time.time()
        if self.log_path:
            with self.lock, open(self.log_path, 'a') as f:
                f.write(json.dumps(record) + '\n')

    def new_challenge(self):
        value = secrets.token_hex(32)
        now = time.time()
        with self.lock:
            for key in [k for k, v in self.challenges.items() if v < now]:
                del self.challenges[key]
            if len(self.challenges) > 1000:
                self.challenges.pop(next(iter(self.challenges)))
            self.challenges[value] = now + 60
        return value

    def take_challenge(self, value):
        with self.lock:
            expiry = self.challenges.pop(value, None)
        return expiry is not None and expiry >= time.time()

    def forward(self, path, body):
        try:
            document = json.loads(body)
        except ValueError:
            return 400, json.dumps({'error': {'message': 'Request body is not JSON.', 'code': 'gateway_bad_request'}}).encode()
        if isinstance(document, dict) and path == '/v1/responses':
            document['store'] = False                     # never retain XP25 conversations upstream
        data = json.dumps(document).encode()
        request = urllib.request.Request(self.upstream + path, data=data, method='POST', headers={
            'Authorization': 'Bearer ' + self.api_key, 'Content-Type': 'application/json',
            'User-Agent': 'XP25-Gateway/1.0'})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as reply:
                return reply.status, reply.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()
        except (urllib.error.URLError, OSError, ssl.SSLError) as error:
            return 502, json.dumps({'error': {'message': 'The gateway could not reach the AI provider: ' +
                                              type(error).__name__, 'code': 'gateway_upstream_unreachable'}}).encode()


def handler_for(gateway):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'XP25-Gateway/1.0'
        sys_version = ''

        def reply(self, status, body, secret=None, nonce=None):
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            if secret is not None and nonce is not None:
                self.send_header('X-XP25-Response-Signature', sign_response(secret, nonce, status, body))
            self.end_headers()
            self.wfile.write(body)

        def error(self, status, code, message, secret=None, nonce=None):
            self.reply(status, json.dumps({'error': {'code': code, 'message': message}}).encode(), secret, nonce)

        def do_GET(self):
            if self.path != '/xp25/v1/challenge':
                return self.error(404, 'not_found', 'Unknown path.')
            self.reply(200, json.dumps({'challenge': gateway.new_challenge(), 'expires_in': 60}).encode())
            gateway.log(event='challenge', client=self.client_address[0])

        def do_POST(self):
            started = time.time()
            route = ROUTES.get(self.path)
            client = self.headers.get('X-XP25-Client', '')
            nonce = self.headers.get('X-XP25-Nonce', '')
            challenge = self.headers.get('X-XP25-Challenge', '')
            secret = gateway.clients.get(client)
            if route is None:
                return self.error(404, 'not_found', 'Unknown path.')
            length = int(self.headers.get('Content-Length', '0') or 0)
            if length <= 0 or length > gateway.max_body:
                return self.error(413, 'gateway_body_size', 'Request body is empty or too large.')
            body = self.rfile.read(length)
            if secret is None or not (len(nonce) == 32 and HEX.match(nonce)):
                gateway.log(event='rejected', reason='unknown_client_or_nonce', client=client, peer=self.client_address[0])
                return self.error(401, 'gateway_unauthorized', 'Unknown client.')
            digest = hashlib.sha256(body).hexdigest()
            expected = sign_request(secret, 'POST', self.path, challenge, nonce, body)
            given = self.headers.get('X-XP25-Signature', '')
            if (self.headers.get('X-XP25-Content-SHA256', '') != digest or
                    not hmac.compare_digest(expected, given) or not gateway.take_challenge(challenge)):
                gateway.log(event='rejected', reason='signature_or_challenge', client=client, peer=self.client_address[0])
                return self.error(401, 'gateway_unauthorized', 'Request authentication failed.', secret, nonce)
            status, payload = gateway.forward(route, body)
            gateway.log(event='forwarded', client=client, path=route, status=status, request_bytes=len(body),
                        response_bytes=len(payload), seconds=round(time.time() - started, 3))
            self.reply(status, payload, secret, nonce)

        def log_message(self, fmt, *args):
            pass

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--listen', default='127.0.0.1:8443', help='address:port to accept XP25 clients on')
    parser.add_argument('--clients', type=Path, required=True,
                        help='JSON file {"client-id": {"secret_hex": "..."}} with secrets of at least 16 bytes')
    parser.add_argument('--upstream', default='https://api.openai.com')
    parser.add_argument('--api-key-env', default='OPENAI_API_KEY', help='environment variable holding the API key')
    parser.add_argument('--allow-insecure-loopback-upstream', action='store_true',
                        help='testing only: permit an http:// upstream on the loopback interface')
    parser.add_argument('--max-body', type=int, default=4 * 1024 * 1024)
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--log', type=Path, help='JSON lines audit log (no bodies)')
    args = parser.parse_args()
    clients = {}
    for name, value in json.loads(args.clients.read_text()).items():
        secret = bytes.fromhex(value['secret_hex'])
        if len(secret) < 16:
            parser.error('client secrets must be at least 16 bytes')
        clients[name] = secret
    api_key = os.environ.get(args.api_key_env, '')
    if not api_key:
        parser.error('the API key environment variable is empty')
    host, port = args.listen.rsplit(':', 1)
    gateway = Gateway(clients, args.upstream, api_key, args.allow_insecure_loopback_upstream, args.max_body,
                      args.log, args.timeout)
    server = ThreadingHTTPServer((host, int(port)), handler_for(gateway))
    print('XP25 gateway listening on', args.listen, 'for', len(clients), 'client(s); upstream', args.upstream, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
