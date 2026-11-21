"""XP25-MERLIN1 request authentication, the server side of
components/merlin/core/merlin_proto.c.

A client fetches a single-use challenge (GET .../challenge), then signs
  label "\n" METHOD "\n" path "\n" principal "\n" challenge "\n" nonce "\n" hex(sha256(body))
with HMAC-SHA256 under its own key. Replies carry
  HMAC-SHA256(key, label "-RESPONSE\n" nonce "\n" status "\n" hex(sha256(body))).
No clock is involved, so guests with a wrong RTC still authenticate.
Builder keys, deployment-agent keys and the builder's own agent credential
are different keys under different labels: none can stand in for another."""
import hashlib
import hmac
import re
import secrets
import threading
import time

LABEL_BUILDER = 'XP25-MERLIN1'
LABEL_DEPLOY = 'XP25-MERLIN-DEPLOY1'
TOKEN = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
HEX32 = re.compile(r'^[0-9a-f]{32}$')
PATH = re.compile(r'^/[\x21-\x7e]{0,199}$')


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body or b'').hexdigest()


def canonical(label, method, path, principal, challenge, nonce, body):
    return '\n'.join([label, method, path, principal, challenge, nonce, body_hash(body)]).encode()


def sign_request(label, key, method, path, principal, challenge, nonce, body):
    return hmac.new(key, canonical(label, method, path, principal, challenge, nonce, body), hashlib.sha256).hexdigest()


def sign_response(label, key, nonce, status, body):
    message = ('%s-RESPONSE\n%s\n%d\n%s' % (label, nonce, status, body_hash(body))).encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_response(label, key, nonce, status, body, mac):
    return hmac.compare_digest(sign_response(label, key, nonce, status, body), mac or '')


class Challenges:
    """Single-use challenges with a short lifetime and a bounded number outstanding."""

    def __init__(self, lifetime=120, limit=4096):
        self.lifetime, self.limit = lifetime, limit
        self.issued = {}
        self.lock = threading.Lock()

    def issue(self):
        now = time.monotonic()
        value = secrets.token_hex(32)
        with self.lock:
            if len(self.issued) >= self.limit:
                self.issued = {c: t for c, t in self.issued.items() if now - t < self.lifetime}
                if len(self.issued) >= self.limit:
                    raise OverflowError('too many outstanding challenges')
            self.issued[value] = now
        return value

    def consume(self, value):
        with self.lock:
            issued = self.issued.pop(value, None)
        return issued is not None and time.monotonic() - issued < self.lifetime


def check_request(label, keys, challenges, method, path, headers, body):
    """Authenticate one request. keys(principal) -> key bytes or None.
    Returns (principal, nonce, key) or raises PermissionError with a short reason."""
    principal = headers.get('X-Merlin-Installation', '')
    challenge = headers.get('X-Merlin-Challenge', '')
    nonce = headers.get('X-Merlin-Nonce', '')
    mac = headers.get('X-Merlin-Signature', '')
    if not TOKEN.match(principal) or not HEX64.match(challenge) or not HEX32.match(nonce) or not HEX64.match(mac) or not PATH.match(path):
        raise PermissionError('malformed_authentication')
    key = keys(principal)
    if key is None:
        raise PermissionError('unknown_principal')
    if not challenges.consume(challenge):
        raise PermissionError('challenge_unknown_or_used')
    expected = sign_request(label, key, method, path, principal, challenge, nonce, body)
    if not hmac.compare_digest(expected, mac):
        raise PermissionError('bad_signature')
    return principal, nonce, key


class Client:
    """Python client for the same protocol (deployment agent, tests, admin tools)."""

    def __init__(self, base_url, principal, key, label=LABEL_BUILDER, prefix='/merlin/v1', timeout=60, opener=None):
        import urllib.request
        self.base, self.principal, self.key, self.label, self.prefix = base_url.rstrip('/'), principal, key, label, prefix
        self.timeout = timeout
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _raw(self, method, path, body=None, headers=None):
        import urllib.error
        import urllib.request
        request = urllib.request.Request(self.base + path, data=body, method=method, headers=headers or {})
        try:
            with self.opener.open(request, timeout=self.timeout) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def call(self, method, path, body=b'', content_type='application/json'):
        import json
        status, _, data = self._raw('GET', self.prefix + '/challenge')
        if status != 200:
            raise ConnectionError('challenge failed: %d' % status)
        challenge = json.loads(data)['challenge']
        nonce = secrets.token_hex(16)
        full = self.prefix + path
        mac = sign_request(self.label, self.key, method, full, self.principal, challenge, nonce, body or b'')
        headers = {'X-Merlin-Installation': self.principal, 'X-Merlin-Challenge': challenge, 'X-Merlin-Nonce': nonce,
                   'X-Merlin-Signature': mac, 'Content-Type': content_type}
        status, reply_headers, data = self._raw(method, full, body if method == 'POST' else None, headers)
        if not verify_response(self.label, self.key, nonce, status, data, reply_headers.get('X-Merlin-Signature')):
            raise PermissionError('reply not authenticated (status %d)' % status)
        return status, data
