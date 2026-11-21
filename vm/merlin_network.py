#!/usr/bin/env python3
"""Run one MerlinAI lab guest in the isolated namespace of
vm/isolated_network.py, with the MerlinAI Builder API (the real control
plane from components/merlin/builder, its data in the run directory) on
10.25.0.1:8740 and, when configured, a deployment-agent test endpoint on
10.25.0.1:8746 that records approvals without touching any VM.

The namespace has no uplink: the builder here only receives reports and
build requests (no runner, no model provider). Invoke under
unshare --user --map-root-user --net, like isolated_network.py."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'components/merlin/builder'))
sys.path.insert(0, str(HERE))


def start_builder(config_path):
    from merlin_builder.server import DEFAULT_LIMITS, Server
    from merlin_builder.store import Store
    config = json.loads(Path(config_path).read_text())
    limits = dict(DEFAULT_LIMITS, **config.get('limits', {}))
    server = Server(('0.0.0.0', 8740), Store(config['data'], limits), limits, log_path=config.get('log'))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def start_deploy_recorder(config_path):
    """Records signed /deploy/v1 requests (the lab never deploys anything)."""
    from merlin_builder import protocol
    config = json.loads(Path(config_path).read_text())
    keys = {config['installation']: bytes.fromhex(config['deploy_key'])}
    challenges = protocol.Challenges()
    log = Path(config['log'])

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def send(self, status, data, key=None, nonce=None):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            if key:
                self.send_header('X-Merlin-Signature', protocol.sign_response(protocol.LABEL_DEPLOY, key, nonce, status, body))
            self.end_headers()
            self.wfile.write(body)

        def handle_any(self, method):
            if self.path == '/deploy/v1/challenge':
                return self.send(200, {'challenge': challenges.issue()})
            length = int(self.headers.get('Content-Length') or 0)
            body = self.rfile.read(min(length, 65536)) if method == 'POST' else b''
            try:
                inst, nonce, key = protocol.check_request(protocol.LABEL_DEPLOY, keys.get, challenges, method, self.path, self.headers, body)
            except PermissionError as e:
                return self.send(401, {'error': str(e)})
            with log.open('a') as f:
                f.write(json.dumps({'installation': inst, 'method': method, 'path': self.path, 'body': body.decode('utf-8', 'replace')}) + '\n')
            if self.path == '/deploy/v1/health':
                return self.send(200, {'recorded': True, 'note': 'lab recorder: nothing is deployed'}, key, nonce)
            if self.path == '/deploy/v1/status':
                return self.send(200, {'state': 'lab recorder (no VM is changed)', 'current': 'lab', 'previous': ''}, key, nonce)
            return self.send(409, {'error': 'lab_recorder_only'}, key, nonce)

        def do_GET(self):
            self.handle_any('GET')

        def do_POST(self):
            self.handle_any('POST')

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('0.0.0.0', 8746), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', type=Path)
    parser.add_argument('--parent-netns', required=True)
    parser.add_argument('--builder-config', type=Path, required=True)
    parser.add_argument('--deploy-config', type=Path)
    args = parser.parse_args()
    if os.readlink('/proc/self/ns/net') == args.parent_netns:
        parser.error('a fresh isolated network namespace is required')
    builder = start_builder(args.builder_config)
    deploy = start_deploy_recorder(args.deploy_config) if args.deploy_config else None
    try:
        sys.argv = [str(HERE / 'isolated_network.py'), str(args.command), '--parent-netns', args.parent_netns]
        import isolated_network
        isolated_network.main()
    finally:
        builder.shutdown()
        if deploy:
            deploy.shutdown()


if __name__ == '__main__':
    main()
