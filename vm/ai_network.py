#!/usr/bin/env python3
"""Run one XP25 AI guest inside the isolated network namespace of
vm/isolated_network.py, plus the XP25 gateway at 10.25.0.1:8443 and the
OpenAI-API test double on namespace loopback. No uplink exists, so neither
the guest nor the gateway can reach the Internet.

Invoke exactly like isolated_network.py (under unshare --user --map-root-user
--net) with --gateway-clients and --mock-key; files land in the caller's
fresh .work/ directory."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', type=Path)
    parser.add_argument('--parent-netns', required=True)
    parser.add_argument('--gateway-clients', type=Path, required=True)
    parser.add_argument('--mock-key', required=True)
    args = parser.parse_args()
    if os.readlink('/proc/self/ns/net') == args.parent_netns:
        parser.error('a fresh isolated network namespace is required')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    mock = subprocess.Popen([sys.executable, str(HERE / 'ai_mock_openai.py'), '--listen', '127.0.0.1:9000',
                             '--key', args.mock_key, '--log', 'mock-openai.jsonl'],
                            stdout=open('mock-openai.log', 'a'), stderr=subprocess.STDOUT)
    env = dict(os.environ, XP25_TEST_UPSTREAM_KEY=args.mock_key)
    gateway_command = [sys.executable, str(ROOT / 'components/xp25-agent/gateway/xp25_gateway.py'),
                       '--listen', '10.25.0.1:8443', '--clients', str(args.gateway_clients),
                       '--upstream', 'http://127.0.0.1:9000', '--allow-insecure-loopback-upstream',
                       '--api-key-env', 'XP25_TEST_UPSTREAM_KEY', '--log', 'gateway.jsonl', '--timeout', '30']
    # The tap address appears once isolated_network.py configures the namespace; retry the bind until then.
    launcher = subprocess.Popen(['sh', '-c', 'for i in $(seq 1 200); do ip -4 addr show xp25tap 2>/dev/null | grep -q 10.25.0.1 '
                                 '&& exec "$@"; sleep 0.1; done; echo tap address never appeared; exit 3', 'gateway']
                                + gateway_command, stdout=open('gateway.log', 'a'), stderr=subprocess.STDOUT, env=env)
    sys.argv = [str(HERE / 'isolated_network.py'), str(args.command), '--parent-netns', args.parent_netns]
    sys.path.insert(0, str(HERE))
    import isolated_network
    try:
        isolated_network.main()
    finally:
        for process in (launcher, mock):
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        time.sleep(0.1)


if __name__ == '__main__':
    main()
