#!/usr/bin/env python3
"""Run one QEMU command inside a network namespace with local DHCP/DNS/HTTP.

Invoke using unshare --user --map-root-user --net. No uplink, bridge, default
route, forwarding backend or public DNS resolver is created. Files are private
test evidence in the caller's fresh .work/ directory.
"""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', type=Path, help='JSON array of QEMU arguments')
    parser.add_argument('--parent-netns', required=True)
    parser.add_argument('--mac', required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--gateway', type=Path)
    parser.add_argument('--provider-clients',type=Path)
    parser.add_argument('--mock-key')
    args = parser.parse_args()
    # Refuse the host network namespace even when invoked with real root.
    if os.readlink('/proc/self/ns/net') == args.parent_netns:
        parser.error('a fresh isolated network namespace is required')
    initial = json.loads(subprocess.check_output(['ip', '-j', 'link']))
    if [row['ifname'] for row in initial] != ['lo']:
        parser.error('namespace must initially contain only loopback')
    command = json.loads(args.command.read_text())
    if not isinstance(command, list) or Path(command[0]).name != 'qemu-system-i386':
        parser.error('expected an explicit qemu-system-i386 command array')
    index = command.index('-nic')
    if command[index + 1] != 'none' or any(x in command for x in ('-net', '-netdev')):
        parser.error('input must have exactly the existing disabled network configuration')
    command[index:index+2] = ['-netdev', 'tap,id=xp25net,ifname=xp25tap,script=no,downscript=no',
                            '-device', 'rtl8139,netdev=xp25net,mac='+args.mac,
                            '-object', 'filter-dump,id=xp25capture,netdev=xp25net,file=network.pcap']
    for cmd in (['ip', 'link', 'set', 'lo', 'up'],
                ['ip', 'tuntap', 'add', 'dev', 'xp25tap', 'mode', 'tap'],
                ['ip', 'link', 'set', 'dev', 'xp25tap', 'address', '52:54:00:25:00:01'],
                ['ip', 'address', 'add', '10.25.0.1/24', 'dev', 'xp25tap'],
                ['ip', 'link', 'set', 'xp25tap', 'up']):
        subprocess.run(cmd, check=True)
    Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
    state = {'interfaces': json.loads(subprocess.check_output(['ip', '-j', 'address'])),
             'routes': json.loads(subprocess.check_output(['ip', '-j', 'route'])),
             'ip_forward': Path('/proc/sys/net/ipv4/ip_forward').read_text().strip(),
             'network_namespace': os.readlink('/proc/self/ns/net'),
             'parent_network_namespace': args.parent_netns,
             'public_uplink': False}
    Path('network-isolation.json').write_text(json.dumps(state, indent=2) + '\n')
    Path('qemu-network-command.json').write_text(json.dumps(command, indent=2) + '\n')
    dns_command = ['dnsmasq', '--conf-file=/dev/null', '--no-daemon', '--user=root', '--interface=xp25tap',
                   '--bind-interfaces', '--no-resolv', '--no-hosts', '--domain-needed',
                   '--dhcp-authoritative', '--dhcp-range=10.25.0.10,10.25.0.10,255.255.255.0,1h',
                   '--dhcp-option=3', '--dhcp-option=6,10.25.0.1',
                   '--address=/xp25.test/10.25.0.1', '--local=/test/',
                   '--log-queries', '--log-dhcp', '--dhcp-leasefile=dhcp.leases',
                   '--pid-file=dnsmasq.pid']
    Path('dnsmasq-command.json').write_text(json.dumps(dns_command, indent=2) + '\n')

    class Handler(BaseHTTPRequestHandler):
        def respond(self, status, body, mime='text/plain'):
            self.send_response(status)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Content-Type', mime)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == '/xp25-network-proof':
                self.respond(200, b'XP25-ISOLATED-HTTP-PASS\n')
            elif self.path.startswith('/local.html') or self.path == '/':
                self.respond(200, (args.fixtures/'local.html').read_bytes(), 'text/html; charset=utf-8')
            elif self.path.startswith('/persistence.html?phase='):
                self.respond(200, (Path(__file__).resolve().parents[1]/'tests/browser-persistence.html').read_bytes(), 'text/html; charset=utf-8')
            elif self.path == '/download.txt':
                self.respond(200, b'XP25 verified download fixture\n', 'application/octet-stream')
            else:
                self.respond(404,b'Not found')

        def do_POST(self):
            n=int(self.headers.get('Content-Length','0'))
            if self.path != '/browser-result' or n>8192:
                self.respond(400,b'Bad request');return
            body=self.rfile.read(n)
            result=json.loads(body)
            with Path('browser-js-results.jsonl').open('a') as f:
                f.write(json.dumps({'time':time.time(),'client':self.client_address,'result':result})+'\n')
            self.respond(200,b'OK')

        def log_message(self, fmt, *values):
            with Path('http.jsonl').open('a') as log:
                log.write(json.dumps({'time': time.time(), 'client': self.client_address,
                                      'message': fmt % values}) + '\n')

    providers=[]
    if args.provider_clients:
        import sys
        if not args.mock_key:parser.error('fixture mock key required')
        root=Path(__file__).resolve().parents[1]
        mock=subprocess.Popen([sys.executable,str(root/'vm/ai_mock_openai.py'),'--listen','127.0.0.1:9000','--key',args.mock_key,'--log','mock-openai.jsonl'],stdout=open('mock-openai.log','a'),stderr=subprocess.STDOUT)
        gateway_command=[sys.executable,str(root/'components/xp25-agent/gateway/xp25_gateway.py'),'--listen','10.25.0.1:8443','--clients',str(args.provider_clients),'--upstream','http://127.0.0.1:9000','--allow-insecure-loopback-upstream','--api-key-env','XP25_TEST_UPSTREAM_KEY','--log','gateway.jsonl','--timeout','30']
        provider=subprocess.Popen(gateway_command,stdout=open('gateway.log','a'),stderr=subprocess.STDOUT,env=dict(os.environ,XP25_TEST_UPSTREAM_KEY=args.mock_key))
        providers=[provider,mock]
    proxy=None
    if args.gateway:
        proxy=subprocess.Popen([__import__('sys').executable,str(Path(__file__).with_name('browser_proxy.py')),'--socket',str(args.gateway),'--parent-netns',args.parent_netns])
    server = HTTPServer(('10.25.0.1', 8080), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    with Path('dnsmasq.log').open('a') as dnslog, Path('qemu.log').open('a') as qlog:
        dns = subprocess.Popen(dns_command, stdout=dnslog, stderr=subprocess.STDOUT)
        qemu = None
        try:
            time.sleep(.25)
            if dns.poll() is not None:
                raise RuntimeError('dnsmasq failed; inspect dnsmasq.log')
            qemu = subprocess.Popen(command, stdout=qlog, stderr=subprocess.STDOUT)
            while qemu.poll() is None:
                if dns.poll() is not None:
                    raise RuntimeError('isolated DNS/DHCP service exited')
                time.sleep(.25)
            if qemu.returncode:
                raise RuntimeError('QEMU failed; inspect qemu.log')
        finally:
            if qemu is not None and qemu.poll() is None:
                qemu.terminate()
                qemu.wait(timeout=15)
            dns.terminate()
            dns.wait(timeout=10)
            for process in providers:
                process.terminate();process.wait(timeout=10)
            if proxy is not None:
                proxy.terminate();proxy.wait(timeout=10)
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    main()
