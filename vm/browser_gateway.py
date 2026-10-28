#!/usr/bin/env python3
"""Private, allowlisted CONNECT gateway for XP25 browser tests.
UNIX socket only on the host. Accepts exactly listed public names on port 443;
resolves and verifies global destination IPs before connecting. TLS is tunneled
unchanged; requests, cookies and page contents are never logged.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import select
import socket
import socketserver
import time


def relay(a,b):
    sockets=[a,b]
    while True:
        readable,_,_=select.select(sockets,[],[],30)
        if not readable:return
        for source in readable:
            data=source.recv(65536)
            if not data:return
            (b if source is a else a).sendall(data)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--socket',type=Path,required=True)
    p.add_argument('--allow',action='append',required=True);p.add_argument('--log',type=Path,required=True)
    a=p.parse_args();allowed=set(a.allow)
    if '.work' not in a.socket.resolve().parts or a.socket.exists():p.error('fresh private UNIX socket required')
    def deny(request,reason,host=None):
        with a.log.open('a') as f:f.write(json.dumps({'utc_epoch':time.time(),'decision':'deny','reason':reason,'host':host})+'\n')
        try:request.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
        except OSError:pass
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            request=self.request;request.settimeout(15);head=bytearray()
            try:
                while not head.endswith(b'\r\n\r\n') and len(head)<4096:
                    part=request.recv(1)
                    if not part:return
                    head+=part
                first=bytes(head).split(b'\r\n',1)[0].decode('ascii')
                # Only CONNECT to an allowlisted DNS name on port 443. The regex rejects
                # non-CONNECT verbs, other ports and malformed requests outright.
                m=re.fullmatch(r'CONNECT ([a-z0-9.-]+):443 HTTP/1\.[01]',first)
                host=m[1] if m else None
                if host is None:
                    deny(request,'malformed_or_wrong_method_or_port');return
                # Reject a literal IP as the CONNECT target: destinations are approved
                # DNS names only, so a direct-IP bypass can never match the allowlist.
                try:
                    ipaddress.ip_address(host);deny(request,'direct_ip_literal',host);return
                except ValueError:
                    pass
                if host not in allowed:
                    deny(request,'not_allowlisted',host);return
                # Resolve host-side (the guest has no public DNS). Every candidate IPv4
                # must be a global address; one private/loopback/link-local/metadata
                # answer (e.g. a DNS-rebind to 169.254.169.254 or 10.x) fails the whole
                # request. We then connect to one *validated* IP and never re-resolve.
                ips=[row[4][0] for row in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM)]
                if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
                    deny(request,'non_global_resolution',host);return
                target=ips[0]
                with socket.create_connection((target,443),timeout=15) as upstream:
                    # Validate the *actual* connected peer, not just the resolved name,
                    # against the validated set and the global-address rule (TOCTOU/rebind guard).
                    peer=upstream.getpeername()[0]
                    if peer!=target or peer not in ips or not ipaddress.ip_address(peer).is_global:
                        deny(request,'peer_target_mismatch',host);return
                    with a.log.open('a') as f:f.write(json.dumps({'utc_epoch':time.time(),'host':host,'port':443,'ip':peer,'decision':'allow'})+'\n')
                    request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                    relay(request,upstream)
            except (OSError,ValueError,UnicodeError) as e:
                with a.log.open('a') as f:f.write(json.dumps({'utc_epoch':time.time(),'decision':'error','error':type(e).__name__})+'\n')
    class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):daemon_threads=True
    with Server(str(a.socket),Handler) as server:
        a.socket.chmod(0o600)
        Path(str(a.socket)+'.policy.json').write_text(json.dumps({'allow':sorted(allowed),'port':443,'other_destinations':'deny','tls_interception':False,'listen':'private UNIX socket'},indent=2)+'\n')
        try:server.serve_forever()
        finally:a.socket.unlink(missing_ok=True)
if __name__=='__main__':main()
