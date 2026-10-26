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
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            request=self.request;request.settimeout(15);head=bytearray()
            try:
                while not head.endswith(b'\r\n\r\n') and len(head)<4096:
                    part=request.recv(1)
                    if not part:return
                    head+=part
                first=bytes(head).split(b'\r\n',1)[0].decode('ascii')
                m=re.fullmatch(r'CONNECT ([a-z0-9.-]+):443 HTTP/1\.[01]',first)
                host=m[1] if m else None
                if host not in allowed:
                    request.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');return
                ips=[row[4][0] for row in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM)]
                if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):raise ValueError('non-global destination')
                with socket.create_connection((ips[0],443),timeout=15) as upstream:
                    with a.log.open('a') as f:f.write(json.dumps({'utc_epoch':time.time(),'host':host,'port':443,'ip':ips[0],'decision':'allow'})+'\n')
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
