#!/usr/bin/env python3
"""Private CONNECT gateway for the XP25 browser.
Listens on a private UNIX socket (browser tests, reached from a namespace through
browser_proxy.py) or on a TCP address for a libvirt VM, accepting only the listed
client addresses. Accepts exactly listed public names on port 443, or with
--allow-any-public every DNS name; either way it resolves the name and verifies
every destination IP is global before connecting. Literal IPs, other ports and
other methods are refused. TLS is tunneled unchanged; requests, cookies and page
contents are never logged, and --no-allow-log leaves visited names out of the log.
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

IP_FREEBIND = 15


def relay(a,b,idle=30):
    sockets=[a,b]
    while True:
        readable,_,_=select.select(sockets,[],[],idle)
        if not readable:return
        for source in readable:
            data=source.recv(65536)
            if not data:return
            (b if source is a else a).sendall(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    where=p.add_mutually_exclusive_group(required=True)
    where.add_argument('--socket',type=Path,help='fresh private UNIX socket under .work')
    where.add_argument('--listen',help='HOST:PORT for a libvirt VM; requires --client')
    p.add_argument('--client',action='append',default=[],help='IPv4 address allowed to connect to --listen')
    names=p.add_mutually_exclusive_group(required=True)
    names.add_argument('--allow',action='append')
    names.add_argument('--allow-any-public',action='store_true',help='any DNS name that resolves only to global addresses')
    p.add_argument('--log',type=Path,required=True)
    p.add_argument('--idle',type=int,default=30,help='seconds without traffic before a tunnel closes')
    p.add_argument('--no-allow-log',action='store_true',help='do not record allowed connections')
    a=p.parse_args();allowed=set(a.allow or [])
    if a.socket and ('.work' not in a.socket.resolve().parts or a.socket.exists()):p.error('fresh private UNIX socket required')
    if a.listen and not a.client:p.error('--listen requires at least one --client')
    clients={str(ipaddress.IPv4Address(c)) for c in a.client}
    if not 5<=a.idle<=3600:p.error('--idle must be 5..3600 seconds')
    def write(row):
        with a.log.open('a') as f:f.write(json.dumps({'utc_epoch':time.time(),**row})+'\n')
    def deny(request,reason,host=None):
        write({'decision':'deny','reason':reason,'host':host})
        try:request.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
        except OSError:pass
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            request=self.request;request.settimeout(15);head=bytearray()
            if a.listen and self.client_address[0] not in clients:
                write({'decision':'deny','reason':'client_not_allowed','client':self.client_address[0]});return
            try:
                while not head.endswith(b'\r\n\r\n') and len(head)<4096:
                    part=request.recv(1)
                    if not part:return
                    head+=part
                first=bytes(head).split(b'\r\n',1)[0].decode('ascii')
                # Only CONNECT to a DNS name on port 443. The regex rejects
                # non-CONNECT verbs, other ports and malformed requests outright.
                m=re.fullmatch(r'CONNECT ([a-z0-9.-]+):443 HTTP/1\.[01]',first)
                host=m[1] if m else None
                if host is None:
                    deny(request,'malformed_or_wrong_method_or_port');return
                # Reject a literal IP as the CONNECT target: destinations are DNS
                # names only, so a direct-IP bypass can never match the policy.
                try:
                    ipaddress.ip_address(host);deny(request,'direct_ip_literal',host);return
                except ValueError:
                    pass
                if not a.allow_any_public and host not in allowed:
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
                    if not a.no_allow_log:write({'host':host,'port':443,'ip':peer,'decision':'allow'})
                    request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                    relay(request,upstream,a.idle)
            except (OSError,ValueError,UnicodeError) as e:
                write({'decision':'error','error':type(e).__name__})
    policy={'allow':'any public name' if a.allow_any_public else sorted(allowed),'port':443,'other_destinations':'deny','tls_interception':False}
    if a.socket:
        class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):daemon_threads=True
        with Server(str(a.socket),Handler) as server:
            a.socket.chmod(0o600)
            Path(str(a.socket)+'.policy.json').write_text(json.dumps({**policy,'listen':'private UNIX socket'},indent=2)+'\n')
            try:server.serve_forever()
            finally:a.socket.unlink(missing_ok=True)
        return
    host,_,port=a.listen.rpartition(':')
    class TCPServer(socketserver.ThreadingMixIn,socketserver.TCPServer):
        daemon_threads=True;allow_reuse_address=True
        def server_bind(self):
            # Bind the bridge address even before libvirt has created the bridge.
            self.socket.setsockopt(socket.SOL_IP,IP_FREEBIND,1);super().server_bind()
    with TCPServer((str(ipaddress.IPv4Address(host)),int(port)),Handler) as server:
        write({'decision':'start','policy':policy,'listen':a.listen,'clients':sorted(clients)})
        server.serve_forever()
if __name__=='__main__':main()
