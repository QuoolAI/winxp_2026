#!/usr/bin/env python3
"""Namespace-side TCP to UNIX connector; requires a private isolated namespace."""
import argparse
import os
from pathlib import Path
import socket
import socketserver
from browser_gateway import relay

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--socket',type=Path,required=True);p.add_argument('--parent-netns',required=True)
    a=p.parse_args()
    if os.readlink('/proc/self/ns/net')==a.parent_netns:p.error('isolated namespace required')
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            if self.client_address[0]!='10.25.0.10':return
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as upstream:
                upstream.connect(str(a.socket));relay(self.request,upstream)
    class Server(socketserver.ThreadingMixIn,socketserver.TCPServer):daemon_threads=True;allow_reuse_address=True
    with Server(('10.25.0.1',3128),Handler) as server:server.serve_forever()
if __name__=='__main__':main()
