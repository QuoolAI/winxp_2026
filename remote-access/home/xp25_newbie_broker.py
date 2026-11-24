#!/usr/bin/env python3
"""A fresh XP25 for every Mise En Abyme Newbie connection.

Listens where the MEA reverse tunnel delivers the shared XP25 desktop's VNC
connections (127.0.0.1:5925). Every accepted connection gets a new disposable
VM: an empty qcow2 overlay of the frozen Newbie template
(remote-access/newbie_template.py), started as the transient libvirt domain
XP25-Newbie with the XP25 hardware profile, the XP25-Isolated network and the
xp25-browser-merlin filter (Internet through the browser gateway, MerlinAI
relay). The connection is relayed byte for byte to that VM's own VNC server,
which keeps the password MEA's Guacamole connection already uses. When either
side closes, the VM is destroyed and its overlay and COM1 log are deleted:
nothing a Newbie did reaches the next connection.

MEA lends the desktop to one user at a time, so there is one seat: a new
connection ends the previous VM before its own starts (a reconnecting browser
therefore also gets a fresh VM). A session also ends after --max-hours.

  xp25_newbie_broker.py --config FILE

FILE (JSON): listen, template, template_sha256, work, vnc_port,
vnc_password_file, domain, mac, network, filter, filter_parameters,
memory_mib, max_hours. The template and its backing file must be read-only.
Events are JSON lines on stdout (the user journal)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import subprocess
import sys
import threading
import time
from xml.sax.saxutils import quoteattr

VIRSH = ['virsh', '-c', 'qemu:///system']
DOMAIN = """<domain type='kvm'>
  <name>{name}</name>
  <description>Disposable XP25 desktop for one Mise En Abyme Newbie connection; created and destroyed by remote-access/home/xp25_newbie_broker.py.</description>
  <memory unit='MiB'>{memory}</memory>
  <vcpu placement='static'>1</vcpu>
  <os><type arch='i686' machine='pc-i440fx-8.2'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <cpu mode='custom' match='exact' check='none'><model fallback='forbid'>qemu32</model></cpu>
  <clock offset='localtime'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-i386</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='writeback'/>
      <source file={disk}/>
      <target dev='hda' bus='ide'/>
    </disk>
    <controller type='usb' index='0' model='piix3-uhci'/>
    <interface type='network'>
      <mac address={mac}/>
      <source network={network}/>
      <model type='rtl8139'/>
      <filterref filter={filter}>{parameters}</filterref>
    </interface>
    <serial type='file'><source path={serial}/><target port='0'/></serial>
    <input type='tablet' bus='usb'/>
    <graphics type='vnc' port='{port}' autoport='no' listen='127.0.0.1' passwd={password}>
      <listen type='address' address='127.0.0.1'/>
    </graphics>
    <audio id='1' type='none'/>
    <video><model type='vga' vram='16384' heads='1' primary='yes'/></video>
    <memballoon model='none'/>
  </devices>
</domain>
"""


def log(**event):
    event['time'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    print(json.dumps(event, sort_keys=True), flush=True)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def virsh(*args, check=True):
    r = subprocess.run(VIRSH + list(args), capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError('virsh %s: %s' % (args[0], r.stderr.strip()))
    return r


class Session:
    def __init__(self, broker, client, peer):
        self.b, self.client, self.peer = broker, client, peer
        self.id = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + secrets.token_hex(3)
        self.disk = broker.work / ('newbie-%s.qcow2' % self.id)
        self.serial = broker.work / ('newbie-%s.serial.log' % self.id)
        self.vm = None
        self.closed = threading.Event()

    def start(self):
        c = self.b.cfg
        subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(self.b.template),
                        str(self.disk)], check=True)
        parameters = ''.join("<parameter name=%s value=%s/>" % (quoteattr(k), quoteattr(str(v)))
                             for k, v in sorted(c['filter_parameters'].items()))
        xml = DOMAIN.format(name=c['domain'], memory=int(c['memory_mib']), disk=quoteattr(str(self.disk)),
                            mac=quoteattr(c['mac']), network=quoteattr(c['network']), filter=quoteattr(c['filter']),
                            parameters=parameters, serial=quoteattr(str(self.serial)), port=int(c['vnc_port']),
                            password=quoteattr(self.b.password))
        definition = self.b.work / ('newbie-%s.xml' % self.id)
        fd = os.open(definition, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(xml)
        try:
            virsh('create', str(definition))
        finally:
            definition.unlink()
        started = time.time()
        while True:
            try:
                self.vm = socket.create_connection(('127.0.0.1', int(c['vnc_port'])), 5)
                break
            except OSError:
                if time.time() - started > 20:
                    raise
                time.sleep(0.3)
        log(event='vm_started', session=self.id, peer=self.peer, seconds=round(time.time() - started, 1))

    def pump(self):
        """Relay until either side closes, the session is stopped or it reaches max_hours."""
        deadline = time.time() + float(self.b.cfg.get('max_hours', 8)) * 3600
        socks = [self.client, self.vm]
        reason = 'closed'
        try:
            while not self.closed.is_set():
                if time.time() > deadline:
                    reason = 'max_hours'
                    break
                ready, _, _ = select.select(socks, [], [], 1)
                for s in ready:
                    data = s.recv(65536)
                    if not data:
                        reason = 'client_closed' if s is self.client else 'vm_closed'
                        raise EOFError
                    (self.vm if s is self.client else self.client).sendall(data)
        except (EOFError, OSError):
            pass
        if self.closed.is_set():
            reason = 'replaced'
        return reason

    def stop(self):
        self.closed.set()
        for s in (self.client, self.vm):
            if s:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def cleanup(self):
        for s in (self.client, self.vm):
            if s:
                s.close()
        r = virsh('destroy', self.b.cfg['domain'], check=False)
        for path in (self.disk, self.serial):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        return r.returncode == 0


class Broker:
    def __init__(self, cfg):
        self.cfg = cfg
        self.template = Path(cfg['template']).resolve()
        self.work = Path(cfg['work']).resolve()
        self.password = Path(cfg['vnc_password_file']).read_text().strip()
        self.lock = threading.Lock()
        self.current = None
        self.current_done = None

    def check(self):
        info = json.loads(subprocess.run(['qemu-img', 'info', '-U', '--backing-chain', '--output=json',
                                          str(self.template)], capture_output=True, text=True, check=True).stdout)
        for image in info:
            if os.stat(image['filename']).st_mode & 0o222:
                raise SystemExit('%s is writable; the template chain must be frozen' % image['filename'])
        if sha(self.template) != self.cfg['template_sha256']:
            raise SystemExit('template hash differs from the configuration')
        if not 6 <= len(self.password) <= 8:
            raise SystemExit('VNC password must be 6 to 8 characters')
        self.work.mkdir(parents=True, exist_ok=True)
        self.work.chmod(0o755)        # QEMU runs as libvirt-qemu and must reach the overlay by its path
        # A broker that stopped abruptly may have left its VM or overlay behind.
        if virsh('domstate', self.cfg['domain'], check=False).returncode == 0:
            virsh('destroy', self.cfg['domain'], check=False)
            log(event='stale_vm_destroyed', domain=self.cfg['domain'])
        for leftover in self.work.glob('newbie-*'):
            leftover.unlink()
            log(event='stale_file_removed', path=str(leftover))

    def handle(self, client, peer):
        with self.lock:
            if self.current:
                self.current.stop()
                self.current_done.wait(60)
            session = Session(self, client, peer)
            done = threading.Event()
            self.current, self.current_done = session, done
        started = time.time()
        log(event='session_start', session=session.id, peer=peer)
        reason = 'start_failed'
        try:
            session.start()
            reason = session.pump()
        except Exception as e:  # the VM could not be started: the client is closed, nothing is kept
            log(event='session_error', session=session.id, error=str(e)[-300:])
        finally:
            destroyed = session.cleanup()
            log(event='session_end', session=session.id, reason=reason, seconds=round(time.time() - started),
                vm_destroyed=destroyed)
            # A replacing connection holds the lock while it waits for this: signal first.
            done.set()
            with self.lock:
                if self.current is session:
                    self.current = None

    def serve(self):
        host, port = self.cfg['listen'].rsplit(':', 1)
        if host not in ('127.0.0.1', 'localhost'):
            raise SystemExit('the broker listens on loopback only')
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, int(port)))
        server.listen(4)

        def stop(*_):
            with self.lock:
                current, done = self.current, self.current_done
            if current:
                current.stop()
                done.wait(60)
            log(event='stopped')
            os._exit(0)
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        log(event='listening', listen=self.cfg['listen'], template=str(self.template), domain=self.cfg['domain'])
        while True:
            client, addr = server.accept()
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=self.handle, args=(client, '%s:%d' % addr), daemon=True).start()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--config', type=Path, required=True)
    a = p.parse_args()
    broker = Broker(json.loads(a.config.read_text()))
    broker.check()
    broker.serve()


if __name__ == '__main__':
    sys.exit(main())
