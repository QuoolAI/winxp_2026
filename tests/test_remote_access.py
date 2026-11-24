"""Static checks of the XP25-AI remote-access scripts (remote-access/)."""
import configparser
import importlib.machinery
import importlib.util
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / 'remote-access'


class RemoteAccessScriptTests(unittest.TestCase):
    def test_shell_scripts_parse(self):
        for name in ('relay-user-data.sh', 'home/install-home.sh', 'home/xp25-tunnel-health'):
            r = subprocess.run(['bash', '-n', str(REMOTE / name)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, name + r.stderr)

    def test_relay_allows_only_the_one_remote_forward(self):
        text = (REMOTE / 'relay-user-data.sh').read_text()
        drop_in, match = text.split('cat >> /etc/ssh/sshd_config <<EOF', 1)
        for line in ('ListenAddress 127.0.0.1', 'PasswordAuthentication no', 'AllowUsers xp25tunnel'):
            self.assertIn(line, drop_in)
        # The Match block is appended to the main file, never left in a drop-in
        # where it could capture later directives.
        self.assertNotIn('Match User', drop_in)
        for line in ('AllowTcpForwarding remote', 'PermitListen $private_ip:@VNC_PORT@', 'PermitOpen none',
                     'PermitTTY no', 'ForceCommand /sbin/nologin', 'AllowAgentForwarding no', 'X11Forwarding no'):
            self.assertIn(line, match)
        self.assertIn('restrict,port-forwarding,permitlisten=', text)

    def test_tunnel_unit_is_unprivileged_and_restarts(self):
        unit = configparser.ConfigParser(strict=False, interpolation=None)
        unit.optionxform = str
        unit.read(REMOTE / 'home' / 'xp25-tunnel.service')
        service = unit['Service']
        self.assertEqual(service['User'], 'xp25-tunnel')
        self.assertEqual(service['Restart'], 'always')
        self.assertEqual(service['NoNewPrivileges'], 'yes')
        self.assertEqual(service['CapabilityBoundingSet'], '')
        self.assertEqual(service['ProtectSystem'], 'strict')
        self.assertEqual(unit['Unit']['StartLimitIntervalSec'], '0')

    def test_ssm_proxy_signature_is_stable(self):
        loader = importlib.machinery.SourceFileLoader('xp25_ssm_proxy', str(REMOTE / 'home' / 'xp25-ssm-proxy'))
        spec = importlib.util.spec_from_loader('xp25_ssm_proxy', loader)
        proxy = importlib.util.module_from_spec(spec)
        loader.exec_module(proxy)
        self.assertTrue(callable(proxy.start_session))
        self.assertEqual(proxy.PLUGIN.rsplit('/', 1)[-1], 'session-manager-plugin')

    def test_no_secrets_in_scripts(self):
        material = re.compile(r'BEGIN OPENSSH PRIVATE KEY|\bA[KS]IA[0-9A-Z]{16}\b|aws_secret_access_key = [A-Za-z0-9/+]{40}')
        for path in REMOTE.rglob('*'):
            if path.is_file():
                self.assertIsNone(material.search(path.read_text(errors='replace')), str(path))


def load_broker():
    spec = importlib.util.spec_from_file_location('xp25_newbie_broker', REMOTE / 'home' / 'xp25_newbie_broker.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NewbieBrokerTests(unittest.TestCase):
    """The broker without libvirt: virsh and qemu-img are replaced, the VM's VNC server is a local socket."""

    def setUp(self):
        import json
        import socket
        import tempfile
        self.broker_mod = load_broker()
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / 'pass').write_text('ab"c<1&\n')
        self.vm = socket.socket()
        self.vm.bind(('127.0.0.1', 0))
        self.vm.listen(4)
        self.cfg = {'listen': '127.0.0.1:0', 'template': str(d / 'template.qcow2'), 'template_sha256': '0' * 64,
                    'work': str(d / 'vms'), 'vnc_port': self.vm.getsockname()[1], 'vnc_password_file': str(d / 'pass'),
                    'domain': 'XP25-Newbie', 'mac': '52:54:00:25:00:09', 'network': 'XP25-Isolated',
                    'filter': 'xp25-browser-merlin', 'filter_parameters': {'GATEWAY_IP': '10.25.0.1', 'RELAY_PORT': '8740'},
                    'memory_mib': 1024, 'max_hours': 1}
        self.calls, self.defined = [], []
        broker_mod = self.broker_mod

        def virsh(*args, check=True):
            self.calls.append(args)
            if args[0] == 'create':
                self.defined.append(Path(args[1]).read_text())
            return subprocess.CompletedProcess(args, 0, '', '')

        def qemu_img(cmd, check=True, **kw):
            Path(cmd[-1]).write_bytes(b'overlay')
            return subprocess.CompletedProcess(cmd, 0, b'', b'')
        broker_mod.virsh = virsh
        broker_mod.subprocess = type('S', (), {'run': staticmethod(qemu_img), 'CompletedProcess': subprocess.CompletedProcess})
        self.json = json

    def tearDown(self):
        self.vm.close()
        self.tmp.cleanup()

    def test_domain_definition_is_escaped_and_uses_the_newbie_network(self):
        import xml.etree.ElementTree as ET
        import socket
        broker = self.broker_mod.Broker(self.cfg)
        broker.work.mkdir()
        client, peer = socket.socketpair()
        session = self.broker_mod.Session(broker, client, 'test')
        session.start()
        dom = ET.fromstring(self.defined[0])
        self.assertEqual(dom.find('name').text, 'XP25-Newbie')
        self.assertEqual(dom.find('./devices/graphics').get('passwd'), 'ab"c<1&')
        self.assertEqual(dom.find('./devices/graphics').get('listen'), '127.0.0.1')
        self.assertEqual(dom.find('./devices/interface/source').get('network'), 'XP25-Isolated')
        self.assertEqual(dom.find('./devices/interface/filterref').get('filter'), 'xp25-browser-merlin')
        self.assertEqual(dom.find('./devices/disk/source').get('file'), str(session.disk))
        self.assertEqual(list(broker.work.glob('*.xml')), [], 'the definition with the password is removed')
        accepted, _ = self.vm.accept()
        client.close()
        peer.close()
        accepted.close()
        self.assertTrue(session.cleanup())
        self.assertFalse(session.disk.exists())
        self.assertIn(('destroy', 'XP25-Newbie'), self.calls)

    def test_bytes_are_relayed_and_the_vm_is_destroyed_when_the_client_leaves(self):
        import socket
        import threading
        broker = self.broker_mod.Broker(self.cfg)
        broker.work.mkdir()
        client, far = socket.socketpair()
        done = threading.Thread(target=broker.handle, args=(client, 'test'))
        done.start()
        vm_side, _ = self.vm.accept()
        vm_side.sendall(b'RFB 003.008\n')
        self.assertEqual(far.recv(12), b'RFB 003.008\n')
        far.sendall(b'RFB 003.008\n')
        self.assertEqual(vm_side.recv(12), b'RFB 003.008\n')
        far.close()
        done.join(10)
        self.assertFalse(done.is_alive())
        self.assertIn(('destroy', 'XP25-Newbie'), self.calls)
        self.assertEqual(list(broker.work.iterdir()), [])
        vm_side.close()

    def test_listens_on_loopback_only_and_needs_a_frozen_template(self):
        broker = self.broker_mod.Broker(dict(self.cfg, listen='0.0.0.0:5925'))
        with self.assertRaises(SystemExit):
            broker.serve()
        template = Path(self.cfg['template'])
        template.write_bytes(b'x')
        template.chmod(0o644)
        self.broker_mod.subprocess = subprocess
        broker = self.broker_mod.Broker(self.cfg)
        with self.assertRaises(SystemExit):
            broker.check()       # a writable template is refused

    def test_broker_unit_runs_as_the_user_and_restarts(self):
        unit = configparser.ConfigParser(strict=False, interpolation=None)
        unit.optionxform = str
        unit.read(REMOTE / 'home' / 'xp25-newbie-broker.service')
        self.assertEqual(unit['Service']['Restart'], 'always')
        self.assertIn('xp25_newbie_broker.py --config', unit['Service']['ExecStart'])
        self.assertNotIn('User', unit['Service'])


if __name__ == '__main__':
    unittest.main()
