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


if __name__ == '__main__':
    unittest.main()
