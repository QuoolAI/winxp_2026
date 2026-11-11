"""Static checks of the XP25 gateway's host deployment (components/xp25-agent/gateway/host/)."""
import re
import subprocess
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / 'components/xp25-agent/gateway/host'


def directives(path):
    pairs = []
    for line in path.read_text().splitlines():
        if '=' in line and not line.startswith(('#', '[')):
            pairs.append(tuple(line.split('=', 1)))
    return pairs


class GatewayServiceTests(unittest.TestCase):
    def test_installer_parses(self):
        r = subprocess.run(['bash', '-n', str(HOST / 'install-gateway-service.sh')], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_unit_is_unprivileged_gets_secrets_as_credentials_and_restarts(self):
        pairs = directives(HOST / 'xp25-gateway.service')
        unit = dict(pairs)
        for key, value in (('DynamicUser', 'yes'), ('Restart', 'always'), ('StartLimitIntervalSec', '0'),
                           ('NoNewPrivileges', 'yes'), ('CapabilityBoundingSet', ''), ('ProtectSystem', 'strict'),
                           ('ProtectHome', 'yes'), ('EnvironmentFile', '/etc/xp25-gateway/gateway.env')):
            self.assertEqual(unit[key], value, key)
        self.assertEqual({v for k, v in pairs if k == 'LoadCredential'},
                         {'openai-api-key:/etc/xp25-gateway/openai-api-key', 'clients.json:/etc/xp25-gateway/clients.json'})
        self.assertNotIn('OPENAI_API_KEY', (HOST / 'xp25-gateway.service').read_text())
        start = unit['ExecStart']
        for part in ('/usr/bin/python3 -I /usr/local/lib/xp25-gateway/xp25_gateway.py', '--listen ${XP25_GATEWAY_LISTEN}',
                     '--freebind', '--clients %d/clients.json', '--api-key-file %d/openai-api-key', '--log -'):
            self.assertIn(part, start)

    def test_installer_writes_what_the_unit_reads(self):
        text = (HOST / 'install-gateway-service.sh').read_text()
        for path in ('$etc/clients.json', '$etc/openai-api-key', '$etc/gateway.env',
                     '/usr/local/lib/xp25-gateway/xp25_gateway.py', '/etc/systemd/system/xp25-gateway.service'):
            self.assertIn(path, text)
        self.assertIn('etc=/etc/xp25-gateway', text)
        self.assertIn('listen=${listen:-10.25.0.1:8443}', text)
        self.assertIn('install -d -m 0700 -o root -g root "$etc"', text)
        self.assertIn("read -rsp 'OpenAI API key: ' key", text)            # prompted without echo
        self.assertIsNone(re.search(r'echo[^\n]*\$key', text))           # and never printed

    def test_nwfilter_allows_only_dhcp_dns_icmp_and_the_gateway_port(self):
        root = ET.parse(HOST / 'xp25-gateway-only.nwfilter.xml').getroot()
        self.assertEqual((root.get('name'), root.get('chain')), ('xp25-gateway-only', 'root'))
        self.assertEqual(root[-1].attrib, {'filter': 'no-other-l2-traffic'})   # everything else is dropped
        self.assertNotIn('$IP', ET.tostring(root, encoding='unicode'))       # independent of the guest address
        allowed = set()
        for rule in root.iter('rule'):
            self.assertEqual(rule.get('action'), 'accept')
            ip = rule.find('ip')
            peer = ip.get('dstipaddr' if rule.get('direction') == 'out' else 'srcipaddr')
            port = ip.get('dstportstart' if rule.get('direction') == 'out' else 'srcportstart')
            if ip.get('protocol') == 'udp' and {ip.get('srcportstart'), ip.get('dstportstart')} == {'67', '68'}:
                allowed.add('dhcp')
                continue
            self.assertEqual(peer, '$GATEWAY_IP')
            allowed.add((ip.get('protocol'), port))
        self.assertEqual(allowed, {'dhcp', ('udp', '53'), ('icmp', None), ('tcp', '$GATEWAY_PORT')})


if __name__ == '__main__':
    unittest.main()
