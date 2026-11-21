#!/bin/bash
# Install (or remove) the XP25 companion gateway as a system service on the KVM host.
# Run as root, from the shell that holds the API key:
#   sudo --preserve-env=OPENAI_API_KEY bash components/xp25-agent/gateway/host/install-gateway-service.sh \
#        --clients ~/.config/xp25-ai/clients.json [--listen 10.25.0.1:8443]
#   sudo bash components/xp25-agent/gateway/host/install-gateway-service.sh --uninstall
#
# The API key comes from OPENAI_API_KEY, else it is prompted for (not echoed);
# a key installed earlier is kept when neither is given. The key and the
# clients file are copied to /etc/xp25-gateway (root only) and reach the
# service as systemd credentials. Re-run to update the gateway, the key, the
# clients or the listen address. Nothing secret is printed.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
etc=/etc/xp25-gateway

[[ $EUID -eq 0 ]] || { echo 'run as root (sudo)' >&2; exit 1; }
clients= listen= uninstall=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --clients) clients=$2; shift 2 ;;
    --listen) listen=$2; shift 2 ;;
    --uninstall) uninstall=1; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

if [[ $uninstall == 1 ]]; then
  systemctl disable --now xp25-gateway.service 2>/dev/null || true
  rm -f /etc/systemd/system/xp25-gateway.service
  systemctl daemon-reload
  rm -rf /usr/local/lib/xp25-gateway "$etc"
  echo 'xp25-gateway removed'
  exit 0
fi

if [[ -z $listen ]]; then
  listen=$( [[ -f $etc/gateway.env ]] && sed -n 's/^XP25_GATEWAY_LISTEN=//p' "$etc/gateway.env" || true)
  listen=${listen:-10.25.0.1:8443}
fi
[[ $listen =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$ ]] || { echo "bad --listen '$listen' (address:port)" >&2; exit 2; }
port=${listen##*:}
if [[ -n $clients ]]; then
  [[ -f $clients ]] || { echo "missing file: '$clients'" >&2; exit 2; }
  /usr/bin/python3 -I - "$clients" <<'EOF' || { echo 'clients file must be {"id": {"secret_hex": "<at least 32 hex digits>"}}' >&2; exit 2; }
import json, sys
clients = json.load(open(sys.argv[1]))
assert isinstance(clients, dict) and clients
assert all(len(bytes.fromhex(v['secret_hex'])) >= 16 for v in clients.values())
EOF
elif [[ ! -f $etc/clients.json ]]; then
  echo 'first install needs --clients FILE' >&2; exit 2
fi
# A gateway started by hand would hold the port and leave the service restarting.
if ! systemctl is-active --quiet xp25-gateway.service && [[ -n $(ss -Hltn "sport = :$port") ]]; then
  echo "TCP port $port is already in use. Stop the gateway you started by hand (Ctrl+C), then re-run." >&2
  ss -Hltnp "sport = :$port" >&2
  exit 1
fi

# 1. Settings and secrets, root only.
install -d -m 0700 -o root -g root "$etc"
[[ -n $clients ]] && install -m 0600 -o root -g root "$clients" "$etc/clients.json"
key=${OPENAI_API_KEY:-}
if [[ -z $key && ! -s $etc/openai-api-key ]]; then
  read -rsp 'OpenAI API key: ' key; echo
  [[ -n $key ]] || { echo 'no API key given' >&2; exit 2; }
fi
if [[ -n $key ]]; then
  (umask 077; printf '%s\n' "$key" > "$etc/openai-api-key.new")
  mv -f "$etc/openai-api-key.new" "$etc/openai-api-key"
fi
unset key OPENAI_API_KEY
cat > "$etc/gateway.env" <<EOF
# Read by xp25-gateway.service: the host address on the XP25 guests' libvirt
# network. ClippyAI's endpoint is http://$listen (or the network's DNS name).
XP25_GATEWAY_LISTEN=$listen
EOF
cat > "$etc/README" <<EOF
xp25-gateway: the XP25 companion gateway (xp25_gateway.py) for ClippyAI's
"XP25 gateway to OpenAI" provider, listening on $listen. It authenticates
every request with the client secrets in clients.json and calls the OpenAI
API with the key in openai-api-key, over verified TLS.
  systemctl status xp25-gateway       journalctl -u xp25-gateway -f
  systemctl restart xp25-gateway      systemctl stop xp25-gateway
The journal holds one JSON line per challenge, forwarded call or rejection
(never request or response bodies). Files: openai-api-key and clients.json
(root only, handed to the service as systemd credentials), gateway.env.
Installed from the winxp_2026 repository's components/xp25-agent/gateway.
EOF
chmod 0644 "$etc/gateway.env" "$etc/README"
install -d -m 0755 /usr/local/lib/xp25-gateway
install -m 0644 "$here/../xp25_gateway.py" /usr/local/lib/xp25-gateway/xp25_gateway.py
install -m 0644 "$here/xp25-gateway.service" /etc/systemd/system/xp25-gateway.service

# 2. Start now and at every boot.
systemctl daemon-reload
systemctl enable xp25-gateway.service >/dev/null
systemctl restart xp25-gateway.service
for _ in $(seq 20); do [[ -n $(ss -Hltn "sport = :$port") ]] && break; sleep 0.5; done
systemctl --no-pager --lines=0 status xp25-gateway.service || true
if /usr/bin/python3 -I -c 'import json, sys, urllib.request
r = json.load(urllib.request.urlopen("http://%s/xp25/v1/challenge" % sys.argv[1], timeout=5))
assert len(r["challenge"]) == 64' "$listen" 2>/dev/null; then
  echo "OK: the gateway answers on http://$listen"
else
  echo "NOTE: no answer on http://$listen yet. If the libvirt network is down the gateway starts"
  echo "serving when it comes up; otherwise see: journalctl -u xp25-gateway"
fi
