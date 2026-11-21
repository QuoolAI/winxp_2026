#!/bin/bash
# Serve Supermium in the XP25-Winlogon-Fix VM: a user service runs vm/browser_gateway.py on the
# XP25-Isolated bridge (10.25.0.1:3128) for the VM's reserved address only, tunnelling HTTPS to any
# public host and nothing else; visited host names are not logged. The VM's NIC gets the
# xp25-browser-gateway filter (the AI gateway rules plus port 3128). No other VM, network rule or
# filter changes. Needs qemu:///system access (libvirt group), no root.
#
# usage: install-browser-gateway.sh [VM] [MAC] [IP]
set -euo pipefail
VM=${1:-XP25-Winlogon-Fix}
MAC=${2:-52:54:00:25:00:07}
IP=${3:-10.25.0.26}
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
UNIT=$HOME/.config/systemd/user/xp25-browser-gateway.service
V="virsh -c qemu:///system"

# 1. The VM keeps one address, so the gateway can admit exactly it.
if ! $V net-dumpxml XP25-Isolated | grep -q "mac='$MAC'"; then
    $V net-update XP25-Isolated add ip-dhcp-host "<host mac='$MAC' name='xp25-winlogon-fix' ip='$IP'/>" --live --config
fi
# 2. The filter. The VM's interface is switched to it in its domain definition (applies at the next start).
$V nwfilter-define "$REPO/components/browser/host/xp25-browser-gateway.nwfilter.xml"
# 3. The gateway as a user service.
mkdir -p "$(dirname "$UNIT")" "$HOME/.local/state/xp25"
cat > "$UNIT" <<EOF
[Unit]
Description=XP25 browser gateway (HTTPS CONNECT for $VM at $IP)
After=network.target

[Service]
ExecStart=/usr/bin/python3 $REPO/vm/browser_gateway.py --listen 10.25.0.1:3128 --client $IP --allow-any-public --idle 300 --no-allow-log --log $HOME/.local/state/xp25/browser-gateway.jsonl
Restart=always
RestartSec=5
NoNewPrivileges=yes

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now xp25-browser-gateway.service
systemctl --user --no-pager status xp25-browser-gateway.service | head -5
