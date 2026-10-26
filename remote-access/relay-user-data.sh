#!/bin/bash
# First-boot configuration of the XP25 VNC relay (Amazon Linux 2023).
# provision_relay.py replaces @TUNNEL_PUBLIC_KEY@ and @VNC_PORT@ before launch.
#
# The relay only terminates the home host's SSH reverse tunnel:
#   - sshd listens on loopback; the home host reaches it through SSM Session
#     Manager (AWS-StartSSHSession), so the instance has no inbound SSH rule.
#   - The single account, xp25tunnel, may open one remote forward on this
#     instance's private address and nothing else: no shell, no TTY, no local
#     forwarding, no agent or X11 forwarding.
#   - Its security group admits that port only from the Guacamole task.
set -euo pipefail
token=$(curl -sS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
private_ip=$(curl -sS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/local-ipv4)
[[ $private_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]

useradd --system --create-home --home-dir /var/lib/xp25tunnel --shell /sbin/nologin xp25tunnel
install -d -m 700 -o xp25tunnel -g xp25tunnel /var/lib/xp25tunnel/.ssh
printf 'restrict,port-forwarding,permitlisten="%s:@VNC_PORT@" %s\n' "$private_ip" '@TUNNEL_PUBLIC_KEY@' \
  > /var/lib/xp25tunnel/.ssh/authorized_keys
chown xp25tunnel:xp25tunnel /var/lib/xp25tunnel/.ssh/authorized_keys
chmod 600 /var/lib/xp25tunnel/.ssh/authorized_keys

# Global settings go first (sshd keeps the first value it reads); the Match
# block goes at the very end of the main file so that it cannot capture any
# later directive.
cat > /etc/ssh/sshd_config.d/10-xp25-relay.conf <<EOF
ListenAddress 127.0.0.1
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AuthenticationMethods publickey
AllowUsers xp25tunnel
EOF
cat >> /etc/ssh/sshd_config <<EOF

# XP25 relay: the tunnel account may only open its one remote forward.
Match User xp25tunnel
    AllowTcpForwarding remote
    GatewayPorts clientspecified
    PermitListen $private_ip:@VNC_PORT@
    PermitOpen none
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    PermitTTY no
    ForceCommand /sbin/nologin
    ClientAliveInterval 15
    ClientAliveCountMax 3
EOF
sshd -t
systemctl restart sshd

# dnf needs more than a t4g.nano's 512 MiB: add 1 GiB of swap first.
if ! swapon --show=NAME --noheadings | grep -q /swapfile; then
  dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  echo '/swapfile none swap defaults 0 0' >> /etc/fstab
fi
# Security updates only, applied daily. Reboots stay manual.
dnf -y -q install dnf-automatic
sed -i -e 's/^upgrade_type *=.*/upgrade_type = security/' -e 's/^apply_updates *=.*/apply_updates = yes/' /etc/dnf/automatic.conf
systemctl enable --now dnf-automatic.timer
install -d -m 755 /var/lib/xp25-relay
echo "XP25_RELAY_READY private_ip=$private_ip" | tee /var/lib/xp25-relay/ready
