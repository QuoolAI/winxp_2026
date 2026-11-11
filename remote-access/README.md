# XP25-AI remote access through Guacamole

Operational scripts that make the home-hosted **XP25-AI** VM usable from a
browser through the existing Mise En Abyme (MEA) Guacamole deployment. Any
verified Newbie user can borrow it there, one user at a time. The milestone
record, with results and evidence, is
[docs/xp25-ai-remote-access.md](../docs/xp25-ai-remote-access.md).

```text
Browser (anywhere) --HTTPS + MEA sign-in--> MEA (CloudFront / ALB)
  --> Guacamole + guacd (ECS Fargate)
  --> relay EC2, private address:5900   (security group: Guacamole task only)
  <== SSH reverse tunnel, carried over AWS SSM Session Manager (outbound only)
  --> home KVM host: QEMU VNC on 127.0.0.1 (password)
  --> XP25-AI (one filtered NIC: DHCP/DNS/ICMP and the XP25 gateway port on the host)
```

There is no port forwarding on the home router and no public VNC, RDP, SSH or
guacd port, and no VPN client. Since 2026-11-11 the guest has one network
adapter. Its libvirt filter, `xp25-gateway-only`, lets it reach only the host's
DHCP and DNS, ICMP, and the XP25 gateway port. See
[docs/xp25-ai-gateway.md](../docs/xp25-ai-gateway.md).

## Files

| File | Runs on | Purpose |
| --- | --- | --- |
| `provision_relay.py` | operator workstation (AWS CLI) | Creates or finds the relay: EC2 role/profile (SSM core only), security group (VNC from the Guacamole task's group, HTTPS out), t4g.nano Amazon Linux 2023 with IMDSv2 and termination protection, and the IAM user the home host uses. Writes a record with no secrets. |
| `relay-user-data.sh` | relay, first boot | sshd on loopback only; the `xp25tunnel` account may open one remote forward on the relay's private address and nothing else; swap; daily security updates. |
| `home/install-home.sh` | home host, as root | Installs the pinned Session Manager plugin, the `xp25-tunnel` system account, `/etc/xp25-tunnel/*` and `xp25-tunnel.service`. `--uninstall` removes them. |
| `home/xp25-ssm-proxy` | home host | SSH `ProxyCommand`: a signed `ssm:StartSession` (`AWS-StartSSHSession`) with only the Python standard library, handed to the Session Manager plugin. |
| `home/xp25-tunnel-health` | home host | Logs whether the local VNC console answers before each tunnel attempt. |
| `home/xp25-tunnel.service` | home host | systemd unit: starts after the network, restarts forever every 15 s, runs as the unprivileged account with a read-only system and no capabilities. |

No private key, access key or VNC password is stored in this repository.

## Setup

1. **VM.** XP25-AI's VNC console listens on a fixed loopback port with a
   password, the VM has a USB tablet for absolute pointing, and its network
   adapter is removed (see `docs/virt-manager-xp25-ai.md`).
2. **Relay.** Generate the tunnel key outside the repository
   (`ssh-keygen -t ed25519 -N '' -f KEYFILE`), then run:

   ```sh
   python3 remote-access/provision_relay.py --guacamole-sg GUACAMOLE_TASK_SG \
     --subnet DESKTOP_SUBNET --public-key KEYFILE.pub \
     --record .work/<topic>/relay/record.json --access-key-out CREDENTIALS_FILE
   ```

3. **Home host.** Run as root:

   ```sh
   sudo bash remote-access/home/install-home.sh --record .work/<topic>/relay/record.json \
     --key KEYFILE --aws-credentials CREDENTIALS_FILE
   ```

   Delete the staging copies of the key and credentials afterwards.
4. **MEA.** Register the shared desktop with the MEA control function's
   `shared-desktop` action, giving the relay's private address, port 5900 and
   the VNC password (documented in the Type3-hypervisor-manager repository,
   `mvp/docs/SHARED_DESKTOPS.md`).

## Operating the tunnel

```sh
systemctl status xp25-tunnel            # state and the last log lines
journalctl -u xp25-tunnel -f            # live log: session opened, authenticated, forward set up
sudo systemctl restart xp25-tunnel      # reconnect now
sudo systemctl stop xp25-tunnel         # take XP25-AI offline for everyone
sudo systemctl start xp25-tunnel
```

The service starts at boot, reconnects within about 15 s after the SSH or SSM
session drops, and keeps retrying while AWS, the network or the VM is down.
One unit means one ssh process. `ExitOnForwardFailure` also stops a second
client from starting while the relay still holds the port. The relay drops a
dead session after 45 s, so a reconnect after a network cut can take up to a
minute.

| Symptom | Check |
| --- | --- |
| `xp25-tunnel-health: WARNING local VNC ... does not answer` | XP25-AI is shut off: `virsh -c qemu:///system start XP25-AI`. |
| `StartSession refused (400 ... TargetNotConnected)` | Relay stopped or SSM agent offline: `aws ssm describe-instance-information`. Start the instance. |
| `StartSession refused (...AccessDenied...)` or `InvalidSignature` | Wrong or rotated access key in `/etc/xp25-tunnel/aws-credentials`, or the host clock is wrong. |
| `Host key verification failed` | The relay was replaced. Update the pinned key in `/etc/xp25-tunnel/known_hosts` from a new provisioning record. |
| `remote port forwarding failed` | A previous session still holds the port; it clears within 45 s and the service retries. |
| Guacamole shows a VNC authentication error | The VNC password in libvirt and in the MEA registration differ; re-register. |

The relay's own state can be checked with SSM Run Command
(`ss -ltn` should show sshd on `127.0.0.1:22`, and port 5900 on the private
address while the tunnel is up).

## Rotation and removal

- **Tunnel key or access key:** create the new one, re-run `install-home.sh`
  with the new files, then remove the old public key from the relay or delete
  the old access key (`aws iam delete-access-key`).
- **VNC password:** change `passwd` on the VM's `<graphics>` element (effective
  at the next VM start), then re-register the shared desktop with the new value.
- **Take XP25-AI out of MEA:** register it again with `"enabled": false`.
- **Remove everything:** `install-home.sh --uninstall`; then, in AWS, disable
  termination protection and terminate the relay, and delete its security group,
  the role and instance profile, and the IAM user and its access keys.
