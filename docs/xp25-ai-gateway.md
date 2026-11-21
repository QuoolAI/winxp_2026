# XP25-AI and the XP25 gateway on the KVM host (2026-11-11)

**Result:** ClippyAI in the running XP25-AI VM reaches the OpenAI API through
the XP25 gateway on the KVM host. In ClippyAI Settings, *Test connection*
returned "Connected. The model replied: READY" (provider "XP25 gateway to
OpenAI", Responses API, `gpt-4.1-mini`). This is the first call from an XP25
guest to the real OpenAI service; earlier runs used a local test double.

The VM got a network adapter back. A libvirt network filter limits it to DHCP,
DNS and ICMP to the host, plus TCP to the gateway port. Everything else is
dropped at the guest's tap device.

A hardened system service for the gateway is in the repository and was tested
as a sandboxed user unit. It is **not installed**, because installing it needs
root on the host. Until then the gateway runs as the process started by hand.

## Why ClippyAI failed

- XP25-AI has had no network adapter since 2026-10-26
  ([remote access record](xp25-ai-remote-access.md)).
- ClippyAI's own diagnostics reported `tcp_connect 10.25.0.1:8443 - no
  connection within 3 seconds` and `XP25 gateway error [connect_failed]`
  (`01-before.png`).
- The gateway itself was fine. It was listening on `10.25.0.1:8443` on the
  `XP25-Isolated` bridge, but no guest was attached, so the bridge had no carrier.

## Change to the VM

| Setting | Before | After |
| --- | --- | --- |
| Network | none | RTL8139, MAC `52:54:00:25:00:05`, `XP25-Isolated`, PCI slot 3 (the MAC and slot it had before 2026-10-26) |
| Filter | — | `xp25-gateway-only`, `GATEWAY_IP=10.25.0.1`, `GATEWAY_PORT=8443` |
| Everything else | unchanged | unchanged (`inactive-before.xml` vs `inactive-after.xml` differ only by the interface) |

```bash
virsh -c qemu:///system nwfilter-define components/xp25-agent/gateway/host/xp25-gateway-only.nwfilter.xml
virsh -c qemu:///system attach-device XP25-AI nic.xml --live --config   # nic.xml: evidence directory
```

The NIC was hot-plugged into the running guest, with nobody connected to its
console and the Guacamole tunnel down. XP enumerated it without a wizard, and
dnsmasq leased `10.25.0.13` (`xp25-ai`) about 18 s later. The overlay and its
image-05 backing file are unchanged in role, and image-05 is still opened read-only.

## The network filter

`components/xp25-agent/gateway/host/xp25-gateway-only.nwfilter.xml` contains
only layer-2 (ebtables) rules, so they apply without `br_netfilter`, which is
not loaded on this host. It references no guest address, so a different DHCP
reservation or a different guest needs no change.

| Direction | Allowed |
| --- | --- |
| Guest → anywhere | DHCP (UDP 68 → 67) |
| Guest → `GATEWAY_IP` | DNS (UDP 53), ICMP, TCP `GATEWAY_PORT` |
| `GATEWAY_IP` → guest | the matching replies (UDP from 67 and 53, ICMP, TCP from `GATEWAY_PORT`), plus ARP |
| Anything else | dropped (`no-other-l2-traffic`); MAC spoofing is dropped as well (`no-mac-spoofing`) |

| Check | Result | Evidence |
| --- | --- | --- |
| DHCP through the filter | Lease `10.25.0.13`, hostname `xp25-ai` | `virsh net-dhcp-leases` |
| Filter bound | `vnet1` → `xp25-gateway-only` | `nwfilter-binding-list` |
| Host → guest ICMP | 3/3 replies | — |
| Host → guest TCP 139 and 445 | Time out | — |
| A/B: same TCP 139 probe with the filter removed from the live NIC, then restored (about 5 s without it) | Unfiltered: **connected**. Filtered again: times out, binding back. So the filter blocks this traffic, not the guest's firewall. | `filter-ab.txt` |
| Guest → gateway | *Test connection* succeeded. The host saw connections from `10.25.0.13:1036` and `:1037` to `:8443`. | `03-settings.png`, `04-test-result.png` |

Not tested: a guest-initiated connection to another host port. The rules are
symmetric, but only host-initiated blocked traffic was observed.

## Gateway changes

`xp25_gateway.py` gains three options. Without them, behaviour is unchanged.

- `--api-key-file PATH`: reads the key from a file (a systemd credential)
  instead of the environment.
- `--freebind`: on Linux, sets `IP_FREEBIND`, so the gateway can bind the
  bridge address before libvirt creates the bridge at boot. It keeps listening
  while the network is restarted.
- `--log -`: writes the JSON audit lines to standard output (the journal). As
  before, it never logs request or response bodies.

The test above went through the gateway started by hand from the previous
revision (`xp25_gateway.py` `c4f4b00e…5e7a`). The new revision is `deefecf8…3c9d`.

## The gateway as a system service

| File | SHA-256 | Purpose |
| --- | --- | --- |
| `gateway/host/xp25-gateway.service` | `64aed5bb…d505` | Systemd unit. Starts after the network and libvirtd, and restarts every 5 s forever. Runs as a dynamic user with no capabilities, a read-only system, no home directories, a seccomp `@system-service` filter and W^X memory. The API key and `clients.json` are handed over as credentials (`%d`). `systemd-analyze security`: exposure 1.5. |
| `gateway/host/install-gateway-service.sh` | `6e1b2875…21c3` | Run as root. It copies the gateway to `/usr/local/lib/xp25-gateway/`, the key and clients file to `/etc/xp25-gateway/` (root only), and writes `gateway.env` (listen address, default `10.25.0.1:8443`). It then enables and starts the unit, and fetches a challenge as a smoke test. It refuses to run while another process holds the port, never prints the key, and `--uninstall` removes everything. |
| `gateway/host/xp25-gateway-only.nwfilter.xml` | `601bb613…fe3a` | The filter above. |

To install, stop the gateway started by hand (Ctrl+C), then run this in the
same shell, which still has `OPENAI_API_KEY` exported:

```bash
sudo --preserve-env=OPENAI_API_KEY bash components/xp25-agent/gateway/host/install-gateway-service.sh \
  --clients ~/.config/xp25-ai/clients.json
journalctl -u xp25-gateway -f        # one JSON line per challenge, forwarded call or rejection
```

If the key is not in the environment, the installer prompts for it without
echoing. Re-running it updates the gateway, the key, the clients file or
`--listen`.

Verification without root:

- `systemd-analyze verify` passes.
- A runtime-only user unit generated from the real unit file (same
  `ExecStart`, credentials and sandboxing) started, read both credentials
  through `%d`, and accepted a signed request. It forwarded the request to
  `vm/ai_mock_openai.py`, which saw the right key, and returned a correctly
  signed reply. The journal held the startup line plus `challenge` and
  `forwarded`. User mode cannot run `DynamicUser`. `ProtectHome` was left out
  in user mode only, because there it hides `/run/user`, where user-mode
  credentials live.
- Verified TLS 1.3 to `api.openai.com` works under the unit's seccomp,
  address-family and W^X settings.

The installed system service itself has not been observed yet.

## When addresses change

- **The guest's address.** Nothing depends on it. The gateway authenticates
  each request by client ID and HMAC, not by source address, and the filter
  names only the host side. Any guest on `XP25-Isolated` that holds the client
  secret and has the filter can use the gateway.
- **The host's LAN address.** It is not involved. The gateway listens on the
  libvirt network's own address, `10.25.0.1`.
- **Re-addressing `XP25-Isolated` itself.** Change three things:
  - the service's listen address (`install-gateway-service.sh --listen`);
  - the filter's `GATEWAY_IP` (`virsh edit XP25-AI`);
  - ClippyAI's endpoint.

  ClippyAI accepts host names (`gethostbyname`), and the network's dnsmasq
  publishes the host as `xp25.test`. With `http://xp25.test:8443` as the
  endpoint, the guest would follow the DNS record. That name has not been
  tested from the guest; the endpoint is still `http://10.25.0.1:8443`.

## Security notes

- Whoever holds the XP25-AI seat, including any MEA user borrowing it through
  Guacamole while the tunnel runs, can use ClippyAI with the gateway, and so
  spends the OpenAI key. The gateway has no rate limit, spending cap or model
  allowlist. Set a usage limit on the OpenAI project that owns the key.
- The guest still cannot reach the LAN, the internet or the host's other
  services. Some of those listen on all addresses, including `10.25.0.1`: on
  2026-11-11 that was TCP 3389, 8123 and 18555. The filter is what keeps the
  guest away from them.
- The link between XP25 and the gateway stays unencrypted. It is authenticated
  and integrity-protected, and it never leaves the isolated bridge.
- The gateway started by hand runs as the desktop account, which is in the
  `docker` and `libvirt` groups. The installed service would run as an
  unprivileged dynamic user instead.
- XP25-Winlogon, now shut off, is on the same network without a filter. When
  it runs, it can reach those host services on `10.25.0.1`. This predates this
  change and is left as it was. The same `filterref` would close it.

## Evidence

`.work/xp25-ai-gateway-20261111/`:
- domain and network XML before and after;
- `nic.xml` and `nic-unfiltered.xml`, `nwfilter-defined.xml`;
- `attach.txt`, `filter-ab.txt`, screenshots `01`–`05`;
- `unit-test/` (the user-mode unit and its journal; test secrets only);
- `unittest-full.txt`: 65 host tests, 7 skipped for private inputs that this
  worktree does not have.
