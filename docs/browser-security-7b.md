# Milestone 7B: secure Internet browsing — architecture and evidence

Continues the `xp25-browser` worktree. This records the security hardening work:
what is enforceable on NT 5.1, what was implemented and verified, and what remains
infeasible or outstanding. Milestone 7B is **not** accepted and no Internet-safe
production image is produced. Private evidence lives under `.work/browser-fix-20261026/`
(abbreviated `X`); no host paths, credentials or guest disks are committed.

## Phase 1 — host-enforced network containment: DEPLOYED and VERIFIED (2026-10-28)

Secure, controlled Internet access was built and tested end-to-end, with every
restriction verified **independently from the Linux host** (packet capture, firewall
drop counters, gateway decision log) — not from a browser timeout. It uses a network
namespace plus namespace-local nftables and a host CONNECT gateway; **no sudo and no
change to any global/host firewall rule**, so the Ubuntu host, home LAN, `XP25-AI`
VM, Mise En Abyme/Guacamole (LXD), the SSH tunnel and other libvirt networks are
untouched. Evidence under `X7b = .work/browser-7b-20261028/`.

### Network architecture (default-deny by construction)
The disposable guest runs inside `unshare --user --map-root-user --net` (`browser_network.py`).
The namespace starts with only `lo`; a tap `xp25tap` is created at `10.25.0.1/24`.
There is **no uplink, no bridge to the host, no default route, `ip_forward=0`, and no
public DNS** (dnsmasq answers only `xp25.test`, `--no-resolv`). The guest (DHCP
`10.25.0.10`) can therefore reach *only* `10.25.0.1`. Its **sole** path off-namespace
is an in-namespace proxy `10.25.0.1:3128` (`browser_proxy.py`, accepts only
`10.25.0.10`) that relays over a **UNIX-domain socket** to the host gateway — a
filesystem IPC path, not a network route, so the guest's IP stack never touches the
host network, the LAN, other VMs or metadata. Verified: `X7b/runs/b7net-03/network-isolation.json`
shows `public_uplink:false`, `ip_forward:0`, routes = only `10.25.0.0/24`.

### Namespace-local firewall (nftables, default-deny, with drop counters)
`browser_network.py --firewall` installs an `inet` table `xp25iso` inside the namespace
(namespace-local → cannot affect the host). Input policy **drop**; accept only
`xp25tap` DHCP and `10.25.0.10→10.25.0.1` on DNS(53)/HTTP(8080)/proxy(3128)/gateway(8443);
all IPv6 dropped; forward policy drop. Counters are host-independent proof of
enforcement — in `X7b/runs/b7net-03/nft-counters.txt`: `guest_other_denied` = 23 pkts
dropped (the guest's NetBIOS broadcasts to `10.25.0.255`), `ipv6_to_guest_denied` =
12 pkts dropped, `forward_denied` = 0 (no routing attempts).

### HTTPS CONNECT gateway (host, allowlist-only, fail-closed)
`vm/browser_gateway.py` (UNIX socket only) permits `CONNECT <name>:443` **only** for
allowlisted DNS names, resolves host-side, requires every resolved IPv4 to be
**global** (rejecting private/loopback/link-local and the `169.254.169.254` metadata
address), connects to one validated IP and re-validates the connected peer
(TOCTOU/DNS-rebind guard), **rejects literal-IP CONNECTs** (no direct-IP bypass),
tunnels TLS unmodified (**end-to-end certificate validation preserved — no
interception**), and **fails closed** when unavailable (the namespace has no other
egress). Standalone host test with live DNS/TLS, `X7b/gw-test-02.log`: **8/8** —
`example.com:443` allowed (real TLS, cert CN `example.com`, `HTTP/1.1 200 OK`);
denied: non-allowlisted name, public direct-IP, metadata IP, loopback, port 22,
non-CONNECT GET, and an allowlisted name resolving to a non-global IP.

### Disposable guest and runtime security tests (KVM, two-vCPU/MP)
Base = the verified **7A experimental image** `XP25-Browser-Experimental.qcow2`
(SHA-256 `6cad84c6c39e056e24bb84165665e0c47bbf13ec1e433d0de43c3b37a63b101f`,
read-only), driven through a fresh throwaway overlay; the allowlist was
`example.com`/`www.example.com`/`example.org`/`example.net`; unrestricted browsing
stays disabled.

| Test | Result | Evidence |
| --- | --- | --- |
| **Positive**: approved HTTPS (`https://example.com/`) loads through the gateway | **PASS** — 2 gateway `allow` lines to resolved global IP `104.20.23.154`, 264 guest↔proxy packets, end-to-end TLS, clean guest shutdown | `X7b/runs/b7net-03`, `gw-run-01.log` |
| **Negative**: unapproved host blocked | **PASS** — gateway `deny not_allowlisted` (incl. real Chromium phone-home to `www.google.com`, `*.googleapis.com`, `*.gvt1.com`) | `X7b/gw-run-01.log` |
| **Negative**: home LAN / host services / other VMs / metadata unreachable | **PASS** — pcap shows **0 packets** leave `10.25.0.0/24`; no default route; metadata/direct-IP denied at the gateway | `X7b/runs/b7net-03/network.pcap` |
| **Negative**: unauthorized DNS blocked | **PASS** — only `xp25.test` resolvable locally; public names resolved only host-side by the gateway for allowlisted hosts | `network-isolation.json`, dnsmasq config |
| **Negative**: IPv6 bypass blocked | **PASS** — namespace has no IPv6 route; nft drops IPv6 (counter 12) | `nft-counters.txt` |
| **Negative**: gateway unavailable ⇒ no Internet | **PASS** — fail-closed by construction (sole egress is the gateway socket) | design + `b7net-01` (DHCP-bug run showed zero egress) |
| Direct-IP / DNS-rebinding bypass | **PASS** — literal-IP CONNECT rejected; allowlisted-name→non-global resolution rejected | `gw-test-02.log` |

### Browser-process containment re-verified on the 7A image (criterion 4)
`b7cont-01` (2026-10-28, 7A image, MP, `--firewall`) launched the browser through the
SAFER-token + Job-Object `XP25Browser.exe` launcher and ran the `browser_sandbox`
probe over the whole tree (`SANDBOX_PROCESS_COUNT=6`: root + 2 renderers + 2
utility + gpu). **Every one of the 6 processes was denied** system-file write, SYSTEM
process injection, admin file write and admin registry write — all `error=5`
(`PRIVBOUNDARY ... system_file_error=5 ... system_inject_error=5`, `BOUNDARY ...
file_error=5 registry_error=5`). The probe's own `baseline` process could do those
(so the denials are real, not environmental) and its `known_restricted` reference was
denied everything, validating the check. **Honest limit:** the browser processes can
still write their *own* user profile and open *peer user* processes
(`user_profile_write=1`, `shell_injection_rights=1`) — containment is at the
**admin/SYSTEM boundary (SAFER Normal User + Job Object)**, **not** a per-renderer
sandbox. Contained, not "fully sandboxed." Evidence: `X7b/runs/b7cont-01/serial.log`.

### Regression matrix (secure network config) — UP / MP / TCG
| Mode | OS boot + clean shutdown | Network isolation (host-verified) | Approved HTTPS in guest |
| --- | --- | --- | --- |
| **MP (two-vCPU KVM)** | **PASS** (`b7net-03`, guest-initiated shutdown) | **PASS** — 0 off-subnet leak, nft drops, all non-allowlisted denied | **PASS** — `example.com` 2 gateway allows, E2E TLS |
| **UP (single-vCPU KVM)** | **PASS** (`b7net-up-01`, clean shutdown) | **PASS** — 0 off-subnet leak | **NOT DEMONSTRATED** — single-vCPU browser cold-start too slow to navigate in-window (UI-bound >130 s, chrome alive, 0 proxy packets); positive proven on MP |
| **TCG (emulated)** | **PASS** (`b7tcg-01`, guest-initiated shutdown) | **PASS** — 15/15 shell checks, 0 off-subnet leak, nft dropped guest-other + IPv6 | n/a — practical non-DevTools path; browser navigation impractical under emulation (documented) |

### Status, remaining vulnerabilities, and rollback
Network-containment acceptance criteria 1–3, 6, 7 are **met and host-verified**, and
criterion 4 (browser-process containment) is **re-verified PASS on the 7A image**;
`XP25-AI` and all other agents' VMs were untouched throughout. **Not Internet-safe /
not accepted**: NT 5.1 has **no Chromium renderer sandbox** (Phase 2 below) and the
intermittent GPU-process `0x842214`/EGL cold-start fragility remains (Milestone 7A;
the `b7net-03` chrome log shows the usual benign XP startup churn — missing `mf.dll`,
EGL "no renderers", one child restart — before the page loaded). **Outstanding**: the
UP positive browser navigation (performance, not isolation — proven on MP) and the
full DevTools functional regression over the gateway (previously PASS in
`matrix-150-02`, not re-run this session). **Rollback is trivial and disposable**: every
run is a throwaway qcow2 overlay over a read-only base, the gateway/namespace exist
only for the run's lifetime, and nftables is namespace-local — discarding a
compromised environment is `rm -rf` of the `X7b/runs/<name>` overlay; the base images
and host firewall are byte-unchanged.

## Phase 2 verification (2026-11-10) — network-security verification and browser hardening

Continues Phase 1 without restarting development; all existing browser integration,
containment and regression functionality is preserved. Every result below is
observed **from the Linux host** (the gateway's own decision log, packet-level
`connect(2)` errno, nftables counters, and the guest's own serial records), and a
blocked request is always distinguished from an ordinary network failure. Evidence
root `X2 = .work/browser-7b2-20261110/` (zstd-compressed). The milestone stays
**experimental and not accepted**: NT 5.1 has no Chromium renderer sandbox and the
intermittent `0x842214` CHECK is unresolved. XP25 is **not** safe for unrestricted
Internet browsing.

### Task 1 — network-isolation bypass matrix (host-observed)

Two independent, reproducible host-side harnesses now gate the egress design.

**Gateway bypass matrix** (`tests/test_browser_gateway.py`, committed) drives the
real `vm/browser_gateway.py` over its private UNIX socket and asserts its own JSON
decision for every bypass class — **11/11**: a resolvable-but-non-allowlisted host
and an unresolvable host are both refused `not_allowlisted` (so the denial is policy,
not a DNS failure); literal public, metadata (`169.254.169.254`) and loopback IPs are
refused `direct_ip_literal`; an IPv6 literal, a non-443 port and a non-CONNECT verb
are refused by the strict grammar; an encoded-CRLF host is refused; an allowlisted
name that resolves to a non-global address is refused `non_global_resolution` (the
DNS-rebind / internal-pivot defense); and an approved HTTPS host connects with
**end-to-end TLS preserved** (the real `example.com` certificate reaches the client —
the gateway never terminates TLS). Evidence `X2/gateway-tests/gateway-bypass-matrix.json`.

**Namespace isolation probe** (`vm/network_isolation_probe.py`) runs inside the
*same* `unshare --user --map-root-user --net` isolation the guest runs in and attempts
every forbidden egress, recording the exact outcome — **12/12**, both with and without
the namespace nftables firewall (proving the containment is structural, not solely
nft): the public Internet, an alternative public DNS resolver, the host's own LAN
address, the home-LAN router, the libvirt `default` and LXD/docker bridges, the cloud
metadata address and public IPv6 are all `ENETUNREACH` (no route — contained, not a
timeout); the gateway proxy port with nothing listening is `ECONNREFUSED`
(fail-closed); and a bound control port is reachable (the probe discriminates). The
namespace holds exactly one route (`10.25.0.0/24`) and no IPv6 route. Because the
guest runs only inside this namespace and is a less-privileged tap client, anything
unreachable here is unreachable for the guest. Evidence `X2/isolation-fw/` and
`X2/isolation-nofw/`.

Mapping to the ten required checks: direct Internet without the gateway (1), host
management interfaces (2), home LAN / other libvirt/LXD nets (3), cloud metadata (4),
direct-IP bypass (5), DNS rebinding (6), redirects/unauthorized destinations (7, see
Task 2 — real Chromium phone-home denied at the gateway), IPv6 (8), alternative DNS
resolvers (9) and gateway-stopped (10) are each demonstrated with host-observed
evidence and an errno/decision that distinguishes a block from a failure.

### Task 2 — full functional regression through the HTTPS gateway (MP/two-vCPU KVM)

`vm/browser_matrix.py --mode mp` on the frozen 7A image
(`XP25-Browser-Experimental.qcow2` `6cad84c6…`, read-only overlay), with the browser's
HTTPS routed through the Phase-1 gateway (host allowlist = `example.com`,
`www.example.com` and the three `badssl.com` cert-test hosts). Run `X2/runs/b7reg-mp`,
genuine guest shutdown. **Every enumerated regression item passed:**

| Item | Result |
| --- | --- |
| JavaScript execution | PASS (`modern_javascript`) |
| Multiple tabs | PASS (`multiple_tabs`) |
| HTTPS certificate validation (through the gateway) | PASS — valid `example.com` loads; `expired`, `wrong.host` and `self-signed` badssl are each rejected with `net::ERR_CERT_*` (reached end-to-end, so the verdict is a real cert error) |
| File downloads | PASS (`download_completed`) |
| Browser profile persistence | PASS (`profile_persists`) across restart |
| Appearance/settings persistence | PASS (`appearance_setting_persists`) |
| Repeated navigation | PASS (local + HTTP fixtures, multi-tab) |
| Browser restart | PASS (reopen exit 0, persistence re-read) |
| Normal guest shutdown | PASS (`{"guest":true,"reason":"guest-shutdown"}`) |
| AI regression (62 cases) | PASS (`AI_PROBE_COMPLETE passes=55/0` and `passes=7/0`) |
| URL-policy block (public site) | PASS (`net::ERR_BLOCKED_BY_ADMINISTRATOR`) |

Host-side gateway decision log for the run (`X2/regression-gateway.log`),
independently corroborating isolation: **12 allows** to exactly the four approved
hosts (`example.com` ×2, `expired`/`wrong.host`/`self-signed.badssl.com`), and **51
denies** — **44 `not_allowlisted`** (real Chromium phone-home to `www.google.com`,
`accounts.google.com`, `*.googleapis.com`, `redirector.gvt1.com`, …, and
`www.wikipedia.org`) plus **7 `malformed_or_wrong_method_or_port`**. This is Task 1
check 7 (unauthorized/redirect destinations) proven with live browser traffic: every
destination the browser reached for that was not on the allowlist was refused.

**Two checks are not green and are reported honestly, not as passes:**
`rendered_ShellExecute_HTTP` and `rendered_ShellExecute_URL` produced no render
receipt. Root cause (from the gateway log): the ShellExecute/shell-association launch
path opens the browser *without* the explicit `--proxy-bypass-list` that the
DevTools-driven browser carries, so with the test-only system proxy set it sends the
internal `http://xp25.test` fixture to the gateway as a **plain (non-CONNECT) request**,
which the gateway correctly refuses (the 7 `malformed` denials). The ShellExecute
*launch itself* succeeded for all five verbs (`XP25_SHELLEXECUTE_{HTTP,HTTPS,HTML,HTM,URL}=0`,
rejected-scheme `=87`), and the `file://` HTML/HTM cases rendered. This is a
test-harness/proxy interaction, **not** a product defect (the shipping image ships no
system proxy — only the `URLBlocklist` policy) and **not** a security weakness (a
gateway refusing a non-CONNECT request is correct behaviour). Separately,
`full_regression_coverage` stays **false** because of the four long-standing
`not_tested` probe cases (`login_transition`, `legacy_games`, `security_mitigations`,
`shutdown`) — an unchanged, documented coverage gap, not converted to a pass.

### Task 3 — SAFER token + Job Object containment, re-verified on the 7A image

Fresh run `X2/runs/b7cont2-01` (MP, 7A image), the browser launched through both the
windowed launcher and a shell association, `browser_sandbox` run over the whole tree
after each. **6 browser processes per probe (root + renderers + utility + gpu); all
12 primary samples denied, `ERROR_ACCESS_DENIED` (5), on every privileged object:**
`system32` file write (12/12), SYSTEM-process injection (12/12), administrator file
write (12/12) and administrator registry write (12/12). The probe's controls
discriminate (a baseline token succeeds; a known-restricted token is denied), and the
guest inventory confirms **all 6 `chrome.exe` processes are `job_member=1`** in both
runs — with no breakaway flag, none can escape the Job Object. **Documented residual
(not hidden):** all 12 samples retain `user_profile_write=1` — a compromised renderer
can still write the *user's own profile* and message peer-user processes (no UIPI /
integrity levels on NT 5.1). This is the **admin/SYSTEM boundary (SAFER Normal User +
Job Object), not a per-renderer Chromium sandbox**; XP25 is contained, not "fully
sandboxed."

### Task 4 — 0x842214: review of the latest Supermium builds (no supported fix)

Read-only release-metadata review (`X2/gpu-0x842214-update-review.json`): the newest
official stable build is **v150-r2.02** (2026-11-05), the **same Chromium
`150.0.7871.255`** as the pinned R2.01; its changelog (a Win7 `SetDefaultDllDirectories`
fix and a bookmarks-bar/compact-ui fix) does not touch the gpu/child field-trial-handle
`TakeHandleOfType` CHECK. Upstream's own R2.01 notes state the Windows XP
"occasional process failures" solution **is still being worked on**. There is
therefore **no supported correction** in the latest builds; `0x842214` remains
separately tracked, unpatched, with no assertion disabled and no handle fabricated.
R2.02 is **not** adopted here — it is the same Chromium with no relevant fix, and a
build change belongs to Milestone 7A (and would require re-running its stability
matrix). Root cause unchanged (see Phase 3 / `browser-stability-security.md`).

### Task 5 — recovery verification

- **Disposable overlay discard + base integrity** (`X2/recovery/disposable-overlay.json`):
  a throwaway overlay of the read-only base is created, checked and `rm`-ed; the base
  stays `0444` and its SHA-256 is byte-identical before and after. PASS.
- **Clean image boots afterward** (`X2/runs/b7coldboot-01`): a fresh overlay of the
  7A base boots after all Phase-2 experiments, passes the shell-integration checks and
  shuts down normally — the base remains bootable and uncorrupted. PASS.
- **Gateway returns to a secure state after restart** (`X2/recovery/gateway-recovery.json`,
  **9/9**): before and after a stop/restart the gateway denies an unapproved host and
  allows the approved one; the socket is removed when stopped and a connect is refused
  (fail-closed) while it is down; the published policy is byte-identical across the
  restart; end-to-end TLS is preserved each time.
- **Isolation persists / is independent of host services**: the namespace isolation is
  per-run and namespace-local, so no shared host service governs it; the isolation
  probe is deterministic across fresh namespaces (identical 12/12 with and without the
  firewall). PASS by construction.
- **XP25-AI and Mise En Abyme unaffected**: host-state snapshots before and after the
  session (`X2/host-state/before`, `/after`) show the `XP25-AI` libvirt domain still
  running, the `default`/`XP25-Isolated` libvirt networks and LXD bridges unchanged,
  no global firewall rule added, and no sudo used throughout.

### Acceptance (Phase 2)

The gateway passes all required positive and negative network tests; Supermium runs
the complete practical regression through the gateway (every enumerated item green;
two shell-association render receipts and the four `not_tested` probe cases are the
only non-green checks, both reported as open, not as passes); existing containment is
re-verified functional; network restrictions survive a gateway restart and are
service-independent; disposable recovery is verified; and all unresolved limitations
(no NT 5.1 renderer sandbox; unresolved `0x842214`) are documented. **XP25 is not
classified as safe for unrestricted Internet browsing.** The environment is ready only
for *allowlisted* browsing of a small set of approved HTTPS hosts in a disposable,
host-contained guest — not for general Internet use. Committed locally; not pushed.

## Phase 2 — renderer isolation (priority)

### Why Supermium's per-renderer sandbox is off on NT 5.1

Supermium compiles the renderer sandbox **off on every pre-Windows-10 OS**. In
`content/renderer/renderer_main.cc` (v144-r5, lines 241–251) `need_sandbox` is set
`true` only on Windows 10+ (and then only with DirectWrite); the `else` branch sets
`need_sandbox = false`, so the renderer never lowers itself into a restricted
token. The in-tree comment attributes this to GDI/DirectWrite font-rendering
limitations under lockdown. Corroborating, `sandbox/win/src/target_services.cc`
`LowerToken()` calls `SetProcessIntegrityLevel`, a **Vista+** primitive; the
lockdown path assumes mandatory integrity levels that NT 5.1 does not have. This
decision is baked into `chrome.dll`, so the per-renderer sandbox cannot be
re-enabled from the `pwrp_k32` compatibility layer without rebuilding Chromium, and
the browser binary must not be modified. Evidence:
`X/sandbox-analysis-01/nt51-sandbox-capability.json`, and the upstream sources under
`.work/browser-stability-20261026/upstream-inspection/`.

### What NT 5.1 can and cannot enforce

Available on NT 5.1 (x86): restricted tokens (`CreateRestrictedToken`), SAFER/WinSafer
levels, Job Objects (process/memory caps, breakaway control, UI restrictions),
alternate desktops (`CreateDesktop`), and privilege removal. **Unavailable**
(Vista+/Win8+/Win10+): mandatory integrity levels / low-IL, AppContainer / LowBox,
process-mitigation policies, Win32k lockdown, and UIPI cross-process message
filtering. A compromised process on NT 5.1 therefore cannot be integrity-isolated
or AppContainer-sandboxed; only token, job and desktop boundaries apply.

### Implemented: documented alternative containment architecture

Because the per-renderer sandbox is unavailable, XP25 contains the **whole browser
process tree** from its launcher `XP25Browser.exe` (`components/browser/browserctl.c`),
which every XP25 entry point (Start menu, shortcuts, shell associations) routes
through. Since Supermium does not restrict its own children, the browser root's
token and job are inherited by every renderer, GPU and utility child:

- **Restricted token** — SAFER Normal User: the Administrators SID becomes
  deny-only and privileges are reduced to `SeChangeNotify`. Launch fails closed if
  the token cannot be built; there is no unrestricted `CreateProcessW` fallback.
- **Job Object** — the root is created `CREATE_SUSPENDED`, assigned to a job, then
  resumed, so children join the job before any are spawned. Limits: active-process
  cap (96), total job-memory cap (1536 MiB), `DIE_ON_UNHANDLED_EXCEPTION`, and **no
  breakaway flag** so no child can escape the job. No `KILL_ON_JOB_CLOSE`, so the
  tree survives the transient launcher and the job is destroyed when the tree exits.

UI job restrictions (clipboard/desktop/handle isolation) are deliberately **not**
applied: the browser root needs desktop and GDI access on NT 5.1, and per-renderer
UI lockdown is a Chromium-broker capability that is compiled off here. Running the
browser on an alternate desktop is possible on NT 5.1 but is not enabled by default
because it would hide the browser from the interactive/Guacamole desktop.

### Verified (live MP KVM guest, `X/runs/fcontain150-mp-02`)

Launched via both the windowed launcher and a shell association, every process in
the browser tree (confirmed `member=1` in the job; non-browser processes
`member=0`) is **denied**, with `ERROR_ACCESS_DENIED` (5):

- writing an administrator-only file and registry key (`BOUNDARY … file_write=0
  error=5 registry_write=0 error=5`);
- writing under `%WINDIR%\system32` (`PRIVBOUNDARY … system_file_write=0 error=5`);
- opening a SYSTEM process (`services.exe`) for VM-write/thread injection
  (`PRIVBOUNDARY … system_inject=0 error=5`).

A known-restricted control token is denied the same objects while a baseline
unrestricted token succeeds, so the probe discriminates. Pages still render under
the token+job (JavaScript receipts recorded). The negative tests are
`tests/guest/browser_sandbox.c`; the probe duplicates and impersonates the observed
browser tokens in the probe process without injecting browser code.

### Residual risk (documented, not hidden)

This is process-tree containment, **not** per-renderer isolation. A compromised
renderer shares the browser's token, so it can read and write the **user's own
profile**, and — with no UIPI or integrity levels on NT 5.1 — can send window
messages on the shared desktop. It cannot write admin/system files or registry,
inject into SYSTEM processes, or break out of the job. Because meaningful
per-renderer isolation is not achievable on NT 5.1, the experimental image keeps
unrestricted Internet browsing **disabled by default** (see Phase 4).

## Phase 1 — host-enforced network isolation (architecture)

Requirement 8 is "enforced by the Linux host, not solely inside XP25." The
available privileges are the `libvirt` and `docker` groups but **no passwordless
root**, so custom host nftables/iptables rules and a libvirt NAT network with
strict egress filtering cannot be installed directly. The enforceable, root-free
model already used by the lab is stronger for default-deny: each test guest runs
in a fresh **network namespace with no uplink, default route or forwarding**
(`vm/browser_network.py` under `unshare --user --map-root-user --net`), and the
**only** egress is an allowlisted host-side CONNECT gateway (`vm/browser_gateway.py`)
that accepts exactly the named HTTPS destinations on port 443, resolves them on the
host, **rejects non-global (RFC1918/link-local/metadata) addresses**, and tunnels
TLS unchanged. The guest cannot reconfigure its way out because it has no route to
anything but the gateway socket.

Mapped to the Phase 1 requirements: no guest→host service access, no host-LAN
access, no other-network access, no cloud metadata endpoint, no inbound, HTTPS-only
egress, no SSH/SMB/RDP tunnelling (CONNECT :443 only), host-enforced, and no IPv6
uplink in the namespace. A libvirt NAT network with equivalent host firewall rules
is the alternative if root becomes available; it is **not** implemented here, and
that limitation is explicit. The existing `XP25-Isolated` and `default` libvirt
networks and the `XP25-AI` domain are untouched.

## Phase 3 — 0x842214 GPU-process handle CHECK

Investigated in the previous checkpoint (see `browser-stability-security.md`):
the gpu-process reads its inherited `--field-trial-handle` value as a `File`, not
the field-trial `Section`, at `TakeHandleOfType`. A native `browser_inherit` probe
shows progwrp's handle-list inheritance preserves a listed Section's value and type
on XP25 and stock SP3, and the crash reproduces on stock SP3 — a browser
gpu-process handle-lifetime defect, intermittent, with no safe compat-layer fix
(the CHECK is a real type-confusion guard and is not suppressed). It does not affect
the containment boundaries above, which are enforced by the inherited token and job
regardless.

## Phase 4 — secure browser configuration (status)

The production launch arguments (`browser_config.py`, `browserctl.c
launch_arguments`) enable TLS verification (no certificate-bypass flag), carry **no
`--no-sandbox`** and **no `--remote-debugging-port`** (remote debugging and the test
bridge exist only in the test media, never the install image), select software
rendering on the verified VGA profile, and the installer writes the default
Internet-block policy (`URLBlocklist=*` with a local/internal/lab allowlist) under
`HKLM\SOFTWARE\Policies\Supermium`. Profile data is isolated from privileged
accounts by the restricted token (the tree runs as the deny-only-admin user).
Update policy is metadata-only and documented (`check_browser_update.py`). Remaining
Phase 4 hardening (extension/plugin allowlisting, legacy-protocol disables) is
outstanding and tracked here, not silently claimed.

## Phase 5 — disposable environment (status)

The lab already embodies the core of this: an immutable, hash-pinned base image is
never written (each run is a fresh qcow2 overlay with its own name, MAC and private
QMP socket, created via `qemu-img create -b`), failed runs are frozen read-only with
a `failure.json` and never repaired, and normal runs end on a verified guest
shutdown. Concurrent-write protection is inherent (each overlay is distinct and the
base is read-only). A dedicated snapshot-rollback/cleanup tool and a documented
clean-baseline restoration for a future multi-user integration remain outstanding.

## Phases 6–7 — regression and controlled Internet (status)

The full functional regression already passes on KVM single- and two-vCPU with the
containment launcher in place (see `browser-stability-security.md`: JS, HTML,
multi-tab, HTTPS certificate matrix, download, Internet-block policy, restart
persistence, AI cases, normal shutdown; TCG renders but DevTools automation is
emulation-speed-limited). A full Phase 7 guest Internet session through the
allowlisted gateway — gated behind the security checks and using a disposable guest
with no sensitive data — is the remaining step and is not performed here.

## Acceptance

Not accepted. Verified: an explicitly documented alternative containment
architecture (restricted token + job, negative tests passing live), a host-enforced
default-deny egress architecture, and the full KVM functional regression. Open:
Chromium per-renderer sandbox is unavailable on NT 5.1 (documented, not faked); the
`0x842214` CHECK; a full Phase 7 Internet run; root-dependent libvirt firewalling;
and the remaining Phase 4/5 items. No security check is disabled, no API result is
faked, and no renderer-sandbox or kernel mitigation is claimed that is not actually
enforced.
