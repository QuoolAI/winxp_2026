# Milestone 7B: secure Internet browsing — architecture and evidence

Continues the `xp25-browser` worktree. This records the security hardening work:
what is enforceable on NT 5.1, what was implemented and verified, and what remains
infeasible or outstanding. Milestone 7B is **not** accepted and no Internet-safe
production image is produced. Private evidence lives under `.work/browser-fix-20261026/`
(abbreviated `X`); no host paths, credentials or guest disks are committed.

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
