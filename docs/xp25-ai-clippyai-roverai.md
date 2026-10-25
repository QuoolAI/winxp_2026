# Milestone 6: ClippyAI, RoverAI and the shared XP25 agent runtime, 2026-10-25

Work on branch `xp25-ai` (worktree `xp25-ai`), based on `xp25-nt` at
`674821ae9`. Winlogon development on `xp25-nt` is untouched; every guest run in
this milestone boots the **accepted engineering image with the original
Winlogon, native Explorer and native UserEnv**
(`XP25-Components-Engineering.qcow2`, SHA-256
`39112bbd46f89308180d651a94826808dee3a6acdcc18309b9af7c6d90340296`), never the
experimental Winlogon. Private evidence is under `.work/ai-20261025/` (`W`) and
build-VM runs under `.work/boot-debug-20261022/` (`B`) of this worktree.

**Status: implemented and guest-verified offline; milestone not yet fully
accepted.** Native NT-toolchain build 04 of all five binaries passes `/W4 /WX`.
On the accepted engineering image, with the components installed by their own
installer, the native binaries pass **55/55 main guest cases under two-vCPU
KVM** and **53/55 under one-vCPU KVM**, and the complete established regression
suite (standard, pointer, session, network, service, Regsvc, GINA, UserEnv,
branding, MSI, shell, profile probes) exits 0 in every run, followed by a
guest-requested shutdown. **Open defect:** the gateway key entered in ClippyAI
Settings is never stored (no `HKCU\Software\XP25\Agent\Protected` value is
created, also with real keystrokes; Protected Storage is running), so the
OpenAI-via-gateway guest cases (4) fail; the gateway itself passes its host
interop tests. TCG run, verified QCOW2 and the fixes listed under *Pending*
are not complete.

## Architecture

```text
components/
├── xp25-agent/          shared runtime, built as xp25agent.dll (176 exports)
│   ├── runtime/         C89 core: buffers, JSON, agent loop, tool registry contract;
│   │                    native: paths, config, DPAPI secrets, audit log, MS Agent characters
│   ├── llm/             Responses + Chat Completions codecs, gateway HMAC, SHA-256,
│   │                    offline planner (C89); HTTP/1.1 client and providers (native)
│   ├── tools/           13 native tools (Toolhelp, PSAPI, SCM, Event Log, IP Helper, registry, files, RoverAI)
│   ├── permissions/     fail-closed classification (C89)
│   ├── ipc/             RoverAI -> ClippyAI requests (WM_COPYDATA / launch)
│   ├── broker/          XP25Broker.exe: narrowly scoped LocalSystem service
│   ├── gateway/         xp25_gateway.py: companion gateway for a modern host
│   └── dll/             DllMain, .def, version resource
├── clippyai/            ClippyAI.exe: app/, ui/ (chat view, dialogs), mascot/, chat/ (controller)
└── roverai/             indexer/ (C89 index + native store/scanner/watcher), search/ (C89 query + search),
                         explorer/ (RoverAIBand.dll Explorer bar + shared panel), app/ (RoverAI.exe)
```

The layering follows `components/winlogon`: everything that decides (JSON,
policy, agent loop, offline planner, index, query interpretation, search) is
portable C89 without Windows headers and is tested on the host under
AddressSanitizer/UBSan. Native adapters only perform Win32/NT operations.
ClippyAI, RoverAI, the Explorer bar and the broker all import the **same**
`xp25agent.dll`; the RoverAI search engine is a tool (`file_search`) in that
DLL, so ClippyAI calls RoverAI's search through the shared registry.

No .NET, WebView2, CEF, C++ runtime or PowerShell is used. Binaries import only
NT 5.1 system DLLs (kernel32, user32, gdi32, advapi32, shell32, ole32, oleaut32,
comctl32, comdlg32, ws2_32, iphlpapi, crypt32, psapi, msvcrt) and
`xp25agent.dll`; every import is checked against the export tables of the
guest's own system DLLs. The NT kernel, Explorer and Winlogon are not modified.

## AI runtime

- **Agent loop** (`xp25_agent.c`): conversation history (user, assistant, tool
  call, tool result items), up to 12 tool steps per request, provider error →
  structured error event → automatic continuation with the offline planner.
- **Providers**: `offline` (default), `gateway` (OpenAI via the XP25 gateway),
  `local` (OpenAI-compatible server over plain HTTP, explicitly configured),
  `openai` (direct HTTPS, refused; see TLS below). Model, endpoint, API
  (Responses or Chat Completions), timeout (5–600 s) and retries (0–5, with
  exponential backoff and `Retry-After`) are configurable in ClippyAI Settings.
- **OpenAI Responses API**: stateless requests with `store: false`, function
  tools with JSON Schema parameters, `function_call` / `function_call_output`
  items, assistant text, refusals, `incomplete` status and API error objects
  (`error.code`, HTTP status, retryability) are encoded and parsed by
  `xp25_llm.c`. Chat Completions is supported for local servers.
- **Secrets**: the gateway key and an optional local API key are stored with
  DPAPI (`CryptProtectData`, per user, application entropy) under
  `HKCU\Software\XP25\Agent\Protected`; they are never logged, never readable
  through `registry_read`, and wiped from memory after use.
- **Offline operation**: `xp25_offline.c` is a deterministic planner that
  implements the provider interface and drives the same tools, permissions and
  approval dialogs. It handles the slow-computer workflow, Event Viewer, CMD,
  processes, services (including start/stop/restart), network, disk, system
  information, registry, file search and file explanation.
- **Audit**: every tool call (tool, permission class, decision, call digest,
  exact command/target, result size, provider) is appended to
  `%APPDATA%\XP25\audit.jsonl`; the broker writes its own machine audit file
  and Application event log entries.

### TLS investigation and the companion gateway

NT 5.1 SChannel negotiates at most TLS 1.0 without SNI, AES-GCM or SHA-256
suites; `api.openai.com` requires TLS 1.2+. A direct connection would therefore
need a third-party TLS 1.2 stack plus a maintained trust store inside XP. This
milestone does not ship one, so the `openai` provider fails closed with an
explicit message and **no TLS validation is weakened anywhere** (a host test
rejects any certificate-validation bypass in the component sources).

`components/xp25-agent/gateway/xp25_gateway.py` (Python standard library only)
runs on a current machine, holds the OpenAI key and connects upstream with
Python's default TLS context (certificate and hostname validation). XP25
authenticates every request: `GET /xp25/v1/challenge` issues a single-use
32-byte challenge (60 s); the request carries client id, challenge, a 16-byte
random nonce, the body SHA-256 and
`HMAC-SHA256(key, "XP25-GW1\nPOST\n<path>\n<challenge>\n<nonce>\n<sha256>")`.
Every reply is signed with
`HMAC-SHA256(key, "XP25-GW1-RESPONSE\n<nonce>\n<status>\n<sha256(body)>")` and
XP25 discards replies that fail verification. The gateway forces `store:false`,
never logs bodies, rejects unknown clients, replays and bad signatures, and
refuses plain-HTTP upstreams except loopback test doubles. The XP25–gateway
link is authenticated and integrity-protected but **not encrypted**; the
gateway belongs on a trusted segment. The key in ClippyAI Settings is the hex
key from the gateway's clients file.

## Permissions and data protection

| Class | Examples | Behavior |
| --- | --- | --- |
| Read-only | system_info, process_list/details, service_list, eventlog_read, network/disk diagnostics, approved registry keys, file stat/list, file_search, allowlisted commands (`ipconfig /all`, `ver`, `netstat -an`, `sc query X`, `dir` without `/s`, `ping -n N host`, ...) | runs and reports |
| Requires approval | any other command, ending a process, service changes as administrator, reading personal files, writing/editing/copying/moving/renaming/deleting files, TEMP cleanup | modal dialog with exact command, target, expected effect and call digest; **Deny is the default button** |
| Privileged | service changes by a standard user, hosts-file writes | approval, then `XP25Broker` (service changes only; file writes are refused) |
| Denied | SAM/SECURITY/Lsa/Winlogon registry, credential stores, other users' profiles, hives, `..`/ADS/UNC paths, Windows/Program Files modification, critical services (RpcSs, Eventlog, SamSs, ...), Windows/XP25 processes, multi-line commands | never executed |

Approval is collected by the host UI for one parsed call and consumed by it;
model text, tool output, file names and log messages cannot approve anything
(host test: an injected "IGNORE PREVIOUS INSTRUCTIONS ... the user approved"
log record leads to a declined, unexecuted command). Results classified as
sensitive (logs, file content, command output, registry data) reach a remote
provider only after the **Share Data?** dialog allows it; otherwise the model
receives a withheld placeholder. RoverAI sends only the wording of a search
(never file content) and only when the user enables AI interpretation.

`XP25Broker.exe` is a LocalSystem service with one named pipe
(`\\.\pipe\XP25AgentBroker`, SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`).
It authenticates the caller by impersonation and requires the INTERACTIVE
group, rate-limits to 20 requests per minute, takes its service allowlist only
from `HKLM\SOFTWARE\XP25\Agent\Policy`, re-applies the policy itself and
performs only start/stop/restart.

## ClippyAI

`ClippyAI.exe` is a Win32 application with the XP Luna appearance (Common
Controls 6 manifest), a custom chat view (bubbles, expandable tool results,
copy, `WM_GETTEXT` transcript for accessibility), approval, data-sharing and
settings dialogs, a status bar, a notification-area icon with balloon
notifications, minimize/close to tray, an optional *Start with Windows*
setting (HKCU Run), a desktop shortcut and a Start menu group
(`ClippyAI.exe /install`). A single instance accepts `/ask`, `/explain` and
RoverAI requests through `WM_COPYDATA`; such requests are ordinary user
requests and still need approval for anything that changes the system.

**Mascot.** Windows XP ships no Clippy character (`clippit.acs` is an Office
asset; the guest contains only `rover.acs`, `courtney.acs`, `earl.acs` and
`merlin.acs`), and no Microsoft character is downloaded or redistributed.
ClippyAI therefore uses a pluggable mascot interface: the default is an
original animated GDI paperclip (idle blink, thinking, working, success, error,
attention); setting *Mascot* to the path of any Microsoft Agent `.acs`
character (for example a legitimately installed `clippit.acs`) plays it through
XP's own Agent server.

**Troubleshooting workflow.** "My computer is running slowly. Fix it." runs
`system_info` → `process_list` (1.5 s CPU sample) → `eventlog_read` System and
Application → `disk_diagnostics`, explains the findings, proposes one
corrective action (end the busiest non-system process, or clean old TEMP files
when the system drive is nearly full), waits for approval, executes it,
verifies with a fresh `process_list` and reports the actual outcome; a
declined proposal is reported as "nothing was changed".

## RoverAI

**Index.** `rover_index.c` keeps entries sorted by case-insensitive path so a
folder and everything below it are contiguous; rename/move rewrites a subtree,
deletion removes it, and the store is a versioned file with a trailing
SHA-256 (`%LOCALAPPDATA%\XP25\RoverAI\index.dat`, written atomically under a
named mutex). An incremental scan lists every reachable directory and
reconciles direct children (added/changed/removed); unreadable directories are
purged (permissions are respected), reparse points are not followed, and
privacy exclusions are applied by default: other users' profiles, credential
and DPAPI folders, browser caches/cookies/history, TEMP, registry hives,
`system32\config`, `repair`, paging files, `System Volume Information` and
RECYCLER. Roots and exclusions are configurable (`IndexRoots`,
`IndexExcludes`). `RoverAI.exe /background` (started at logon) applies
`ReadDirectoryChangesW` notifications for additions, changes, renames, moves
and deletions in real time and falls back to a reconcile on buffer overflow.
Text content of small text documents under the user's profile and All Users is
indexed as sorted word hashes (≤512 words, first 32 KB).

**Search.** `rover_query.c` interprets natural language into structured
criteria: types (documents, PDF, pictures, videos, music, spreadsheets, code,
configuration...), extensions, today/yesterday/this or last week/month/year,
named months and years, last N days, size phrases and largest/smallest/newest,
locations ("on the desktop", "in my documents", drive letters, "in X folder"),
quoted names, and personal phrasing ("my ...", "I edited ...") that prefers the
user's profile. Name, folder and content matches are scored; if no file
matches every word, the structured criteria alone are used and the result
says so. For complex wording an optional model call returns JSON criteria that
are validated strictly (unknown fields, wildcards and bad dates are rejected);
the local index then produces the results, so **paths always come from real
files**. Searching a folder outside the indexed roots scans that folder live.

**UI and Explorer integration.** The same panel is hosted by `RoverAI.exe`
(left criteria column, results on the right) and by `RoverAIBand.dll`, a
vertical Explorer bar (`IDeskBand`, `IObjectWithSite`, `IPersistStream`,
`IInputObject`) with a RoverAI toolbar button. It provides the natural-language
box, Look in (current folder / entire computer / My Documents / Desktop),
date, type, size and folder filters, results with system icons, sortable
columns, Open, Open containing folder and *Ask ClippyAI*. Rover is XP's own
Search Companion character (`%windir%\srchasst\chars\rover.acs`, 29 animations)
played through Microsoft Agent.

The Search Companion is replaced without binary patches: browseui creates
search bars with `CoCreateInstance` (`shbrows2.cpp` `_GetInfoBandBS`), and F3
in folder windows asks for shell32's `CLSID_FileSearchBand`
(`defview.cpp` `_OnSearchFiles`). `RoverAI.exe /replace-search on` adds COM
`TreatAs` keys for `CLSID_SearchBand` and `CLSID_FileSearchBand` that point to
RoverAI classes reporting those CLSIDs, saving any previous value;
`/replace-search off` (also run by `/unregister`) restores them. In a running
session it takes effect after the next logon or restart (observed: the first
run, installed under a live Explorer, still showed the original companion), so
the installer flow restarts once. The original Search Companion files are not
touched and remain recoverable. Because `CLSID_SearchBand` also hosts Internet
Explorer's search pane, that pane shows RoverAI while the redirect is enabled.

## Build

- Host static path: `build/ai_build.py` cross-compiles all five binaries and
  the guest probe with the private MinGW toolchain (`-std=gnu89 -Wall -Wextra
  -Werror`, no MinGW runtime, NT 5.1 headers) and verifies PE headers and every
  import against the guest's DLLs.
- Native path (canonical binaries): `build/prepare_ai.py` copies only these
  sources plus classic DIB icons and generated one-line wrapper files (NT
  `build.exe` accepts only sources in each target directory) into an ISO;
  `build/native-ai-build.cmd` builds them with the NT 5.1 toolchain
  (`razzle offline`, `build -cZ`, `/W4 /WX /wd4201`) in a disposable,
  NIC-free child of the prepared build VM; `build/ai_collect_native.py`
  extracts binaries, PDBs and logs read-only, confirms the 91 compiled sources
  match the media manifest and verifies imports.

| Native build 04 artifact (`W/native-04/collect.json`) | SHA-256 |
| --- | --- |
| `xp25agent.dll` (152,064 bytes) | `ab2329d41fda7040463e1522ef3d730f6a2842db1239da35fa8265bc8aaab654` |
| `ClippyAI.exe` (51,200) | `5265f211319dfaa49f36e3ad841874fade0d2bf064576e81eb35d45aa0cee3f3` |
| `RoverAI.exe` (35,328) | `66463c846c415e10187a1cf175b483ff7c7511f5ea386a9d14547105305f4877` |
| `RoverAIBand.dll` (38,400) | `593015df306c4643c43b3c4f0b98aa8a9ebc32999ee88e2e423511f0998e63e5` |
| `XP25Broker.exe` (10,240) | `d3a323dcb4c05624c6de6666949c71e60fc7208c10070bf625d2c5b3f7459111` |
| Build media ISO (`W/native-media-05`) | `ea5a4853bc2254127a01dff472ec17cb74a9a416ab9288fcaf7bb231e6a98834` |
| Guest probe `ai_probe.exe` (MinGW, `W/mingw-08`) | `905812ebeadfa83cbb80c2fe45e043c1cc3445c7a37ba3f0359b424b2291c988` |

PE OS version 5.1, subsystem 4.0 (NT toolchain default); build.err/build.wrn
absent; 91 compiled sources match the media manifest.

## Tests and guest evidence

Host: `python3 -m unittest discover -s tests -p test_ai.py` (7 tests) compiles
`tests/ai_core.c` with the strict C89 flags under ASan/UBSan (195 checks: JSON
edge cases, SHA-256/HMAC vectors, policy classes, agent loop with injection and
egress cases, Responses/Chat codecs, offline workflows, index scan/incremental
rename/move/delete/permissions/exclusions/persistence/corruption, the five
natural-language example queries and strict criteria validation), checks the C
signer against the Python gateway, runs a live gateway against the OpenAI test
double (authentication, single-use challenges, wrong keys, `store:false`, no
body logging) and repeats the cross-build with import verification.

Guest: `vm/ai_lab.py` boots a fresh overlay of the hash-verified engineering
image (`--mode up|mp|tcg`; MP uses the accepted two-vCPU parent
`shell-userenv-combined-kvm-mp-02`, SHA-256 `d46fa4bf…73b8f`), stages the
binaries into `C:\xp25` and a Startup fixture, attaches the frozen established
regression CD (`test-media-05/native-tests.iso`, SHA-256 `c3b851d3…a390`) and
runs the isolated network of `vm/isolated_network.py` plus the XP25 gateway at
`10.25.0.1:8443` and the OpenAI-API test double on namespace loopback
(`vm/ai_network.py`, `vm/ai_mock_openai.py`; no uplink exists). At logon the
installer runs (broker service, Explorer bar, search redirect, shortcuts,
background indexer) and restarts the guest; after the next logon
`tests/guest/ai_probe.c` drives the real windows, dialogs and command lines,
then the provider checks and `D:\compat-regress.cmd` run, and
`vm/ai_monitor.py` requests a normal shutdown. Gates come from COM1 records.

| Native build 04 | KVM 1 vCPU `W/runs/ai-native-kvm-up-01` | KVM 2 vCPUs `W/runs/ai-native-kvm-mp-01` | TCG `W/runs/ai-native-tcg-01` |
| --- | --- | --- | --- |
| Installer: broker service, Explorer bar, search redirect, shortcuts | 0/0/0/0 | 0/0/0/0 | running when recorded |
| RoverAI index (315,852 entries, all of C:), filename/date/type/size searches, five NL examples, incremental rename/delete | Pass | Pass | not recorded |
| RoverAI real-time watcher (new/rename/delete) | 1/3 (save starvation, fix pending) | 3/3 | not recorded |
| RoverAI window, results, Open, Open containing folder | Pass | Pass | not recorded |
| Explorer Search command opens RoverAI band, search, close, Explorer PID stable, navigation after | Pass | Pass | not recorded |
| ClippyAI start, chat UI, offline default, desktop shortcut | Pass | Pass | not recorded |
| Event Viewer tool and answer; read-only CMD; approval dialog shows exact command and runs it; denial leaves file; failed command reported | Pass | Pass | not recorded |
| Slow-computer workflow: real tools, proposes ending `ai_cpuhog.exe`, approved, verified resolved | Pass | Pass | not recorded |
| Find network config → approve read → approve line fix → file fixed with .bak | Pass | Pass | not recorded |
| RoverAI "Ask ClippyAI" hand-off, tray minimize/restore | Pass | Pass | not recorded |
| Gateway key stored, OpenAI via gateway, share prompt, auth failure | **Fail** (key not stored) | **Fail** | not recorded |
| Unreachable provider falls back to offline | Pass | Pass | not recorded |
| Established regression suite (12 probes + MSI) | all exit 0 | all exit 0 | not recorded |
| Guest-requested shutdown (`SHUTDOWN guest=true`) | Observed | Observed | not recorded |

Results: `ai-results.json` in each run directory. Earlier MinGW-built runs
`ai-kvm-up-01` and `-02` are listed under failures.

## Failures and corrections (retained)

- `W/runs/ai-kvm-up-01` (MinGW build): 28 pass / 21 fail. The probe set
  control text with `SetDlgItemText`, which cannot change controls in another
  process (fixed with explicit `WM_SETTEXT`/`WM_GETTEXT`). A thread capture
  (`vm/capture_memory.py`, `vm/inspect_threads.py`) showed ClippyAI idle in
  `GetMessageW`, and keyboard input from the host proved the request path.
  F3 showed the original Search Companion: F3 uses `CLSID_FileSearchBand`, and
  the redirect was installed under a running Explorer. The audit log exposed a
  real ClippyAI defect: hand-off requests embedded unquoted paths, so trailing
  words became part of the file name. The `proj` synonym matched `msproj95.cmd`
  inside the 290,440-file `C:\nt` tree. The full established regression suite
  passed in this run.
- `W/runs/ai-kvm-up-02` (MinGW build): 54/55 main cases; the gateway key typed
  via `WM_SETTEXT` never reached the password-style edit, and ClippyAI used the
  key text instead of its hex-decoded bytes (fixed on both sides).
- `B/ai-native-build-01`: missing `makefile` stubs and `..\` entries rejected
  by `build.exe`; `B/ai-native-build-02`: SDK nameless unions under `/W4`,
  `FD_SET` C4127, comparators lacking `__cdecl` under the NT `__stdcall`
  default, a missing include, const casts, one C4701, and RC2176 on
  PNG-compressed icons (XP-era RC and XP itself need DIB icons). Builds 03 and
  04 succeed; 04 is used.

## Pending

- Gateway key storage defect (above); diagnostic boot `W/runs/ai-debug-key-01`.
- Watcher save starvation fix and ClippyAI focus restoration after dialogs are
  in the sources and host-tested only (no native rebuild or guest run yet).
- TCG run result, image install run, `build/ai_package_image.py` QCOW2 and its
  independent boot proof; a real OpenAI call (needs a key and an uplink).

## Recovery

`RoverAI.exe /replace-search off` restores the Search Companion (and any
previous `TreatAs`), `RoverAI.exe /unregister` removes the Explorer bar and
button, `XP25Broker.exe /uninstall` stops and deletes the service,
`ClippyAI.exe /uninstall` removes shortcuts and the autostart value. Remove
`C:\Program Files\XP25`, `HKCU\Software\XP25`, `HKLM\SOFTWARE\XP25` and
`%LOCALAPPDATA%\XP25`/`%APPDATA%\XP25`. The accepted engineering image remains
the immediate fallback; no reference image or registered VM is modified.

## Limitations

- **No call to the real OpenAI API was made.** The guest network is isolated
  by design and no API key was used; the Responses-API path was exercised end
  to end against the deterministic test double *through the real gateway*,
  including function calling, data-sharing consent and signed replies. The
  wire format follows the published Responses API; compatibility with a given
  live model is not verified.
- Direct HTTPS from XP is not implemented (see TLS); the gateway link is not
  encrypted.
- The offline planner understands English phrasings listed in ClippyAI's help;
  open-ended questions need a configured provider.
- Content indexing covers small text formats only (no Office/PDF text).
  Non-ASCII case-insensitive matching is byte-wise. The first full index of the
  engineering image (315,852 entries) takes about 30 s under KVM.
- The Search Companion redirect also affects Internet Explorer's search pane
  and requires a logon/restart to take effect in a running session.
- The broker performs only service changes; privileged file changes are
  refused. Domain environments, multiple simultaneous users, non-English UI,
  accelerated graphics and long-term stability are not tested.
