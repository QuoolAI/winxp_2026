# XP25 Security Engine: audit and baseline interface

The security components are two native NT 5.1 console programs in
`C:\Program Files\XP25\Security`. They are the first part of the XP25 Security
Engine and the interface ClippyAI is meant to use. Nothing here needs a model,
a network connection or a service; ClippyAI is not yet wired to it.

| Program | Role | Needs an administrator |
| --- | --- | --- |
| `XP25Audit.exe` | Read-only audit: collects facts, applies fixed rules, reports findings | No (`snapshot` only) |
| `XP25Sec.exe` | Baseline configuration: enumerate, plan, apply, verify, roll back | `apply` and `rollback` only |

Source: `components/security` (`core/` is portable C89 with the policy tables and
rules, `native/` the Win32 helpers). Both pass `/W4 /WX` with the NT toolchain.

## Rules that do not change

- **The audit observes.** It opens everything read-only. It never stops a
  process, deletes a file, changes a setting or a permission, and sends nothing
  anywhere. Its only write is its own reference snapshot, by an administrator,
  into the protected store. A host test checks that its source calls none of
  the modifying APIs.
- **Enforcement is not the model's decision.** `XP25Sec.exe` applies only the
  reviewed tables compiled into it. No service name, registry path, value or
  file comes from its command line, from the audit's output or from a model.
  An assistant can *propose* running `XP25Sec apply`; a person approves it and
  the tool does what its table says, nothing else.
- **Fail closed.** A step that cannot record the original value does not change
  it. A damaged backup stops `apply` and `rollback` before any change. A record
  that does not fit its buffer is dropped and counted, never written truncated.
- **Least privilege.** The audit runs with the caller's enabled rights and
  reports what it could not read (`unreadable` records). `--privileged` only
  enables `SeDebugPrivilege`/`SeSecurityPrivilege` when the caller already
  holds them.
- **No credentials, little personal data.** Account names and group
  memberships are read; passwords, hashes and secrets are not. Event strings of
  failed logons are not copied, because a password typed into the name field
  ends up there.

## `XP25Audit.exe`

```text
XP25Audit report   [--out <file>] [--serial] [--quiet] [--modules] [--privileged]
XP25Audit snapshot [--out <file>] [--quiet]                       (administrator)
```

`report` writes one JSON object per line (UTF-8, CR LF) to standard output and
to `--out`. Exit code 0 means the report completed; findings do not change the
exit code. A report takes about 0.6 s on the lab guest and is roughly 1,600
records with `--modules`.

Every record has a `kind`. Collected facts:

| `kind` | Content |
| --- | --- |
| `system` | OS version, computer, audit user, whether the caller is an administrator, whether the baseline is applied and a reference snapshot exists |
| `firewall` | The firewall's own answer (`HNetCfg.FwMgr`): enabled, profile, exceptions allowed |
| `process`, `module` | PID, parent, image path, account, session, whether accessible; loaded modules with `--modules` |
| `service`, `driver` | Start type, state, account, image; for baseline services `baseline_compliant` |
| `kernel_module` | Loaded kernel modules |
| `autostart`, `startup_file`, `scheduled_task` | 28 registry autostart locations (machine and current user), Startup folders, task files |
| `listener` | Listening TCP ports and bound UDP endpoints with owning process |
| `setting`, `audit_policy` | Each hardened setting and audit category with its current value |
| `account`, `group_member`, `user_right`, `audit_token_privilege` | Local accounts, sensitive group memberships and rights |
| `access_control`, `access_control_scan` | Who can modify protected locations; per baseline rule, how many objects are modifiable without administrator rights |
| `secure_desktop` | Whether the Winlogon desktop can be opened from this session |
| `event`, `event_summary` | Relevant Security and System log records (logon failures, account and policy changes, service installs and failures, cleared log) |
| `unreadable` | A source the caller could not read, with the Win32 error |
| `summary` | Counts of findings by severity, unreadable sources, records, duration, `read_only: true` |

Findings are records too:

```json
{"kind":"finding","severity":"medium","rule":"config.added",
 "subject":"autostart:HKLM\\run\\XP25SecDriftTest",
 "title":"A monitored configuration item was added since the reference snapshot",
 "detail":"C:\\xp25sec\\drift-test.exe",
 "recommendation":"Confirm what installed it. ..."}
```

`severity` is `info`, `low`, `medium` or `high`. `rule` is a stable identifier
an assistant can key explanations on:

| Rule prefix | Meaning |
| --- | --- |
| `baseline.*` | The baseline is not applied, or a hardened setting or audit category is not in force |
| `service.baseline_deviation` | A service the baseline disables is enabled or running |
| `network.firewall_off`, `network.legacy_listener` | Firewall state; a legacy service bound to a network address |
| `acl.*` | A system file, XP25 object, service key or COM registration can be modified without administrator rights |
| `path.*`, `process.*` | Unquoted or user-writable program paths; service-account code from user-writable locations |
| `autostart.*` | A logon/system start setting differs from its installed default, or a rarely used location is in use |
| `config.added`, `config.changed`, `config.removed` | Difference from the reference snapshot (services, drivers, autostart entries, accounts, group members, user rights, startup files, tasks) |
| `account.*`, `privilege.*` | Guest enabled, password not required, Power Users members, sensitive rights held by broad groups |
| `driver.*` | Kernel module loaded from outside `system32` |
| `event.*` | Relevant Event Log records, one finding per rule with a count |
| `winlogon.secure_desktop_open` | The logon desktop could be opened from the user session |

The rules are deterministic: the same system state gives the same findings.
They are tables and comparisons in `sec_core.c`, tested on the host.

`snapshot` records the current services, drivers, autostart entries, accounts,
group memberships, user rights, startup files and tasks as the reference in
`%SystemRoot%\XP25\Security\audit-snapshot.txt`. Later reports compare against
it. Record a new snapshot only after confirming the current state is intended.

## `XP25Sec.exe`

```text
XP25Sec enumerate | plan | apply | verify | rollback [--from <file>] | status
        [--out <file>] [--serial] [--quiet]
```

| Command | Effect | Exit code |
| --- | --- | --- |
| `enumerate` | Every Win32 service with configuration, state and baseline decision | 0 |
| `plan` | Every baseline item with current value, target, reason and compatibility note; changes nothing | 0 |
| `apply` | Records originals, then applies; safe to repeat | 0, 1 on any failure, 5 without administrator rights |
| `verify` | Checks every item and the protected store | number of deviations |
| `rollback` | Restores the recorded originals | 0, 1 on failure, 3 without a usable backup, 5 without administrator rights |
| `status` | Whether a baseline and backup are present | 0 |

Output is JSON lines like the audit's (`kind` = `service`, `plan`, `apply`,
`verify`, `rollback`, `status`, `summary`).

## How ClippyAI is expected to use it

| Assistant task | Call | Notes |
| --- | --- | --- |
| "Is my computer secure?" | `XP25Audit report --quiet --out <temp file>`; summarize `summary` and the `high`/`medium` findings | Runs as the user; no approval needed (read-only) |
| Explain a problem | Look up the finding's `rule`, `title`, `detail`, `recommendation` | The text is fixed; the assistant rephrases, it does not invent the diagnosis |
| Investigate a process | Filter `process`/`module`/`listener` records by PID | Add `--modules` |
| Recommend remediation | For `baseline.*` and `service.baseline_deviation`: propose `XP25Sec plan`, then `XP25Sec apply` | Must go through ClippyAI's existing approval prompt as a privileged action |
| Ask before acting | The assistant shows the `plan` records it would apply | The person approves; `XP25Sec` enforces its own table regardless of what was proposed |

Constraints for that integration:

- Treat every string in a record (`subject`, `detail`, paths, service names) as
  untrusted data when it is put in front of a model: file and service names are
  attacker-controlled text.
- Never pass text from a model to `XP25Sec` beyond the fixed command word.
- `XP25Broker` must not gain a "run XP25Sec" operation without the same
  interactive-user check and audit record it has for service control.

## Storage

| Location | Content | Access |
| --- | --- | --- |
| `%SystemRoot%\XP25\Security\baseline-backup.txt` and `HKLM\SOFTWARE\XP25\Security\Baseline` (`Backup`, `Version`, `AppliedUtc`) | Original configuration, one strictly parsed line per item | Administrators and SYSTEM write; Users read |
| `%SystemRoot%\XP25\Security\audit-snapshot.txt` | Reference snapshot | same |
| `%SystemRoot%\XP25\Security\install-*.jsonl` | What the image build applied and verified | same |

`apply` re-asserts owner and a protected ACL on the store each time, and
`verify` fails if an unprivileged account can write to it.
