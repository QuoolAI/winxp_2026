#!/usr/bin/env python3
"""Guest-side fixtures of the XP25 security lab (vm/security_lab.py).

Each role is one self-removing Startup script for the XP25 account. Payload
is staged offline into the XP25 profile as xp25sec-* files and copied to the
work directory C:\\xp25sec; nothing is staged into a directory the baseline
manages. Results are JSON-lines files in C:\\xp25sec (read from the frozen
disk afterwards) and short markers on COM1.

Roles:
  regression     established AI and compatibility suites, nothing installed
  audit          XP25Sec enumerate/plan/verify, XP25Audit report and the
                 security probe on an unhardened guest (the inventory)
  harden         install the tools, apply the baseline, restart, then verify,
                 audit, probe, drift detection, AI and compatibility suites
  image-install  install, apply, restart, verify, record the reference
                 snapshot and remove every test payload
  proof          the hardened image as shipped: verify, audit, probe, drift
                 detection, AI and compatibility suites
  rollback       roll the baseline back, restart, show the original
                 configuration is in force again"""

STAGED = 'C:\\Documents and Settings\\XP25'
STARTUP = '@call "%USERPROFILE%\\xp25sec-suite.cmd"\r\n'

HEAD = r'''@echo off
set W=C:\xp25sec
set U=%USERPROFILE%
set I=C:\Program Files\XP25\Security
if not exist %W% mkdir %W%
if not exist %W%\tools mkdir %W%\tools
if exist "%U%\xp25sec-security_probe.exe" copy /y "%U%\xp25sec-security_probe.exe" %W%\tools\security_probe.exe >nul
'''

UNINSTALLED_TOOLS = r'''copy /y "%U%\xp25sec-XP25Sec.exe" %W%\tools\XP25Sec.exe >nul
copy /y "%U%\xp25sec-XP25Audit.exe" %W%\tools\XP25Audit.exe >nul
set T=%W%\tools
'''

INSTALL = r'''echo XP25_SEC_INSTALL_STARTED > COM1
if not exist "%I%" mkdir "%I%"
copy /y "%U%\xp25sec-XP25Sec.exe" "%I%\XP25Sec.exe" >nul
echo XP25_SEC_INSTALL_SEC=%ERRORLEVEL% > COM1
copy /y "%U%\xp25sec-XP25Audit.exe" "%I%\XP25Audit.exe" >nul
echo XP25_SEC_INSTALL_AUDIT=%ERRORLEVEL% > COM1
"%I%\XP25Sec.exe" enumerate --quiet --out %W%\enumerate-before.jsonl
"%I%\XP25Sec.exe" plan --quiet --out %W%\plan.jsonl
"%I%\XP25Sec.exe" apply --quiet --out %W%\apply.jsonl
echo XP25_SEC_APPLY_EXIT=%ERRORLEVEL% > COM1
"%I%\XP25Sec.exe" verify --quiet --out %W%\verify-before-restart.jsonl
echo XP25_SEC_VERIFY_BEFORE_RESTART_EXIT=%ERRORLEVEL% > COM1
'''

RESTART = r'''echo done > %W%\phase1.done
echo XP25_SEC_RESTARTING > COM1
%W%\tools\security_probe.exe power restart
goto :eof
'''

# {tag} names the result files; {probe} carries the probe's expectation flags.
# During the scan window the guest resolves names that do not exist, so it broadcasts NetBIOS name
# queries the whole time; the namespace scanner probes while that is happening.
TESTS = r'''"%T%\XP25Sec.exe" status --quiet --out %W%\status-{tag}.jsonl
"%T%\XP25Sec.exe" enumerate --quiet --out %W%\enumerate-{tag}.jsonl
"%T%\XP25Sec.exe" plan --quiet --out %W%\plan-{tag}.jsonl
"%T%\XP25Sec.exe" verify --quiet --out %W%\verify-{tag}.jsonl
echo XP25_SEC_VERIFY_EXIT=%ERRORLEVEL% > COM1
"%T%\XP25Audit.exe" report --quiet --modules --out %W%\audit-{tag}.jsonl
echo XP25_SEC_AUDIT_EXIT=%ERRORLEVEL% > COM1
%W%\tools\security_probe.exe admin {probe} --tools "%T%"
echo XP25_SEC_PROBE_EXIT=%ERRORLEVEL% > COM1
netsh firewall show state > %W%\firewall-{tag}.txt 2>&1
netstat -ano > %W%\netstat-{tag}.txt 2>&1
echo XP25_SEC_SCAN_WINDOW_OPEN > COM1
for /l %%N in (1,1,{window}) do ping -n 1 -w 200 xp25-nbprobe-%%N > nul 2>&1
echo XP25_SEC_SCAN_WINDOW_CLOSED > COM1
'''

# A reference snapshot, then two deliberate changes the audit must report, then repair.
DRIFT = r'''{snapshot}"%T%\XP25Audit.exe" report --quiet --out %W%\audit-clean-{tag}.jsonl
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v XP25SecDriftTest /d "C:\xp25sec\drift-test.exe" /f > nul
sc config RemoteRegistry start= demand > nul
"%T%\XP25Audit.exe" report --quiet --out %W%\audit-drift-{tag}.jsonl
echo XP25_SEC_DRIFT_AUDIT_EXIT=%ERRORLEVEL% > COM1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v XP25SecDriftTest /f > nul
"%T%\XP25Sec.exe" apply --quiet --out %W%\reapply-drift-{tag}.jsonl
echo XP25_SEC_DRIFT_REAPPLY_EXIT=%ERRORLEVEL% > COM1
'''
SNAPSHOT = r'''"%T%\XP25Audit.exe" snapshot --quiet --out %W%\snapshot-{tag}.jsonl
echo XP25_SEC_SNAPSHOT_EXIT=%ERRORLEVEL% > COM1
'''

# The AI probe keeps its fixtures beside itself in C:\xp25\ai, as in vm/ai_lab.py.
AI = r'''if not exist C:\xp25\ai mkdir C:\xp25\ai
copy /y "%U%\xp25sec-ai_probe.exe" C:\xp25\ai\ai_probe.exe >nul
echo XP25_AI_TESTS_STARTED > COM1
C:\xp25\ai\ai_probe.exe suite {slow}
echo XP25_AI_PROBE_EXIT=%ERRORLEVEL% > COM1
call "%U%\xp25sec-gateway-secret.cmd"
C:\xp25\ai\ai_probe.exe provider %XP25_GW_SECRET% {slow}
echo XP25_AI_PROVIDER_EXIT=%ERRORLEVEL% > COM1
'''

COMPAT = r'''call D:\compat-regress.cmd
echo XP25_COMPAT_DONE > COM1
'''

# The established suite, unchanged except around Remote Registry: the baseline
# disables that service, so the unchanged probe is first shown to be refused,
# then run after an administrator re-enables the service, and the baseline is
# applied again. Every other step is the sequence of D:\compat-regress.cmd.
COMPAT_HARDENED = r'''call D:\regress.cmd
echo XP25_SEC_REGSVC_REFUSED_START > COM1
D:\regsvc_probe.exe
echo REGSVC_PROBE_WHILE_DISABLED_EXIT=%ERRORLEVEL% > COM1
echo XP25_SEC_REGSVC_REFUSED_END > COM1
sc config RemoteRegistry start= demand > nul
echo XP25_SEC_REMOTE_REGISTRY_ENABLED_BY_ADMIN=%ERRORLEVEL% > COM1
D:\regsvc_probe.exe
echo REGSVC_PROBE_EXIT=%ERRORLEVEL% > COM1
"%T%\XP25Sec.exe" apply --quiet --out %W%\reapply-{tag}.jsonl
echo XP25_SEC_REAPPLY_EXIT=%ERRORLEVEL% > COM1
D:\gina_probe.exe
echo GINA_PROBE_EXIT=%ERRORLEVEL% > COM1
call D:\userenv-test.cmd --compat
call D:\identity.cmd --branded
call D:\msi-test.cmd
D:\shell_probe.exe
echo SHELL_PROBE_EXIT=%ERRORLEVEL% > COM1
D:\profile_probe.exe
echo PROFILE_PROBE_EXIT=%ERRORLEVEL% > COM1
echo EXTENSION_REGRESSION_FINISHED > COM1
echo XP25_COMPAT_DONE > COM1
"%T%\XP25Sec.exe" verify --quiet --out %W%\verify-final-{tag}.jsonl
echo XP25_SEC_FINAL_VERIFY_EXIT=%ERRORLEVEL% > COM1
"%T%\XP25Audit.exe" report --quiet --out %W%\audit-final-{tag}.jsonl
'''

END = r'''del "%USERPROFILE%\Start Menu\Programs\Startup\XP25Security.cmd"
echo XP25_SEC_SUITE_DONE > COM1
%W%\tools\security_probe.exe power shutdown
'''

# The image keeps the tools, the protected store and the apply record; every
# test payload goes. The last line is read completely before this file is deleted.
IMAGE_END = r'''copy /y %W%\apply.jsonl "%SystemRoot%\XP25\Security\install-apply.jsonl" >nul
copy /y %W%\enumerate-before.jsonl "%SystemRoot%\XP25\Security\install-services-before.jsonl" >nul
copy /y %W%\plan.jsonl "%SystemRoot%\XP25\Security\install-plan.jsonl" >nul
"%I%\XP25Sec.exe" verify --quiet --out "%SystemRoot%\XP25\Security\install-verify.jsonl"
echo XP25_SEC_VERIFY_EXIT=%ERRORLEVEL% > COM1
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25Security.cmd"
del /q "%U%\xp25sec-XP25Sec.exe" "%U%\xp25sec-XP25Audit.exe" "%U%\xp25sec-security_probe.exe"
"%I%\XP25Audit.exe" snapshot --quiet --out "%SystemRoot%\XP25\Security\install-snapshot.jsonl"
echo XP25_SEC_SNAPSHOT_EXIT=%ERRORLEVEL% > COM1
"%I%\XP25Audit.exe" report --quiet --out "%SystemRoot%\XP25\Security\install-audit.jsonl"
echo XP25_SEC_AUDIT_EXIT=%ERRORLEVEL% > COM1
"%I%\XP25Sec.exe" verify --quiet
echo XP25_SEC_FINAL_VERIFY_EXIT=%ERRORLEVEL% > COM1
cd /d C:\
rmdir /s /q C:\xp25sec
echo XP25_SEC_WORKDIR_REMOVED=%ERRORLEVEL% > COM1
del "%U%\xp25sec-suite.cmd" & echo XP25_SEC_SUITE_DONE > COM1
'''

ROLLBACK = r'''echo XP25_SEC_ROLLBACK_STARTED > COM1
"%I%\XP25Sec.exe" status --quiet --out %W%\status-before-rollback.jsonl
"%I%\XP25Sec.exe" rollback --quiet --out %W%\rollback.jsonl
echo XP25_SEC_ROLLBACK_EXIT=%ERRORLEVEL% > COM1
'''
AFTER_ROLLBACK = r'''set T=%I%
"%T%\XP25Sec.exe" status --quiet --out %W%\status-rolled-back.jsonl
"%T%\XP25Sec.exe" enumerate --quiet --out %W%\enumerate-rolled-back.jsonl
"%T%\XP25Sec.exe" verify --quiet --out %W%\verify-rolled-back.jsonl
echo XP25_SEC_VERIFY_AFTER_ROLLBACK_EXIT=%ERRORLEVEL% > COM1
"%T%\XP25Audit.exe" report --quiet --out %W%\audit-rolled-back.jsonl
netsh firewall show state > %W%\firewall-rolled-back.txt 2>&1
netstat -ano > %W%\netstat-rolled-back.txt 2>&1
D:\regsvc_probe.exe
echo REGSVC_PROBE_EXIT=%ERRORLEVEL% > COM1
echo XP25_SEC_SCAN_WINDOW_OPEN > COM1
for /l %%N in (1,1,{window}) do ping -n 1 -w 200 xp25-nbprobe-%%N > nul 2>&1
echo XP25_SEC_SCAN_WINDOW_CLOSED > COM1
'''


def suite(role, mode, xp25_winlogon=True, provider=True):
    """The Startup suite of one role as CR LF text."""
    slow = 'slow' if mode == 'tcg' else ''
    # Each unresolvable single-label name costs about 2.5 s of NetBIOS broadcasts from UDP 137:
    # the scan window is a period in which the guest keeps the firewall's broadcast-response window open.
    window = 110
    flags = '--xp25-winlogon' if xp25_winlogon else ''
    ai = AI.format(slow=slow) if provider else ''
    two_phase = 'if exist %W%\\phase1.done goto phase2\n'
    if role == 'regression':
        text = HEAD + 'echo XP25_SEC_REGRESSION_STARTED > COM1\n' + ai + COMPAT + END
    elif role == 'audit':
        text = HEAD + UNINSTALLED_TOOLS + 'echo XP25_SEC_AUDIT_STARTED > COM1\n' + \
            TESTS.format(tag='before', probe=flags, window=window) + END
    elif role == 'harden':
        text = HEAD + two_phase + INSTALL + RESTART + ':phase2\nset T=%I%\necho XP25_SEC_PHASE2_STARTED > COM1\n' + \
            TESTS.format(tag='hardened', probe=flags + ' --hardened', window=window) + \
            DRIFT.format(tag='hardened', snapshot=SNAPSHOT.format(tag='hardened')) + ai + \
            COMPAT_HARDENED.format(tag='hardened') + END
    elif role == 'image-install':
        text = HEAD + two_phase + INSTALL + RESTART + ':phase2\necho XP25_SEC_PHASE2_STARTED > COM1\n' + IMAGE_END
    elif role == 'proof':
        text = HEAD + 'set T=%I%\necho XP25_SEC_PROOF_STARTED > COM1\n' + \
            TESTS.format(tag='proof', probe=flags + ' --hardened', window=window) + \
            DRIFT.format(tag='proof', snapshot='') + ai + COMPAT_HARDENED.format(tag='proof') + END
    elif role == 'rollback':
        text = HEAD + two_phase + ROLLBACK + RESTART + ':phase2\necho XP25_SEC_PHASE2_STARTED > COM1\n' + \
            AFTER_ROLLBACK.format(window=window) + END
    else:
        raise ValueError(role)
    return text.replace('\r\n', '\n').replace('\n', '\r\n')


ROLES = ('regression', 'audit', 'harden', 'image-install', 'proof', 'rollback')
# Which staged payload a role needs (xp25sec-<name> in the XP25 profile).
PAYLOAD = {
    'regression': ('security_probe.exe', 'ai_probe.exe'),
    'audit': ('XP25Sec.exe', 'XP25Audit.exe', 'security_probe.exe'),
    'harden': ('XP25Sec.exe', 'XP25Audit.exe', 'security_probe.exe', 'ai_probe.exe'),
    'image-install': ('XP25Sec.exe', 'XP25Audit.exe', 'security_probe.exe'),
    'proof': ('security_probe.exe', 'ai_probe.exe'),
    'rollback': ('security_probe.exe',),
}
# Roles that run the AI provider checks need the gateway and the OpenAI test double.
PROVIDER = ('regression', 'harden', 'proof')
