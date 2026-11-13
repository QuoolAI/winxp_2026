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
                 configuration is in force again
  ai-repeat      the AI suite and provider checks several times in one boot,
                 ClippyAI and RoverAI ended and fixtures removed between rounds
  standard-user  an administrator creates a standard account, makes MSGINA
                 offer it and restarts; the standard user logs on, runs the
                 desktop checks, the programs and games, and restarts the
                 computer; logs on again after the restart, repeats the
                 desktop checks and powers the computer off
  apps           the administrator starts the programs and games installed
                 with Windows (security_probe.exe apps)
  image-upgrade  a hardened image to the current baseline: replace the tools,
                 apply (new items only), restart, verify, new reference
                 snapshot, remove every test payload
  firewall       the Windows Firewall on a hardened image: guest-observed
                 state, a test listener probed from the adjacent network in
                 every state (blocked, port opened by the administrator,
                 removed, after the unprivileged attempts, disabled and
                 re-enabled by the administrator, service stopped and
                 started), and continuous probing across a restart

Host observations are requested by the guest itself (XP25_HOST_REQUEST on
COM1) and awaited with "security_probe.exe hostwait", so guest steps and host
probes are ordered without timing assumptions (vm/security_network.py)."""

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

# While broadcast.on exists the guest resolves names that do not exist, so it broadcasts NetBIOS
# name queries from UDP 137 the whole time (unless NetBIOS is a point-to-point node): the
# firewall's "replies to my own broadcasts" window is exercised by every observation made
# meanwhile. The test listener broadcasts from its own UDP port at the same time
# (security_probe.exe listen ... broadcast): the same window, independent of NetBIOS.
LISTENER_PORT = 5025
NAMES_ON = r'''echo on > %W%\broadcast.on
start "XP25 broadcast" /min cmd /c "for /l %%N in (1,1,4000) do if exist %W%\broadcast.on ping -n 1 -w 200 xp25-nbprobe-%%N > nul 2>&1"
'''
NAMES_OFF = r'''del %W%\broadcast.on
'''
LISTEN = r'''if exist %W%\listener.ready del %W%\listener.ready
if exist %W%\listener.stop del %W%\listener.stop
start "XP25 listener" /min %W%\tools\security_probe.exe listen 5025 %W% broadcast
:listener{n}
if not exist %W%\listener.ready ping -n 2 127.0.0.1 > nul
if not exist %W%\listener.ready goto listener{n}
echo XP25_FW_LISTENER_READY > COM1
'''
LISTEN_STOP = r'''echo stop > %W%\listener.stop
'''
BROADCAST_ON = NAMES_ON + LISTEN.replace('{n}', 'scan')
BROADCAST_OFF = NAMES_OFF + LISTEN_STOP
# The guest asks for an observation and waits until the observer has finished it.
OBSERVE = r'''echo XP25_HOST_REQUEST={kind}:{label} > COM1
%W%\tools\security_probe.exe hostwait {label} {seconds}
echo XP25_HOST_WAIT_{marker}=%ERRORLEVEL% > COM1
'''


def observe(kind, label, seconds=900):
    return OBSERVE.format(kind=kind, label=label, seconds=seconds, marker=label.upper().replace('-', '_'))


# {tag} names the result files; {probe} carries the probe's expectation flags.
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
%W%\tools\security_probe.exe fwcheck {tag} {probe}
echo XP25_SEC_FWCHECK_EXIT=%ERRORLEVEL% > COM1
''' + '{broadcast_on}{scan}{broadcast_off}'

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

# The image keeps the tools, the protected store and the apply record ({prefix} is "install", or
# "upgrade-81" so that an upgraded image keeps its original install record beside the upgrade's);
# every test payload goes. The last line is read completely before this file is deleted.
IMAGE_END = r'''copy /y %W%\apply.jsonl "%SystemRoot%\XP25\Security\{prefix}-apply.jsonl" >nul
copy /y %W%\enumerate-before.jsonl "%SystemRoot%\XP25\Security\{prefix}-services-before.jsonl" >nul
copy /y %W%\plan.jsonl "%SystemRoot%\XP25\Security\{prefix}-plan.jsonl" >nul
"%I%\XP25Sec.exe" verify --quiet --out "%SystemRoot%\XP25\Security\{prefix}-verify.jsonl"
echo XP25_SEC_VERIFY_EXIT=%ERRORLEVEL% > COM1
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25Security.cmd"
del /q "%U%\xp25sec-XP25Sec.exe" "%U%\xp25sec-XP25Audit.exe" "%U%\xp25sec-security_probe.exe"
"%I%\XP25Audit.exe" snapshot --quiet --out "%SystemRoot%\XP25\Security\{prefix}-snapshot.jsonl"
echo XP25_SEC_SNAPSHOT_EXIT=%ERRORLEVEL% > COM1
"%I%\XP25Audit.exe" report --quiet --out "%SystemRoot%\XP25\Security\{prefix}-audit.jsonl"
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
''' + '{broadcast_on}{scan}{broadcast_off}'

# One round of the AI suite. ClippyAI and RoverAI are ended first, the fixtures and the probe's
# results of the previous round removed, so that no case can pass on an earlier round's state.
AI_ROUND = r'''echo XP25_AI_ROUND_STARTED={n} > COM1
%W%\tools\security_probe.exe aireset
echo XP25_AI_RESET_EXIT=%ERRORLEVEL% > COM1
rmdir /s /q "%USERPROFILE%\My Documents\XP25AI-Fixtures" > nul 2>&1
rem The previous round's outputs are kept for the record, out of this round's way.
if not exist C:\xp25\ai\kept\before-{n} mkdir C:\xp25\ai\kept\before-{n}
move /y C:\xp25\ai\*.json C:\xp25\ai\kept\before-{n}\ > nul 2>&1
move /y C:\xp25\ai\*.txt C:\xp25\ai\kept\before-{n}\ > nul 2>&1
if exist C:\xp25\ai\results.jsonl move /y C:\xp25\ai\results.jsonl C:\xp25\ai\kept\before-{n}\ > nul
del /q C:\xp25\ai\ai_cpuhog.exe > nul 2>&1
C:\xp25\ai\ai_probe.exe suite {slow}
echo XP25_AI_PROBE_EXIT=%ERRORLEVEL% > COM1
C:\xp25\ai\ai_probe.exe provider %XP25_GW_SECRET% {slow}
echo XP25_AI_PROVIDER_EXIT=%ERRORLEVEL% > COM1
echo XP25_AI_ROUND_DONE={n} > COM1
'''

APPS = r'''%W%\tools\security_probe.exe apps %W%\apps-{tag}.jsonl {slow}
echo XP25_SEC_APPS_EXIT=%ERRORLEVEL% > COM1
'''

# Standard user. The administrator's first session creates the account and installs one All Users
# Startup script, which then serves every later session and decides by account and by what has
# happened so far (marker files in C:\xp25sec, where standard users may create files).
STD_ADMIN_FIRST = r'''echo XP25_STD_STARTED > COM1
call "%U%\xp25sec-standard-account.cmd"
net user %XP25_STD_USER% %XP25_STD_PASSWORD% /add /comment:"XP25 standard-user test" > %W%\std-account.txt 2>&1
echo XP25_STD_ACCOUNT_CREATED=%ERRORLEVEL% > COM1
net localgroup Users > %W%\std-groups-users.txt 2>&1
net localgroup Administrators > %W%\std-groups-admins.txt 2>&1
copy /y "%U%\xp25sec-std-startup.cmd" "%ALLUSERSPROFILE%\Start Menu\Programs\Startup\XP25Standard.cmd" >nul
echo XP25_STD_STARTUP_INSTALLED=%ERRORLEVEL% > COM1
rem MSGINA offers the account named here at the next logon; the lab then types only the password.
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /d %XP25_STD_USER% /f > nul
echo XP25_STD_NEXT_ACCOUNT_OFFERED=%ERRORLEVEL% > COM1
echo done > %W%\std-admin1.done
del "%USERPROFILE%\Start Menu\Programs\Startup\XP25Security.cmd"
rem The next account logs on after a restart: after a logoff the XP25 Winlogon's logon dialog does not
rem paint its fields (known defect; runs logon-focus-*), so keys cannot be aimed at them.
echo XP25_STD_ADMIN_RESTART > COM1
%W%\tools\security_probe.exe power restart
'''

STD_STARTUP = r'''@echo off
set W=C:\xp25sec
if /i not "%USERNAME%"=="xp25user" goto :eof
if exist %W%\std-user1.done goto second
echo XP25_STD_USER_SESSION=1 > COM1
echo %USERDOMAIN%\%USERNAME% > %W%\std-whoami-1.txt
%W%\tools\security_probe.exe desktop %W%\std-desktop-1.jsonl --hardened {slow}
echo XP25_STD_DESKTOP_EXIT_1=%ERRORLEVEL% > COM1
%W%\tools\security_probe.exe apps %W%\std-apps-1.jsonl {slow}
echo XP25_STD_APPS_EXIT_1=%ERRORLEVEL% > COM1
echo done > %W%\std-user1.done
echo XP25_STD_USER_RESTART > COM1
%W%\tools\security_probe.exe power restart
echo XP25_STD_RESTART_REQUEST_EXIT=%ERRORLEVEL% > COM1
goto :eof
:second
echo XP25_STD_USER_SESSION=2 > COM1
echo %USERDOMAIN%\%USERNAME% > %W%\std-whoami-2.txt
%W%\tools\security_probe.exe desktop %W%\std-desktop-2.jsonl --hardened {slow}
echo XP25_STD_DESKTOP_EXIT_2=%ERRORLEVEL% > COM1
echo done > %W%\std-user2.done
rem The standard user powers the computer off; the results stay in C:\xp25sec for the frozen disk.
echo XP25_SEC_SUITE_DONE > COM1
%W%\tools\security_probe.exe power shutdown
echo XP25_STD_SHUTDOWN_REQUEST_EXIT=%ERRORLEVEL% > COM1
'''

UPGRADE = r'''echo XP25_SEC_UPGRADE_STARTED > COM1
"%I%\XP25Sec.exe" status --quiet --out %W%\status-before-upgrade.jsonl
"%I%\XP25Sec.exe" verify --quiet --out %W%\verify-before-upgrade.jsonl
echo XP25_SEC_VERIFY_BEFORE_UPGRADE_EXIT=%ERRORLEVEL% > COM1
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


def stage(label):
    return observe('ports', label, 600)


def admin(command, marker, log):
    return '%s > %%W%%\\%s.txt 2>&1\necho XP25_FW_%s=%%ERRORLEVEL%% > COM1\n' % (command, log, marker)


def firewall_suite(flags):
    state = r'''sc query SharedAccess > %W%\fw-sc-query-{boot}.txt 2>&1
sc query IPNAT > %W%\fw-sc-ipnat-{boot}.txt 2>&1
netsh firewall show state > %W%\fw-state-{boot}.txt 2>&1
netsh firewall show config > %W%\fw-config-{boot}.txt 2>&1
%W%\tools\security_probe.exe fwcheck {boot} --hardened
echo XP25_FW_CHECK_{BOOT}=%ERRORLEVEL% > COM1
'''
    text = HEAD + 'set T=%I%\nif exist %W%\\fw-phase1.done goto fwphase2\necho XP25_FW_STARTED > COM1\n'
    text += 'sc qc SharedAccess > %W%\\fw-sc-qc.txt 2>&1\nsc sdshow SharedAccess > %W%\\fw-sc-sdshow.txt 2>&1\nsc qc IPNAT > %W%\\fw-sc-ipnat-qc.txt 2>&1\n'
    text += state.format(boot='boot1', BOOT='BOOT1') + LISTEN.replace('{n}', '1') + NAMES_ON + stage('blocked')
    text += admin('netsh firewall add portopening protocol=TCP port=%d name=XP25FwTestTcp' % LISTENER_PORT, 'ADMIN_ADD_TCP', 'fw-admin-add-tcp')
    text += admin('netsh firewall add portopening protocol=UDP port=%d name=XP25FwTestUdp' % LISTENER_PORT, 'ADMIN_ADD_UDP', 'fw-admin-add-udp')
    text += stage('permitted')
    text += admin('netsh firewall delete portopening protocol=TCP port=%d' % LISTENER_PORT, 'ADMIN_DELETE_TCP', 'fw-admin-delete-tcp')
    text += admin('netsh firewall delete portopening protocol=UDP port=%d' % LISTENER_PORT, 'ADMIN_DELETE_UDP', 'fw-admin-delete-udp')
    text += stage('removed') + observe('udp-expiry', 'removed-expiry', 400)
    # The unprivileged attempts (ordinary account, restricted token) run here, with the listener up.
    text += '%%W%%\\tools\\security_probe.exe admin %s --hardened --tools "%%T%%"\necho XP25_SEC_PROBE_EXIT=%%ERRORLEVEL%% > COM1\n' % flags
    text += '%W%\\tools\\security_probe.exe fwcheck after_unprivileged --hardened\necho XP25_FW_CHECK_AFTER_UNPRIVILEGED=%ERRORLEVEL% > COM1\n'
    text += stage('after-unprivileged')
    text += admin('netsh firewall set opmode mode=DISABLE', 'ADMIN_DISABLE', 'fw-admin-disable') + stage('admin-disabled')
    text += admin('netsh firewall set opmode mode=ENABLE', 'ADMIN_ENABLE', 'fw-admin-enable') + stage('admin-enabled')
    text += admin('net stop SharedAccess', 'ADMIN_STOP', 'fw-admin-stop') + stage('service-stopped')
    text += admin('net start SharedAccess', 'ADMIN_START', 'fw-admin-start') + stage('service-started')
    text += '"%T%\\XP25Sec.exe" verify --quiet --out %W%\\verify-fw-boot1.jsonl\necho XP25_FW_VERIFY_BOOT1=%ERRORLEVEL% > COM1\n'
    text += NAMES_OFF + LISTEN_STOP + observe('watch-start', 'restart-started', 120).replace('restart-started > COM1', 'restart > COM1')
    text += 'echo done > %W%\\fw-phase1.done\necho XP25_SEC_RESTARTING > COM1\n%W%\\tools\\security_probe.exe power restart\ngoto :eof\n'
    text += ':fwphase2\necho XP25_FW_PHASE2_STARTED > COM1\n' + LISTEN.replace('{n}', '2')
    text += state.format(boot='boot2', BOOT='BOOT2') + NAMES_ON + stage('after-restart')
    text += observe('watch-stop', 'restart', 120) + NAMES_OFF + LISTEN_STOP
    text += '"%T%\\XP25Sec.exe" verify --quiet --out %W%\\verify-fw-boot2.jsonl\necho XP25_SEC_FINAL_VERIFY_EXIT=%ERRORLEVEL% > COM1\n'
    return text + END


def suite(role, mode, xp25_winlogon=True, provider=True, repeat=1):
    """The Startup suite of one role as CR LF text."""
    slow = 'slow' if mode == 'tcg' else ''
    flags = '--xp25-winlogon' if xp25_winlogon else ''

    def scanned(label):
        return {'broadcast_on': BROADCAST_ON, 'scan': observe('scan', label), 'broadcast_off': BROADCAST_OFF}
    ai = AI.format(slow=slow) if provider else ''
    two_phase = 'if exist %W%\\phase1.done goto phase2\n'
    if role == 'regression':
        text = HEAD + 'echo XP25_SEC_REGRESSION_STARTED > COM1\n' + ai + COMPAT + END
    elif role == 'audit':
        text = HEAD + UNINSTALLED_TOOLS + 'echo XP25_SEC_AUDIT_STARTED > COM1\n' + \
            TESTS.format(tag='before', probe=flags, **scanned('before')) + END
    elif role == 'harden':
        text = HEAD + two_phase + INSTALL + RESTART + ':phase2\nset T=%I%\necho XP25_SEC_PHASE2_STARTED > COM1\n' + \
            TESTS.format(tag='hardened', probe=flags + ' --hardened', **scanned('hardened')) + \
            DRIFT.format(tag='hardened', snapshot=SNAPSHOT.format(tag='hardened')) + ai + \
            COMPAT_HARDENED.format(tag='hardened') + END
    elif role == 'image-install':
        text = HEAD + two_phase + INSTALL + RESTART + ':phase2\necho XP25_SEC_PHASE2_STARTED > COM1\n' + IMAGE_END.replace('{prefix}', 'install')
    elif role == 'proof':
        text = HEAD + 'set T=%I%\necho XP25_SEC_PROOF_STARTED > COM1\n' + \
            TESTS.format(tag='proof', probe=flags + ' --hardened', **scanned('proof')) + \
            DRIFT.format(tag='proof', snapshot='') + ai + COMPAT_HARDENED.format(tag='proof') + APPS.format(tag='proof', slow=slow) + END
    elif role == 'rollback':
        text = HEAD + two_phase + ROLLBACK + RESTART + ':phase2\necho XP25_SEC_PHASE2_STARTED > COM1\n' + \
            AFTER_ROLLBACK.format(**scanned('rolled-back')) + END
    elif role == 'firewall':
        text = firewall_suite(flags)
    elif role == 'ai-repeat':
        text = HEAD + 'echo XP25_AI_REPEAT_STARTED=%d > COM1\n' % repeat + AI[:AI.index('echo XP25_AI_TESTS_STARTED')] + \
            'call "%U%\\xp25sec-gateway-secret.cmd"\n' + ''.join(AI_ROUND.format(n=n, slow=slow) for n in range(1, repeat + 1)) + END
    elif role == 'standard-user':
        text = HEAD + 'if exist %W%\\std-admin1.done goto :eof\n' + STD_ADMIN_FIRST
    elif role == 'apps':
        text = HEAD + 'echo XP25_SEC_APPS_STARTED > COM1\n' + APPS.format(tag='admin', slow=slow) + END
    elif role == 'image-upgrade':
        text = HEAD + two_phase + UPGRADE + RESTART + ':phase2\necho XP25_SEC_PHASE2_STARTED > COM1\n' + IMAGE_END.replace('{prefix}', 'upgrade-81')
    elif role == 'cve':
        # Milestone 8.2: verify the installed (patched) lsasrv.dll. The login itself exercises the
        # rebuilt LSASS authentication path; the admin probe adds the MS04-011 DsRole checks across
        # the administrator, ordinary-account and restricted-token contexts (--cve) plus the baseline
        # privilege checks (--hardened).
        text = HEAD + 'echo XP25_SEC_CVE_STARTED > COM1\n' + \
            '%%W%%\\tools\\security_probe.exe admin %s --cve --hardened --tools "%%I%%"\n' % flags + \
            'echo XP25_SEC_PROBE_EXIT=%ERRORLEVEL% > COM1\n' + END
    else:
        raise ValueError(role)
    return text.replace('\r\n', '\n').replace('\n', '\r\n')


def extra_files(role, mode):
    """Further files a role stages into the XP25 profile, as {name: CR LF text}."""
    if role == 'standard-user':
        text = STD_STARTUP.replace('{slow}', 'slow' if mode == 'tcg' else '')
        return {'std-startup.cmd': text.replace('\r\n', '\n').replace('\n', '\r\n')}
    return {}


ROLES = ('regression', 'audit', 'harden', 'image-install', 'proof', 'rollback', 'firewall', 'ai-repeat', 'standard-user', 'image-upgrade', 'apps', 'cve')
STD_USER = 'xp25user'
# Interactive sessions of a role, in order, when they are not all the XP25 administrator.
LOGONS = {'standard-user': ('admin', 'standard', 'standard')}
# Which staged payload a role needs (xp25sec-<name> in the XP25 profile).
PAYLOAD = {
    'regression': ('security_probe.exe', 'ai_probe.exe'),
    'audit': ('XP25Sec.exe', 'XP25Audit.exe', 'security_probe.exe'),
    'harden': ('XP25Sec.exe', 'XP25Audit.exe', 'security_probe.exe', 'ai_probe.exe'),
    'image-install': ('XP25Sec.exe', 'XP25Audit.exe', 'security_probe.exe'),
    'proof': ('security_probe.exe', 'ai_probe.exe'),
    'rollback': ('security_probe.exe',),
    'firewall': ('security_probe.exe',),
    'ai-repeat': ('ai_probe.exe', 'security_probe.exe'),
    'standard-user': ('security_probe.exe',),
    'image-upgrade': ('XP25Sec.exe', 'XP25Audit.exe', 'security_probe.exe'),
    'apps': ('security_probe.exe',),
    'cve': ('security_probe.exe',),
}
# Roles that run the AI provider checks need the gateway and the OpenAI test double.
PROVIDER = ('regression', 'harden', 'proof', 'ai-repeat')
