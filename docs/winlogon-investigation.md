# Independent NT 5.1 Winlogon investigation

The original `ds/security/gina/winlogon` implementation is absent. Its parent
`dirs` file still requires it. Microsoft Winlogon remains active in the accepted
engineering images and user VMs. Milestone 5 now supplies an independently
authored native prototype tested only as a boot replacement in disposable
overlays. Initialization and console authentication reach a deliberate error
before profile/shell startup; no replacement has been accepted. MSGINA alone
does not implement Winlogon, and no ReactOS/Wine/Linux core is substituted.
[Current implementation and exact remaining boundary](native-winlogon.md)

## Established contracts

Microsoft documents Winlogon, GINA and network providers as separate parts of
the XP interactive-logon model. Replacing GINA is the documented extension path;
implementing that DLL does not implement its Winlogon host.
[Winlogon and GINA](https://learn.microsoft.com/en-us/windows/win32/secauthn/winlogon-and-gina)

A compatible host must negotiate and initialize the GINA, preserve its context
and dispatch the correct callbacks while logged out, logged on and locked. It
must also run the logoff and shutdown callbacks in the required order. A shell
launcher alone does not meet this state-machine contract.
[Interaction contract](https://learn.microsoft.com/en-us/windows/win32/secauthn/interaction-between-winlogon-and-gina)

Desktop/window-station ACLs, trusted Ctrl+Alt+Del routing, profile activation,
user-token shell creation, idle/secure-screen-saver handling and network-provider
coordination are separate obligations. The loaded user hive must be available
before the shell starts. None can be replaced by an unconditional logon-success
return or by launching Explorer as SYSTEM.
[Winlogon responsibilities](https://learn.microsoft.com/en-us/windows/win32/secauthn/responsibilities-of-winlogon)

Existing notification packages must keep receiving appropriate logon/logoff and
state events. Their ordering, blocking behavior and failure handling need
compatibility tests alongside the GINA callbacks.
[Notification packages](https://learn.microsoft.com/en-us/windows/win32/secauthn/winlogon-notification-packages)

The supplied SDK's `public/sdk/inc/winwlx.h` defines version 1.4 and its dispatch
structure. The original MSGINA source implements the corresponding client side.
The local Win32k source `windows/core/ntuser/kernel/logon.c` provides concrete
additional constraints: `_RegisterLogonProcess` requires TCB privilege and rejects
a second logon-process registration; window-station locking and logon-notify
registration check the registered process ID. A normal user application cannot
stand in for that boot-time role merely by adopting the filename.

The inspected installed executable imports twenty direct DLLs and six delay
modules. The private artifact `winlogon-binary-contract.json` records all imported
names/ordinals and its hash. Dependencies include UserEnv's private profile/policy
entry points, authentication/security libraries, window-station services,
Profmap/Regapi, networking and GINA. This static inventory does not discover all
dynamic lookup, RPC, notification or kernel interactions.

## Implementation route and acceptance boundary

An independent implementation can target the NT 5.1 x86 interfaces and retain
the verified original kernel, CSRSS/Win32 subsystem, LSASS/authentication packages,
original MSGINA, UserEnv and Explorer. Its specification should identify each
public API and each privately observed dependency, with provenance and tests.
Reading surrounding supplied source is not evidence of a formally separated
clean-room process or of redistribution rights.

The implementation and acceptance stages are:

1. Specify and test the logon state machine without privileged registration or
   boot replacement. Include cancellation, failed authentication, repeated SAS,
   lock/unlock and teardown paths; record ownership of tokens and credentials.
2. Account for SMSS/CSRSS startup, trusted USER registration, window stations,
   desktop ACLs, LSA registration, critical-process behavior and failure recovery.
3. Implement versioned WLX dispatch, profile/environment/GPO work, notification
   packages, network providers and user-token shell startup. Preserve security
   errors rather than concealing unavailable operations.
4. Test one replacement in a new child with an exact original recovery copy.
   Require positive/negative logon, correct Explorer/user token identity, secure
   desktop denial to the user, lock/unlock, logoff, orderly shutdown and the full
   KVM/MP/TCG regression matrix. Domain, smart-card, FUS and RDP coverage remain
   separate acceptance work.

The current tests improve evidence for MSGINA and its host: they read the DLL
actually mapped in Winlogon, test secure-desktop write denial, and exercise real
login UI transitions. They are not a Winlogon replacement or a complete security
certification. The installation manifest must retain the installed Winlogon as
an original-binary dependency until a replacement meets these gates, and must
identify the licensed source of that binary.
