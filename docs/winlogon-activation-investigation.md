# Winlogon licensing and activation boundary

2026-10-24. This is a static source-tree investigation of the supplied XP SP1
reference tree and the independent XP25 Winlogon prototype. It is not evidence
that a Windows guest is activated, that a licence is valid, or that a desktop
can safely be started.

## Result

The [later native policy/session investigation](winlogon-policy-session-contract.md)
supersedes the static kernel-boundary finding below: the linked kernel does
contain the implementation in prebuilt `ex:systime.obj`. Its two-output ABI
and successful original-host calls are recorded, and the independent host now
performs real key protection. Complete licensing admission remains unresolved;
the historical source-search gap must not be read as absent machine code.

The original Winlogon source and its licensing orchestration contract are not
present in `Source/`. The independent implementation consequently stops at the session-admission
boundary with `ERROR_CALL_NOT_IMPLEMENTED` (120), records
`activation_policy_contract_unresolved`, and does not invoke the GINA shell
callback. It neither changes activation data nor returns an invented success
result.

The continued desktop milestone must preserve these checks. Two incoming
uncommitted edits instead forced shell-admission success and substituted a
zero SYSKEY. Their exact bytes and diff are retained privately under
`.work/winlogon-lifecycle-20261024/incoming/` and `incoming.diff`; both overrides
were restored to the committed checks before any build in this continuation.
SYSKEY is an LSASS startup authentication contract, distinct from product
activation. No forced-success variant was built or installed by this work.

## Evidence retained

The following read-only commands were run from the repository root; their
terminal output is retained in the task transcript:

```sh
rg --files -g '*winlogon*' -g '*licens*' -g '*activat*'
rg -n -i --glob '!Source/**' 'activat|licen|wpa|product.?key|product.?id|slmgr' components build tests docs vm
rg -n -i --glob '*.{c,cc,cpp,cxx,h,hxx,idl,inc,def,asm}' \
  'NtLockProductActivationKeys|ProductActivation|WPAEvents|OEMBIOS|WPA|activation' \
  Source/XPSP1/NT/ds/security Source/XPSP1/NT/base/ntsetup/oobe Source/XPSP1/NT/base/win32
```

`components/winlogon/session.c` is the only current prototype boundary. Its
comment and return value explicitly prevent shell activation after profile
preparation. A repeated source search in the lifecycle continuation again found
no Winlogon C source, `activation.h` or `licdll.h`; commands/results are retained
in `activation-contract-search.json` and `.log` under that continuation. The static search found an OOBE-side caller at
`Source/XPSP1/NT/base/ntsetup/oobe/oobebaln/activate.cpp`; it constructs
`CLSID_COMLicenseAgent`, uses `ICOMLicenseAgent`, obtains expiration values,
and drives asynchronous handshake/new-license/reissue-license requests. The
headers that define that COM contract (`activation.h`, `licdll.h`, and its
implementation) are absent from the supplied reference tree, so this caller
does not establish the Winlogon contract.

## Interfaces whose semantics remain unestablished

| Boundary | What static inspection establishes | What is unresolved |
| --- | --- | --- |
| Winlogon activation decision | Installed original Winlogon is documented as importing/using WPA, OEMBIOS, a WPA mutex and `NtLockProductActivationKeys`; its source is absent. | Call sequence, parameters, return/error mapping, state transitions, ordering relative to GINA/userinit, and whether a given product channel takes the path. |
| Licensing COM agent | OOBE code references `CLSID_COMLicenseAgent` and `ICOMLicenseAgent` methods `Initialize`, `SetIsoLanguage`, `GetExpirationInfo`, `AsyncProcessHandshakeRequest`, `AsyncProcessNewLicenseRequest`, `AsyncProcessReissueLicenseRequest`, and `GetAsyncProcessReturnCode`. | ABI/IDL, class registration, server DLL, persistence, authorization, network protocol, result semantics and all error handling. |
| Activation state | Existing project probes recognize `WPAEvents` and `OOBETimer` as identity-sensitive registry data and deliberately do not print their contents. | Data schema, protection/integrity mechanism, ownership, update timing, and how state is reconciled with the licensing agent. |
| OEM activation | The installed-binary investigation identifies OEMBIOS handling only. | OEMBIOS files/markers, validation algorithm, channel applicability, ordering, and relationship to ordinary activation. |
| Kernel boundary | `NtLockProductActivationKeys` is named by installed-binary investigation but no declaration or implementation was found in the supplied source search. | ABI, required privilege/process context, lock lifetime, failure handling, and whether it is called before or after the licensing decision. |
| Shell admission | GINA exposes `WlxActivateUserShell`; the prototype has a typed function pointer but deliberately does not call it at the unresolved boundary. | Preconditions set by original Winlogon, environment/policy ownership, userinit command selection, rollback behaviour and complete session lifecycle. |

None of these unknowns may be filled with a success-returning stub. A future
implementation needs an established licensing-preserving orchestration contract
and recorded guest tests using legitimately licensed media. Until then, Winlogon activation compatibility is **unresolved**
and the independent replacement is **not accepted** for desktop use.

## Documentation validation

`git diff --check` passed. The first host-test invocation,
`python3 -m unittest tests.test_winlogon`, did not run a test because `tests/`
is not a Python package (`ModuleNotFoundError: No module named
'tests.test_winlogon'`). The repository's direct entry point,
`python3 tests/test_winlogon.py`, then passed all three portable tests. These
tests exercise only transition/decoder/environment helpers; they do not test
activation, licensing, a guest boot, or a completed login.

## Fresh runtime verification continuation

The [fresh native verification](winlogon-runtime-verification.md) first builds
exact input `68f098042`; genuine C2065/C4505 compiler failures prevent linking.
The corrected build restores real SYSKEY validation and keeps the shell work
behind `security.c:wl_session_policy`. Hardware-breakpoint captures demonstrate
real LSA failure/success, correct token/profile/environment state, and that
boundary before the GINA shell callback. Its error 120 is a local unimplemented
orchestration result, not a rejected activation request or a licensing-server
response. The original engineering Winlogon's freshly inspected PE confirms
its `ntdll!NtLockProductActivationKeys` import; the required orchestration has
not been established. No forced-success variant was installed or executed.
