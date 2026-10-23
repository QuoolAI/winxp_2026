#!/usr/bin/env python3
"""Generate the x86 XP pointer-encoding compatibility patch under .work/."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / 'Source/XPSP1/NT'


def prepare(output):
    output = output.resolve()
    if not output.is_relative_to(ROOT / '.work'):
        raise ValueError('Generated source belongs under .work/')
    output.mkdir(parents=True, exist_ok=False)
    manifest = {}

    def change(name, old, new):
        original = (REFERENCE / name).read_bytes()
        text = original.decode('latin1')
        if text.count(old) != 1:
            raise ValueError(f'Expected one patch location in {name}')
        patched = text.replace(old, new).encode('latin1')
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(patched)
        manifest[name] = dict(original_sha256=hashlib.sha256(original).hexdigest(),
                              patched_sha256=hashlib.sha256(patched).hexdigest())

    change('base/ntos/inc/ps.h',
           '    UCHAR WorkingSetAcquiredUnsafe;\n\n} EPROCESS;',
           '    UCHAR WorkingSetAcquiredUnsafe;\n\n'
           '#if defined(_X86_)\n'
           '    // XP25: appended kernel-held, lazily initialized process cookie.\n'
           '    ULONG PointerCookie;\n'
           '#endif\n\n} EPROCESS;')

    change('base/ntos/kd64/kddata.c',
           'C_ASSERT(sizeof(EPROCESS) == X86_NT51_EPROCESS_SIZE);',
           '// XP25: retain the original layout; only the cookie tail is new.\n'
           'C_ASSERT(FIELD_OFFSET(EPROCESS, PointerCookie) == X86_NT51_EPROCESS_SIZE);\n'
           'C_ASSERT(sizeof(EPROCESS) == 0x260);')

    cookie_case = '''#if defined(_X86_)
    // XP25: class 36 is the XP SP2/SP3 process cookie query. The pseudo
    // current-process handle is required even if another handle names self.
    // Match the installed SP3 x86 time/PRCB counter mixing and atomic publish.
    case (PROCESSINFOCLASS)36: {
        LARGE_INTEGER CookieTime;
        ULONG Cookie;
        ULONG Candidate;
        PKPRCB Prcb;

        if (ProcessInformationLength != sizeof(ULONG)) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        if (ProcessHandle != NtCurrentProcess()) {
            return STATUS_INVALID_PARAMETER;
        }
        Process = PsGetCurrentProcess();
        Cookie = Process->PointerCookie;
        while (Cookie == 0) {
            KeQuerySystemTime(&CookieTime);
            Prcb = KeGetCurrentPrcb();
            Candidate = CookieTime.LowPart ^ CookieTime.HighPart ^
                        Prcb->KeSystemCalls ^ Prcb->InterruptTime;
            if (Candidate != 0) {
                InterlockedCompareExchange((PLONG)&Process->PointerCookie,
                                           (LONG)Candidate, 0);
            }
            Cookie = Process->PointerCookie;
        }
        try {
            *(PULONG)ProcessInformation = Cookie;
            if (ARGUMENT_PRESENT(ReturnLength)) {
                *ReturnLength = sizeof(ULONG);
            }
        } except(EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
        return STATUS_SUCCESS;
    }
#endif

'''
    change('base/ntos/ps/psquery.c',
           '    case ProcessImageFileName:\n',
           cookie_case + '    case ProcessImageFileName:\n')

    # Keep the cookie out of persistent user-mode state. XP x86 uses the
    # same XOR operation for encoding and decoding; encoded values are opaque.
    rtl = '''
#if defined(_X86_)
PVOID
NTAPI
RtlEncodePointer(IN PVOID Pointer)
{
    ULONG Cookie;
    NTSTATUS Status;

    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       (PROCESSINFOCLASS)36,
                                       &Cookie, sizeof(Cookie), NULL);
    if (!NT_SUCCESS(Status)) {
        RtlRaiseStatus(Status);
    }
    return (PVOID)((ULONG_PTR)Pointer ^ Cookie);
}

PVOID
NTAPI
RtlDecodePointer(IN PVOID Pointer)
{
    return RtlEncodePointer(Pointer);
}
#endif
'''
    name = 'base/ntdll/query.c'
    original = (REFERENCE / name).read_bytes()
    target = output / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(original + rtl.encode('ascii'))
    manifest[name] = dict(original_sha256=hashlib.sha256(original).hexdigest(),
                          patched_sha256=hashlib.sha256(target.read_bytes()).hexdigest())

    change('base/ntdll/ntdlldef.src', '    RtlRaiseStatus\n',
           '#if defined(_X86_)\n    RtlEncodePointer\n    RtlDecodePointer\n#endif\n'
           '    RtlRaiseStatus\n')
    change('base/win32/client/kernel32.src',
           '    SetLastError = NTDLL.RtlSetLastWin32Error\n',
           '#if defined(_X86_)\n'
           '    EncodePointer = NTDLL.RtlEncodePointer\n'
           '    DecodePointer = NTDLL.RtlDecodePointer\n'
           '#endif\n'
           '    SetLastError = NTDLL.RtlSetLastWin32Error\n')
    (output / 'patch-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    print(json.dumps(prepare(parser.parse_args().output), indent=2))
