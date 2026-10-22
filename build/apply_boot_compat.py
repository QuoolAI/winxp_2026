#!/usr/bin/env python3
"""Prepare narrowly scoped x86 boot experiments; never alter Source/."""
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
    files = {}

    def change(name, old, new):
        original = (REFERENCE / name).read_bytes()
        text = original.decode('latin1')
        if text.count(old) != 1:
            raise ValueError(f'Expected exactly one patch location in {name}')
        patched = text.replace(old, new).encode('latin1')
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(patched)
        files[name] = {'original_sha256': hashlib.sha256(original).hexdigest(),
                       'patched_sha256': hashlib.sha256(patched).hexdigest()}

    change('base/hals/halmps/i386/mpirql.asm',
           '        cmp     ecx, eax                        ; Verify IRQL read back is same as\n'
           '        je      short @f                        ; set value\n',
           '; XP25: AMD KVM SVM synchronizes TPR through the four-bit CR8 class.\n'
           '; The read above remains the serialization point. Verify every bit\n'
           '; except the low priority sub-class nibble, which does not map IRQL.\n'
           '        xor     eax, ecx\n'
           '        test    eax, 0fffffff0h\n'
           '        je      short @f\n')

    change('base/hals/inc/ntapic.inc',
           'CHECKTPR macro reg1, reg2\nif DBG\n'
           '        cmp     reg1, reg2\n',
           'CHECKTPR macro reg1, reg2\nif DBG\n'
           '; XP25: check the IRQL class; preserve registers and serialization.\n'
           '        push    reg1\n'
           '        xor     reg1, reg2\n'
           '        test    reg1, 0fffffff0h\n'
           '        pop     reg1\n')

    name = 'base/hals/halmps/i386/mpspin.asm'
    original = (REFERENCE / name).read_bytes()
    text = original.decode('latin1')
    # The same APIC readback invariant appears in five release/failure paths.
    # EAX/ECX are scratch in all these paths; keep ownership and IRQL checks.
    import re
    pattern = (r'        cmp     (?:ecx, eax|eax, ecx) +; Verify (?:IRQL read back is same as|TPR is what was)\n'
               r'        je      short @f +; (?:set value|written)\n')
    text, count = re.subn(pattern,
        '; XP25: preserve the serialized TPR class check on AMD KVM.\n'
        '        xor     eax, ecx\n'
        '        test    eax, 0fffffff0h\n'
        '        je      short @f\n', text)
    assert count == 5, count
    # These checked fast-mutex guards also compare a TPR class, rather than
    # interpreting its low nibble as a separate Windows IRQL.
    assert text.count('        cmp     eax, APC_VECTOR\n') == 3
    text = text.replace('        cmp     eax, APC_VECTOR\n',
        '        and     eax, 0fffffff0h\n'
        '        cmp     eax, (APC_VECTOR and 0fffffff0h)\n')
    target = output / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(text.encode('latin1'))
    files[name] = {'original_sha256': hashlib.sha256(original).hexdigest(),
                   'patched_sha256': hashlib.sha256(target.read_bytes()).hexdigest()}

    # This experiment selects ntdll's original INT 2E implementation. It avoids
    # changing the SYSENTER trap frame or removing any privilege checks. The
    # old inline ABI remains selected when the pointer-ABI exports are absent.
    name = 'base/ntos/ke/i386/misc.c'
    original = (REFERENCE / name).read_bytes()
    text = original.decode('latin1')
    anchor = 'PVOID KiFastSystemCallCode = KiDefaultSystemCall;'
    assert text.count(anchor) == 1
    text = text.replace(anchor, anchor + '\n\n// XP25: optional SP2/SP3 ntdll pointer ABI, using its INT 2E entry.\nPVOID KiSystemCallPointer = NULL;\nPVOID KiSystemCallPointerReturn = NULL;')
    old = ('        RtlCopyMemory(SharedUserData->SystemCall,\n'
           '                      KiFastSystemCallCode,\n'
           '                      sizeof(SharedUserData->SystemCall));')
    assert text.count(old) == 1
    text = text.replace(old,
        '        if (KiSystemCallPointer != NULL) {\n'
        '            RtlZeroMemory(SharedUserData->SystemCall,\n'
        '                          sizeof(SharedUserData->SystemCall));\n'
        '            ((PVOID *)SharedUserData->SystemCall)[0] = KiSystemCallPointer;\n'
        '            ((PVOID *)SharedUserData->SystemCall)[1] = KiSystemCallPointerReturn;\n'
        '        } else {\n' + old + '\n        }')
    target = output / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(text.encode('latin1'))
    files[name] = {'original_sha256': hashlib.sha256(original).hexdigest(),
                   'patched_sha256': hashlib.sha256(target.read_bytes()).hexdigest()}

    change('base/ntos/ps/psinit.c',
           '    st = PspLookupKernelUserEntryPoints();',
           '#if defined(_X86_)\n'
           '    {\n'
           '        extern PVOID KiSystemCallPointer;\n'
           '        extern PVOID KiSystemCallPointerReturn;\n'
           '        PVOID IntCall;\n'
           '        PVOID ReturnCall;\n'
           '        // Detect the pointer ABI from the mapped system DLL itself.\n'
           '        if (NT_SUCCESS(PspLookupSystemDllEntryPoint("KiIntSystemCall", &IntCall)) &&\n'
           '            NT_SUCCESS(PspLookupSystemDllEntryPoint("KiFastSystemCallRet", &ReturnCall))) {\n'
           '            KiSystemCallPointer = IntCall;\n'
           '            KiSystemCallPointerReturn = ReturnCall;\n'
           '            RtlZeroMemory(SharedUserData->SystemCall, sizeof(SharedUserData->SystemCall));\n'
           '            ((PVOID *)SharedUserData->SystemCall)[0] = IntCall;\n'
           '            ((PVOID *)SharedUserData->SystemCall)[1] = ReturnCall;\n'
           '        }\n'
           '    }\n'
           '#endif\n\n'
           '    st = PspLookupKernelUserEntryPoints();')
    # Source GUI stubs otherwise execute the shared-data pointer bytes as code
    # when paired with SP2/SP3 ntdll. INT 2E uses the original NT x86 service
    # dispatcher and remains independent of the shared inline/pointer ABI.
    # At this stub's entry, ESP+4 points to the first caller argument.
    change('windows/core/kmode/i386/services.stb',
           '#define USRSTUBS_ENTRY4( ServiceNumber, Name, NumArgs )      __asm   mov     edx, call_func\n'
           '#define USRSTUBS_ENTRY5( ServiceNumber, Name, NumArgs )      __asm   call    edx\n',
           '// XP25: keep the original INT 2E argument and privilege checks.\n'
           '#define USRSTUBS_ENTRY4( ServiceNumber, Name, NumArgs )      __asm   lea     edx, [esp+4]\n'
           '#define USRSTUBS_ENTRY5( ServiceNumber, Name, NumArgs )      __asm   int     2eh\n')
    (output / 'patch-manifest.json').write_text(json.dumps(files, indent=2) + '\n')
    return files


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    print(json.dumps(prepare(parser.parse_args().output), indent=2))
