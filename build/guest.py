#!/usr/bin/env python3
"""Cross-compile the XP guest probe; record static evidence, not runtime success."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[1]
ALLOWED_DLLS = {"kernel32.dll", "user32.dll", "advapi32.dll", "ws2_32.dll"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(text, expected_dlls=ALLOWED_DLLS):
    imports = {name.lower() for name in re.findall(r"DLL Name:\s+(\S+)", text)}
    if imports != expected_dlls:
        raise ValueError("unexpected guest runtime dependency set: " + str(sorted(imports)))
    if "file format pei-i386" not in text:
        raise ValueError("probe is not an i386 PE executable")
    for name, expected in (("MajorOSystemVersion", "5"), ("MinorOSystemVersion", "1"),
                           ("MajorSubsystemVersion", "5"), ("MinorSubsystemVersion", "1")):
        if not re.search(r"^" + name + r"\s+" + expected + r"\s*$", text, re.M):
            raise ValueError("incorrect XP PE header field: " + name)
    return sorted(imports)


def import_symbols(text, expected_dlls=ALLOWED_DLLS):
    result, current = {}, None
    for line in text.splitlines():
        module = re.search(r"DLL Name:\s+(\S+)", line)
        if module:
            current = module[1].lower()
            result[current] = set()
        elif not line.strip():
            current = None
        elif current:
            entry = re.fullmatch(r"\s*[0-9a-fA-F]+\s+\d+\s+([A-Za-z_]\w*)\s*", line)
            if entry:
                result[current].add(entry[1])
    if set(result) != expected_dlls or any(not names for names in result.values()):
        raise ValueError("incomplete named import inspection")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", type=Path, help="directory containing MinGW GCC and objdump")
    parser.add_argument("--probe", choices=("xp", "pointer", "session", "network", "service", "branding", "regsvc", "gina", "userenv", "shell", "profile", "oem"), default="xp",
                        help="standard, pointer, session, network, service, branding or component checks")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, default=REPO / "Source/XPSP1/NT/public/sdk/lib/i386",
                        help="local XP SDK import libraries; read only, never copied to output")
    parser.add_argument("--userenv-reference", type=Path, help="private SP3 UserEnv export contract for the userenv probe")
    args = parser.parse_args()
    output = args.output.resolve()
    protected = (REPO / "Source").resolve()
    if output == protected or protected in output.parents:
        parser.error("probe output cannot be inside the reference source")
    names = {"cc": "i686-w64-mingw32-gcc-posix", "objdump": "i686-w64-mingw32-objdump",
             "nm": "i686-w64-mingw32-nm"}
    tools = {}
    for key, name in names.items():
        value = args.toolchain.resolve() / name if args.toolchain else shutil.which(name)
        if not value or not Path(value).is_file():
            parser.error("missing tool: " + name)
        tools[key] = str(value)
    output.mkdir(parents=True, exist_ok=False)
    contract = None
    if args.probe == 'userenv':
        if not args.userenv_reference or not args.userenv_reference.resolve().is_relative_to(REPO / '.work'):
            parser.error('userenv probe requires a private SP3 reference')
        from inspect_component import PE
        from userenv_sp3_compat import exports
        names, ordinals = exports(PE(args.userenv_reference))
        if len(names) != 49 or ordinals.keys() != set(range(100, 210)):
            parser.error('unreviewed UserEnv contract')
        header = output / 'userenv_contract.h'
        header.write_text('static const struct {const char *name; WORD ordinal;} userenv_exports[] = {\n' +
                          ''.join('    {"' + n + '",' + str(o) + '},\n' for n,o in sorted(names.items())) + '};\n')
        contract = {'reference_sha256': digest(args.userenv_reference), 'header_sha256': digest(header)}
    stem = args.probe + "_probe"
    source = REPO / ("tests/guest/" + stem + ".c")
    executable = output / (stem + ".exe")
    expected_dlls = ALLOWED_DLLS if args.probe == "xp" else {"kernel32.dll", "user32.dll"}
    if args.probe in ("session", "service", "branding", "regsvc", "gina", "userenv", "profile", "shell", "oem"):
        expected_dlls = expected_dlls | {"advapi32.dll"}
    elif args.probe == "network":
        expected_dlls |= {"advapi32.dll", "ws2_32.dll", "iphlpapi.dll"}
    if args.probe == 'shell':
        expected_dlls |= {'shell32.dll'}
    if args.probe == 'profile':
        expected_dlls |= {'netapi32.dll'}
    if args.probe in ("branding", "oem"):
        expected_dlls |= {"gdi32.dll"}
    command = [tools["cc"], "-Os", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
               "-fno-builtin", "-fno-stack-protector", "-nostdlib",
               "-Wl,--entry,_ProbeMain@0", "-Wl,--subsystem,console:5.1",
               "-Wl,--major-os-version,5,--minor-os-version,1", "-Wl,--no-insert-timestamp",
               "-Wl,--disable-dynamicbase", str(source), "-o", str(executable),
               "-lkernel32", "-luser32"]
    if args.probe == "xp":
        command += ["-ladvapi32", "-lws2_32"]
    elif args.probe in ("session", "service", "branding", "regsvc", "gina", "userenv", "profile", "shell", "oem"):
        command += ["-ladvapi32"]
    elif args.probe == "network":
        command += ["-ladvapi32", "-lws2_32", "-liphlpapi"]
    if args.probe in ("branding", "oem"):
        command += ["-lgdi32"]
    if args.probe == 'shell':
        command += ['-lshell32']
    if args.probe == 'profile':
        command += ['-lnetapi32']
    if contract:
        command += ['-I', str(output)]
    result = {"schema": 1, "started_utc": datetime.now(timezone.utc).isoformat(),
              "status": "failed", "guest_execution": "not_attempted",
              "source_sha256": digest(source), "command": command, "tools": {}, "additional_contract": contract}
    environment = {**os.environ, "LC_ALL": "C"}
    try:
        for key, path in tools.items():
            result["tools"][key] = {"path": path, "sha256": digest(Path(path)),
                                    "version": subprocess.check_output([path, "--version"],
                                    text=True, env=environment).splitlines()[0]}
        with (output / "build.log").open("w") as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True,
                           timeout=60, env=environment)
        inspection = subprocess.check_output([tools["objdump"], "-p", str(executable)],
                                             text=True, env=environment)
        (output / "inspection.txt").write_text(inspection)
        result["imports"] = verify(inspection, expected_dlls)
        result["xp_sdk_imports"] = {}
        for module, symbols in import_symbols(inspection, expected_dlls).items():
            library = args.sdk.resolve() / (module[:-4] + ".lib")
            listing = subprocess.check_output([tools["nm"], "-g", "--defined-only", str(library)],
                                               text=True, env=environment)
            available = set(re.findall(r"\b__imp__([A-Za-z_]\w*?)(?:@\d+)?$", listing, re.M))
            missing = sorted(symbols - available)
            if missing:
                raise ValueError("imports absent from local XP SDK " + module + ": " + str(missing))
            result["xp_sdk_imports"][module] = {"library_sha256": digest(library),
                                                "matched_imports": len(symbols)}
        result.update(status="compiled_static_checks_passed", executable_sha256=digest(executable))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
    result["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "compiled_static_checks_passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
