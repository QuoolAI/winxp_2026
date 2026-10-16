#!/usr/bin/env python3
"""Build selected One-Core-API forwarders using the checked-in XP export surface.

Uses the pinned upstream spec2def and API-set specifications without modifying
either source tree. A source-declared target is not proof of runtime compatibility.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def export_names(text):
    active = False
    names = set()
    for line in text.splitlines():
        line = line.split(";", 1)[0].strip()
        if line == "EXPORTS":
            active = True
        elif active and line:
            match = re.match(r"([A-Za-z_?$][\w?$@]*)", line)
            if not match:
                raise ValueError("unrecognized XP export line: " + line)
            names.add(match[1])
    if not names:
        raise ValueError("no XP exports parsed")
    return names


def forwarders(text, available):
    """Reject the entire contract if any symbol needs more than XP kernel32."""
    result, missing = {}, []
    active = False
    for line in text.splitlines():
        line = line.split(";", 1)[0].strip()
        if line == "EXPORTS":
            active = True
        elif active and line:
            match = re.fullmatch(r"([\w?$@]+)=([\w]+)\.([\w?$@]+)\s+@\d+", line)
            if not match:
                missing.append({"entry": line, "reason": "not_a_named_pure_forwarder"})
                continue
            name, module, target = match.groups()
            if module.lower() != "kernel32" or target not in available:
                missing.append({"entry": line, "reason": "target_not_in_XP_kernel32"})
            elif name in result:
                raise ValueError("duplicate export: " + name)
            else:
                result[name] = module + "." + target
    if not result and not missing:
        missing.append({"reason": "empty_contract"})
    return result, missing


def verify_objdump(text, expected, arch):
    machine = "pei-i386" if arch == "x86" else "pei-x86-64"
    if "file format " + machine not in text:
        raise ValueError("PE machine mismatch")
    for key, value in (("AddressOfEntryPoint", 0), ("MajorOSystemVersion", 5),
                       ("MinorOSystemVersion", 1 if arch == "x86" else 2),
                       ("MajorSubsystemVersion", 5),
                       ("MinorSubsystemVersion", 1 if arch == "x86" else 2)):
        found = re.search(r"^" + key + r"\s+([0-9a-fA-F]+)\s*$", text, re.M)
        if not found or int(found[1], 16) != value:
            raise ValueError("unexpected PE field: " + key)
    addresses, names = {}, {}
    named_table = False
    for line in text.splitlines():
        if line.startswith("[Ordinal/Name Pointer] Table"):
            named_table = True
            continue
        address = re.search(r"\[\s*(\d+)\].*Forwarder RVA -- (\S+)", line)
        if address:
            addresses[int(address[1])] = address[2]
        elif named_table:
            name = re.fullmatch(r"\s*\[\s*(\d+)\]\s+(\S+)\s*", line)
            if name:
                names[int(name[1])] = name[2]
    actual = {name: addresses.get(index) for index, name in names.items()}
    if actual != expected or len(addresses) != len(expected):
        raise ValueError("linked exports differ from the validated specification")
    return {"machine": machine, "exports": len(actual), "entrypoint": 0,
            "runtime": "unverified"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=REPO / "Source/XPSP1/NT")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--arch", choices=("x86", "amd64"), default="x86")
    parser.add_argument("--binutils-dir", type=Path)
    parser.add_argument("--cc", default="gcc", help="native C compiler, also used for preprocessing")
    args = parser.parse_args()
    upstream, source, output = args.upstream.resolve(), args.source.resolve(), args.output.resolve()
    lock = json.loads((REPO / "build/onecore.lock.json").read_text())
    try:
        for root in (upstream, source, REPO / "Source"):
            if output == root or root in output.parents:
                raise ValueError("output must be outside both source trees")
        revision = subprocess.check_output(
            ["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
        if revision != lock["commit"]:
            raise ValueError("upstream revision differs from build/onecore.lock.json")
        dirty = subprocess.check_output(
            ["git", "-C", str(upstream), "status", "--porcelain", "--untracked-files=no"], text=True)
        if dirty:
            raise ValueError("upstream checkout has tracked modifications")
        tool_source = upstream / "sdk/tools/spec2def/spec2def.c"
        if sha256(tool_source) != lock["spec2def_sha256"]:
            raise ValueError("spec2def source hash mismatch")
        tracked = subprocess.check_output(
            ["git", "-C", str(upstream), "ls-tree", "-r", "--name-only", revision,
             "--", "oca/api-sets"], text=True).splitlines()
        specs = sorted(upstream / name for name in tracked if name.endswith(".spec"))
        if not specs:
            raise ValueError("upstream API-set specifications are missing")
        if any(not path.is_file() or path.is_symlink() for path in specs):
            raise ValueError("tracked API-set specifications must all be checked out as regular files")
        cc = shutil.which(args.cc)
        if not cc:
            raise ValueError("native C compiler unavailable: " + args.cc)
        prefix = "i686-w64-mingw32-" if args.arch == "x86" else "x86_64-w64-mingw32-"
        binaries = {}
        for name in ("ld", "objdump"):
            binary = args.binutils_dir.resolve() / (prefix + name) if args.binutils_dir else shutil.which(prefix + name)
            if not binary or not Path(binary).is_file():
                raise ValueError("missing MinGW binutils executable: " + prefix + name)
            binaries[name] = str(binary)
        xp_def = source / "base/win32/client/kernel32.src"
        definitions = ["-D_X86_=1"] if args.arch == "x86" else ["-D_AMD64_=1", "-D_WIN64=1"]
        xp_text = subprocess.check_output(
            [cc, "-E", "-P", "-x", "c"] + definitions + [str(xp_def)], text=True)
        available = export_names(xp_text)
        output.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, str(error) + "\n")

    version = "0x501" if args.arch == "x86" else "0x502"
    environment = {**os.environ, "LC_ALL": "C"}
    report = {"schema": 1, "started_utc": datetime.now(timezone.utc).isoformat(),
              "upstream": lock, "arch": args.arch, "status": "failed",
              "spec_os_version": version,
              "runtime": "not_tested", "windows_boot": "not_attempted",
              "xp_exports": {"path": str(xp_def), "sha256": sha256(xp_def),
                             "preprocessor_definitions": definitions, "count": len(available)},
              "tools": {}, "contracts": [], "built": []}
    with (output / "build.log").open("w") as log:
        def run(command):
            log.write(json.dumps([str(arg) for arg in command]) + "\n")
            log.flush()
            return subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                  check=True, timeout=120, env=environment)

        try:
            for name, executable in {"cc": cc, **binaries}.items():
                tool_version = subprocess.check_output([executable, "--version"], text=True,
                                                       env=environment).splitlines()[0]
                report["tools"][name] = {"path": executable, "version": tool_version,
                                         "sha256": sha256(Path(executable))}
            for directory in ("host-tools", "defs", "dlls", "inspection"):
                (output / directory).mkdir()
            tool = output / "host-tools/spec2def"
            run([cc, "-O2", "-Wall", "-Wextra", "-o", str(tool), str(tool_source)])
            report["tools"]["spec2def"] = {"source_sha256": sha256(tool_source), "sha256": sha256(tool)}
            (output / "kernel32.preprocessed.def").write_text(xp_text)
            cases = Counter(path.stem.lower() for path in specs)
            for spec in specs:
                name = spec.stem.lower()
                contract = {"source": spec.relative_to(upstream).as_posix(),
                            "sha256": sha256(spec), "name": name, "status": "rejected"}
                report["contracts"].append(contract)
                if cases[name] > 1:
                    contract["reason"] = "case_colliding_contract_names"
                    continue
                definition = output / "defs" / (name + ".def")
                architecture = "i386" if args.arch == "x86" else "x86_64"
                try:
                    run([str(tool), "-a=" + architecture, "--version=" + version,
                         "-n=" + name + ".dll", "-d=" + str(definition), str(spec)])
                except subprocess.CalledProcessError:
                    contract["reason"] = "spec2def_failed"
                    continue
                try:
                    expected, missing = forwarders(definition.read_text(), available)
                except ValueError as error:
                    contract["reason"] = "invalid_contract"
                    contract["error"] = str(error)
                    continue
                contract["covered_exports"] = len(expected)
                if missing:
                    contract["reason"] = "outside_verified_forwarder_scope"
                    contract["unresolved"] = missing
                    continue
                minor = "1" if args.arch == "x86" else "2"
                dll = output / "dlls" / (name + ".dll")
                run([binaries["ld"], "--shared", "--entry", "0", "--subsystem", "windows:5." + minor,
                     "--major-os-version", "5", "--minor-os-version", minor,
                     "--no-insert-timestamp", "--disable-dynamicbase", "-o", str(dll), str(definition)])
                inspection = subprocess.check_output([binaries["objdump"], "-p", str(dll)], text=True,
                                                     env=environment)
                (output / "inspection" / (name + ".txt")).write_text(inspection)
                verification = verify_objdump(inspection, expected, args.arch)
                contract.update(status="built", exports=expected, verification=verification,
                                dll=dll.relative_to(output).as_posix(), dll_sha256=sha256(dll))
                report["built"].append(name)
            if not report["built"]:
                raise ValueError("no contracts satisfied the source export checks")
            report["status"] = "selective_forwarders_built"
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            report["error"] = str(error)
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "arch": args.arch,
                      "built": len(report["built"]), "examined": len(report["contracts"]),
                      "runtime": report["runtime"], "error": report.get("error")}, indent=2))
    return 0 if report["status"] == "selective_forwarders_built" else 2


if __name__ == "__main__":
    raise SystemExit(main())
