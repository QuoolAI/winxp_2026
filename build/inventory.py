#!/usr/bin/env python3
"""Read-only NT source inventory. Reports evidence, never buildability."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import struct

REPO = Path(__file__).resolve().parents[1]
VERSION_KEYS = ("VER_PRODUCTMAJORVERSION", "VER_PRODUCTMINORVERSION",
                "VER_PRODUCTBUILD", "VER_PRODUCTBUILD_QFE")
TOOLS = ["tools/x86/" + name for name in (
    "build.exe", "nmake.exe", "cl.exe", "c1.dll", "c1xx.dll", "c2.dll",
    "link.exe", "lib.exe", "ml.exe", "mspdb60.dll", "rc.exe", "mc.exe",
    "midl.exe", "binplace.exe", "perl/bin/perl.exe")]
TOOLS += ["tools/win64/x86/amd64/" + name for name in (
    "cl.exe", "link.exe", "ml64.exe", "c1.dll", "c2.dll", "mspdb70.dll")]
MARKERS = ["dirs", "tools/razzle.cmd", "tools/ntenv.cmd", "tools/makefile.def",
           "public/sdk/inc/ntverp.h", "published/sdk/inc/ntverp.h",
           "base/ntos/dirs", "base/ntos/init/up/sources.cmn", "base/hals/dirs",
           "base/boot/dirs", "ds/security/gina/dirs",
           "mergedcomponents/setupinfs/hivesys.inx"]
COMPONENTS = {
    "kernel": "base/ntos", "hal": "base/hals", "boot": "base/boot",
    "native_api": "base/ntdll", "win32": "base/win32",
    "session_manager": "base/subsys/sm", "csr": "base/subsys/csr",
    "gui": "windows/core", "explorer": "shell/explorer",
    "themes": "shell/themes", "registry": "base/ntos/config",
    "services": "ds/netapi/svcctrl/server",
    "service_control_client": "ds/netapi/svcctrl/client", "filesystems": "base/fs",
    "drivers": "drivers", "networking": "net", "security": "ds/security",
    "winlogon": "ds/security/gina/winlogon", "setup": "base/ntsetup",
}


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def version(path):
    # Comments can appear between a macro name and its value.
    data = re.sub(r"/\*.*?\*/", "", path.read_text(errors="replace"), flags=re.S)
    values = {}
    for key in VERSION_KEYS:
        match = re.search(r"^\s*#define\s+" + key + r"\s+(\d+)\b", data, re.M)
        values[key] = int(match[1]) if match else None
    return values


def pe_machine(path):
    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) < 64 or header[:2] != b"MZ":
            return None
        stream.seek(struct.unpack_from("<I", header, 60)[0])
        pe = stream.read(6)
    if len(pe) != 6 or pe[:4] != b"PE\0\0":
        return None
    machine = struct.unpack_from("<H", pe, 4)[0]
    return {0x14c: "x86", 0x8664: "amd64", 0x200: "ia64"}.get(machine, hex(machine))


def literal_dirs_gaps(root, manifest):
    """Only unconditional, literal DIRS entries. Not an NMAKE evaluator.

    Skip conditional sections, OPTIONAL_DIRS and variable references. Tags are
    retained in the report; absent tagged directories may be target-specific.
    """
    path = root / manifest
    if not path.is_file():
        return []
    lines = re.sub(r"\\[ \t]*\r?\n", " ", path.read_text(errors="replace")).splitlines()
    conditional = 0
    gaps = []
    def directory_exists(name):
        # DIRS uses Windows separators and case-insensitive directory names.
        current = path.parent
        for part in name.replace("\\", "/").split("/"):
            if not part or part == ".":
                continue
            matches = [p for p in current.iterdir()
                       if p.name.casefold() == part.casefold() and p.is_dir()]
            if not matches:
                return False
            current = matches[0]
        return True

    for line in lines:
        stripped = line.strip()
        if re.match(r"!if(?:n?def)?\b", stripped, re.I):
            conditional += 1
        elif re.match(r"!endif\b", stripped, re.I):
            conditional = max(0, conditional - 1)
        elif not conditional:
            match = re.match(r"DIRS\s*=\s*(.*)", stripped, re.I)
            if match:
                for entry in match[1].split("#", 1)[0].split():
                    if "$" in entry:
                        continue
                    name = entry.split("{", 1)[0]
                    if not name or not name.strip("\\/"):
                        continue
                    if not directory_exists(name):
                        gaps.append({"manifest": manifest, "entry": entry,
                                     "missing": (Path(manifest).parent / name.replace("\\", "/")).as_posix()})
    return gaps


def inventory(root, output, hash_all=False):
    root = root.resolve()
    if not (root / "public/sdk/inc/ntverp.h").is_file():
        raise ValueError("source root must contain public/sdk/inc/ntverp.h")
    output = output.resolve()
    if output == root or root in output.parents:
        raise ValueError("inventory output must be outside the source tree")
    output.mkdir(parents=True, exist_ok=False)
    counts, sizes, extensions, arch_dirs = Counter(), Counter(), Counter(), Counter()
    manifests, media, binaries, collisions = [], [], {}, []
    total_bytes = 0
    total_files = 0
    with (output / "files.jsonl").open("w", encoding="utf-8") as listing:
        for parent, dirs, files in os.walk(root):
            dirs.sort()
            files.sort()
            for name in dirs:
                if (Path(parent) / name).is_symlink():
                    raise ValueError("source symlink needs review: " +
                                     str((Path(parent) / name).relative_to(root)))
            names = dirs + files
            folded = Counter(n.casefold() for n in names)
            collisions.extend(str(Path(parent).relative_to(root) / n)
                              for n in names if folded[n.casefold()] > 1)
            arch_dirs.update(d for d in dirs if d in ("i386", "amd64", "ia64"))
            for name in files:
                path = Path(parent) / name
                rel = path.relative_to(root).as_posix()
                if path.is_symlink():
                    raise ValueError("source symlink needs review: " + rel)
                size = path.stat().st_size
                row = {"path": rel, "bytes": size}
                if hash_all:
                    row["sha256"] = digest(path)
                listing.write(json.dumps(row, sort_keys=True) + "\n")
                total_files += 1
                total_bytes += size
                counts[rel.split("/", 1)[0]] += 1
                sizes[rel.split("/", 1)[0]] += size
                extensions[path.suffix.lower()] += 1
                if name.lower() == "dirs":
                    manifests.append(rel)
                if path.suffix.lower() in (".iso", ".qcow2", ".vhd", ".vhdx", ".vmdk", ".img", ".ima"):
                    media.append(rel)
                if name.lower() in ("ntoskrnl.exe", "ntkrnlmp.exe", "hal.dll", "winlogon.exe", "ntldr", "cmd.exe", "cdimage.exe"):
                    binaries.setdefault(name.lower(), []).append(rel)
    tools = {}
    for rel in TOOLS + MARKERS:
        path = root / rel
        tools[rel] = {"present": path.is_file()}
        if path.is_file():
            tools[rel].update(sha256=digest(path), bytes=path.stat().st_size)
            if path.suffix in (".exe", ".dll"):
                tools[rel]["pe_machine"] = pe_machine(path)
    report = {
        "schema": 1, "source_root": str(root), "files": total_files,
        "bytes": total_bytes, "all_files_hashed": hash_all,
        "file_manifest_sha256": digest(output / "files.jsonl"),
        "versions": {p: version(root / p) if (root / p).is_file() else None
                     for p in MARKERS if p.endswith("ntverp.h")},
        "subsystems": {p: {"files": counts[p], "bytes": sizes[p]} for p in sorted(counts)},
        "extensions": dict(extensions), "architecture_directory_counts": dict(arch_dirs),
        "components": {k: {"path": v, "present": (root / v).is_dir()} for k, v in COMPONENTS.items()},
        "tools_and_markers": tools,
        "literal_dirs_gaps": [gap for m in manifests for gap in literal_dirs_gaps(root, m)],
        "case_collisions": collisions, "media_candidates": media,
        "named_binaries": binaries,
        "limitations": "Static presence and hashes do not establish completeness, trust, build success or bootability. DIRS audit skips conditional sections and does not expand NMAKE variables.",
    }
    (output / "inventory.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=REPO / "Source/XPSP1/NT")
    parser.add_argument("--output", type=Path, required=True, help="new private output directory")
    parser.add_argument("--hash-all", action="store_true", help="hash every source file (reads about 6.3 GB)")
    args = parser.parse_args()
    try:
        report = inventory(args.source, args.output, args.hash_all)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + "\n")
    print(json.dumps({k: report[k] for k in ("files", "bytes", "all_files_hashed", "file_manifest_sha256")}, indent=2))


if __name__ == "__main__":
    main()
