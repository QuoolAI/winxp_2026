#!/usr/bin/env python3
"""Retain Milestone 1 build attempts and firmware diagnostics in one private run."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="verified disposable NT source copy")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--bios", required=True, type=Path)
    args = parser.parse_args()
    source, output, bios = args.source.resolve(), args.output.resolve(), args.bios.resolve()
    protected = (REPO / "Source").resolve()
    if source == protected or protected in source.parents:
        parser.error("use build/stage.py; the reference source is protected")
    if (output == source or source in output.parents or output == protected or
            protected in output.parents):
        parser.error("output must be outside source trees")
    if not (source / "tools/razzle.cmd").is_file() or not bios.is_file():
        parser.error("source and BIOS must exist")
    output.mkdir(parents=True, exist_ok=False)
    result = {"schema": 1, "milestone": 1, "status": "blocked",
              "started_utc": datetime.now(timezone.utc).isoformat(), "steps": {},
              "custom_xp_image": "not_produced", "windows_boot": "not_attempted",
              "guest_regressions": "blocked_no_bootable_custom_guest", "blockers": []}

    def run(name, script, arguments, timeout=7300):
        command = [sys.executable, str(REPO / script)] + [str(value) for value in arguments]
        print(name, flush=True)
        step = {"command": command}
        with (output / (name + ".launcher.log")).open("w") as log:
            try:
                completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                           check=False, timeout=timeout)
                step["returncode"] = completed.returncode
            except (OSError, subprocess.TimeoutExpired) as error:
                step["error"] = str(error)
        file = output / name / ("inventory.json" if name == "inventory" else "result.json")
        if file.is_file():
            step["report"] = file.relative_to(output).as_posix()
            step["result"] = json.loads(file.read_text())
        result["steps"][name] = step

    run("inventory", "build/inventory.py", ["--source", source, "--hash-all", "--output", output / "inventory"])
    for arch, scope in (("x86", "kernel"), ("x86", "base"), ("amd64", "kernel")):
        name = "build-" + arch + "-" + scope
        run(name, "build/attempt.py", ["--source", source, "--arch", arch,
            "--scope", scope, "--flavor", "checked", "--output", output / name])
        report = result["steps"][name].get("result", {})
        if report.get("status") != "command_completed":
            result["blockers"].append({"step": name, "error": report.get("error", "inspect native build logs")})
        else:
            result["blockers"].append({"step": name, "error": "linked OS artifacts and custom image still require verification"})
    for arch in ("x86", "amd64"):
        name = "qemu-" + arch
        run(name, "vm/run.py", ["--arch", arch, "--firmware-smoke", "--bios", bios,
            "--output", output / name], timeout=45)
    result["blockers"].extend([
        {"step": "image", "error": "no linked custom kernel/HAL and complete bootable OS payload established"},
        {"step": "amd64", "error": "no identified NT 5.2 / XP Professional x64 product source baseline"}])
    inventory = result["steps"]["inventory"].get("result", {})
    result["diagnostic_baseline"] = "established" if inventory.get("all_files_hashed") and all(
        result["steps"]["qemu-" + arch].get("result", {}).get("status") == "harness_passed"
        for arch in ("x86", "amd64")) else "incomplete"
    result["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("status", "diagnostic_baseline", "windows_boot", "blockers")}, indent=2))
    return 2  # No custom Windows boot has been established by this diagnostic run.


if __name__ == "__main__":
    raise SystemExit(main())
