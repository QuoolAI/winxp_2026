#!/usr/bin/env python3
"""Record a native NT build attempt, including failures before compiler launch."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="disposable NT source copy on Windows")
    parser.add_argument("--arch", choices=("x86", "amd64"), default="x86")
    parser.add_argument("--flavor", choices=("checked", "free"), default="checked")
    parser.add_argument("--scope", choices=("kernel", "base", "all"), default="kernel")
    parser.add_argument("--output", type=Path, required=True, help="new private output directory")
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    protected = (REPO / "Source").resolve()
    if (output == source or source in output.parents or output == protected or
            protected in output.parents):
        parser.error("build output must be outside the source trees")
    output.mkdir(parents=True, exist_ok=False)
    command = [shutil.which("cmd.exe") or "cmd.exe", "/d", "/c",
               str(REPO / "build/native-build.cmd"), str(source),
               args.arch, args.flavor, args.scope, str(output)]
    report = {"schema": 1, "started_utc": datetime.now(timezone.utc).isoformat(),
              "host": platform.platform(), "command": command,
              "arch": args.arch, "flavor": args.flavor, "scope": args.scope,
              "source": str(source), "compiler_status": "not_started",
              "status": "not_started", "windows_boot": "not_attempted"}
    with (output / "launcher.log").open("w") as log:
        try:
            if source == protected or protected in source.parents:
                raise ValueError("reference Source tree is protected; use build/stage.py first")
            if not (source / "tools/razzle.cmd").is_file():
                raise ValueError("source must contain tools/razzle.cmd")
            # Windows cmd parses batch arguments; reject shell metacharacters.
            for value in (str(args.source.resolve()), str(output), str(REPO)):
                if any(c in value for c in '&|<>^%!"\r\n'):
                    raise ValueError("unsupported cmd metacharacter in path")
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=7200, check=False)
            report["returncode"] = result.returncode
            report["status"] = "command_completed" if result.returncode == 0 else "failed"
            # Only native logs can establish whether the compiler ran.
            report["compiler_status"] = "unverified"
            report["note"] = "Command completion is not proof of a linked kernel or bootable OS. Inspect native logs and output binaries."
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            report["status"] = "blocked"
            report["error"] = str(error)
            log.write(str(error) + "\n")
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "command_completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
