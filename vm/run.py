#!/usr/bin/env python3
"""Bounded, offline QEMU diagnostic run; never infers Windows boot from QMP."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

REPO = Path(__file__).resolve().parents[1]


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def qemu_value(path):
    return str(path).replace(",", ",,")


def command(profile, output, control, disk=None, disk_format=None, iso=None, bios=None):
    args = [profile["executable"], "-machine", profile["machine"], "-accel", "tcg",
            "-cpu", profile["cpu"], "-m", str(profile["memory_mib"]),
            "-smp", str(profile["cpus"]), "-nodefaults", "-nic", "none",
            "-vga", profile["vga"], "-display", "none", "-monitor", "none",
            "-serial", "file:" + str(output / "serial.log"),
            "-qmp", "unix:" + qemu_value(control) + ",server=on,wait=off",
            "-no-reboot", "-no-shutdown", "-boot", "order=dc,menu=off,strict=on"]
    if bios:
        args += ["-bios", str(bios)]
    if disk:
        if disk_format not in ("raw", "qcow2"):
            raise ValueError("explicit disk format raw or qcow2 required")
        args += ["-drive", "file=" + qemu_value(disk) + ",format=" + disk_format +
                 ",if=ide,index=0,media=disk,snapshot=on"]
    if iso:
        args += ["-drive", "file=" + qemu_value(iso) +
                 ",format=raw,if=ide,index=2,media=cdrom,readonly=on"]
    return args


class QMP:
    def __init__(self, path, process):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(5)
        deadline = time.monotonic() + 10
        while True:
            try:
                self.socket.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if process.poll() is not None or time.monotonic() > deadline:
                    self.socket.close()
                    raise RuntimeError("QEMU did not open its QMP socket; inspect qemu.log")
                time.sleep(0.05)
        self.stream = self.socket.makefile("rwb")
        self.greeting = self.read()
        if "QMP" not in self.greeting:
            raise RuntimeError("missing QMP greeting")
        self.sequence = 0
        self.execute("qmp_capabilities")

    def read(self):
        line = self.stream.readline()
        if not line:
            raise RuntimeError("QMP connection closed")
        return json.loads(line)

    def execute(self, name, arguments=None):
        self.sequence += 1
        request = {"execute": name, "id": self.sequence}
        if arguments:
            request["arguments"] = arguments
        self.stream.write(json.dumps(request).encode() + b"\n")
        self.stream.flush()
        while True:
            response = self.read()
            if response.get("id") == self.sequence:
                if "error" in response:
                    raise RuntimeError(str(response["error"]))
                return response["return"]

    def close(self):
        self.stream.close()
        self.socket.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("x86", "amd64"), default="x86")
    parser.add_argument("--output", required=True, type=Path, help="new private directory")
    parser.add_argument("--firmware-smoke", action="store_true", help="no media, not a Windows test")
    parser.add_argument("--disk", type=Path)
    parser.add_argument("--disk-format", choices=("raw", "qcow2"))
    parser.add_argument("--iso", type=Path)
    parser.add_argument("--bios", type=Path, help="explicit SeaBIOS binary; recorded by SHA-256")
    parser.add_argument("--seconds", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 300:
        parser.error("--seconds must be 1..300")
    if args.firmware_smoke == bool(args.disk or args.iso):
        parser.error("choose --firmware-smoke OR provide --disk/--iso")
    if bool(args.disk) != bool(args.disk_format):
        parser.error("--disk and --disk-format must be supplied together")
    for path in (args.disk, args.iso, args.bios):
        if path and not path.is_file():
            parser.error("input must be an existing regular file: " + str(path))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    profiles = json.loads((REPO / "vm/profiles.json").read_text())
    profile = profiles[args.arch]
    profile["executable"] = shutil.which(profile["executable"]) or profile["executable"]
    result = {"schema": 1, "started_utc": datetime.now(timezone.utc).isoformat(),
              "arch": args.arch, "profile": profile, "status": "failed",
              "windows_boot": "not_attempted" if args.firmware_smoke else "unverified",
              "firmware_smoke": args.firmware_smoke, "inputs": {}}
    process, qmp = None, None
    with tempfile.TemporaryDirectory(prefix="xp-qmp-") as control_dir:
        cmd = command(profile, output, Path(control_dir) / "control.sock",
                      args.disk.resolve() if args.disk else None, args.disk_format,
                      args.iso.resolve() if args.iso else None,
                      args.bios.resolve() if args.bios else None)
        result["command"] = cmd
        with (output / "qemu.log").open("wb") as log:
            try:
                for label in ("disk", "iso", "bios"):
                    path = getattr(args, label)
                    if path:
                        result["inputs"][label] = {"path": str(path.resolve()), "sha256": sha256(path)}
                version = subprocess.run([profile["executable"], "--version"],
                                         capture_output=True, text=True, check=True, timeout=10)
                result["qemu_version"] = version.stdout.splitlines()[0]
                process = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
                qmp = QMP(Path(control_dir) / "control.sock", process)
                result["qmp_greeting"] = qmp.greeting
                time.sleep(args.seconds)
                for name in ("query-status", "query-cpus-fast", "query-pci", "query-block"):
                    result[name] = qmp.execute(name)
                qmp.execute("screendump", {"filename": str(output / "screen.ppm")})
                result["screenshot_sha256"] = sha256(output / "screen.ppm")
                if not result["query-status"]["running"]:
                    raise RuntimeError("QEMU stopped before observation")
                result["status"] = "harness_passed" if args.firmware_smoke else "guest_unverified"
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
                result["error"] = str(error)
            finally:
                if qmp:
                    try:
                        qmp.execute("quit")
                    except (OSError, RuntimeError):
                        pass
                    qmp.close()
                if process:
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    result["qemu_returncode"] = process.returncode
    for label, info in result["inputs"].items():
        info["sha256_after"] = sha256(Path(info["path"]))
        if info["sha256_after"] != info["sha256"]:
            result["status"] = "failed"
            result["error"] = "input changed: " + label
    result["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("status", "windows_boot", "arch")}, indent=2))
    return 0 if result["status"] == "harness_passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
