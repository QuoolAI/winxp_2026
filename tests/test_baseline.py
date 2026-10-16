"""Regression checks for source-audit accuracy and real QEMU disk preservation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("inventory", REPO / "build/inventory.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class InventoryTests(unittest.TestCase):
    def test_windows_dirs_syntax_does_not_invent_missing_components(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Existing" / "Child").mkdir(parents=True)
            (root / "not_a_directory").touch()
            (root / "dirs").write_text(
                "!IF 0\nDIRS=ignored\n!ENDIF\n"
                "DIRS=existing\\child{x86} \\   \n"
                "    existing\\child\\\t\n\n"
                "DIRS={x86} missing{amd64,ia64} not_a_directory $(DYNAMIC)\n"
                "OPTIONAL_DIRS=optional\n"
                "!IFDEF FEATURE\nDIRS=conditional\n"
                "!IF 1\nDIRS=nested\n!ENDIF\n"
                "!ELSE\nDIRS=other_branch\n!ENDIF\n"
                "DIRS=last # comment\n"
            )
            gaps = audit.literal_dirs_gaps(root, "dirs")
            self.assertEqual([g["entry"] for g in gaps],
                             ["missing{amd64,ia64}", "not_a_directory", "last"])

    def test_inventory_handles_missing_published_header_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "source"
            header = root / "public/sdk/inc/ntverp.h"
            header.parent.mkdir(parents=True)
            header.write_text("#define VER_PRODUCTBUILD /* comment */ 2600\n")
            before = header.read_bytes()
            paths_before = sorted(root.rglob("*"))
            report = audit.inventory(root, Path(temp) / "report", hash_all=True)
            self.assertEqual(report["files"], 1)
            self.assertEqual(report["versions"]["public/sdk/inc/ntverp.h"]
                             ["VER_PRODUCTBUILD"], 2600)
            self.assertIsNone(report["versions"]["published/sdk/inc/ntverp.h"])
            self.assertEqual(header.read_bytes(), before)
            self.assertEqual(sorted(root.rglob("*")), paths_before)

    def test_output_inside_source_is_rejected_before_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            header = root / "public/sdk/inc/ntverp.h"
            header.parent.mkdir(parents=True)
            header.touch()
            with self.assertRaisesRegex(ValueError, "outside the source tree"):
                audit.inventory(root, root / "report")
            self.assertFalse((root / "report").exists())

    @unittest.skipUnless(hasattr(Path, "symlink_to") and sys.platform != "win32",
                         "requires unprivileged directory symlinks")
    def test_source_directory_symlink_requires_review(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "source"
            header = root / "public/sdk/inc/ntverp.h"
            header.parent.mkdir(parents=True)
            header.touch()
            (root / "external").symlink_to(Path(temp), target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "source symlink needs review"):
                audit.inventory(root, Path(temp) / "report")


@unittest.skipUnless(shutil.which("qemu-system-i386"), "requires QEMU i386")
class QemuTests(unittest.TestCase):
    def test_real_guest_uses_snapshot_and_does_not_claim_windows_boot(self):
        with tempfile.TemporaryDirectory(prefix="xp-vm-test-") as temp:
            root = Path(temp)
            disk = root / "blank, disk.raw"
            with disk.open("wb") as stream:
                stream.truncate(1024 * 1024)
            before = hashlib.sha256(disk.read_bytes()).hexdigest()
            output = root / "observation"
            run = subprocess.run(
                [sys.executable, str(REPO / "vm/run.py"), "--arch", "x86",
                 "--disk", str(disk), "--disk-format", "raw", "--seconds", "1",
                 "--output", str(output)], capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
            report = json.loads((output / "result.json").read_text())
            self.assertEqual(report["status"], "guest_unverified", report)
            self.assertEqual(report["windows_boot"], "unverified")
            self.assertEqual(report["qemu_returncode"], 0)
            self.assertEqual(report["inputs"]["disk"]["sha256_after"], before)
            self.assertEqual(hashlib.sha256(disk.read_bytes()).hexdigest(), before)
            # QMP must expose an actual temporary overlay backed by our raw input.
            inserted = report["query-block"][0]["inserted"]
            self.assertEqual(inserted["image"]["format"], "qcow2")
            self.assertEqual(inserted["image"]["backing-image"]["filename"], str(disk))
            # No network adapter is attached to the emulated PCI bus.
            for bus in report["query-pci"]:
                self.assertFalse(any(device["class_info"]["class"] >> 8 == 2
                                     for device in bus["devices"]))


if __name__ == "__main__":
    unittest.main()
