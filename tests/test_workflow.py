"""Source-copy isolation, blocked native launches and real probe compilation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "build"))
import stage
import guest

TOOLCHAIN = REPO / ".work/toolchains/mingw-binutils/usr/bin"


def source_fixture(root):
    (root / "public/sdk/inc").mkdir(parents=True)
    (root / "public/sdk/inc/ntverp.h").write_text("#define VER_PRODUCTBUILD 2600\n")
    (root / "tools").mkdir()
    (root / "tools/razzle.cmd").write_text("@echo off\n")


class StagingTests(unittest.TestCase):
    def test_verified_copy_is_independent_and_cannot_overwrite_existing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "reference"
            source_fixture(source)
            output = Path(temp) / "stage"
            result = stage.stage(source, output)
            self.assertEqual(result["status"], "verified")
            self.assertEqual(result["reference_manifest_sha256"], result["staged_manifest_sha256"])
            (output / "NT/tools/razzle.cmd").write_text("changed copy\n")
            self.assertEqual((source / "tools/razzle.cmd").read_text(), "@echo off\n")
            with self.assertRaises(FileExistsError):
                stage.stage(source, output)

    def test_cannot_stage_into_source(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "reference"
            source_fixture(source)
            with self.assertRaisesRegex(ValueError, "separate"):
                stage.stage(source, source / "copy")
            self.assertFalse((source / "copy").exists())

    def test_native_launcher_rejects_output_inside_source(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "reference"
            source_fixture(source)
            run = subprocess.run([sys.executable, str(REPO / "build/attempt.py"),
                                  "--source", str(source), "--output", str(source / "build")],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            self.assertFalse((source / "build").exists())

    @unittest.skipIf(os.name == "nt", "checks missing Windows command host on this Unix host")
    def test_blocked_launch_records_no_compiler_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "copy"
            source_fixture(source)
            output = Path(temp) / "attempt"
            run = subprocess.run([sys.executable, str(REPO / "build/attempt.py"),
                                  "--source", str(source), "--output", str(output)],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            result = json.loads((output / "result.json").read_text())
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["compiler_status"], "not_started")
            self.assertIn("cmd.exe", result["error"])
            self.assertTrue((output / "launcher.log").read_text())


@unittest.skipUnless((TOOLCHAIN / "i686-w64-mingw32-gcc-posix").is_file(),
                     "requires private MinGW C cross-compiler")
class GuestBuildTests(unittest.TestCase):
    def test_probe_reproducibility_and_runtime_dependency_checks(self):
        with tempfile.TemporaryDirectory(prefix="xp25-probe-test-") as temp:
            hashes = []
            for name in ("first", "second"):
                output = Path(temp) / name
                run = subprocess.run([sys.executable, str(REPO / "build/guest.py"),
                                      "--toolchain", str(TOOLCHAIN), "--output", str(output)],
                                     capture_output=True, text=True, timeout=60)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                result = json.loads((output / "result.json").read_text())
                self.assertEqual(result["status"], "compiled_static_checks_passed")
                self.assertEqual(result["guest_execution"], "not_attempted")
                self.assertEqual(set(result["imports"]), guest.ALLOWED_DLLS)
                self.assertEqual(set(result["xp_sdk_imports"]), guest.ALLOWED_DLLS)
                self.assertTrue(all(check["matched_imports"] > 0
                                    for check in result["xp_sdk_imports"].values()))
                hashes.append(result["executable_sha256"])
                inspection = (output / "inspection.txt").read_text()
                with self.assertRaisesRegex(ValueError, "runtime dependency"):
                    guest.verify(inspection + "\nDLL Name: libgcc_s_dw2-1.dll\n")
            self.assertEqual(hashes[0], hashes[1])


if __name__ == "__main__":
    unittest.main()
