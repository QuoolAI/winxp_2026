"""Checks for rejecting incomplete API contracts and inspecting real linked DLLs."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("onecore", REPO / "build/onecore.py")
onecore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(onecore)
UPSTREAM = REPO / ".work/upstream/one-core-api"
BINUTILS = REPO / ".work/toolchains/mingw-binutils/usr/bin"


class ContractTests(unittest.TestCase):
    def test_existing_exports_do_not_mask_missing_modern_targets(self):
        available = onecore.export_names("LIBRARY KERNEL32\nEXPORTS\nGetTickCount\n")
        covered, missing = onecore.forwarders(
            "EXPORTS\nGetTickCount=kernel32.GetTickCount @1\n"
            "GetTickCount64=kernel32.GetTickCount64 @2\n", available)
        self.assertEqual(covered, {"GetTickCount": "kernel32.GetTickCount"})
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["reason"], "target_not_in_XP_kernel32")

    def test_local_stubs_other_modules_and_ordinal_only_exports_are_rejected(self):
        for entry in ("DebugBreak=_DebugBreak@0 @1", "DebugBreak @1",
                      "DebugBreak=kernelex.DebugBreak @1",
                      "DebugBreak=kernel32.DebugBreak @1 NONAME"):
            with self.subTest(entry=entry):
                covered, missing = onecore.forwarders("EXPORTS\n" + entry, {"DebugBreak"})
                self.assertEqual(covered, {})
                self.assertTrue(missing)

    def test_duplicate_exports_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate export"):
            onecore.forwarders("EXPORTS\nDebugBreak=kernel32.DebugBreak @1\n"
                               "DebugBreak=kernel32.DebugBreak @2\n", {"DebugBreak"})

    def test_target_names_remain_case_sensitive(self):
        covered, missing = onecore.forwarders(
            "EXPORTS\nDebugBreak=kernel32.debugbreak @1\n", {"DebugBreak"})
        self.assertFalse(covered)
        self.assertTrue(missing)


@unittest.skipUnless((UPSTREAM / "oca/api-sets").is_dir() and
                     (BINUTILS / "i686-w64-mingw32-ld").is_file(),
                     "requires pinned One-Core-API checkout and local MinGW binutils")
class OneCoreIntegrationTests(unittest.TestCase):
    def test_real_dlls_are_reproducible_and_do_not_include_incomplete_contracts(self):
        source = REPO / "Source/XPSP1/NT/base/win32/client/kernel32.src"
        before = onecore.sha256(source)
        with tempfile.TemporaryDirectory(prefix="xp-onecore-test-") as temp:
            reports = []
            for attempt in ("first", "second"):
                output = Path(temp) / attempt
                run = subprocess.run(
                    [sys.executable, str(REPO / "build/onecore.py"), "--upstream", str(UPSTREAM),
                     "--binutils-dir", str(BINUTILS), "--output", str(output)],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                report = json.loads((output / "result.json").read_text())
                self.assertEqual(report["status"], "selective_forwarders_built")
                self.assertEqual(report["runtime"], "not_tested")
                contracts = {item["name"]: item for item in report["contracts"]}
                debug = contracts["api-ms-win-core-debug-l1-1-0"]
                self.assertEqual(debug["status"], "built")
                self.assertEqual(debug["verification"]["exports"], 4)
                incomplete = contracts["api-ms-win-core-synch-l1-2-0"]
                self.assertEqual(incomplete["status"], "rejected")
                self.assertTrue(any("WaitOnAddress" in item["entry"]
                                    for item in incomplete["unresolved"]))
                reports.append({item["name"]: item["dll_sha256"]
                                for item in report["contracts"] if item["status"] == "built"})
            self.assertEqual(reports[0], reports[1])
        self.assertEqual(onecore.sha256(source), before)


if __name__ == "__main__":
    unittest.main()
