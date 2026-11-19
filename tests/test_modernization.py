"""Milestone 8.4 host checks: sanitizer fuzzing of the portable parsers, the RoverAI index
compared with its pre-8.4 implementation, a smoke run of the RoverAI benchmark, and the audit
tools' parsers. Synthetic inputs only; nothing here establishes native Windows behaviour.
"""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
A = ROOT / 'components/xp25-agent'
R = ROOT / 'components/roverai'
STRICT = ['-std=c89', '-pedantic', '-Wall', '-Wextra', '-Werror', '-Wno-overlength-strings']
SANITIZE = ['-fsanitize=address,undefined', '-fno-sanitize-recover=all'] if sys.platform.startswith('linux') else []
INCLUDES = ['-I' + str(p) for p in (A / 'runtime', A / 'llm', A / 'permissions', R / 'indexer', R / 'search',
                                     ROOT / 'components/security/core', ROOT / 'components/winlogon')]
# The RoverAI index as it was before Milestone 8.4 changed rover_index.c (the 8.4 baseline commit).
REFERENCE_COMMIT = 'a77550aa6'
INDEX_SYMBOLS = ('rover_index_init', 'rover_index_free', 'rover_path_compare', 'rover_index_find', 'rover_index_upsert',
                 'rover_index_remove', 'rover_index_rename', 'rover_index_excluded', 'rover_word_hash',
                 'rover_words_from_text', 'rover_entry_has_word', 'rover_text_extension', 'rover_index_scan',
                 'rover_index_apply', 'rover_index_serialize', 'rover_index_deserialize')


def compiler(test):
    cc = shutil.which('cc')
    if not cc:
        test.skipTest('no host C compiler')
    return cc


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    spec.loader.exec_module(module)
    return module


class ParserFuzzTests(unittest.TestCase):
    def test_parsers_survive_sanitized_mutation_fuzzing(self):
        cc = compiler(self)
        sources = [A / 'runtime/xp25_base.c', A / 'runtime/xp25_json.c', A / 'runtime/xp25_agent.c', A / 'llm/xp25_sha256.c',
                   A / 'llm/xp25_llm.c', A / 'llm/xp25_offline.c', A / 'permissions/xp25_policy.c', R / 'indexer/rover_index.c',
                   R / 'search/rover_query.c', ROOT / 'components/security/core/sec_core.c',
                   ROOT / 'components/winlogon/environment.c', ROOT / 'components/winlogon/bootkey_codec.c']
        with tempfile.TemporaryDirectory() as d:
            binary = Path(d) / 'fuzz_parsers'
            subprocess.run([cc] + STRICT + SANITIZE + ['-g', '-O1'] + INCLUDES + [str(ROOT / 'tests/fuzz_parsers.c')] +
                           [str(s) for s in sources] + ['-o', str(binary)], check=True)
            result = subprocess.run([str(binary), '20000', '0x8400'], capture_output=True, text=True, timeout=600)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('failures=0', result.stdout)
        for target in ('json', 'llm_response', 'rover_query', 'rover_index', 'offline_text', 'agent_policy', 'sec_backup',
                       'winlogon_env_bootkey'):
            self.assertRegex(result.stdout, r'target=' + target + r' runs=\d+')
        self.assertIn('seeds=4', result.stdout)


class RoverIndexDifferentialTests(unittest.TestCase):
    def test_index_matches_pre_84_implementation(self):
        cc = compiler(self)
        git = shutil.which('git')
        old = subprocess.run([git, '-C', str(ROOT), 'show', REFERENCE_COMMIT + ':components/roverai/indexer/rover_index.c'],
                             capture_output=True) if git else None
        if not old or old.returncode:
            self.skipTest('reference implementation not available from git')
        renames = ['-D%s=old_%s' % (s, s) for s in INDEX_SYMBOLS]
        with tempfile.TemporaryDirectory() as d:
            reference = Path(d) / 'rover_index_old.c'
            reference.write_bytes(old.stdout)
            subprocess.run([cc] + STRICT + SANITIZE + ['-g', '-O1'] + INCLUDES + renames +
                           ['-c', str(reference), '-o', str(Path(d) / 'old.o')], check=True)
            binary = Path(d) / 'diff'
            subprocess.run([cc] + STRICT + SANITIZE + ['-g', '-O1'] + INCLUDES +
                           [str(ROOT / 'tests/rover_index_diff.c'), str(R / 'indexer/rover_index.c'), str(Path(d) / 'old.o'),
                            str(A / 'runtime/xp25_base.c'), str(A / 'llm/xp25_sha256.c'), '-o', str(binary)], check=True)
            for seed in ('0x84', '0x1984', '0x2026'):
                result = subprocess.run([str(binary), '300', seed], capture_output=True, text=True, timeout=600)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('failures=0', result.stdout)


class RoverBenchTests(unittest.TestCase):
    def test_benchmark_runs_every_phase(self):
        cc = compiler(self)
        sources = [A / 'runtime/xp25_base.c', A / 'runtime/xp25_json.c', A / 'llm/xp25_sha256.c', A / 'permissions/xp25_policy.c',
                   A / 'runtime/xp25_agent.c', R / 'indexer/rover_index.c', R / 'search/rover_query.c']
        with tempfile.TemporaryDirectory() as d:
            binary = Path(d) / 'rover_bench'
            subprocess.run([cc] + STRICT + ['-O2'] + INCLUDES + [str(ROOT / 'tests/rover_bench.c')] +
                           [str(s) for s in sources] + ['-o', str(binary)], check=True)
            result = subprocess.run([str(binary), '400', '6', '1', '1'], capture_output=True, text=True, timeout=600)
        self.assertEqual(result.returncode, 0, result.stderr)
        phases = re.findall(r'"phase":"(\w+)"', result.stdout)
        for phase in ('full_scan', 'unchanged_rescan', 'serialize', 'deserialize', 'search', 'apply_2000_notifications'):
            self.assertIn(phase, phases)
        self.assertIn('"added":0', result.stdout)        # nothing changed between the scans
        self.assertNotIn('deserialize failed', result.stdout)


class AuditToolTests(unittest.TestCase):
    def test_inventory_lexer_keeps_lines_and_finds_functions(self):
        inventory = load('modernization_inventory', ROOT / 'build/modernization_inventory.py')
        text = 'int a; /* x\n y */ static int f(int b)\n{\n  if (b && "}") return 1; // }\n  return 0;\n}\n'
        stripped = inventory.strip_c(text)
        self.assertEqual(stripped.count('\n'), text.count('\n'))
        self.assertNotIn('x', stripped.split('\n')[0])
        self.assertNotIn('"}"', stripped)
        sources = inventory.parse_sources('components/winlogon/sources')
        self.assertEqual(sources['target'], 'winlogon')
        self.assertIn('components/winlogon/session.c', sources['sources'])
        self.assertFalse(sources['gs'])

    def test_static_analysis_reads_gcc_diagnostics(self):
        analysis = load('static_analysis', ROOT / 'build/static_analysis.py')
        log = ('components/winlogon/gina.c:97:5: warning: this ‘if’ clause does not guard... [-Wmisleading-indentation]\n'
               'components/winlogon/gina.c:98:9: note: ...this statement\n'
               'x.c:3:1: warning: leak of file descriptor [CWE-775] [-Wanalyzer-fd-leak]\n')
        found = analysis.parse(log, 'native', 'unit')
        self.assertEqual([f['rule'] for f in found], ['-Wmisleading-indentation', '-Wanalyzer-fd-leak'])
        self.assertEqual(found[0]['line'], 97)


if __name__ == '__main__':
    unittest.main()
