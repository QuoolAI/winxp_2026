"""Milestone 8.2 regression tests for the historical-vulnerability source fixes.

Each harness compiles the vulnerable functions verbatim from Source/XPSP1/NT (and the
same functions after components/cve patches are applied) with AddressSanitizer, and
feeds them the malformed input of the historical attack. The original code must be
caught writing or reading out of bounds (so the harness really reaches the defect);
the patched code must reject or bound the input and still handle valid input like
the original. Nothing is sent over a network and no payload is executed."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
import cve_source  # noqa: E402

HARNESS = ROOT / 'tests/cve'
CC = shutil.which('cc')


def source_text(path):
    return (cve_source.SOURCE / path).read_bytes().decode('latin-1')


# The only edits made to extracted source text: constructs that are valid on x86 but not
# on the x86-64 host, replaced by their portable equivalent. Each must be found exactly.
HOST_ADAPTATIONS = {
    'wvsprintfW': [('    va_list varglist = arglist;\n', '    va_list varglist; va_copy(varglist, arglist);\n')],
}


class Built:
    """One harness compiled against the original and against the patched tree."""

    def __init__(self, workdir, harness, pieces, defines=(), prelude=''):
        self.paths = {}
        trees = cve_source.patched_files()
        for tree in ('original', 'patched'):
            directory = Path(workdir) / tree
            directory.mkdir()
            text = [prelude]
            for path, names in pieces:
                if path in trees:
                    body = trees[path][0 if tree == 'original' else 1]
                else:
                    body = source_text(path)
                for name in names:
                    function = cve_source.extract_function(body, name)
                    for old, new in HOST_ADAPTATIONS.get(name, ()):
                        if function.count(old) != 1:
                            raise AssertionError('host adaptation for %s no longer matches' % name)
                        function = function.replace(old, new)
                    text.append('/* %s: %s */\n' % (path, name))
                    text.append(function)
            (directory / 'extracted.c').write_text(''.join(text), encoding='latin-1')
            output = directory / 'harness'
            command = [CC, '-std=gnu89', '-fshort-wchar', '-g', '-O0', '-fsanitize=address,undefined',
                       '-fno-omit-frame-pointer', '-w', '-I', str(HARNESS), '-I', str(directory)]
            command += ['-D' + d for d in defines]
            command += [str(HARNESS / harness), '-o', str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode:
                raise AssertionError('%s (%s) does not compile:\n%s' % (harness, tree, result.stderr[-4000:]))
            self.paths[tree] = output

    def run(self, tree, *args):
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:abort_on_error=0', UBSAN_OPTIONS='print_stacktrace=1')
        return subprocess.run([str(self.paths[tree])] + list(args), capture_output=True, text=True, timeout=60, env=env)


@unittest.skipUnless(CC, 'no C compiler')
class PatchSetTests(unittest.TestCase):
    def test_every_patch_applies_to_the_audited_source(self):
        files = cve_source.patched_files()
        self.assertTrue(files)
        for path, (original, patched, applied) in files.items():
            self.assertNotEqual(original, patched, path)
            self.assertTrue(applied)

    def test_patches_touch_only_listed_files(self):
        for entry in cve_source.patch_entries():
            diff = cve_source.parse_patch((cve_source.PATCHES / entry['patch']).read_text())
            self.assertEqual(set(diff), set(entry['files']), entry['id'])

    def test_staging_refuses_paths_outside_work(self):
        with self.assertRaises(SystemExit):
            cve_source.stage('/tmp/xp25-cve-stage-test')


def wsprintf_pieces():
    body = source_text('windows/core/ntuser/client/wsprintf.c')
    out_macro = re.search(r'^#define out\(c\).*$', body, re.M).group(0) + '\n'
    return out_macro, ('windows/core/ntuser/client/wsprintf.c',
                       ['SP_PutNumberW', 'SP_ReverseW', 'SP_GetFmtValueW', 'wvsprintfW', 'wsprintfW'])


@unittest.skipUnless(CC, 'no C compiler')
class Ms04011DsRoleLogTests(unittest.TestCase):
    """lsasrv.dll: DsRolepDebugDumpRoutine formats caller-supplied names after the
    time-stamp prolog with wvsprintfW, whose 1024-character limit counts from where it
    starts writing, into a 1024-character stack buffer."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        macro, user32 = wsprintf_pieces()
        cls.built = Built(cls.tmp.name, 'ms04011_dsrole_log.c',
                          [user32, ('ds/security/dsrole/server/log.c', ['DsRolepDebugDumpRoutine', 'DsRolepLogPrintRoutine'])],
                          prelude=macro)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_original_overflows_the_stack_buffer_with_a_long_name(self):
        result = self.built.run('original', 'long')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('stack-buffer-overflow', result.stderr)
        self.assertIn('DsRolepDebugDumpRoutine', result.stderr)

    def test_patched_bounds_a_long_name_and_ends_the_line(self):
        result = self.built.run('patched', 'long')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr[-3000:])

    def test_ordinary_lines_are_unchanged(self):
        for tree in ('original', 'patched'):
            for mode in ('normal', 'boundary'):
                result = self.built.run(tree, mode)
                self.assertEqual(result.returncode, 0, '%s %s\n%s%s' % (tree, mode, result.stdout, result.stderr[-3000:]))

    def test_upgrade_request_checks_the_caller_before_logging(self):
        patched = cve_source.patched_files()['ds/security/dsrole/server/dispatch.c'][1]
        body = cve_source.extract_function(patched, 'DsRolerUpgradeDownlevelServer')
        check = body.index('DsRolepCheckPromoteAccess()')
        self.assertLess(check, body.index('DsRolepInitializeLog()'))
        self.assertLess(check, body.index('DsRolepLogPrint('))
        original = cve_source.extract_function(source_text('ds/security/dsrole/server/dispatch.c'), 'DsRolerUpgradeDownlevelServer')
        self.assertNotIn('DsRolepCheckPromoteAccess', original)


@unittest.skipUnless(CC, 'no C compiler')
class Ms08067CanonTests(unittest.TestCase):
    """netapi32.dll: CanonicalizePathName (reached remotely through the Server service's
    NetprPathCanonicalize) walks back over '..' components; a path with more '..' than
    components, after a leading separator, moves the search pointer before the buffer."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.built = Built(cls.tmp.name, 'ms08067_canon.c',
                          [('ds/netapi/netlib/canon.c',
                            ['CanonicalizePathName', 'ConvertPathCharacters', 'ConvertDeviceName',
                             'ParseLocalDevicePrefix', 'ConvertPathMacros', 'BackUpPath'])])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_original_reads_before_the_buffer_on_excess_traversal(self):
        result = self.built.run('original', 'traversal')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ConvertPathMacros', result.stderr + result.stdout)

    def test_patched_rejects_excess_traversal(self):
        result = self.built.run('patched', 'traversal')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr[-3000:])

    def test_patched_still_resolves_first_component_removal(self):
        result = self.built.run('patched', 'recovered')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr[-3000:])

    def test_valid_paths_canonicalize_identically(self):
        for tree in ('original', 'patched'):
            result = self.built.run(tree, 'valid')
            self.assertEqual(result.returncode, 0, '%s\n%s%s' % (tree, result.stdout, result.stderr[-3000:]))

    def test_patched_bounds_a_maximal_prefix(self):
        result = self.built.run('patched', 'prefix')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr[-3000:])


@unittest.skipUnless(CC, 'no C compiler')
class Ms03026GetMachineNameTests(unittest.TestCase):
    """rpcss.dll: GetMachineName copies the server name out of a remote-activation UNC path
    into a fixed MAX_COMPUTERNAME_LENGTH+1 stack buffer without a bound."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.built = Built(cls.tmp.name, 'ms03026_getmachinename.c',
                          [('com/ole32/dcomss/olescm/actmisc.cxx', ['GetMachineName'])])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_original_overflows_on_a_long_server_name(self):
        result = self.built.run('original', 'overflow')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('GetMachineName', result.stderr)
        self.assertIn('overflow', result.stderr)

    def test_patched_rejects_a_long_server_name(self):
        result = self.built.run('patched', 'overflow')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr[-3000:])

    def test_patched_rejects_an_unterminated_name(self):
        result = self.built.run('patched', 'noseparator')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr[-3000:])

    def test_valid_name_unchanged(self):
        for tree in ('original', 'patched'):
            result = self.built.run(tree, 'valid')
            self.assertEqual(result.returncode, 0, '%s\n%s%s' % (tree, result.stdout, result.stderr[-3000:]))


@unittest.skipUnless(CC, 'no C compiler')
class R1User32AniTests(unittest.TestCase):
    """user32.dll: LoadAniIcon copies RIFF chunks whose sizes come from the .ani file into
    a stack ANIHEADER and into tables sized by the file's frame and step counts, and stores
    frames without checking the declared count (R-1; MS07-017 / MS05-002 class)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.built = Built(cls.tmp.name, 'r1_user32_ani.c',
                          [('windows/core/ntuser/client/acons.c',
                            ['ReadFilePtr', 'ReadFilePtrUnaligned', 'ReadFilePtrCopy', 'ReadTag',
                             'ReadChunk', 'SkipChunk', 'LoadAniIcon'])])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_valid_animation_loads_identically(self):
        outputs = []
        for tree in ('original', 'patched'):
            result = self.built.run(tree, 'valid')
            self.assertEqual(result.returncode, 0, '%s\n%s%s' % (tree, result.stdout, result.stderr[-3000:]))
            outputs.append(result.stdout.split('handle=')[1].split(' ', 1)[1])
        self.assertEqual(outputs[0], outputs[1])

    def test_original_overruns_on_oversized_chunks_and_extra_frames(self):
        for mode, function in (('anih-size', 'LoadAniIcon'), ('rate-size', 'ReadFilePtrCopy'),
                               ('seq-size', 'ReadFilePtrCopy'), ('frames', 'LoadAniIcon')):
            result = self.built.run('original', mode)
            self.assertNotEqual(result.returncode, 0, mode)
            self.assertIn('AddressSanitizer', result.stderr, mode)
            self.assertIn(function, result.stderr, mode)

    def test_patched_rejects_every_malformed_layout(self):
        for mode in ('anih-size', 'rate-size', 'seq-size', 'order', 'frames', 'truncated'):
            result = self.built.run('patched', mode)
            self.assertEqual(result.returncode, 0, '%s\n%s%s' % (mode, result.stdout, result.stderr[-3000:]))


def table_entries(name):
    """Entry count of a function table initializer in fekbd.c (the bound the patch checks)."""
    body = re.search(r'%s\[\]\s*=\s*\{(.*?)\};' % name, source_text('windows/core/ntuser/kernel/fekbd.c'), re.S).group(1)
    return len([item for item in re.sub(r'//[^\n]*', '', body).split(',') if item.strip()])


@unittest.skipUnless(CC, 'no C compiler')
class R1Win32kKeyboardNlsTests(unittest.TestCase):
    """win32k.sys: a keyboard layout's NLS table selects functions by index and type from
    win32k's tables without a bound (R-1; MS10-073 class)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.built = Built(cls.tmp.name, 'r1_win32k_kbdnls.c',
                          [('windows/core/ntuser/kernel/fekbd.c',
                            ['GenerateNlsVkKey', 'GenerateNlsVkAltKey', 'xxxKENLSProcs'])],
                          defines=('NLSKE_COUNT=%d' % table_entries('aNLSKEProc'),
                                   'NLSVKF_COUNT=%d' % table_entries('aNLSVKFProc')))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_valid_layout_dispatches_identically(self):
        for tree in ('original', 'patched'):
            result = self.built.run(tree, 'valid')
            self.assertEqual(result.returncode, 0, '%s\n%s%s' % (tree, result.stdout, result.stderr[-3000:]))
            self.assertEqual(result.stdout, 'called=1 result=1\ncalled=2 result=1\n')

    def test_original_reads_past_the_function_tables(self):
        for mode, function in (('index', 'GenerateNlsVkKey'), ('alt-index', 'GenerateNlsVkAltKey'), ('type', 'xxxKENLSProcs')):
            result = self.built.run('original', mode)
            self.assertNotEqual(result.returncode, 0, mode)
            # One past the end lands in ASan's redzone; index 255 lands far beyond it, where
            # UBSan's array-bounds check reports it.
            self.assertTrue('global-buffer-overflow' in result.stderr or 'out of bounds for type' in result.stderr, mode)
            self.assertIn(function, result.stderr, mode)

    def test_patched_passes_the_key_on_without_a_call(self):
        for mode in ('index', 'alt-index', 'type'):
            result = self.built.run('patched', mode)
            self.assertEqual(result.returncode, 0, '%s\n%s%s' % (mode, result.stdout, result.stderr[-3000:]))


if __name__ == '__main__':
    unittest.main()
