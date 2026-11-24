"""MerlinAI Builder beyond its own components: PE inspection, the recipe registry, Microsoft's reference source
as the effective, read-only source of an investigation, the system-image view, the offline rule for drivers
that import an unexported kernel function, build media, the provenance gate and driver checks."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'components/merlin/builder'))
sys.path.insert(0, str(ROOT / 'build'))
sys.path.insert(0, str(ROOT / 'vm'))
from merlin_builder import investigate as inv, pe, pipeline, recipes, sysimage  # noqa: E402


def make_pe(exports=(), imports=None, code=b'\x55\x8b\xec\xc3' * 8, timestamp=1, version=None, company=None, debug=b''):
    """A minimal PE32 image: .text (code, then a CodeView record when debug is given), .edata, .idata, .rsrc."""
    imports = imports or {}
    sections, align, base = [], 0x1000, 0x400000
    rva = {'.text': 0x1000, '.edata': 0x2000, '.idata': 0x3000, '.rsrc': 0x4000}

    def edata():
        names = sorted(exports)
        start = rva['.edata']
        dll = b'test.dll\0'
        functions = start + 40
        name_ptrs = functions + 4 * len(names)
        ordinals = name_ptrs + 4 * len(names)
        strings = ordinals + 2 * len(names)
        body = bytearray()
        table, pointers, blob = b'', b'', bytearray(dll)
        for i, n in enumerate(names):
            table += struct.pack('<I', 0x1000 + i)
            pointers += struct.pack('<I', strings + len(blob))
            blob += n.encode() + b'\0'
        header = struct.pack('<IIHHIIIIIII', 0, timestamp, 0, 0, strings, 1, len(names), len(names), functions, name_ptrs, ordinals)
        body += header + table + pointers + b''.join(struct.pack('<H', i) for i in range(len(names))) + blob
        return bytes(body)

    def idata():
        start = rva['.idata']
        dlls = sorted(imports)
        descriptors = 20 * (len(dlls) + 1)
        blob = bytearray()
        thunks = []
        cursor = start + descriptors
        layout = []
        for dll in dlls:
            names = imports[dll]
            ilt = cursor
            cursor += 4 * (len(names) + 1)
            layout.append((dll, names, ilt))
        strings = cursor
        entries = []
        for dll, names, ilt in layout:
            values = []
            for n in names:
                if n.startswith('#'):
                    values.append(0x80000000 | int(n[1:]))
                else:
                    values.append(strings + len(blob))
                    blob += b'\0\0' + n.encode() + b'\0'
                    if len(blob) % 2:
                        blob += b'\0'
            name_rva = strings + len(blob)
            blob += dll.encode() + b'\0'
            entries.append((ilt, name_rva, values))
        out = bytearray()
        for ilt, name_rva, _ in entries:
            out += struct.pack('<IIIII', ilt, 0, 0, name_rva, ilt)
        out += b'\0' * 20
        for _, _, values in entries:
            out += b''.join(struct.pack('<I', v) for v in values) + b'\0' * 4
        return bytes(out + blob)

    def rsrc():
        out = b''
        for key, value in (('CompanyName', company), ('FileVersion', version)):
            if value:
                k = key.encode('utf-16-le') + b'\0\0'
                v = value.encode('utf-16-le') + b'\0\0'
                entry = struct.pack('<HHH', 0, len(value) + 1, 1) + k
                entry += b'\0' * ((4 - len(entry) % 4) % 4)
                out += entry + v + b'\0' * ((4 - len(v) % 4) % 4)
        return out or b'\0' * 4

    text = code + debug
    bodies = {'.text': text, '.edata': edata() if exports else b'\0' * 4, '.idata': idata() if imports else b'\0' * 4, '.rsrc': rsrc()}
    order = ['.text', '.edata', '.idata', '.rsrc']
    headers = 0x400
    raw = headers
    table = b''
    data = bytearray()
    for name in order:
        body = bodies[name]
        size = (len(body) + 0x1ff) & ~0x1ff
        table += struct.pack('<8sIIIIIIHHI', name.encode(), len(body), rva[name], size, raw, 0, 0, 0, 0, 0x60000020)
        data += body + b'\0' * (size - len(body))
        raw += size
    directories = [(0, 0)] * 16
    if exports:
        directories[0] = (rva['.edata'], len(bodies['.edata']))
    if imports:
        directories[1] = (rva['.idata'], 20 * (len(imports) + 1))
    if debug:
        # One debug directory entry at the end of .text pointing at a CodeView record just before it.
        directories[6] = (rva['.text'] + len(text) - 28, 28)
    optional = bytearray(0xE0)
    struct.pack_into('<H', optional, 0, 0x10b)
    struct.pack_into('<I', optional, 28, base)
    struct.pack_into('<II', optional, 32, align, 0x200)
    struct.pack_into('<I', optional, 56, 0x5000)
    struct.pack_into('<I', optional, 60, headers)
    struct.pack_into('<I', optional, 92, 16)
    for i, (r, s) in enumerate(directories):
        struct.pack_into('<II', optional, 96 + 8 * i, r, s)
    head = bytearray(b'MZ' + b'\0' * 0x3a + struct.pack('<I', 0x80) + b'\0' * (0x80 - 0x40))
    head += b'PE\0\0' + struct.pack('<HHIIIHH', 0x14c, len(order), timestamp, 0, 0, 0xE0, 0x2102) + optional + table
    head += b'\0' * (headers - len(head))
    return bytes(head + data)


def codeview(stamp):
    """A CodeView record (RSDS + GUID + age + PDB path) followed by its debug directory entry."""
    record = b'RSDS' + bytes([stamp]) * 16 + struct.pack('<I', 1) + b'x.pdb\0'
    record += b'\0' * ((4 - len(record) % 4) % 4)
    return record, len(record)


def with_debug(stamp, code=b'\x55\x8b\xec\xc3' * 8):
    record, size = codeview(stamp)
    # The CodeView record sits after the code; the entry (28 bytes) after the record points back at it.
    text_rva, raw = 0x1000, 0x400
    entry = struct.pack('<IIHHIIII', 0, stamp, 0, 0, 2, size, text_rva + len(code), raw + len(code))
    return make_pe(exports=['A'], code=code, timestamp=stamp, debug=record + entry)


class PETests(unittest.TestCase):
    def test_exports_imports_and_version(self):
        image = pe.PE(make_pe(exports=['RtlA', 'KeB'], imports={'ntoskrnl.exe': ['KeB', 'RtlMissing', '#7'], 'hal.dll': ['HalX']},
                              version='5.1.2600.5512 (xpsp.080413-2111)', company='Microsoft Corporation'))
        self.assertEqual(set(image.exports()), {'RtlA', 'KeB'})
        self.assertEqual(image.export_ordinals(), {'#1', '#2'})
        self.assertEqual(image.imports(), {'ntoskrnl.exe': ['KeB', 'RtlMissing', '#7'], 'hal.dll': ['HalX']})
        self.assertEqual(image.file_version(), '5.1.2600.5512 (xpsp.080413-2111)')
        self.assertEqual(image.version_string('CompanyName'), 'Microsoft Corporation')

    def test_malformed_input_raises(self):
        for data in (b'', b'MZ' + b'\0' * 100, b'XX' + b'\0' * 200):
            with self.assertRaises(pe.PEError):
                pe.PE(data)

    def test_compare_ignores_link_stamps_but_not_code(self):
        a, b = with_debug(1), with_debug(2)
        self.assertNotEqual(a, b)
        self.assertTrue(pe.compare_builds(a, b)['identical'])
        changed = with_debug(2, code=b'\x55\x8b\xec\xc2' * 8)
        result = pe.compare_builds(a, changed)
        self.assertFalse(result['identical'])
        self.assertIn('.text: contents differ', result['differences'])

    def test_compare_can_set_the_export_section_aside(self):
        a, b = make_pe(exports=['A', 'B']), make_pe(exports=['A', 'B', 'C'])
        self.assertFalse(pe.compare_builds(a, b)['identical'])
        self.assertTrue(pe.compare_builds(a, b, ignore_exports=True)['identical'])


class RecipeTests(unittest.TestCase):
    def test_registry_maps_recipes_sources_and_kernel_provenance(self):
        table = recipes.load()
        self.assertEqual(set(table['recipes']), {'merlin', 'winlogon', 'ai', 'security', 'nt-kernel'})
        for name, info in table['binaries'].items():
            if info.get('recipe'):
                self.assertIn(info['recipe'], table['recipes'], name)
                self.assertTrue(info.get('guest_path'), name)
        self.assertEqual(recipes.recipe_of_file('components/winlogon/main.c'), 'winlogon')
        self.assertEqual(recipes.recipe_of_file('components/xp25-agent/llm/xp25_sha256.c'), 'merlin')
        self.assertEqual(recipes.recipe_of_file('Source/XPSP1/NT/base/ntos/init/ntoskrnl.src'), 'nt-kernel')
        self.assertIsNone(recipes.recipe_of_file('Source/XPSP1/NT/shell/explorer/tray.cpp'))
        self.assertEqual(recipes.editable_nt_prefixes(), ('base/ntos/',))
        kernel = table['binaries']['xp25krnl.exe']
        self.assertEqual({v['variant'] for v in kernel['known_builds'].values()}, {'up', 'mp'})

    def test_effective_kernel_export_list_is_the_milestone_8_change(self):
        reference = (ROOT / 'Source/XPSP1/NT/base/ntos/init/ntoskrnl.src').read_bytes().decode('latin-1')
        effective = recipes.effective_nt_text('base/ntos/init/ntoskrnl.src', reference, ROOT)
        self.assertIn('    KeInsertQueueDpc\n    KeFlushQueuedDpcs\n', effective)
        self.assertEqual(len(effective.splitlines()), len(reference.splitlines()) + 1)
        self.assertEqual(recipes.effective_nt_text('base/ntos/rtl/acledit.c', 'x', ROOT), 'x')
        with self.assertRaises(ValueError):
            recipes.apply_exports(effective, {'KeFlushQueuedDpcs': '    KeInsertQueueDpc\n'})


def fake_reference(root):
    """A miniature NT tree: the kernel export list, one implementation and its public declaration."""
    nt = root / 'nt'
    (nt / 'base/ntos/init').mkdir(parents=True)
    (nt / 'base/ntos/rtl').mkdir(parents=True)
    (nt / 'public/sdk/inc').mkdir(parents=True)
    (nt / 'shell').mkdir(parents=True)
    (nt / 'base/ntos/init/ntoskrnl.src').write_bytes(b'NAME ntoskrnl.exe\nEXPORTS\n    KeInsertQueueDpc\n'
                                                       b'    RtlAddAccessAllowedAce\n    RtlAddAce\n')
    (nt / 'base/ntos/rtl/acledit.c').write_bytes(b'NTSTATUS\nRtlAddAccessAllowedAceEx (\n    PACL Acl\n    )\n{\n    return 0;\n}\n')
    (nt / 'public/sdk/inc/ntrtl.h').write_bytes(b'NTSYSAPI\nNTSTATUS\nNTAPI\nRtlAddAccessAllowedAce (\n    PACL Acl\n    );\n\n'
                                                 b'// end_ntifs\n\nNTSYSAPI\nNTSTATUS\nNTAPI\nRtlAddAccessAllowedAceEx (\n    PACL Acl\n    );\n'
                                                 b'NTKERNELAPI\nVOID\nFASTCALL\nExfAcquirePushLockShared (\n    PVOID Lock\n    );\n')
    (nt / 'shell/tray.c').write_bytes(b'int tray;\n')
    repo = root / 'repo'
    (repo / 'build').mkdir(parents=True)
    (repo / 'components').mkdir()
    (repo / 'build/prepare_kernel_exports.py').write_text("EXPORTS = {'KeFlushQueuedDpcs': '    KeInsertQueueDpc\\n'}\n")
    return repo, nt


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo, self.nt = fake_reference(self.tmp)
        self.before = {p: p.read_bytes() for p in self.nt.rglob('*') if p.is_file()}
        self.ws = inv.Workspace(self.repo, reference=self.nt, overlay=self.tmp / 'overlay')

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_reads_the_effective_source(self):
        text = self.ws.read('Source/XPSP1/NT/base/ntos/init/ntoskrnl.src')
        self.assertIn('KeFlushQueuedDpcs', text)
        self.assertIn('Source/XPSP1/NT/base/ntos/init/', self.ws.list('Source/XPSP1/NT/base/ntos'))
        self.assertIn('KeFlushQueuedDpcs', self.ws.search('KeFlush', 'Source/XPSP1/NT/base/ntos'))

    def test_edits_go_to_the_overlay_and_the_reference_is_unchanged(self):
        src = 'Source/XPSP1/NT/base/ntos/init/ntoskrnl.src'
        self.ws.edit(src, '    RtlAddAccessAllowedAce\n', '    RtlAddAccessAllowedAce\n    RtlAddAccessAllowedAceEx\n', 'export')
        self.assertIn('RtlAddAccessAllowedAceEx', self.ws.read(src))
        self.assertEqual({p: p.read_bytes() for p in self.nt.rglob('*') if p.is_file()}, self.before)
        changes = self.ws.nt_changes()
        reference, effective, job = changes['base/ntos/init/ntoskrnl.src']
        self.assertNotIn(b'KeFlushQueuedDpcs', reference)
        self.assertIn(b'KeFlushQueuedDpcs', job)
        diff = self.ws.diff()
        self.assertIn('+    RtlAddAccessAllowedAceEx', diff)
        self.assertNotIn('+    KeFlushQueuedDpcs', diff)            # XP25's own change is not the job's

    def test_refusals(self):
        with self.assertRaises(inv.ToolError):
            self.ws.edit('Source/XPSP1/NT/shell/tray.c', 'int', 'long', 'not rebuildable')
        for bad in ('Source/XPSP1/NT/../../etc/passwd', 'Source/XPSP1/other', 'Source', '/etc/passwd', '../x'):
            with self.assertRaises(inv.ToolError):
                self.ws.read(bad)
        with self.assertRaises(inv.ToolError):
            self.ws.search('x', 'Source/XPSP1/NT/base')       # too wide: a component directory is required
        no_reference = inv.Workspace(self.repo, overlay=self.tmp / 'o2')
        with self.assertRaises(inv.ToolError):
            no_reference.read('Source/XPSP1/NT/base/ntos/init/ntoskrnl.src')


class FakeLab:
    """xp_lab's partition/run for an in-memory disk {guest path: bytes}."""

    def __init__(self, files):
        self.files = files

    @contextlib.contextmanager
    def partition(self, image, writable):
        yield 'device'

    def run(self, argv):
        if argv[0] == 'ntfsls':
            directory = argv[2].rstrip('/') + '/'
            names = {p[len(directory):].split('/')[0] for p in self.files if p.startswith(directory)}
            if not names:
                raise RuntimeError('no such directory')
            return '\n'.join(sorted(names)).encode()
        if argv[0] == 'ntfscat':
            if argv[2] not in self.files:
                raise RuntimeError('no such file')
            return self.files[argv[2]]
        raise RuntimeError(argv[0])


def system_files(kernel_exports=('KeInsertQueueDpc',), stock_exports=('KeInsertQueueDpc', 'RtlAddAccessAllowedAceEx')):
    return {
        '/boot.ini': b'[boot loader]\r\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS\r\n[operating systems]\r\n'
                     b'multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS="XP25" /kernel=xp25krnl.exe /hal=xp25hal.dll\r\n',
        '/WINDOWS/system32/xp25krnl.exe': make_pe(exports=kernel_exports),
        '/WINDOWS/system32/xp25hal.dll': make_pe(exports=['HalX']),
        '/WINDOWS/system32/ntoskrnl.exe': make_pe(exports=stock_exports),
        '/WINDOWS/system32/drivers/fltMgr.sys': make_pe(imports={'ntoskrnl.exe': ['KeInsertQueueDpc', 'RtlAddAccessAllowedAceEx'],
                                                                  'hal.dll': ['HalX']},
                                                         version='5.1.2600.5512 (xpsp.080413-2111)', company='Microsoft Corporation'),
    }


class SystemImageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_resolves_imports_against_the_booted_kernel(self):
        s = sysimage.SystemImage(self.tmp / 'disk.qcow2', self.tmp / 'cache', FakeLab(system_files()))
        self.assertEqual(s.boot(), {'kernel': 'xp25krnl.exe', 'hal': 'xp25hal.dll'})
        self.assertEqual(s.find('FLTMGR.SYS'), '/WINDOWS/system32/drivers/fltMgr.sys')
        d = s.describe('fltmgr.sys')
        self.assertEqual(d['unresolved'], ['ntoskrnl.exe!RtlAddAccessAllowedAceEx'])
        self.assertEqual(d['origin'], 'binary-only')
        self.assertEqual(d['imports']['ntoskrnl.exe']['resolved_from'], '/WINDOWS/system32/xp25krnl.exe')
        self.assertFalse(s.describe('absent.sys')['installed'])
        with self.assertRaises(ValueError):
            s.find('../boot.ini')


class OfflineDriverRuleTests(unittest.TestCase):
    PROBLEM = {'id': 'P-1', 'kind': 'driver', 'component': 'Drivers: ??FltMgr', 'title': 'Boot or system drivers failed to load',
               'evidence': ['System/Service Control Manager 7026: The following boot-start or system-start driver(s) failed to load: ??FltMgr ']}

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo, self.nt = fake_reference(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def investigate(self, files):
        # A system image never changes under a job, so its cache is per call here (as per job in the pipeline).
        cache = Path(tempfile.mkdtemp(dir=self.tmp))
        ws = inv.Workspace(self.repo, reference=self.nt, overlay=cache / 'overlay')
        system = sysimage.SystemImage(self.tmp / 'disk.qcow2', cache / 'system-image', FakeLab(files))
        return ws, inv.OfflineInvestigator(ws, system=system).investigate([self.PROBLEM])['problems'][0]

    def test_driver_names(self):
        self.assertEqual(inv.driver_names(self.PROBLEM), ['FltMgr'])
        self.assertEqual(inv.driver_names({'component': 'Drivers: ??FltMgr??HTTP', 'evidence': []}), ['FltMgr', 'HTTP'])
        self.assertEqual(inv.driver_names({'component': 'Service X', 'evidence': ['nothing here']}), [])

    def test_exports_an_implemented_kernel_function(self):
        ws, r = self.investigate(system_files())
        self.assertTrue(r['change_justified'])
        self.assertEqual(r['result_hint'], 'fix_proposed')
        text = ws.text('Source/XPSP1/NT/base/ntos/init/ntoskrnl.src')
        self.assertIn('    RtlAddAccessAllowedAce\n    RtlAddAccessAllowedAceEx\n', text)
        self.assertIn('KeFlushQueuedDpcs', text)               # XP25's own export stays

    def test_no_change_without_evidence_that_the_export_is_the_same_api(self):
        # Microsoft's own later kernel does not export it: not the same API.
        ws, r = self.investigate(system_files(stock_exports=('KeInsertQueueDpc',)))
        self.assertFalse(r['change_justified'])
        self.assertEqual(ws.edits, [])
        # Exported already: the driver's imports resolve, nothing to change.
        ws, r = self.investigate(system_files(kernel_exports=('KeInsertQueueDpc', 'RtlAddAccessAllowedAceEx')))
        self.assertFalse(r['change_justified'])
        self.assertIn('every import resolves', r['conclusion'])

    def test_fastcall_and_unimplemented_functions_are_not_exported(self):
        self.assertIsNone(inv.public_stdcall_declaration(inv.Workspace(self.repo, reference=self.nt), 'ExfAcquirePushLockShared'))
        self.assertIsNotNone(inv.public_stdcall_declaration(inv.Workspace(self.repo, reference=self.nt), 'RtlAddAccessAllowedAceEx'))
        self.assertIsNone(inv.kernel_definition(inv.Workspace(self.repo, reference=self.nt), 'RtlIpv4AddressToStringExW'))


class MediaTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('xorriso'), 'xorriso is required')
    def test_nt_kernel_media_carry_reference_control_and_candidate(self):
        import prepare_recipe
        with tempfile.TemporaryDirectory(dir=ROOT / '.work' if (ROOT / '.work').is_dir() else None) as tmp:
            tmp = Path(tmp)
            repo, nt = fake_reference(tmp)
            changes = tmp / 'changes/base/ntos/init'
            changes.mkdir(parents=True)
            effective = recipes.effective_nt_text('base/ntos/init/ntoskrnl.src', (nt / 'base/ntos/init/ntoskrnl.src').read_text(), repo)
            (changes / 'ntoskrnl.src').write_text(effective.replace('    RtlAddAccessAllowedAce\n',
                                                                    '    RtlAddAccessAllowedAce\n    RtlAddAccessAllowedAceEx\n'))
            out = tmp / 'media'
            with mock.patch.object(sys, 'argv', ['prepare_recipe.py', '--recipe', 'nt-kernel', '--output', str(out), '--source', str(repo),
                                                 '--reference', str(nt), '--nt-changes', str(tmp / 'changes')]), \
                 contextlib.redirect_stdout(io.StringIO()):
                prepare_recipe.main()
            m = json.loads((out / 'manifest.json').read_text())
            media = out / 'media'
            self.assertEqual((media / 'original/base/ntos/init/ntoskrnl.src').read_bytes(), (nt / 'base/ntos/init/ntoskrnl.src').read_bytes())
            self.assertIn(b'KeFlushQueuedDpcs', (media / 'control/base/ntos/init/ntoskrnl.src').read_bytes())
            self.assertNotIn(b'RtlAddAccessAllowedAceEx', (media / 'control/base/ntos/init/ntoskrnl.src').read_bytes())
            self.assertIn(b'RtlAddAccessAllowedAceEx', (media / 'candidate/base/ntos/init/ntoskrnl.src').read_bytes())
            self.assertEqual((media / 'dirs.txt').read_bytes(), b'base\\ntos\\init\r\n')
            self.assertIn(b'base\\ntos\\init\\mp\\obj\\i386\\ntkrnlmp.exe\r\n', (media / 'outputs.txt').read_bytes())
            self.assertEqual(m['marker'], 'XP25_RECIPE_BUILD')
            self.assertIn('candidate/ntoskrnl.exe', m['collect'])

    def test_nt_media_refuse_files_no_recipe_rebuilds(self):
        import prepare_recipe
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            repo, nt = fake_reference(tmp)
            (tmp / 'changes/shell').mkdir(parents=True)
            (tmp / 'changes/shell/tray.c').write_text('long tray;\n')
            with self.assertRaises(SystemExit):
                prepare_recipe.nt_media('nt-kernel', repo, nt, tmp / 'changes', tmp / 'media', recipes.load())

    def test_build_driver_checks_every_stage(self):
        cmd = (ROOT / 'build/native-nt-recipe-build.cmd').read_text()
        for needed in ('fc /b "D:\\original\\', 'call :build control', 'call :build candidate', 'nmake.exe failed', '+,,',
                       'del /f "C:\\nt\\%%O"', 'XP25_RECIPE_BUILD_EXIT='):
            self.assertIn(needed, cmd)


class JobTestCheckTests(unittest.TestCase):
    def test_driver_check_is_generated_from_a_validated_name(self):
        import merlin_jobtest
        text = merlin_jobtest.suite([{'driver': 'FltMgr'}])
        self.assertIn('sc query FltMgr > C:\\xp25\\jobtest-sc.txt', text)
        self.assertIn('XP25_JOBTEST_DRIVER_FLTMGR=running', text)
        # What the guest writes must survive the results' marker extraction.
        self.assertEqual(merlin_jobtest.serial_markers('XP25_JOBTEST_DRIVER_FLTMGR=running \r\nXP25_JOBTEST_DRIVER_FLTMGR=not_running'),
                         ['XP25_JOBTEST_DRIVER_FLTMGR=running', 'XP25_JOBTEST_DRIVER_FLTMGR=not_running'])
        for bad in ({'driver': 'Flt Mgr'}, {'driver': 'x&del'}, {'driver': 'FltMgr', 'extra': 1}, {'command': 'x'}):
            with self.assertRaises(SystemExit):
                merlin_jobtest.suite([bad])


class ProvenanceTests(unittest.TestCase):
    """The pipeline's provenance step with synthetic kernels."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def job(self, installed, control, candidate, mp_installed, mp_control, mp_candidate):
        collect = self.tmp / 'collect'
        for stage, up, mp in (('control', control, mp_control), ('candidate', candidate, mp_candidate)):
            (collect / 'build' / stage).mkdir(parents=True, exist_ok=True)
            (collect / 'build' / stage / 'ntoskrnl.exe').write_bytes(up)
            (collect / 'build' / stage / 'ntkrnlmp.exe').write_bytes(mp)
        (self.tmp / 'mp.exe').write_bytes(mp_installed)
        files = {'/WINDOWS/system32/xp25krnl.exe': installed}
        job = pipeline.Job.__new__(pipeline.Job)
        job.dir, job.job = self.tmp, 'J-1'
        job.baseline = {'mp_kernel': str(self.tmp / 'mp.exe')}
        job.log = lambda *a, **k: None
        job.system_image = lambda: sysimage.SystemImage(self.tmp / 'disk', self.tmp / 'cache', FakeLab(files))
        info = dict(recipes.load()['binaries']['xp25krnl.exe'])
        info['known_builds'] = {hashlib.sha256(installed).hexdigest(): {'variant': 'up', 'built_as': 'test'}}
        return job, {'nt-kernel': {'candidate': collect, 'control': collect}}, {'nt-kernel': {'xp25krnl.exe': info}}

    def test_accepts_an_added_export_when_the_control_reproduces_the_installed_kernel(self):
        installed, mp = with_debug(1), with_debug(5)
        new = make_pe(exports=['A', 'RtlAddAccessAllowedAceEx'], timestamp=3)
        job, collections, groups = self.job(installed, with_debug(2), new, mp, with_debug(6), new)
        rebuilt, kernels = job.provenance(collections, groups)
        record = rebuilt['xp25krnl.exe'][1]
        self.assertEqual(record['exports_added'], ['RtlAddAccessAllowedAceEx'])
        self.assertTrue(record['control_reproduces_installed'])
        self.assertEqual(kernels['mp'].name, 'ntkrnlmp.exe')

    def test_refuses_when_the_control_build_differs(self):
        installed = with_debug(1)
        other = with_debug(2, code=b'\x90' * 32)
        job, collections, groups = self.job(installed, other, other, with_debug(5), with_debug(6), other)
        with self.assertRaises(pipeline.StepFailed):
            job.provenance(collections, groups)

    def xp25_job(self, installed, control, candidate, extra_files=None):
        root = Path(tempfile.mkdtemp(dir=self.tmp))
        collections = {}
        for stage, data in (('control', control), ('candidate', candidate)):
            build = root / stage / 'build'
            build.mkdir(parents=True)
            (build / 'winlogon.exe').write_bytes(data)
            collections[stage] = root / stage
        files = dict({'/WINDOWS/system32/winlogon.exe': installed}, **(extra_files or {}))
        job = pipeline.Job.__new__(pipeline.Job)
        job.dir, job.job, job.baseline = root, 'J-2', {}
        job.log = lambda *a, **k: None
        job.system_image = lambda: sysimage.SystemImage(root / 'disk', root / 'cache', FakeLab(files))
        info = dict(recipes.load()['binaries']['winlogon.exe'])
        return job, {'winlogon': collections}, {'winlogon': {'winlogon.exe': info}}

    def test_xp25_recipe_needs_a_control_build_that_reproduces_the_installed_file(self):
        job, collections, groups = self.xp25_job(with_debug(1), with_debug(2), with_debug(3, code=b'\x90' * 32))
        rebuilt, _ = job.provenance(collections, groups)
        self.assertTrue(rebuilt['winlogon.exe'][1]['control_reproduces_installed'])
        self.assertFalse(rebuilt['winlogon.exe'][1]['code_identical_to_control'])
        job, collections, groups = self.xp25_job(with_debug(1), with_debug(2, code=b'\x90' * 32), with_debug(3))
        with self.assertRaises(pipeline.StepFailed):
            job.provenance(collections, groups)

    def test_moved_ordinals_are_refused_when_something_imports_by_ordinal(self):
        installed = make_pe(exports=['A', 'C'])
        candidate = make_pe(exports=['A', 'B', 'C'])             # C moves from ordinal 2 to 3
        user = make_pe(imports={'winlogon.exe': ['#2']})
        job, collections, groups = self.xp25_job(installed, installed, candidate,
                                                 {'/WINDOWS/system32/user.dll': user})
        with self.assertRaises(pipeline.StepFailed) as raised:
            job.provenance(collections, groups)
        self.assertIn('/WINDOWS/system32/user.dll', str(raised.exception))
        job, collections, groups = self.xp25_job(installed, installed, candidate)
        rebuilt, _ = job.provenance(collections, groups)
        self.assertEqual(rebuilt['winlogon.exe'][1]['export_ordinals_changed'], 1)

    def test_refuses_imports_the_installed_system_lacks(self):
        new = make_pe(imports={'kernel32.dll': ['GetTickCount', 'GetTickCount64']})
        old = make_pe(imports={'kernel32.dll': ['GetTickCount']})
        files = {'/WINDOWS/system32/kernel32.dll': make_pe(exports=['GetTickCount'])}
        job, collections, groups = self.xp25_job(old, old, new, files)
        with self.assertRaises(pipeline.StepFailed) as raised:
            job.provenance(collections, groups)
        self.assertIn('kernel32.dll!GetTickCount64', str(raised.exception))

    def test_refuses_an_unknown_installed_kernel(self):
        job, collections, groups = self.job(with_debug(1), with_debug(2), with_debug(2), with_debug(5), with_debug(6), with_debug(6))
        groups['nt-kernel']['xp25krnl.exe']['known_builds'] = {}
        with self.assertRaises(pipeline.StepFailed):
            job.provenance(collections, groups)


if __name__ == '__main__':
    unittest.main()
