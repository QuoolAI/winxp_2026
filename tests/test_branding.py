"""Guard resource-only changes and reject unsafe or stale branding evidence."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
sys.path.insert(0, str(ROOT / 'vm'))
from prepare_branding import validate, brand_system_properties, MACHINE_LINES, MACHINE_LINE_CX, BRAND_CONTROL
from pe_resources import Resources, dialog, dialog_data, strings, string_data
from install_branding_overlay import verify_pair
from branding_results import latest_probe


class BrandingGuards(unittest.TestCase):
    def test_title_buffer_locale_and_control_character_guards(self):
        config = json.loads((ROOT / 'branding/en-US.json').read_text())
        validate(config)
        for field, value in [('about_application', 'X' * 32), ('language_id', 1041),
                             ('preserve_registry_product_name', False), ('preserve_start_button', False),
                             ('edition_name', '%s'), ('edition_name', 'XP\t25'),
                             ('system_properties_label', 'one line'), ('start_menu_help', 'X' * 18),
                             ('login_header', 'XP\u2603')]:
            with self.subTest(field=field, value=value):
                modified = copy.deepcopy(config)
                modified[field] = value
                with self.assertRaises((ValueError, UnicodeEncodeError)):
                    validate(modified)

    def test_system_properties_computer_lines_widen_without_moving_controls(self):
        def item(ident, cls, x, y, cx, cy=8):
            return dict(help=0, exstyle=0, style=0x50000000, x=x, y=y, cx=cx, cy=cy, id=ident, cls=cls, text='', extra=b'')
        row = {'title': 'General', 'cx': 256, 'cy': 218,
               'items': [item(51, 0x82, 7, 11, 120, 98), item(52, 0x82, 141, 22, 100), item(69, 0x80, 141, 206, 80, 14)] +
                        [item(i, 'Link Window', 141, 137 + 11 * n, 110) for n, i in enumerate(MACHINE_LINES)]}
        before = copy.deepcopy(row)
        brand_system_properties(row, 'Windows XP\r\n25th Anniversary Edition')
        self.assertEqual((row['cx'], row['cy']), (256 + MACHINE_LINE_CX - 110, 218))
        lines = [i for i in row['items'] if i['id'] in MACHINE_LINES]
        self.assertTrue(all(i['cx'] == MACHINE_LINE_CX and row['cx'] - (i['x'] + i['cx']) == 5 for i in lines))
        self.assertEqual([i for i in row['items'] if i['id'] not in MACHINE_LINES + (BRAND_CONTROL,)],
                         [i for i in before['items'] if i['id'] not in MACHINE_LINES])
        self.assertEqual([(i['x'], i['y'], i['cy']) for i in lines],
                         [(i['x'], i['y'], i['cy']) for i in before['items'] if i['id'] in MACHINE_LINES])
        for change in ({'cx': 270}, {'title': 'Other'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                brand_system_properties({**copy.deepcopy(before), **change}, 'a\r\nb')
        moved = copy.deepcopy(before)
        moved['items'][-1]['x'] = 140
        with self.assertRaisesRegex(ValueError, 'computer lines'):
            brand_system_properties(moved, 'a\r\nb')

    def test_system_properties_branding_on_private_original(self):
        original = ROOT / '.work/branding-20261023/ui-inputs/WINDOWS/system32/sysdm.cpl'
        if not original.is_file():
            self.skipTest('private XP resource inputs unavailable')
        row = dialog(Resources(original).entries[(5, 101, 1033)]['data'])
        before = copy.deepcopy(row)
        brand_system_properties(row, 'Windows XP\r\n25th Anniversary Edition')
        self.assertEqual(dialog(dialog_data(row)), row)
        self.assertEqual(len(row['items']), len(before['items']) + 1)
        self.assertEqual(max(i['x'] + i['cx'] for i in row['items']), row['cx'] - 5)

    def test_utf16_string_tables_preserve_surrogate_pairs(self):
        values = ['Windows XP', '\U0001f5a5', '\u65e5\u672c\u8a9e', ''] + [''] * 12
        self.assertEqual(strings(string_data(values)), values)

    def test_pending_probe_cannot_reuse_old_success(self):
        end, records = latest_probe('BRANDING_PROBE_STARTED\n{"branding_case":"branding_probe_complete","status":"pass"}\nBRANDING_PROBE_EXIT=0\nBRANDING_PROBE_STARTED\n')
        self.assertEqual(end, -1)
        self.assertEqual(records, [])

    def test_native_resource_roundtrip_and_protected_versioninfo(self):
        original = ROOT / '.work/branding-20261023/ui-inputs/WINDOWS/system32/sysdm.cpl'
        if not original.is_file():
            self.skipTest('private XP resource inputs unavailable')
        resources = Resources(original)
        key = (5, 101, 1033)
        row = dialog(resources.entries[key]['data'])
        self.assertEqual(dialog(dialog_data(row)), row)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work') as name:
            output = Path(name) / 'sysdm.cpl'
            resources.write(output)
            verify_pair(original, output, [])
            version = next(k for k in resources.entries if k[0] == 16)
            resources.entries[version]['data'] += b'\0\0'
            resources.write(output)
            with self.assertRaisesRegex(ValueError, 'VERSIONINFO changed'):
                verify_pair(original, output, [list(version)])


if __name__ == '__main__':
    unittest.main()
