#!/usr/bin/env python3
"""Prepare reviewed UI resources; never change OS identity, code or licensing data."""
import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from pe_resources import Resources, strings, string_data, dialog, dialog_data

ROOT = Path(__file__).resolve().parents[1]
BRAND_CONTROL = 0x7f25


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate(config):
    if config['schema'] != 1 or config['language_id'] != 1033 or not config['preserve_registry_product_name'] or not config['preserve_start_button']:
        raise ValueError('only the reviewed en-US pack with preserved compatibility identifiers is supported')
    limits = {'edition_name': 48, 'system_properties_label': 48, 'about_application': 24,
              'start_menu_help': 17, 'login_header': 64}
    for name, limit in limits.items():
        value = config[name]
        if not value or '\0' in value or '%' in value or len(value.encode('utf-16-le')) // 2 > limit:
            raise ValueError('unsafe branding string: ' + name)
        value.encode('ascii')  # This pack deliberately supports the reviewed CP1252/ANSI paths only.
        if any(ord(c) < 32 and not (name == 'system_properties_label' and c in '\r\n') for c in value):
            raise ValueError('control character in branding string: ' + name)
    lines = config['system_properties_label'].split('\r\n')
    if len(lines) != 2 or any(not line or len(line) > 24 or '\r' in line or '\n' in line for line in lines):
        raise ValueError('System Properties requires exactly two reviewed lines')


def string_replace(resources, identifier, expected, value, language=1033):
    key = (6, identifier // 16 + 1, language)
    values = strings(resources.entries[key]['data'])
    if values[identifier % 16] != expected:
        raise ValueError('unrecognized original UI string: ' + str(identifier))
    values[identifier % 16] = value
    resources.entries[key]['data'] = string_data(values)


def add_label(row, text, x, y, cx, cy):
    if any(item['id'] == BRAND_CONTROL for item in row['items']):
        raise ValueError('branding control ID collision')
    row['items'].append(dict(help=0, exstyle=0, style=0x50000081,
                             x=x, y=y, cx=cx, cy=cy, id=BRAND_CONTROL,
                             cls=0x82, text=text, extra=b''))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True, help='private extracted baseline Windows directory')
    parser.add_argument('--config', type=Path, default=ROOT / 'branding/en-US.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--only-explorer', action='store_true', help='prepare only the reviewed Explorer resources on a source-built candidate')
    args = parser.parse_args()
    source, output = args.inputs.resolve(), args.output.resolve()
    if not source.is_relative_to(ROOT / '.work') or not output.is_relative_to(ROOT / '.work'):
        parser.error('all extracted binaries and generated outputs must remain private under .work/')
    config = json.loads(args.config.read_text())
    validate(config)
    output.mkdir(parents=True, exist_ok=False)
    manifests = {}
    components = ('explorer.exe',) if args.only_explorer else ('system32/sysdm.cpl', 'system32/xpsp1res.dll', 'system32/winver.exe',
                     'explorer.exe', 'system32/shell32.dll', 'system32/logonui.exe')
    for relative in components:
        path = source / relative
        resources = Resources(path)
        original = copy.deepcopy(resources.entries)
        if {key[2] for key in original} != {1033}:
            raise ValueError('unreviewed language resources: ' + relative)
        if relative.endswith('sysdm.cpl'):
            key = (5, 101, 1033)
            row = dialog(resources.entries[key]['data'])
            if row['title'] != 'General' or (row['cx'], row['cy']) != (256, 218):
                raise ValueError('unrecognized System Properties layout')
            add_label(row, config['system_properties_label'], 7, 112, 120, 20)
            resources.entries[key]['data'] = dialog_data(row)
        elif relative.endswith('xpsp1res.dll'):
            key = (5, 14352, 1033)
            row = dialog(resources.entries[key]['data'])
            if row['title'] != 'About %s' or (row['cx'], row['cy']) != (275, 198):
                raise ValueError('unrecognized About dialog layout')
            row['cy'] += 12
            for item in row['items']:
                if item['y'] >= 55:
                    item['y'] += 12
            add_label(row, config['edition_name'], 7, 49, 261, 10)
            resources.entries[key]['data'] = dialog_data(row)
        elif relative.endswith('winver.exe'):
            string_replace(resources, 101, 'Windows', config['about_application'])
        elif relative == 'explorer.exe':
            string_replace(resources, 7021, '&Help and Support', config['start_menu_help'])
            key = (4, 204, 1033)
            old = '&Help and Support'
            needle = old.encode('utf-16-le') + b'\0\0'
            if resources.entries[key]['data'].count(needle) != 1:
                raise ValueError('unrecognized classic Start menu help item')
            # Equal-length padding preserves MENUEX item alignment and every command ID.
            replacement = config['start_menu_help'].ljust(len(old)).encode('utf-16-le') + b'\0\0'
            resources.entries[key]['data'] = resources.entries[key]['data'].replace(needle, replacement)
        elif relative.endswith('shell32.dll'):
            string_replace(resources, 12709, '&Help and Support', config['start_menu_help'])
        else:
            key = ('UIFILE', 1000, 1033)
            data = resources.entries[key]['data'].decode('ascii')
            anchor = '<element id=atom(toppanel) sheet=styleref(toppanelss) layout=borderlayout() layoutpos=top height=80rp>'
            if data.count(anchor) != 1 or (6, 251, 1033) in resources.entries:
                raise ValueError('unrecognized login header or private string ID collision')
            label = '\r\n        <element id=atom(XP25Brand) layoutpos=client contentalign=middlecenter content=rcstr(4000) fontsize=12pt foreground=white fontface=rcstr(1)/>'
            resources.entries[key]['data'] = data.replace(anchor, anchor + label).encode('ascii')
            resources.entries[(6, 251, 1033)] = {'data': string_data([config['login_header']] + [''] * 15), 'codepage': 1252, 'reserved': 0}
        changed = [key for key in resources.entries if key not in original or resources.entries[key] != original[key]]
        if any(key[0] == 16 for key in changed):
            raise ValueError('VERSIONINFO must remain byte-identical')
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        result = resources.write(target)
        manifests[relative] = {'original_sha256': sha(path.read_bytes()), **result,
            'changed_resources': [list(key) for key in changed],
            'all_other_resource_payloads_preserved': all(resources.entries[key] == value for key, value in original.items() if key not in changed),
            'versioninfo_preserved': all(resources.entries[key] == value for key, value in original.items() if key[0] == 16),
            'compatibility_identity_changes': [], 'registry_changes': []}
    manifest = {'command': [sys.executable, *sys.argv], 'config': config, 'config_sha256': sha(args.config.read_bytes()),
                'inputs': str(source), 'components': manifests,
                'scope': 'Visible en-US resource labels only; no kernel/code/API/version/product/licensing modifications.',
                'limitations': ['Modified UI files do not retain any original Authenticode validity; signed-file trust behavior must not be claimed unchanged.',
                    'Localization beyond the provided en-US/CP1252 resources is not validated.',
                    'Runtime rendering, clipping, WFP retention and application compatibility require guest tests.']}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({key: {'changed_resources': row['changed_resources'], 'mode': row['mode']} for key, row in manifests.items()}))


if __name__ == '__main__':
    main()
