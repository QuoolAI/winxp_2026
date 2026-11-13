#!/usr/bin/env python3
"""Source-level fixes for historical Windows XP vulnerabilities (Milestone 8.2).

The reference tree is never written. Each fix is a unified diff in components/cve/,
listed in components/cve/patches.json together with the SHA-256 of every original
file it changes. This module copies those originals out of Source/XPSP1/NT, checks
their hashes, and applies the diffs exactly: no fuzz, no offsets. A patch either
applies to the audited source or the run stops.

  cve_source.py check                                    every patch applies to the reference tree
  cve_source.py stage --output DIR [--patch ID ...]      DIR/original, DIR/patched and DIR/manifest.json

The host regression tests (tests/test_cve.py) compile functions taken from both
trees with extract_function(), so a test always exercises the real source text."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'Source/XPSP1/NT'
PATCHES = ROOT / 'components/cve'
HUNK = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')


def manifest():
    return json.loads((PATCHES / 'patches.json').read_text())


def patch_entries(ids=None):
    entries = manifest()['patches']
    known = {e['id'] for e in entries}
    unknown = sorted(set(ids or ()) - known)
    if unknown:
        raise SystemExit('unknown patch: ' + ', '.join(unknown))
    return [e for e in entries if not ids or e['id'] in ids]


def parse_patch(text):
    """{relative path: [(old_start, old_lines, new_lines)]} from a unified diff."""
    files, current, hunk = {}, None, None
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    for line in lines:
        if line.startswith('--- '):
            current, hunk = None, None
            continue
        if line.startswith('+++ '):
            path = line[4:].split('\t')[0]
            if not path.startswith('b/'):
                raise ValueError('patch paths must be b/<path relative to Source/XPSP1/NT>: ' + path)
            current = files.setdefault(path[2:], [])
            continue
        match = HUNK.match(line)
        if match:
            hunk = (int(match.group(1)), [], [])
            current.append(hunk)
            continue
        if hunk is None or current is None:
            if line.startswith('diff ') or not line.strip():
                continue
            raise ValueError('text outside a hunk: ' + line)
        if line == '\\ No newline at end of file':
            continue
        tag, body = line[:1], line[1:]
        if tag == ' ':
            hunk[1].append(body)
            hunk[2].append(body)
        elif tag == '-':
            hunk[1].append(body)
        elif tag == '+':
            hunk[2].append(body)
        else:
            raise ValueError('bad hunk line: ' + line)
    return files


def apply_hunks(text, hunks, label):
    """Apply hunks to text exactly where they say; any mismatch is an error."""
    lines = text.split('\n')
    offset = 0
    for start, old, new in hunks:
        at = start - 1 + offset if old else start + offset
        if lines[at:at + len(old)] != old:
            raise SystemExit('%s: hunk at line %d does not match the source' % (label, start))
        lines[at:at + len(old)] = new
        offset += len(new) - len(old)
    return '\n'.join(lines)


def sha256_text(text):
    return hashlib.sha256(text.encode('latin-1')).hexdigest()


def patched_files(ids=None):
    """{path: (original text, patched text, [patch ids])} for the selected patches, in manifest order."""
    result = {}
    for entry in patch_entries(ids):
        diff = parse_patch((PATCHES / entry['patch']).read_text())
        if set(diff) != set(entry['files']):
            raise SystemExit('%s: patch files %s differ from the manifest %s' % (entry['id'], sorted(diff), sorted(entry['files'])))
        for path, hunks in diff.items():
            if path not in result:
                original = (SOURCE / path).read_bytes().decode('latin-1')
                if sha256_text(original) != entry['files'][path]:
                    raise SystemExit('%s: %s is not the audited original' % (entry['id'], path))
                result[path] = [original, original, []]
            elif sha256_text(result[path][0]) != entry['files'][path]:
                raise SystemExit('%s: %s recorded with a different original hash' % (entry['id'], path))
            result[path][1] = apply_hunks(result[path][1], hunks, '%s %s' % (entry['id'], path))
            result[path][2].append(entry['id'])
    return {path: tuple(value) for path, value in result.items()}


def extract_function(text, name):
    """The definition of function `name` in NT style: the return type lines above
    `name(` at the start of a line, through the closing brace in column 0."""
    lines = text.split('\n')
    start = None
    pattern = re.compile(r'^(?:[A-Za-z_][\w \*]*\s+)?' + re.escape(name) + r'\s*\(')
    for index, line in enumerate(lines):
        if pattern.match(line) and not line.rstrip().endswith(';'):
            # a prototype ends with ');'; a definition reaches '{' first, possibly after
            # a /*++ ... --*/ description block between the parameters and the body
            in_comment = False
            for probe in lines[index:index + 400]:
                code = probe
                if in_comment:
                    if '*/' not in code:
                        continue
                    code, in_comment = code.split('*/', 1)[1], False
                if '/*' in code and '*/' not in code.split('/*', 1)[1]:
                    code, in_comment = code.split('/*', 1)[0], True
                code = re.sub(r'/\*.*?\*/', '', code).split('//')[0].rstrip()
                if code.startswith('{'):
                    start = index
                    break
                if code.endswith(';'):
                    break
            if start is not None:
                break
    if start is None:
        raise KeyError(name)
    first = start
    while first > 0 and lines[first - 1].strip() and not lines[first - 1].rstrip().endswith(('}', '*/', ';')) \
            and not lines[first - 1].lstrip().startswith(('//', '#')):
        first -= 1
    end = start
    while not (lines[end].startswith('}')):
        end += 1
    return '\n'.join(lines[first:end + 1]) + '\n'


def stage(output, ids=None):
    output = Path(output).resolve()
    if not output.is_relative_to(ROOT / '.work'):
        raise SystemExit('output must be under .work/')
    if output.exists():
        raise SystemExit('refusing to overwrite ' + str(output))
    files = patched_files(ids)
    record = {'source_root': str(SOURCE.relative_to(ROOT)), 'patches': [e['id'] for e in patch_entries(ids)], 'files': {}}
    for path, (original, patched, applied) in sorted(files.items()):
        for tree, text in (('original', original), ('patched', patched)):
            target = output / tree / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(text.encode('latin-1'))
        record['files'][path] = {'original_sha256': sha256_text(original), 'patched_sha256': sha256_text(patched),
                                 'patches': applied}
    (output / 'manifest.json').write_text(json.dumps(record, indent=1) + '\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('check')
    staging = sub.add_parser('stage')
    staging.add_argument('--output', required=True)
    staging.add_argument('--patch', action='append')
    args = parser.parse_args()
    if args.command == 'check':
        files = patched_files()
        for path, (original, patched, applied) in sorted(files.items()):
            print('%s %s -> %s (%s)' % (path, sha256_text(original)[:12], sha256_text(patched)[:12], ', '.join(applied)))
    else:
        print(json.dumps(stage(args.output, args.patch), indent=1))


if __name__ == '__main__':
    main()
