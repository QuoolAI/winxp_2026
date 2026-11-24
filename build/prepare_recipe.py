#!/usr/bin/env python3
"""Prepare native NT build media for one MerlinAI Builder recipe (components/merlin/builder/merlin_builder/
components.json), as an ISO for the private build VM, with a manifest that vm/native_recipe_build.py follows.

  xp25 recipes (merlin, winlogon, ai, security): the component's tree from --source, made by the
      component's own media script (build/prepare_<x>.py make_tree) and built by its own driver
      (build/native-<x>-build.cmd);
  nt recipes (nt-kernel): the changed reference files, each as the reference copy (checked against the
      build VM's C:\\nt), XP25's effective source (control build) and the job's file (candidate build),
      built by build/native-nt-recipe-build.cmd.

The reference tree is only read; nothing is written under Source/.

usage: prepare_recipe.py --recipe NAME --output .work/<fresh> [--source TREE]
                         [--reference .../Source/XPSP1/NT --nt-changes DIR]
  --source      the repository (a job workspace); defaults to this one
  --nt-changes  for nt recipes: the job's changed files, laid out as below Source/XPSP1/NT"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
sys.path.insert(0, str(ROOT / 'components/merlin/builder'))
from merlin_builder import recipes  # noqa: E402

XP25 = {  # recipe: (media script, build driver, COM1 marker prefix, ISO volume)
    'merlin': ('prepare_merlin', 'native-merlin-build.cmd', 'XP25_MERLIN_BUILD', 'XP25MERLIN'),
    'winlogon': ('prepare_winlogon', 'native-winlogon-build.cmd', 'XP25_WINLOGON_BUILD', 'XP25WL'),
    'ai': ('prepare_ai', 'native-ai-build.cmd', 'XP25_AI_BUILD', 'XP25AI'),
    'security': ('prepare_security', 'native-security-build.cmd', 'XP25_SECURITY_BUILD', 'XP25SEC'),
}
COMPILED = ('.c', '.h', '.rc', '.def', '.idl', '.mc', '.asm', '.inc', '.src')


def crlf(data):
    return data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def xp25_media(name, source, out, media, table):
    script, driver, marker, volume = XP25[name]
    module = __import__(script)
    extra = module.make_tree(source, out, media) or {}
    (media / 'build.cmd').write_bytes(crlf((ROOT / 'build' / driver).read_bytes()))
    tree = table['recipes'][name]['tree']
    outputs = [{'binary': b, 'target': info['target'], 'guest': '/nt/xp25/%s/%s' % (tree, info['output'])}
               for b, info in sorted(recipes.binaries_of(name, table).items())]
    compiled = sorted(str(f.relative_to(media)) for f in (media / tree).rglob('*')
                      if f.is_file() and (f.suffix.lower() in COMPILED or f.name in ('sources', 'dirs', 'makefile')))
    return {'marker': marker, 'volume': volume, 'tree': tree, 'outputs': outputs,
            # Each compiled file must be found unchanged at /nt/xp25/<media path> after the build.
            'compiled': {f: '/nt/xp25/' + f for f in compiled}, 'wrappers': extra}


def nt_media(name, source, reference, changes, media, table):
    recipe = table['recipes'][name]
    files = sorted(str(f.relative_to(changes)) for f in changes.rglob('*') if f.is_file())
    editable = recipes.editable_nt_prefixes(table)
    rows = {}
    for nt in files:
        if not any(nt.startswith(prefix) for prefix in editable) or not recipe_owns(recipe, nt):
            raise SystemExit('%s is not rebuilt by recipe %s' % (nt, name))
        original = (reference / nt).read_bytes()
        effective = recipes.effective_nt_text(nt, original.decode('latin-1'), source, table).encode('latin-1')
        candidate = (changes / nt).read_bytes()
        for stage, data in (('original', original), ('control', effective), ('candidate', candidate)):
            target = media / stage / nt
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        rows[nt] = {'reference': digest(original), 'control': digest(effective), 'candidate': digest(candidate)}
    # XP25's own changes are part of every build, also when the job did not touch those files.
    for nt in recipes.xp25_changed_files(table):
        if recipe_owns(recipe, nt) and nt not in rows:
            original = (reference / nt).read_bytes()
            effective = recipes.effective_nt_text(nt, original.decode('latin-1'), source, table).encode('latin-1')
            for stage, data in (('original', original), ('control', effective), ('candidate', effective)):
                target = media / stage / nt
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            rows[nt] = {'reference': digest(original), 'control': digest(effective), 'candidate': digest(effective)}
    link = recipe['link_dir']
    dirs = sorted({str(Path(nt).parent) for nt in rows} - {link}) + [link]
    outputs = []
    for b, info in sorted(recipes.binaries_of(name, table).items()):
        for variant, built in sorted(info.get('variants', {}).items()):
            stem = built.rsplit('.', 1)[0]
            for suffix in ('.exe', '.pdb', '.map') if built.endswith('.exe') else (built[built.rindex('.'):],):
                outputs.append(stem + suffix)
    win = lambda paths: crlf(('\n'.join(p.replace('/', '\\') for p in paths) + '\n').encode())
    (media / 'files.txt').write_bytes(win(sorted(rows)))
    (media / 'dirs.txt').write_bytes(win(dirs))
    (media / 'outputs.txt').write_bytes(win(outputs))
    (media / 'build.cmd').write_bytes(crlf((ROOT / 'build/native-nt-recipe-build.cmd').read_bytes()))
    collected = [{'binary': b, 'variant': v, 'file': Path(built).name, 'target': info['target']}
                 for b, info in sorted(recipes.binaries_of(name, table).items()) for v, built in sorted(info['variants'].items())]
    return {'marker': 'XP25_RECIPE_BUILD', 'volume': 'XP25NT', 'files': rows, 'dirs': dirs, 'outputs': collected,
            'collect': ['control/' + Path(o).name for o in outputs] + ['candidate/' + Path(o).name for o in outputs]}


def recipe_owns(recipe, nt):
    return any((recipes.NT_PREFIX + nt).startswith(s.rstrip('/') + '/') for s in recipe['sources'])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--recipe', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--nt-changes', type=Path)
    args = parser.parse_args()
    out, source = args.output.resolve(), args.source.resolve()
    if not out.is_relative_to(ROOT / '.work') and not out.is_relative_to(source):
        parser.error('private .work/ output required')
    for tree in (source, args.reference):
        if tree and (tree / 'Source').exists() and out.is_relative_to(tree / 'Source'):
            parser.error('output inside Source/ refused')
    table = recipes.load()
    if args.recipe not in table['recipes']:
        parser.error('unknown recipe ' + args.recipe)
    kind = table['recipes'][args.recipe]['kind']
    out.mkdir(parents=True, exist_ok=False)
    media = out / 'media'
    media.mkdir()
    if kind == 'xp25':
        record = xp25_media(args.recipe, source, out, media, table)
    else:
        if not args.reference or not args.nt_changes:
            parser.error('an nt recipe needs --reference and --nt-changes')
        reference = args.reference.resolve()
        if out.is_relative_to(reference):
            parser.error('output inside the reference tree refused')
        record = nt_media(args.recipe, source, reference, args.nt_changes.resolve(), media, table)
    iso = out / ('native-%s.iso' % args.recipe)
    command = ['xorriso', '-as', 'mkisofs', '-quiet', '-iso-level', '3', '-J', '-R', '-V', record.pop('volume'), '-o', str(iso), str(media)]
    subprocess.run(command, check=True)
    files = {str(f.relative_to(media)): digest(f.read_bytes()) for f in sorted(media.rglob('*')) if f.is_file()}
    git = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'], capture_output=True, text=True)
    manifest = dict(record, recipe=args.recipe, kind=kind, command=command, iso=iso.name, iso_sha256=digest(iso.read_bytes()),
                    source=str(source), source_commit=git.stdout.strip() or None, media_files=files,
                    scope='%s sources only; the reference tree is read, never written.' % args.recipe)
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(iso)


if __name__ == '__main__':
    main()
