"""The builder's component registry (components.json): which recipe rebuilds an installed binary, where its
sources are, and how XP25's own changes to Microsoft reference files are applied.

A Microsoft file's *effective* source is the reference file (Source/XPSP1/NT, never modified) plus XP25's own
change to it, if any: what the installed binary was actually built from. Investigations read and edit the
effective source; build media carry the reference file (checked against the build VM's copy), the effective
file (control build) and the job's file (candidate build)."""
import ast
import json
from pathlib import Path

NT_PREFIX = 'Source/XPSP1/NT/'


def load():
    return json.loads((Path(__file__).parent / 'components.json').read_text())


def component(name, table=None):
    table = table or load()
    return dict(table['binaries'].get((name or '').lower(), table['default']), name=name)


def recipe_of_file(rel, table=None):
    """The recipe whose sources contain the repository path rel (longest prefix), or None."""
    table = table or load()
    rel = rel.replace('\\', '/')
    best = None
    for name, recipe in table['recipes'].items():
        for source in recipe['sources']:
            prefix = source.rstrip('/') + '/'
            if rel.startswith(prefix) and (best is None or len(prefix) > best[1]):
                best = (name, len(prefix))
    return best[0] if best else None


def binaries_of(recipe, table=None):
    table = table or load()
    return {name: info for name, info in table['binaries'].items() if info.get('recipe') == recipe}


def editable_nt_prefixes(table=None):
    """NT-relative directories that a recipe can rebuild (an investigation may change files only there)."""
    table = table or load()
    return tuple(source[len(NT_PREFIX):].rstrip('/') + '/' for recipe in table['recipes'].values() if recipe['kind'] == 'nt'
                 for source in recipe['sources'])


# ---- XP25's own changes to Microsoft reference files ----
def kernel_exports(script_text):
    """EXPORTS of build/prepare_kernel_exports.py ({export: line it is inserted after}), read without running it."""
    for node in ast.parse(script_text).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'EXPORTS' for t in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError('no EXPORTS in the kernel export script')


def apply_exports(text, exports):
    """The insertion build/prepare_kernel_exports.py makes in ntoskrnl.src (kept identical; a host test compares)."""
    for name, anchor in exports.items():
        if ('    ' + name + '\n') in text or text.count(anchor) != 1:
            raise ValueError('unexpected export list state for ' + name)
        text = text.replace(anchor, anchor + '    ' + name + '\n')
    return text


def effective_nt_text(nt_rel, reference_text, repository, table=None):
    """The effective source of a Microsoft file: reference_text plus XP25's change to it, taken from the
    repository (a job workspace at the baseline commit)."""
    table = table or load()
    for recipe in table['recipes'].values():
        script = recipe.get('xp25_changes', {}).get(nt_rel)
        if script:
            if script != 'build/prepare_kernel_exports.py':
                raise ValueError('unknown kind of XP25 change: ' + script)
            return apply_exports(reference_text, kernel_exports((Path(repository) / script).read_text()))
    return reference_text


def xp25_changed_files(table=None):
    table = table or load()
    return {f: script for recipe in table['recipes'].values() for f, script in recipe.get('xp25_changes', {}).items()}
