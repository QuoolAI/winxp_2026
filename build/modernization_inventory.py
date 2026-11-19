#!/usr/bin/env python3
"""Milestone 8.4 repository inventory: what XP25 builds from its own sources, how the pieces depend
on each other, and per-file/per-function facts that guide the code-quality audit. It reads only
tracked files outside Source/ (Source/ is the immutable reference tree and is not scanned). Nothing
is compiled or executed. The C scan is a lexical approximation (comments and literals stripped,
functions found at brace depth 0); it locates code for review, it does not prove anything.

usage: modernization_inventory.py --output .work/<fresh>
writes inventory.json, graph.dot, graph.mmd, duplicates.json, summary.md"""
import argparse
import ast
import collections
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]

CATEGORIES = {
    'alloc': r'malloc|calloc|realloc|free|HeapAlloc|HeapReAlloc|HeapFree|LocalAlloc|LocalReAlloc|LocalFree|GlobalAlloc|'
             r'GlobalFree|VirtualAlloc|VirtualFree|CoTaskMemAlloc|CoTaskMemFree|SysAllocString\w*|SysFreeString|'
             r'xp25_alloc|xp25_calloc|xp25_realloc|xp25_free|xp25_strdup|ExAllocatePool\w*|ExFreePool\w*',
    'unbounded_string': r'strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat|swprintf|wsprintfA|wsprintfW|wsprintf|wvsprintf\w*|'
                        r'lstrcpyA|lstrcpyW|lstrcpy|lstrcatA|lstrcatW|lstrcat|gets',
    'truncating_string': r'strncpy|wcsncpy|_snprintf|_snwprintf|_vsnprintf|_vsnwprintf|lstrcpynA|lstrcpynW|lstrcpyn|'
                         r'StringCch\w+|StringCb\w+',
    'sync': r'InitializeCriticalSection\w*|EnterCriticalSection|LeaveCriticalSection|DeleteCriticalSection|'
            r'Interlocked\w+|WaitForSingleObject\w*|WaitForMultipleObjects\w*|MsgWaitForMultipleObjects\w*|'
            r'CreateMutex\w*|CreateEvent\w*|CreateSemaphore\w*|SetEvent|ResetEvent|ReleaseMutex|ReleaseSemaphore',
    'threads': r'CreateThread|_beginthreadex|_beginthread|ExitThread|TerminateThread|QueueUserWorkItem|'
               r'CreateTimerQueueTimer|SetTimer|Sleep|SleepEx',
    'error': r'GetLastError|SetLastError|NT_SUCCESS|FAILED|SUCCEEDED|HRESULT_FROM_WIN32|RtlNtStatusToDosError',
    'privilege': r'AdjustTokenPrivileges|ImpersonateNamedPipeClient|ImpersonateLoggedOnUser|RevertToSelf|'
                 r'CreateProcessAsUser\w*|CreateProcessWithLogon\w*|LogonUser\w*|OpenProcessToken|OpenThreadToken|'
                 r'DuplicateTokenEx|SetTokenInformation|CreateRestrictedToken|SetSecurityInfo|SetNamedSecurityInfo\w*|'
                 r'SetFileSecurity\w*|RegSetKeySecurity|CreateService\w*|ChangeServiceConfig\w*|ControlService|'
                 r'StartService\w*|DeleteService|OpenSCManager\w*|SetKernelObjectSecurity|LsaOpenPolicy|LsaAddAccountRights',
    'process': r'CreateProcess\w*|ShellExecute\w*|WinExec|TerminateProcess|OpenProcess|CreateRemoteThread|'
               r'WriteProcessMemory|ReadProcessMemory|LoadLibrary\w*|GetProcAddress',
    'registry_write': r'RegSetValue\w*|RegCreateKey\w*|RegDeleteKey\w*|RegDeleteValue\w*',
    'file_write': r'CreateFile\w*|WriteFile|MoveFile\w*|DeleteFile\w*|CopyFile\w*|CreateDirectory\w*|RemoveDirectory\w*',
    'network': r'socket|connect|bind|listen|accept|recv|send|WSAStartup|InternetOpen\w*|HttpSendRequest\w*|'
               r'WinHttp\w+|CreateNamedPipe\w*|ConnectNamedPipe|CallNamedPipe\w*|TransactNamedPipe',
}
CATEGORY_RES = {k: re.compile(r'(?<![\w.>])(' + v + r')\s*\(') for k, v in CATEGORIES.items()}
BRANCH = re.compile(r'\b(if|for|while|case|catch)\b|&&|\|\||\?')
KEYWORDS = {'if', 'for', 'while', 'switch', 'return', 'sizeof', 'do', 'else', 'case', 'goto', 'typedef', 'struct',
            'union', 'enum', '__declspec', '__try', '__except', '__finally'}


def tracked():
    out = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z'])
    return sorted(p for p in out.decode().split('\0') if p and not p.startswith('Source/'))


def sha256(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def strip_c(text):
    """Comments and string/char literals become spaces (newlines kept), so line numbers stay valid."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith('/*', i):
            j = text.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r'[^\n]', ' ', text[i:j]))
            i = j
        elif text.startswith('//', i):
            j = text.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
        elif c in '"\'':
            j = i + 1
            while j < n and text[j] != c and text[j] != '\n':
                j += 2 if text[j] == '\\' else 1
            j = min(j + 1, n)
            out.append(c + re.sub(r'[^\n]', ' ', text[i + 1:j - 1]) + c if j - i >= 2 else text[i:j])
            i = j
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def without_preprocessor(code):
    lines = code.split('\n')
    result, cont = [], False
    for line in lines:
        is_pp = cont or line.lstrip().startswith('#')
        cont = is_pp and line.rstrip().endswith('\\')
        result.append(' ' * len(line) if is_pp else line)
    return '\n'.join(result)


def scan_c(path):
    raw = (ROOT / path).read_text(encoding='latin-1')
    code = without_preprocessor(strip_c(raw))
    includes = re.findall(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', raw, re.M)
    functions, globals_, depth, start = [], [], 0, None
    stmt_start = 0
    i = 0
    line_of = lambda pos: code.count('\n', 0, pos) + 1
    while i < len(code):
        c = code[i]
        if c == '{':
            if depth == 0:
                head = code[stmt_start:i]
                m = re.search(r'([A-Za-z_]\w*)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*$', head.strip())
                if m and m.group(1) not in KEYWORDS and not re.search(r'=\s*$', head):
                    start = (m.group(1), i, stmt_start + head.rfind(m.group(1)))
                else:
                    start = None
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                if start:
                    name, open_pos, name_pos = start
                    body = code[open_pos:i + 1]
                    nest, deepest = 0, 0
                    for ch in body:
                        if ch == '{':
                            nest += 1
                            deepest = max(deepest, nest)
                        elif ch == '}':
                            nest -= 1
                    functions.append({
                        'name': name, 'line': line_of(name_pos),
                        'lines': body.count('\n') + 1,
                        'complexity': 1 + len(BRANCH.findall(body)),
                        'max_nesting': deepest - 1,
                        'static': bool(re.search(r'\bstatic\b', head)),
                        'gotos': len(re.findall(r'\bgoto\b', body)),
                    })
                start = None
                stmt_start = i + 1
        elif c == ';' and depth == 0:
            decl = ' '.join(code[stmt_start:i].split())
            stmt_start = i + 1
            if decl and not re.match(r'(typedef|extern)\b', decl) and not re.search(r'^[^=]*\)\s*$', decl) \
                    and not re.match(r'(struct|union|enum)\s+\w+\s*\{?\s*$', decl) and not re.search(r'\)\s*;?$', decl.split('=')[0]):
                name = re.findall(r'([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*(?:=|$)', decl.split('=')[0] + '=')
                globals_.append({'decl': decl[:160], 'name': name[-1] if name else '?', 'line': line_of(i),
                                 'static': decl.startswith('static') or ' static ' in decl,
                                 'const': bool(re.search(r'\bconst\b', decl.split('=')[0])) and '*' not in decl.split('=')[0].split('const')[-1]})
        i += 1
    calls = {k: collections.Counter(m.group(1) for m in r.finditer(code)) for k, r in CATEGORY_RES.items()}
    return {
        'lines': raw.count('\n') + 1,
        'code_lines': sum(1 for l in code.split('\n') if l.strip()),
        'includes': includes,
        'functions': functions,
        'globals': globals_,
        'calls': {k: dict(v) for k, v in calls.items() if v},
        'norm_lines': [(n + 1, ' '.join(l.split())) for n, l in enumerate(code.split('\n')) if len(l.strip()) > 3 and l.strip() not in ('{', '}', '};')],
    }


def scan_py(path):
    text = (ROOT / path).read_text(encoding='utf-8', errors='replace')
    info = {'lines': text.count('\n') + 1, 'functions': [], 'imports': []}
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        info['syntax_error'] = str(e)
        return info
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            branches = sum(isinstance(n, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.BoolOp, ast.IfExp,
                                          ast.ExceptHandler, ast.comprehension)) for n in ast.walk(node))
            info['functions'].append({'name': node.name, 'line': node.lineno,
                                      'lines': (node.end_lineno or node.lineno) - node.lineno + 1,
                                      'complexity': 1 + branches})
        elif isinstance(node, ast.Import):
            info['imports'] += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            info['imports'].append(node.module)
    return info


def parse_sources(path):
    text = (ROOT / path).read_text(encoding='latin-1').replace('\\\n', ' ')
    macros = dict(re.findall(r'^\s*([A-Z_]+)\s*=\s*(.*?)\s*$', text, re.M))
    base = (ROOT / path).parent
    sources = []
    for s in macros.get('SOURCES', '').split():
        p = (base / s.replace('\\', '/')).resolve()
        sources.append(str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else s)
    libs = []
    for key in ('TARGETLIBS', 'UMLIBS', 'LINKLIBS'):
        for lib in macros.get(key, '').split():
            libs.append(lib.replace('$(SDK_LIB_PATH)\\', '').replace('$(O)\\', '').replace('\\', '/'))
    return {'sources_file': path, 'target': macros.get('TARGETNAME'), 'type': macros.get('TARGETTYPE'),
            'umtype': macros.get('UMTYPE'), 'warnings': macros.get('MSC_WARNING_LEVEL'),
            'defines': macros.get('C_DEFINES'), 'gs': 'BUFFER_OVERFLOW_CHECKS' in macros,
            'entry': macros.get('UMENTRY'), 'sources': sources, 'libs': libs}


def duplicates(c_files, window=6):
    seen = collections.defaultdict(list)
    for path, info in c_files.items():
        lines = info['norm_lines']
        for k in range(len(lines) - window + 1):
            chunk = '\n'.join(t for _, t in lines[k:k + window])
            if len(chunk) < 160:
                continue
            seen[hashlib.sha1(chunk.encode()).hexdigest()].append((path, lines[k][0], lines[k + window - 1][0]))
    clusters = {}
    for key, places in seen.items():
        files = {p for p, _, _ in places}
        if len(places) > 1:
            sig = tuple(sorted(files))
            clusters.setdefault(sig, []).append(places)
    merged = []
    for files, groups in clusters.items():
        merged.append({'files': list(files), 'windows': len(groups),
                       'first': [{'file': p, 'from': a, 'to': b} for p, a, b in groups[0]]})
    merged.sort(key=lambda d: -d['windows'])
    return merged


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        parser.error('private .work/ output required')
    out.mkdir(parents=True, exist_ok=False)
    files = tracked()
    head = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    manifest = {p: sha256(p) for p in files if (ROOT / p).is_file()}
    targets = [parse_sources(p) for p in files if p.startswith('components/') and p.endswith('/sources')]
    c_files = {p: scan_c(p) for p in files if p.endswith(('.c', '.h')) and (ROOT / p).is_file()}
    py_files = {p: scan_py(p) for p in files if p.endswith('.py') and (ROOT / p).is_file()}
    built_by = collections.defaultdict(list)
    for t in targets:
        for s in t['sources']:
            built_by[s].append(t['target'])
    scripts = {p: (ROOT / p).read_text(errors='replace') for p in files if p.startswith('build/') and p.endswith('.py')}
    for p in c_files:
        if p.endswith('.c') and not built_by.get(p):
            refs = [s for s, text in scripts.items() if Path(p).name in text or Path(p).stem in text.split()]
            if refs:
                built_by[p] = ['host/mingw: ' + ', '.join(sorted(refs))]
    # Graph: native targets -> system import libraries, XP25 libraries and shared source directories.
    edges = set()
    for t in targets:
        for lib in t['libs']:
            edges.add((t['target'], Path(lib).stem.lower() if '..' not in lib else Path(lib).stem + ' (XP25)'))
        home = str(Path(t['sources_file']).parent)
        for s in t['sources']:
            parts = Path(s).parts
            if len(parts) > 2 and parts[0] == 'components' and not s.startswith(home.rsplit('/', 1)[0]) and s.endswith('.c'):
                edges.add((t['target'], 'src:' + '/'.join(parts[1:3])))
    for p, info in c_files.items():
        if not p.startswith('components/'):
            continue
        comp = Path(p).parts[1]
        for inc in info['includes']:
            target = (ROOT / p).parent.joinpath(inc).resolve()
            if target.is_relative_to(ROOT / 'components') and target.relative_to(ROOT / 'components').parts[0] != comp:
                edges.add(('comp:' + comp, 'comp:' + target.relative_to(ROOT / 'components').parts[0]))
    dot = ['digraph xp25 {', '  rankdir=LR; node [shape=box, fontsize=10];']
    dot += ['  "%s" -> "%s";' % e for e in sorted(edges)]
    dot.append('}')
    (out / 'graph.dot').write_text('\n'.join(dot) + '\n')
    ids = {}
    node = lambda n: ids.setdefault(n, 'n%d' % len(ids))
    mmd = ['graph LR'] + ['  %s["%s"] --> %s["%s"]' % (node(a), a, node(b), b) for a, b in sorted(edges)]
    (out / 'graph.mmd').write_text('\n'.join(mmd) + '\n')
    dups = duplicates({p: i for p, i in c_files.items() if p.endswith('.c')})
    (out / 'duplicates.json').write_text(json.dumps(dups, indent=1) + '\n')
    for info in c_files.values():
        info.pop('norm_lines')
    inventory = {'head': head, 'tracked_files_outside_source': len(manifest), 'manifest': manifest,
                 'manifest_sha256': hashlib.sha256(''.join('%s  %s\n' % (h, p) for p, h in sorted(manifest.items())).encode()).hexdigest(),
                 'native_targets': targets, 'built_by': dict(built_by), 'c_files': c_files, 'py_files': py_files,
                 'edges': sorted(edges)}
    (out / 'inventory.json').write_text(json.dumps(inventory, indent=1) + '\n')
    # Summary for the audit document.
    s = ['# Inventory summary', '', 'HEAD `%s`; %d tracked files outside `Source/`; manifest SHA-256 `%s`.' %
         (head, len(manifest), inventory['manifest_sha256']), '']
    by_dir = collections.Counter()
    for p in manifest:
        parts = p.split('/')
        by_dir['/'.join(parts[:2]) if parts[0] == 'components' and len(parts) > 2 else parts[0] if len(parts) > 1 else '(root)'] += 1
    s += ['| Area | Files |', '| --- | --- |'] + ['| `%s` | %d |' % kv for kv in sorted(by_dir.items())] + ['']
    s += ['## Native targets', '', '| Target | Type | Sources | Libraries | /GS | Warnings |', '| --- | --- | --- | --- | --- | --- |']
    for t in targets:
        s.append('| %s | %s | %d | %s | %s | `%s` |' % (t['target'], t['type'], len(t['sources']),
                 ', '.join(Path(l).stem for l in t['libs']), 'yes' if t['gs'] else 'no', t['warnings']))
    s += ['', '## Components (C)', '', '| Component | Files | Lines | Functions | CC>15 | >150 lines | Globals (non-const) | Unbounded string calls | Alloc calls | Sync calls | Thread calls |',
          '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |']
    comp = collections.defaultdict(lambda: collections.Counter())
    for p, info in c_files.items():
        key = '/'.join(p.split('/')[:2]) if p.startswith('components/') else p.split('/')[0] + ('/guest' if '/guest/' in p else '')
        c = comp[key]
        c['files'] += 1
        c['lines'] += info['lines']
        c['functions'] += len(info['functions'])
        c['cc15'] += sum(f['complexity'] > 15 for f in info['functions'])
        c['long'] += sum(f['lines'] > 150 for f in info['functions'])
        c['globals'] += sum(not g['const'] for g in info['globals'])
        for cat, key2 in (('unbounded_string', 'unsafe'), ('alloc', 'alloc'), ('sync', 'sync'), ('threads', 'threads')):
            c[key2] += sum(info['calls'].get(cat, {}).values())
    for key, c in sorted(comp.items()):
        s.append('| `%s` | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d |' % (key, c['files'], c['lines'], c['functions'], c['cc15'], c['long'],
                 c['globals'], c['unsafe'], c['alloc'], c['sync'], c['threads']))
    s += ['', '## Most complex C functions', '', '| Function | File | Lines | Complexity | Nesting |', '| --- | --- | --- | --- | --- |']
    allf = [(f, p) for p, i in c_files.items() for f in i['functions']]
    for f, p in sorted(allf, key=lambda x: -x[0]['complexity'])[:30]:
        s.append('| `%s` | `%s:%d` | %d | %d | %d |' % (f['name'], p, f['line'], f['lines'], f['complexity'], f['max_nesting']))
    s += ['', '## Duplicate code (6-line windows shared between places)', '', '| Files | Shared windows | First match |', '| --- | --- | --- |']
    for d in dups[:25]:
        s.append('| %s | %d | %s |' % (', '.join('`%s`' % f for f in d['files']), d['windows'],
                 '; '.join('%s:%d-%d' % (x['file'], x['from'], x['to']) for x in d['first'][:3])))
    s += ['', '## Python tooling', '', '| Area | Files | Lines | Functions | CC>15 |', '| --- | --- | --- | --- | --- |']
    pyc = collections.defaultdict(collections.Counter)
    for p, info in py_files.items():
        c = pyc[p.split('/')[0]]
        c['files'] += 1
        c['lines'] += info['lines']
        c['functions'] += len(info['functions'])
        c['cc15'] += sum(f['complexity'] > 15 for f in info['functions'])
    for key, c in sorted(pyc.items()):
        s.append('| `%s` | %d | %d | %d | %d |' % (key, c['files'], c['lines'], c['functions'], c['cc15']))
    (out / 'summary.md').write_text('\n'.join(s) + '\n')
    print(json.dumps({'output': str(out), 'files': len(manifest), 'c_files': len(c_files), 'py_files': len(py_files),
                      'targets': len(targets), 'edges': len(edges), 'duplicate_clusters': len(dups)}))


if __name__ == '__main__':
    main()
