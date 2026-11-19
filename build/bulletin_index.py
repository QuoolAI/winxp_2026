#!/usr/bin/env python3
"""Index Microsoft's security bulletins (2002-2014) by the source-built XP25 component they touch.

R-1 uses this to list, for each binary XP25 builds from 5.1.2600.1106 source, the bulletins that
fixed it later for Windows XP. Microsoft's bulletin pages are fetched once into a private .work/
directory (untrusted HTML: it is only parsed here, never executed or rendered) and indexed offline.

  bulletin_index.py fetch --output .work/<fresh>/html       one page per bulletin MS02-001..MS14-085
  bulletin_index.py index HTML_DIR OUT.json                  title, date, CVEs, XP affected, components
  bulletin_index.py report OUT.json                          XP-affected bulletins per component

A bulletin counts as affecting Windows XP when a table row starts with "Windows XP ..." outside its
Non-Affected Software section. Components are matched on the bulletin title and its CVE titles
(and win32k also on the text, since "Windows Kernel" bulletins fixed it too); later bulletins list
their files only in Knowledge Base articles, so a match is a candidate, not proof of the file."""
import argparse
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
YEARS = {2002: 72, 2003: 51, 2004: 45, 2005: 57, 2006: 78, 2007: 69, 2008: 78,
         2009: 74, 2010: 106, 2011: 100, 2012: 83, 2013: 106, 2014: 85}
URL = 'https://learn.microsoft.com/en-us/security-updates/securitybulletins/%d/ms%02d-%03d'
COMPONENTS = {
    'lsasrv.dll': [r'\bLSASS\b', r'Local Security Authority', r'lsasrv'],
    'services.exe': [r'Service Control Manager', r'\bservices\.exe'],
    'ws2_32.dll': [r'\bWinsock\b', r'ws2_32'],
    'win32k.sys': [r'win32k', r'Kernel-Mode Driver'],
    'gdi32.dll/user32.dll': [r'\bGDI\b', r'Graphics Rendering Engine', r'Graphics Device Interface',
                             r'Animated Cursor', r'Metafile', r'gdi32', r'user32'],
    'csrss/winsrv': [r'CSRSS', r'Client/Server Run-?time', r'csrsrv', r'winsrv'],
    'kernel (xp25krnl)': [r'Windows Kernel\b', r'ntoskrnl', r'ntkrnl'],
}


class Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.skip += 1
        if tag in ('br', 'p', 'tr', 'li', 'h1', 'h2', 'h3', 'h4', 'div', 'td', 'th'):
            self.parts.append('\n')

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def page_text(raw):
    parser = Text()
    parser.feed(raw)
    return re.sub(r'[ \t\r\f\v]+', ' ', html.unescape(''.join(parser.parts)))


def fetch(output):
    output = output.resolve()
    if not output.is_relative_to(ROOT / '.work'):
        raise SystemExit('private .work/ output required')
    output.mkdir(parents=True, exist_ok=True)
    log = []
    for year, last in YEARS.items():
        for number in range(1, last + 1):
            name = 'ms%02d-%03d' % (year % 100, number)
            target = output / (name + '.html')
            if target.exists():
                continue
            try:
                with urllib.request.urlopen(URL % (year, year % 100, number), timeout=60) as response:
                    target.write_bytes(response.read())
                log.append([name, 200])
            except Exception as error:      # 404 for unused numbers
                log.append([name, str(error)])
            time.sleep(0.2)
    (output / 'fetch.json').write_text(json.dumps(log, indent=0) + '\n')


def index(directory, out):
    rows = []
    for page in sorted(Path(directory).glob('ms*.html')):
        raw = page.read_text(errors='replace')
        if '<h1' not in raw:
            continue
        text = page_text(raw)
        titles = re.findall(r'\n\s*([^\n]{10,200}\(\d{6,7}\))\s*\n', text)
        published = re.search(r'Published:\s*([A-Za-z]+ \d+, \d{4})', text)
        xp, skip = False, False
        for line in (l.strip() for l in text.split('\n')):
            if line == 'Non-Affected Software':
                skip = True
                continue
            if skip and line.startswith(('Frequently Asked', 'Top of section', 'Vulnerability Information',
                                         'Executive Summary', 'Update FAQ')):
                skip = False
            if not skip and re.match(r'Windows XP (Service Pack|Professional|Home|Media|Tablet|64-Bit|x64)', line):
                xp = True
        cve_titles = sorted(set(m.strip() for m in re.findall(r'\n\s*([^\n|]{6,120}?)\s*-\s*\[?(?:CVE|CAN)-\d{4}-\d{4,5}', text)))
        named = (titles[0] if titles else '') + '\n' + '\n'.join(cve_titles)
        components = [c for c, patterns in COMPONENTS.items() if any(re.search(p, named, re.I) for p in patterns)]
        if 'win32k.sys' not in components and re.search(r'win32k', text, re.I):
            components.append('win32k.sys')
        rows.append({'id': page.stem.upper(), 'title': titles[0].strip() if titles else '',
                     'published': published.group(1) if published else None, 'xp_affected': xp,
                     'cves': sorted(set(re.findall(r'(?:CVE|CAN)-\d{4}-\d{4,5}', text))),
                     'cve_titles': cve_titles, 'components': components})
    Path(out).write_text(json.dumps(rows, indent=1) + '\n')
    print(len(rows), 'bulletins;', sum(r['xp_affected'] for r in rows), 'list Windows XP as affected')


def report(path):
    rows = json.loads(Path(path).read_text())
    for component in COMPONENTS:
        selected = [r for r in rows if r['xp_affected'] and component in r['components']]
        print('== %s: %d bulletins, %d CVE identifiers' % (component, len(selected),
                                                            len({c for r in selected for c in r['cves']})))
        for r in selected:
            print('  %s  %-18s %s' % (r['id'], r['published'] or '', r['title'][:100]))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('fetch'); p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('index'); p.add_argument('html', type=Path); p.add_argument('out', type=Path)
    p = sub.add_parser('report'); p.add_argument('index', type=Path)
    args = parser.parse_args()
    if args.command == 'fetch':
        fetch(args.output)
    elif args.command == 'index':
        index(args.html, args.out)
    else:
        report(args.index)


if __name__ == '__main__':
    sys.exit(main())
