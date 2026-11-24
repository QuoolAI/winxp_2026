"""The files installed in an installation's baseline image, read-only, for investigations: where a binary is,
its version and hash, and which of its imports the installed system cannot resolve.

The image is opened through the lab tools' read-only partition export (vm/xp_lab.py); every file read is
cached under the job's directory. Names come from reports and model tool calls, so they are validated."""
import contextlib
import hashlib
import os
from pathlib import Path
import re

from . import pe, recipes

NAME = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.$-]{0,63}$')
SEARCH = ('/WINDOWS/system32/drivers', '/WINDOWS/system32', '/WINDOWS', '/Program Files/XP25', '/Program Files/XP25/MerlinAI',
          '/Program Files/XP25/Security')


class SystemImage:
    def __init__(self, image, cache, lab):
        self.image, self.cache, self.lab = Path(image), Path(cache), lab
        self.device = None
        self.listings = {}
        self._boot = None

    @contextlib.contextmanager
    def open(self):
        """One read-only export of the image for a batch of reads (the lab tools write their helper files
        into the working directory, so that is the cache directory meanwhile)."""
        if self.device:
            yield self
            return
        self.cache.mkdir(parents=True, exist_ok=True)
        cwd = os.getcwd()
        os.chdir(self.cache)
        try:
            with self.lab.partition(self.image, False) as device:
                self.device = device
                try:
                    yield self
                finally:
                    self.device = None
        finally:
            os.chdir(cwd)

    def listing(self, directory):
        if directory not in self.listings:
            with self.open():
                try:
                    names = self.lab.run(['ntfsls', '-p', directory, self.device]).decode('latin-1').split('\n')
                except RuntimeError:
                    names = []
            self.listings[directory] = {n.lower(): n for n in names if n and n not in ('.', '..')}
        return self.listings[directory]

    def read(self, guest_path):
        cached = self.cache / 'files' / hashlib.sha256(guest_path.lower().encode()).hexdigest()
        if cached.exists():
            return cached.read_bytes()
        with self.open():
            data = self.lab.run(['ntfscat', self.device, guest_path])
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(data)
        return data

    def find(self, name):
        """The guest path of an installed file by its name, or None."""
        if not NAME.match(name or ''):
            raise ValueError('a file name is required (letters, digits, . _ - $)')
        for directory in SEARCH:
            found = self.listing(directory).get(name.lower())
            if found:
                return directory + '/' + found
        return None

    def boot(self):
        """The kernel and HAL that boot.ini's default entry starts (defaults ntoskrnl.exe and hal.dll)."""
        if self._boot is None:
            text = self.read('/boot.ini').decode('latin-1')
            default = re.search(r'(?im)^\s*default\s*=\s*(\S+)', text)
            entry = ''
            for line in text.splitlines():
                if default and line.strip().lower().startswith(default.group(1).lower() + '='):
                    entry = line
                    break
            kernel = re.search(r'/kernel=(\S+)', entry, re.I)
            hal = re.search(r'/hal=(\S+)', entry, re.I)
            self._boot = {'kernel': kernel.group(1) if kernel else 'ntoskrnl.exe', 'hal': hal.group(1) if hal else 'hal.dll'}
        return self._boot

    def exporter(self, dll):
        """The installed file that resolves imports from dll (the kernel and HAL as boot.ini selects them)."""
        dll = dll.lower()
        if dll in ('ntoskrnl.exe', 'ntkrnlpa.exe', 'ntkrnlmp.exe'):
            return '/WINDOWS/system32/' + self.boot()['kernel']
        if dll == 'hal.dll':
            return '/WINDOWS/system32/' + self.boot()['hal']
        return self.find(dll) if NAME.match(dll) else None

    def importers_by_ordinal(self, names):
        """Installed executables that import any of names (DLL names, lower case) by ordinal: {guest path: [dll#n]}."""
        out = {}
        with self.open():
            for directory in SEARCH:
                for low, real in sorted(self.listing(directory).items()):
                    if not low.endswith(('.dll', '.exe', '.sys', '.cpl', '.drv', '.ocx')):
                        continue
                    try:
                        imports = pe.PE(self.read(directory + '/' + real)).imports()
                    except (pe.PEError, RuntimeError):
                        continue
                    hits = ['%s!%s' % (dll, n) for dll in names for n in imports.get(dll, []) if n.startswith('#')]
                    if hits:
                        out[directory + '/' + real] = hits
        return out

    def describe(self, name, table=None):
        """Version, hash, provenance and import resolution of an installed binary."""
        with self.open():
            path = self.find(name)
            if not path:
                return {'name': name, 'installed': False}
            data = self.read(path)
            image = pe.PE(data)
            info = recipes.component(name, table)
            company = image.version_string('CompanyName')
            origin = info.get('origin')
            if origin == 'unknown' and company and company.startswith('Microsoft'):
                origin = 'binary-only'                     # a Microsoft binary XP25 does not build (e.g. an SP3 driver)
            out = {'name': name, 'installed': True, 'guest_path': path, 'sha256': hashlib.sha256(data).hexdigest(),
                   'bytes': len(data), 'file_version': image.file_version(), 'company': company, 'origin': origin,
                   'recipe': info.get('recipe'), 'imports': {}}
            known = info.get('known_builds', {}).get(out['sha256'])
            if known:
                out['provenance'] = known
            for dll, names in sorted(image.imports().items()):
                source = self.exporter(dll)
                row = {'count': len(names)}
                if not source:
                    row['resolved_from'] = None
                    row['missing'] = 'the whole DLL is not installed'
                else:
                    exporter = pe.PE(self.read(source))
                    exports = set(exporter.exports()) | exporter.export_ordinals()
                    row['resolved_from'] = source
                    row['missing'] = sorted(n for n in names if n not in exports)
                out['imports'][dll] = row
            out['unresolved'] = sorted('%s!%s' % (dll, n) for dll, row in out['imports'].items()
                                       if isinstance(row['missing'], list) for n in row['missing'])
            return out
