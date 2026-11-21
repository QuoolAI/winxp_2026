#!/usr/bin/env python3
"""Where the XP25 security lab keeps its evidence.

Milestone 8 evidence (.work/security-20261111) is closed: its frozen inputs
are read from there, nothing new is written into it. In the xp25-cve worktree
that directory holds hash-checked reflink copies of the Milestone 8 inputs the
lab needs. New runs go under the Milestone 8.2 root, or wherever XP25_SEC_WORK
points."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
M8 = ROOT / '.work/security-20261111'
M82 = ROOT / '.work/cve82-20261112'
WORK = Path(os.environ.get('XP25_SEC_WORK', M82)).resolve()
REFERENCE = M8 / 'reference'
RUNS = WORK / 'runs'
# Hardened images by name: the directory holds a manifest.json naming the image and its SHA-256.
# m81 is the accepted Milestone 8.1 image (a frozen copy under M82/reference); m82 is the Milestone 8.2 image once packaged.
IMAGES = {'m81': M82 / 'reference/image-81', 'm82': M82 / 'image-82',
          # Milestone 9 baseline: 8.2 + R-0 Winlogon + R-1 win32k/user32/gdi32 + AI build 17 (build/package_image.py).
          'm9': ROOT / '.work/merlin-20261121/baseline-01'}


def image(name):
    """(image file, recorded SHA-256) of a packaged hardened image."""
    directory = IMAGES[name]
    manifest = json.loads((directory / 'manifest.json').read_text())
    return Path(manifest['image']), manifest['image_sha256']
