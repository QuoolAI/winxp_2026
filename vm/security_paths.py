#!/usr/bin/env python3
"""Where the XP25 security lab keeps its evidence.

Milestone 8 evidence (.work/security-20261111) is closed: its frozen inputs
and its image are read from there, nothing new is written into it. New runs
go under the Milestone 8.1 root, or wherever XP25_SEC_WORK points."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
M8 = ROOT / '.work/security-20261111'
WORK = Path(os.environ.get('XP25_SEC_WORK', ROOT / '.work/security81-20261112')).resolve()
REFERENCE = M8 / 'reference'
RUNS = WORK / 'runs'
# Hardened images by name: the directory holds the image and the manifest.json written by build/security_package_image.py.
# m81 is the current Milestone 8.1 candidate; image-81 (AI build 13) was superseded by image-81-02 (AI build 14).
IMAGES = {'m8': M8 / 'image-02', 'm81-01': WORK / 'image-81', 'm81': WORK / 'image-81-02'}


def image(name):
    """(image file, recorded SHA-256) of a packaged hardened image."""
    directory = IMAGES[name]
    manifest = json.loads((directory / 'manifest.json').read_text())
    return Path(manifest['image']), manifest['image_sha256']
