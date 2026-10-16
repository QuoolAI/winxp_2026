#!/usr/bin/env python3
"""Prepare and hash-verify a disposable NT source copy; never overwrite output."""
import argparse
import json
from pathlib import Path
import shutil
from inventory import inventory

REPO = Path(__file__).resolve().parents[1]


def stage(source, output):
    source, output = source.resolve(), output.resolve()
    if output == source or source in output.parents or output in source.parents:
        raise ValueError("staging output must be separate from the source tree")
    if (REPO / "Source").resolve() in output.parents:
        raise ValueError("staging output cannot be inside the reference Source tree")
    if not (source / "tools/razzle.cmd").is_file():
        raise ValueError("source must contain tools/razzle.cmd")
    output.mkdir(parents=True, exist_ok=False)
    print("Hashing reference source", flush=True)
    reference = inventory(source, output / "reference-inventory", hash_all=True)
    print("Copying disposable NT tree", flush=True)
    target = output / "NT"
    shutil.copytree(source, target)
    print("Verifying copied source", flush=True)
    copied = inventory(target, output / "staged-inventory", hash_all=True)
    result = {"schema": 1, "source": str(source), "staged_source": str(target),
              "reference_manifest_sha256": reference["file_manifest_sha256"],
              "staged_manifest_sha256": copied["file_manifest_sha256"],
              "files": copied["files"], "bytes": copied["bytes"],
              "status": "verified" if reference["file_manifest_sha256"] ==
                        copied["file_manifest_sha256"] else "failed"}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=REPO / "Source/XPSP1/NT")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = stage(args.source, args.output)
    except (OSError, ValueError, shutil.Error) as error:
        parser.exit(2, str(error) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "verified" else 2


if __name__ == "__main__":
    raise SystemExit(main())
