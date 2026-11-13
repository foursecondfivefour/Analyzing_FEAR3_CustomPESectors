#!/usr/bin/env python3
"""Verify the evidence and optionally compare raw sections with an original EXE."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / 'evidence' / 'fear3-engine-sections'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_file(name):
    if not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\\' in name:
        raise ValueError(f'Invalid filename: {name!r}')
    return EVIDENCE / name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', type=Path, help='Optional original F.E.A.R. 3 executable')
    args = parser.parse_args()
    problems = []
    sums = (EVIDENCE / 'SHA256SUMS.txt').read_text(encoding='utf-8').splitlines()
    for line in sums:
        expected, name = line.split('  ', 1)
        if digest(safe_file(name).read_bytes()) != expected:
            problems.append(f'SHA256SUMS mismatch: {name}')
    manifest = json.loads((EVIDENCE / 'manifest.json').read_text(encoding='utf-8'))
    source = args.exe.read_bytes() if args.exe else None
    if source is not None:
        print(f'EXE: {len(source)} bytes; SHA-256 {digest(source)}')
        if len(source) != manifest['source_size']:
            problems.append('EXE size differs from manifest')
    for section in manifest['sections']:
        name = section['file']
        data = safe_file(name).read_bytes()
        if len(data) != section['raw_size'] or digest(data) != section['sha256']:
            problems.append(f'Manifest mismatch: {name}')
        if source is not None:
            start = section['raw_offset']
            if source[start:start + section['raw_size']] != data:
                problems.append(f'EXE raw bytes mismatch: {name}')
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print(f'OK: {len(sums)} checksums, {len(manifest["sections"])} manifest sections' +
          (' and EXE raw bytes match' if source is not None else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
