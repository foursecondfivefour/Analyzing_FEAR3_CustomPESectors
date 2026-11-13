#!/usr/bin/env python3
"""Make a static PE inventory and compare section headers with the supplied manifest."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tooling' / 'python'))
import pefile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('exe', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = args.exe.read_bytes()
    pe = pefile.PE(data=data)
    manifest = json.loads((ROOT / 'evidence/fear3-engine-sections/manifest.json').read_text(encoding='utf-8'))
    sections = []
    for index, s in enumerate(pe.sections):
        raw = data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
        sections.append({
            'index': index, 'raw_name_hex': s.Name.hex(),
            'name': s.Name.rstrip(b'\0').decode('ascii', 'backslashreplace'),
            'virtual_address': s.VirtualAddress, 'virtual_size': s.Misc_VirtualSize,
            'raw_offset': s.PointerToRawData, 'raw_size': s.SizeOfRawData,
            'characteristics': s.Characteristics, 'sha256': sha(raw),
            'entropy_bits_per_byte': round(entropy(raw), 6),
        })
    comparisons = []
    fields = ('raw_name_hex', 'virtual_address', 'virtual_size', 'raw_offset',
              'raw_size', 'characteristics', 'sha256')
    for s in manifest['sections']:
        idx = s['index']
        differences = [field for field in fields if idx >= len(sections) or sections[idx][field] != s[field]]
        comparisons.append({'index': idx, 'file': s['file'], 'differing_fields': differences})
    imports = []
    for dll in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        imports.append({
            'dll': dll.dll.decode('ascii', 'backslashreplace'),
            'symbols': [{'name': sym.name.decode('ascii', 'backslashreplace') if sym.name else None,
                         'ordinal': sym.ordinal if sym.import_by_ordinal else None,
                         'iat_va': sym.address} for sym in dll.imports],
        })
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    result = {
        'scope': 'Static inventory, not signature verification or code analysis',
        'file': str(args.exe), 'size': len(data), 'sha256': sha(data),
        'machine': pe.FILE_HEADER.Machine, 'timestamp_raw': pe.FILE_HEADER.TimeDateStamp,
        'image_base': pe.OPTIONAL_HEADER.ImageBase,
        'entrypoint_rva': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'pe_checksum_header': pe.OPTIONAL_HEADER.CheckSum,
        'pe_checksum_calculated': pe.generate_checksum(),
        'security_directory_file_offset': security.VirtualAddress,
        'security_directory_size': security.Size,
        'sections': sections, 'manifest_comparisons': comparisons,
        'imports': imports, 'pefile_warnings': pe.get_warnings(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    failed = [c for c in comparisons if c['differing_fields']]
    print(f'{len(sections)} PE sections, {len(imports)} import DLLs; '
          f'{len(comparisons) - len(failed)}/{len(comparisons)} section headers and hashes match manifest')
    print(f'Saved {args.output}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
