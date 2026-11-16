#!/usr/bin/env python3
"""Inventory MSVC x86 RTTI candidates from every byte of every on-disk PE section.

No binary code is executed. Output addresses are preferred VAs, not runtime addresses.
See analysis/cpp-classes/REPORT.md for methodology and limits.
"""
import argparse
from collections import Counter, defaultdict
import csv
import ctypes
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tooling/python'))
import pefile

EXPECTED_SHA = 'caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2'
MANIFEST = ROOT / 'evidence/fear3-engine-sections/manifest.json'
SIMPLE = re.compile(r'^\.\?A[UV]([A-Za-z_][A-Za-z0-9_]*(?:@[A-Za-z_][A-Za-z0-9_]*)*)@@$')
LIB = ROOT / 'tooling/python/undname-0.2-local/libundname.so'


def hx(value):
    return f'0x{value:X}'


def csv_write(path, fields, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fields, lineterminator='\n', extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


class Demangler:
    def __init__(self, libpath=None):
        self.lib = None
        if libpath:
            self.lib = ctypes.CDLL(str(libpath))
            self.lib.undname_compat.argtypes = [ctypes.c_char_p]
            self.lib.undname_compat.restype = ctypes.c_void_p
            self.c = ctypes.CDLL(None)
            self.c.free.argtypes = [ctypes.c_void_p]
            self.c.free.restype = None

    def symbol(self, decorated):
        if not self.lib:
            return ''
        ptr = self.lib.undname_compat(decorated.encode('ascii'))
        if not ptr:
            return ''
        try:
            value = ctypes.string_at(ptr).decode('ascii', 'replace')
        finally:
            self.c.free(ptr)
        return value if value != decorated else ''

    def name(self, decorated):
        # The Wine demangler lacks RTTI-type support; synthesize a vftable symbol
        # solely for parsing, never treat it as proof that a vtable exists.
        if self.lib and decorated.startswith(('.?AV', '.?AU')):
            symbol = '??_7' + decorated[4:] + '6B@'
            value = self.symbol(symbol)
            suffix = "::`vftable'"
            if value.startswith('const ') and value.endswith(suffix):
                return value[6:-len(suffix)], 'wine_synthetic_vftable'
        match = SIMPLE.fullmatch(decorated)
        if match:
            return '::'.join(reversed(match.group(1).split('@'))), 'simple_fallback'
        return '', 'unresolved'


class Image:
    def __init__(self, raw):
        self.raw = raw
        self.pe = pefile.PE(data=raw, fast_load=True)
        if self.pe.FILE_HEADER.Machine != 0x14c or self.pe.OPTIONAL_HEADER.Magic != 0x10b:
            raise ValueError('Only MSVC-style PE32 x86 images supported')
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.sections = []
        for index, s in enumerate(self.pe.sections):
            start, size = s.PointerToRawData, s.SizeOfRawData
            if start + size > len(raw):
                raise ValueError('Truncated section ' + str(index))
            if self.base + s.VirtualAddress + size > 0x100000000:
                raise ValueError('Section exceeds PE32 address space')
            self.sections.append({'index': index, 'name': s.Name.rstrip(b'\0').decode('ascii', 'replace').strip(),
                                  'raw': start, 'size': size, 'rva': s.VirtualAddress,
                                  'virtual_size': s.Misc_VirtualSize, 'flags': s.Characteristics,
                                  'data': raw[start:start + size]})
        # Overlapping raw-backed virtual ranges make address attribution ambiguous.
        ranges = sorted((s['rva'], s['rva'] + s['size']) for s in self.sections if s['size'])
        if any(b[0] < a[1] for a, b in zip(ranges, ranges[1:])):
            raise ValueError('Overlapping raw-backed section RVAs')

    def at(self, va, size):
        rva = va - self.base
        for s in self.sections:
            off = rva - s['rva']
            if 0 <= off and off + size <= s['size']:
                return s, off
        return None

    def read(self, va, size):
        hit = self.at(va, size)
        return hit[0]['data'][hit[1]:hit[1] + size] if hit else None

    def unpack(self, fmt, va):
        data = self.read(va, struct.calcsize(fmt))
        return struct.unpack(fmt, data) if data is not None else None

    def executable(self, va):
        hit = self.at(va, 1)
        return bool(hit and hit[0]['flags'] & 0x20000000)


def pointer_hits(image, targets):
    """Search all unaligned and aligned 32-bit little-endian absolute pointers."""
    if not targets:
        return
    high = sorted({x >> 24 for x in targets})
    pattern = re.compile(b'[' + b''.join(b'\\x%02x' % x for x in high) + b']')
    for s in image.sections:
        data = s['data']
        for m in pattern.finditer(data):
            off = m.start() - 3
            if off < 0:
                continue
            value = struct.unpack_from('<I', data, off)[0]
            if value in targets:
                yield s, off, value


def find_names(image, demangler):
    candidates, types, per_section = [], {}, Counter()
    for s in image.sections:
        data = s['data']
        pos = 0
        while True:
            pos = data.find(b'.?A', pos)
            if pos < 0:
                break
            start = pos
            pos += 1
            per_section[s['index']] += 1
            end = data.find(b'\0', start)
            # Retain all prefix hits even if malformed; truncate rendered snippets only.
            fragment = data[start:end if end != -1 else min(len(data), start + 512)]
            valid = end != -1 and len(fragment) >= 7 and all(33 <= b <= 126 for b in fragment)
            text = fragment.decode('ascii', 'backslashreplace') if valid else fragment[:512].decode('ascii', 'backslashreplace')
            va = image.base + s['rva'] + start
            kind = 'class' if fragment[3:4] == b'V' else 'struct' if fragment[3:4] == b'U' else 'other'
            reason = ''
            header = image.unpack('<II', va - 8) if start >= 8 else None
            if not valid: reason = 'invalid_or_unterminated_printable_string'
            elif kind == 'other': reason = 'unsupported_kind_marker'
            elif not header: reason = 'no_raw_backed_header'
            elif header[1] != 0: reason = 'nonzero_spare'
            elif not image.read(header[0], 4): reason = 'unmapped_type_info_vftable'
            elif not image.executable(image.unpack('<I', header[0])[0]): reason = 'type_info_first_slot_not_executable'
            else: reason = 'type_descriptor_candidate'
            row = {'section_index': s['index'], 'section': s['name'], 'section_offset': hx(start),
                   'file_offset': hx(s['raw'] + start), 'name_va': hx(va),
                   'type_descriptor_va': hx(va - 8) if header else '', 'kind': kind,
                   'vftable_pointer': hx(header[0]) if header else '', 'spare': hx(header[1]) if header else '',
                   'status': reason, 'decorated_name': text}
            candidates.append(row)
            if reason == 'type_descriptor_candidate':
                name, status = demangler.name(text)
                types[va - 8] = dict(row, display_name=name, demangle_status=status)
    return candidates, types, per_section


def find_cols(image, types):
    cols = {}
    for s, offset, td in pointer_hits(image, types):
        if offset < 12 or offset + 8 > s['size']:
            continue
        loc = offset - 12
        sig, displacement, cd, _, ch = struct.unpack_from('<IIIII', s['data'], loc)
        # A raw-backed PE32 COL signature is zero. Keep limits explicit.
        if sig != 0 or displacement > 0x10000 or cd > 0x10000:
            continue
        header = image.unpack('<IIII', ch)
        if not header:
            continue
        hs, flags, count, array = header
        if hs != 0 or not 1 <= count <= 1024:
            continue
        raw_array = image.read(array, count * 4)
        if raw_array is None:
            continue
        ptrs = struct.unpack('<' + 'I' * count, raw_array)
        descriptors = [image.unpack('<IIiiiI', ptr) for ptr in ptrs]
        if any(x is None for x in descriptors) or descriptors[0][0] != td:
            continue
        va = image.base + s['rva'] + loc
        cols[va] = {'col_va': hx(va), 'section_index': s['index'], 'section': s['name'],
                    'file_offset': hx(s['raw'] + loc), 'aligned': str(va % 4 == 0).lower(),
                    'type_descriptor_va': hx(td), 'object_offset': hx(displacement), 'cd_offset': hx(cd),
                    'hierarchy_va': hx(ch), 'hierarchy_attributes': hx(flags),
                    'base_count': count, 'base_array_va': hx(array), '_bases': list(zip(ptrs, descriptors))}
    return cols


def find_vtables(image, cols):
    result = []
    for s, offset, col in pointer_hits(image, cols):
        if offset + 8 > s['size']:
            continue
        target = struct.unpack_from('<I', s['data'], offset + 4)[0]
        if not image.executable(target):
            continue
        va = image.base + s['rva'] + offset + 4
        reasons = []
        if va % 4: reasons.append('unaligned')
        if s['flags'] & 0x20000000: reasons.append('in_executable_section')
        result.append({'vtable_va': hx(va), 'section_index': s['index'], 'section': s['name'],
                       'file_offset': hx(s['raw'] + offset + 4), 'col_va': hx(col),
                       'type_descriptor_va': cols[col]['type_descriptor_va'], 'first_slot_va': hx(target),
                       'status': 'rejected_' + '_and_'.join(reasons) if reasons else 'candidate'})
    return result


def member_owner(prototype):
    # Require access qualifier and calling convention, then split on the last
    # top-level scope separator before the parameter list. Never infer owners
    # from namespace-qualified free functions.
    if not prototype.startswith(('public: ', 'protected: ', 'private: ')):
        return ''
    match = re.search(r'\b__(?:thiscall|cdecl|stdcall|fastcall|vectorcall)\s+', prototype)
    if not match:
        return ''
    name = prototype[match.end():]
    depth, separators, end = 0, [], None
    for i, ch in enumerate(name):
        if ch == '<': depth += 1
        elif ch == '>': depth -= 1
        elif ch == '(' and depth == 0:
            end = i
            break
        elif ch == ':' and i + 1 < len(name) and name[i+1] == ':' and depth == 0:
            separators.append(i)
        if depth < 0:
            return ''
    if end is None or depth or not separators:
        return ''
    owner = name[:separators[-1]]
    return owner if owner and not owner.startswith(('`', '?', '*', '&')) else ''


def explicit_type_names(text):
    """Extract explicit Wine `class`/`struct` type expressions, conservatively."""
    result = []
    for match in re.finditer(r'\b(class|struct)\s+', text):
        pos = match.end()
        start = pos
        while True:
            ident = re.match(r'[A-Za-z_][A-Za-z0-9_]*', text[pos:])
            if not ident:
                break
            pos += len(ident.group())
            if pos < len(text) and text[pos] == '<':
                depth = 0
                while pos < len(text):
                    char = text[pos]
                    if char == '<': depth += 1
                    if char == '>':
                        depth -= 1
                        if depth == 0:
                            pos += 1
                            break
                    pos += 1
                if depth:
                    pos = start
                    break
            if text[pos:pos + 2] != '::':
                break
            if not re.match(r'[A-Za-z_]', text[pos + 2:]):
                pos = start
                break
            pos += 2
        if pos > start:
            result.append((match.group(1), text[start:pos]))
    return result


def symbol_inventory(image, demangler, types):
    image.pe.parse_data_directories(directories=[0, 1])
    symbols, refs = [], []
    known = {v['display_name']: hx(k) for k, v in types.items() if v['display_name']}
    exports = getattr(getattr(image.pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
    entries = [('export', '', e) for e in exports]
    for dll in getattr(image.pe, 'DIRECTORY_ENTRY_IMPORT', []):
        entries.extend(('import', dll.dll.decode('ascii', 'backslashreplace'), e) for e in dll.imports)
    for origin, dll, entry in entries:
        if not entry.name or not entry.name.startswith(b'?'):
            continue
        try: decorated = entry.name.decode('ascii')
        except UnicodeDecodeError: continue
        prototype = demangler.symbol(decorated)
        symbol_id = f'{origin}:{dll}:{entry.ordinal if origin == "export" else hx(entry.address)}:{decorated}'
        owner = member_owner(prototype) if prototype else ''
        symbols.append({'symbol_id': symbol_id, 'origin': origin, 'dll': dll,
                        'ordinal': entry.ordinal if entry.ordinal is not None else '',
                        'name_file_offset': hx(entry.name_offset) if entry.name_offset is not None else '',
                        'target_or_iat_va': hx(image.base + entry.address) if origin == 'export' else hx(entry.address),
                        'forwarder': entry.forwarder.decode('ascii', 'backslashreplace') if origin == 'export' and entry.forwarder else '',
                        'decorated_symbol': decorated, 'demangled_prototype': prototype,
                        'status': 'demangled' if prototype else 'unresolved'})
        candidates = []
        if owner:
            candidates.append(('member_owner', owner))
        for _, name in explicit_type_names(prototype):
            candidates.append(('explicit_type_mention', name))
        for role, name in sorted(set(candidates)):
            refs.append({'symbol_id': symbol_id, 'origin': origin, 'dll': dll, 'role': role,
                         'class_name_candidate': name, 'matched_rtti_type_descriptor_va': known.get(name, '')})
    return symbols, refs


def validate_manifest(image, path):
    manifest = json.loads(path.read_text(encoding='utf-8'))
    if manifest['source_size'] != len(image.raw):
        raise ValueError('Manifest source size mismatch')
    seen = set()
    for item in manifest['sections']:
        index = item['index']
        if index in seen or not 0 <= index < len(image.sections):
            raise ValueError('Invalid or duplicate manifest section index')
        seen.add(index)
        section = image.sections[index]
        if (item['name'] != section['name'] or item['raw_offset'] != section['raw'] or
                item['raw_size'] != section['size'] or item['virtual_address'] != section['rva'] or
                item['virtual_size'] != section['virtual_size'] or item['characteristics'] != section['flags'] or
                hashlib.sha256(section['data']).hexdigest() != item['sha256']):
            raise ValueError('Manifest mismatch at section ' + str(index))
    return len(seen)


def scan(raw, output, demangler, manifest=None):
    image = Image(raw)
    verified = validate_manifest(image, manifest) if manifest else None
    output.mkdir(parents=True, exist_ok=True)
    raw_names, types, section_counts = find_names(image, demangler)
    cols = find_cols(image, types)
    tables = find_vtables(image, cols)
    symbols, symbol_refs = symbol_inventory(image, demangler, types)
    known = {v['display_name']: hx(k) for k, v in types.items() if v['display_name']}
    rtti_refs = []
    for va, row in sorted(types.items()):
        for kind, name in sorted(set(explicit_type_names(row['display_name']))):
            rtti_refs.append({'owner_type_descriptor_va': hx(va), 'kind': kind, 'referenced_name_candidate': name,
                              'matched_rtti_type_descriptor_va': known.get(name, '')})
    registry = {}
    def entry(name, fmt='demangled'):
        return registry.setdefault((name, fmt), {'name':name, 'name_format':fmt, 'rtti_descriptors':[],
            'rtti_reference_rows':0, 'export_owner_rows':0, 'export_type_rows':0, 'import_owner_rows':0, 'import_type_rows':0})
    for va, row in types.items():
        item = entry(row['display_name'] or row['decorated_name'], 'demangled' if row['display_name'] else 'decorated_unresolved')
        item['rtti_descriptors'].append(hx(va))
    for row in rtti_refs:
        entry(row['referenced_name_candidate'])['rtti_reference_rows'] += 1
    for row in symbol_refs:
        key = row['origin'] + ('_owner_rows' if row['role'] == 'member_owner' else '_type_rows')
        entry(row['class_name_candidate'])[key] += 1
    names = []
    for item in sorted(registry.values(), key=lambda x: (x['name'].casefold(), x['name_format'])):
        item['rtti_descriptors'] = ';'.join(item['rtti_descriptors'])
        names.append(item)
    by_type = defaultdict(list)
    for col in cols.values(): by_type[col['type_descriptor_va']].append(col)
    by_table = defaultdict(list)
    for table in tables:
        if table['status'] == 'candidate': by_table[table['type_descriptor_va']].append(table)
    classes = []
    for va, row in sorted(types.items()):
        key = hx(va)
        classes.append(dict(row, col_count=len(by_type[key]), vtable_candidate_count=len(by_table[key]),
                            evidence='COL_and_vtable_candidate' if by_table[key] else 'COL_candidate' if by_type[key] else 'type_descriptor_candidate_only'))
    hierarchies = {}
    for col in cols.values(): hierarchies.setdefault(col['hierarchy_va'], col)
    bases = []
    for col in hierarchies.values():
        for i, (ptr, fields) in enumerate(col['_bases']):
            td, contained, mdisp, pdisp, vdisp, flags = fields
            bases.append({'hierarchy_va': col['hierarchy_va'], 'owner_type_descriptor_va': col['type_descriptor_va'],
                          'index': i, 'base_descriptor_va': hx(ptr), 'base_type_descriptor_va': hx(td),
                          'base_decorated_name': types.get(td, {}).get('decorated_name', ''),
                          'base_display_name': types.get(td, {}).get('display_name', ''),
                          'contained_bases': contained, 'mdisp': mdisp, 'pdisp': pdisp, 'vdisp': vdisp, 'attributes': hx(flags)})
    csv_write(output/'raw-name-candidates.csv', ['section_index','section','section_offset','file_offset','name_va','type_descriptor_va','kind','vftable_pointer','spare','status','decorated_name'], raw_names)
    csv_write(output/'classes.csv', ['type_descriptor_va','display_name','demangle_status','kind','decorated_name','section_index','section','section_offset','file_offset','name_va','vftable_pointer','spare','evidence','col_count','vtable_candidate_count'], classes)
    csv_write(output/'names.csv', ['name','name_format','rtti_descriptors','rtti_reference_rows','export_owner_rows','export_type_rows','import_owner_rows','import_type_rows'], names)
    csv_write(output/'complete-object-locators.csv', ['col_va','section_index','section','file_offset','aligned','type_descriptor_va','object_offset','cd_offset','hierarchy_va','hierarchy_attributes','base_count','base_array_va'], cols.values())
    csv_write(output/'vtable-candidates.csv', ['vtable_va','section_index','section','file_offset','col_va','type_descriptor_va','first_slot_va','status'], tables)
    csv_write(output/'base-descriptors.csv', ['hierarchy_va','owner_type_descriptor_va','index','base_descriptor_va','base_type_descriptor_va','base_display_name','base_decorated_name','contained_bases','mdisp','pdisp','vdisp','attributes'], bases)
    csv_write(output/'cpp-symbols.csv', ['symbol_id','origin','dll','ordinal','name_file_offset','target_or_iat_va','forwarder','decorated_symbol','demangled_prototype','status'], symbols)
    csv_write(output/'symbol-type-references.csv', ['symbol_id','origin','dll','role','class_name_candidate','matched_rtti_type_descriptor_va'], symbol_refs)
    csv_write(output/'rtti-type-references.csv', ['owner_type_descriptor_va','kind','referenced_name_candidate','matched_rtti_type_descriptor_va'], rtti_refs)
    section_rows = [dict(section_index=s['index'], section=s['name'], raw_offset=hx(s['raw']), raw_size=hx(s['size']), rva=hx(s['rva']), virtual_size=hx(s['virtual_size']), characteristics=hx(s['flags']), prefix_hits=section_counts[s['index']], sha256=hashlib.sha256(s['data']).hexdigest()) for s in image.sections]
    csv_write(output/'section-coverage.csv', ['section_index','section','raw_offset','raw_size','rva','virtual_size','characteristics','prefix_hits','sha256'], section_rows)
    summary = {'sha256': hashlib.sha256(raw).hexdigest(), 'file_size':len(raw), 'machine':'PE32 x86', 'image_base':hx(image.base),
               'section_count':len(image.sections), 'manifest_sections_verified_against_exe': verified,
               'bytes_scanned_sum':sum(s['size'] for s in image.sections),
               'prefix_hits':len(raw_names), 'name_status':dict(sorted(Counter(x['status'] for x in raw_names).items())),
               'type_descriptors':len(types), 'combined_distinct_exact_name_spellings':len(names),
               'kind':dict(sorted(Counter(x['kind'] for x in classes).items())),
               'demangle_status':dict(sorted(Counter(x['demangle_status'] for x in classes).items())),
               'unique_decorated_names':len({x['decorated_name'] for x in classes}),
               'col_candidates':len(cols), 'hierarchies':len(hierarchies), 'base_descriptors_rows':len(bases),
               'base_rows_unmatched_type_descriptor':sum(not x['base_decorated_name'] for x in bases),
               'vtable_status':dict(sorted(Counter(x['status'] for x in tables).items())),
               'class_evidence':dict(sorted(Counter(x['evidence'] for x in classes).items())),
               'cpp_symbols':dict(sorted(Counter(x['origin'] for x in symbols).items())),
               'symbol_status':dict(sorted(Counter(x['status'] for x in symbols).items())),
               'symbol_type_references':dict(sorted(Counter(x['origin'] + ':' + x['role'] for x in symbol_refs).items())),
               'symbol_only_distinct_names': len({x['class_name_candidate'] for x in symbol_refs if not x['matched_rtti_type_descriptor_va']}),
               'rtti_type_reference_rows':len(rtti_refs),
               'rtti_reference_names_without_descriptor':len({x['referenced_name_candidate'] for x in rtti_refs if not x['matched_rtti_type_descriptor_va']}),
               'demangler': 'undname 0.2 Wine-derived LGPL-2.1-or-later (synthetic vftable)' if demangler.lib else 'simple fallback only'}
    (output/'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', type=Path, default=ROOT/'evidence/source-exe/F.E.A.R. 3.exe')
    parser.add_argument('--out', type=Path, default=ROOT/'analysis/cpp-classes')
    parser.add_argument('--sha256', default=EXPECTED_SHA, help='expected SHA-256; explicitly supply another for a different image')
    parser.add_argument('--demangler', type=Path, default=LIB)
    parser.add_argument('--no-demangler', action='store_true')
    parser.add_argument('--manifest', type=Path, help='verify listed section hashes and metadata against the PE')
    parser.add_argument('--no-manifest', action='store_true', help='skip default FEAR3 manifest verification')
    args = parser.parse_args()
    raw = args.exe.read_bytes()
    if hashlib.sha256(raw).hexdigest().lower() != args.sha256.lower():
        raise SystemExit('EXE SHA-256 mismatch')
    if not args.no_demangler and not args.demangler.is_file():
        raise SystemExit('Optional demangler not found: run python tooling/install_undname.py or use --no-demangler')
    if args.manifest and args.no_manifest:
        parser.error('--manifest and --no-manifest are mutually exclusive')
    manifest = args.manifest or (MANIFEST if not args.no_manifest and args.sha256.lower() == EXPECTED_SHA else None)
    summary = scan(raw, args.out, Demangler(None if args.no_demangler else args.demangler), manifest)
    print(json.dumps(summary, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
