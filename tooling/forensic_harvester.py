#!/usr/bin/env python3
"""Read-only workbench for the checked-in FEAR3 forensic indexes (stdlib only)."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

import harvester_extras as extra
import harvester_advanced as advanced

ROOT = Path(__file__).resolve().parent.parent
EXE_REL = Path('evidence/source-exe/F.E.A.R. 3.exe')
INVENTORY = Path('evidence/pe-inventory.json')
DATA = {
    'classes': ('analysis/cpp-classes/classes.csv', ('type_descriptor_va', 'display_name', 'decorated_name')),
    'names': ('analysis/cpp-classes/names.csv', ('name', 'rtti_descriptors')),
    'symbols': ('analysis/cpp-classes/cpp-symbols.csv', ('decorated_symbol', 'demangled_prototype', 'dll')),
    'api': ('analysis/script-api-audit/all-api-evidence.csv', ('api_path', 'namespace')),
    'literals': ('analysis/script-classes/script-literals.csv', ('ascii_nul_terminated',)),
}
ADDRESS_TABLES = {
    'classes': ('analysis/cpp-classes/classes.csv', ('type_descriptor_va', 'name_va', 'vftable_pointer')),
    'locators': ('analysis/cpp-classes/complete-object-locators.csv', ('col_va', 'type_descriptor_va', 'hierarchy_va', 'base_array_va')),
    'vtables': ('analysis/cpp-classes/vtable-candidates.csv', ('vtable_va', 'col_va', 'type_descriptor_va', 'first_slot_va')),
    'bases': ('analysis/cpp-classes/base-descriptors.csv', ('hierarchy_va', 'owner_type_descriptor_va', 'base_descriptor_va', 'base_type_descriptor_va')),
    'symbols': ('analysis/cpp-classes/cpp-symbols.csv', ('target_or_iat_va',)),
    'api_proxy': ('analysis/script-api-audit/proxy-cfg-candidates.csv', ('mov_site_va', 'method_string_va', 'native_function_va', 'builder_va', 'vtable_va', 'col_va', 'type_descriptor_va', 'next_call_va', 'heuristic_entry_va')),
    'api_game': ('analysis/script-api-audit/gamescript-game-all-methods.csv', ('name_push_va', 'method_string_va', 'proxy_builder_va', 'target_va_only_if_immediate_eax', 'vtable_va', 'col_va', 'type_descriptor_va')),
    'compression_refs': ('analysis/compression/xref-candidates.csv', ('site_preferred_va', 'target_preferred_va')),
    'resource_refs': ('analysis/resource/address_matches.csv', ('preferred_va', 'target_preferred_va')),
}
REL = {
    'cols': ('analysis/cpp-classes/complete-object-locators.csv', 'type_descriptor_va'),
    'vtables': ('analysis/cpp-classes/vtable-candidates.csv', 'type_descriptor_va'),
    'bases': ('analysis/cpp-classes/base-descriptors.csv', 'owner_type_descriptor_va'),
    'rtti_mentions': ('analysis/cpp-classes/rtti-type-references.csv', 'matched_rtti_type_descriptor_va'),
    'rtti_outgoing': ('analysis/cpp-classes/rtti-type-references.csv', 'owner_type_descriptor_va'),
    'symbol_mentions': ('analysis/cpp-classes/symbol-type-references.csv', 'matched_rtti_type_descriptor_va'),
    'api_class_comparison': ('analysis/script-api-comparison/class-namespace-comparison.csv', 'native_rtti_class'),
    'api_proxy': ('analysis/script-api-audit/proxy-cfg-candidates.csv', 'api_path_name_correspondence_not_runtime_proof'),
    'api_game': ('analysis/script-api-audit/gamescript-game-all-methods.csv', 'api_path_name_correspondence_not_runtime_proof'),
}


def integer(text):
    try:
        value = int(text, 0)
    except ValueError as e:
        raise argparse.ArgumentTypeError('Use decimal or 0x-prefixed hexadecimal') from e
    if value < 0:
        raise argparse.ArgumentTypeError('Value must be nonnegative')
    return value


def positive(text):
    n = integer(text)
    if not 1 <= n <= 10000:
        raise argparse.ArgumentTypeError('Must be between 1 and 10000')
    return n


def bounded_size(text):
    n = integer(text)
    if not 1 <= n <= 1048576:
        raise argparse.ArgumentTypeError('Must be between 1 and 1048576 bytes')
    return n


def signed_integer(text):
    try:
        return advanced.integer_value(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError('Use a decimal or 0x-prefixed hexadecimal integer') from e


def hexa(n):
    return f'0x{n:X}'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_json(root, rel):
    with (root / rel).open(encoding='utf-8') as f:
        return json.load(f)


def rows(root, rel, required=()):
    with (root / rel).open(encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or not set(required).issubset(reader.fieldnames):
            raise ValueError(f'{rel}: missing required columns {", ".join(required)}')
        yield from reader


def limited(iterable, limit):
    items, total = [], 0
    for item in iterable:
        total += 1
        if total <= limit:
            items.append(item)
    return {'total': total, 'returned': len(items), 'truncated': total > len(items), 'items': items}


def group_refs(iterable, limit):
    groups = {key: {'total': 0, 'returned': 0, 'truncated': False, 'items': []} for key in
              ('absolute_u32_le', 'raw_e8_rel32_candidate', 'raw_e9_rel32_candidate',
               'raw_ff15_indirect_call_candidate', 'raw_ff25_indirect_jump_candidate')}
    for item in iterable:
        group = groups[item['kind']]
        group['total'] += 1
        if len(group['items']) < limit:
            group['items'].append(item)
    for group in groups.values():
        group['returned'] = len(group['items'])
        group['truncated'] = group['total'] > group['returned']
    return groups


def context(root):
    inventory = load_json(root, INVENTORY)
    summary = load_json(root, 'analysis/cpp-classes/summary.json')
    if inventory['sha256'].lower() != summary['sha256'].lower():
        raise ValueError('PE inventory and C++ summary refer to different SHA-256 values')
    return inventory


def verify_exe(root, inventory, path=None):
    path = path or root / EXE_REL
    try:
        raw = path.read_bytes()
    except FileNotFoundError as e:
        raise ValueError(f'EXE not found: {path}; supply --exe or restore the user-supplied file') from e
    actual = digest(raw)
    if len(raw) != inventory['size'] or actual.lower() != inventory['sha256'].lower():
        raise ValueError(f'EXE size/SHA-256 mismatch: {path}; SHA-256={actual}')
    return raw


def area(section, delta):
    raw_size, virtual_size = section['raw_size'], section['virtual_size']
    if delta < raw_size:
        return 'raw_padding_beyond_virtual_size' if delta >= virtual_size else 'raw_backed'
    return 'virtual_tail_no_file_bytes'


def map_address(inventory, kind, address):
    """Use declared half-open section intervals; never invent a mapping for headers."""
    base = inventory['image_base']
    if kind == 'va':
        rva = address - base
        if rva < 0:
            return []
    elif kind == 'rva':
        rva = address
    else:
        rva = None
    matches = []
    for s in inventory['sections']:
        delta = address - s['raw_offset'] if kind == 'file' else rva - s['virtual_address']
        extent = s['raw_size'] if kind == 'file' else max(s['raw_size'], s['virtual_size'])
        if not 0 <= delta < extent:
            continue
        matches.append({'section_index': s['index'], 'section': s['name'], 'section_offset': hexa(delta),
                        'file_offset': hexa(s['raw_offset'] + delta) if delta < s['raw_size'] else None,
                        'rva': hexa(s['virtual_address'] + delta),
                        'preferred_va': hexa(base + s['virtual_address'] + delta),
                        'region': area(s, delta), 'characteristics': hexa(s['characteristics'])})
    return matches


def read_extracted(root, inventory):
    directory = root / 'evidence/fear3-engine-sections'
    manifest = load_json(root, 'evidence/fear3-engine-sections/manifest.json')
    if manifest['source_size'] != inventory['size']:
        raise ValueError('manifest source size differs from inventory')
    by_index = {s['index']: s for s in inventory['sections']}
    seen = set()
    contents = {}
    for item in manifest['sections']:
        name = item['file']
        if not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\\' in name:
            raise ValueError('unsafe manifest filename')
        idx = item['index']
        if idx in seen or idx not in by_index:
            raise ValueError(f'invalid section index {idx}')
        seen.add(idx)
        sec = by_index[idx]
        if item['name'] != sec['name'].strip():
            raise ValueError(f'metadata mismatch for section {idx}: name')
        for key in ('raw_name_hex', 'raw_offset', 'raw_size', 'virtual_address', 'virtual_size', 'characteristics', 'sha256'):
            if item[key] != sec[key]:
                raise ValueError(f'metadata mismatch for section {idx}: {key}')
        # Refuse symlinks that escape the evidence directory.
        target = (directory / name).resolve()
        if target.parent != directory.resolve():
            raise ValueError('manifest file outside evidence directory')
        data = target.read_bytes()
        if len(data) != item['raw_size'] or digest(data) != item['sha256']:
            raise ValueError(f'section checksum mismatch: {name}')
        contents[idx] = data
    if 'manifest_comparisons' in inventory:
        expected = {(x['index'], x['file']) for x in inventory['manifest_comparisons']}
        actual = {(x['index'], x['file']) for x in manifest['sections']}
        if expected != actual:
            raise ValueError('manifest section set differs from PE inventory')
    return contents


def status(root, inventory, exe_path=None, require_exe=False):
    problems, warnings, checks = [], [], []
    def check(label, fn):
        try:
            extra = fn()
            checks.append({'check': label, 'status': 'ok', 'detail': extra})
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as e:
            problems.append(f'{label}: {e}')
            checks.append({'check': label, 'status': 'error', 'detail': str(e)})
    for label, (path, cols) in DATA.items():
        def test_csv(path=path, cols=cols):
            count = sum(1 for _ in rows(root, path, cols))
            return {'path': path, 'rows': count}
        check('csv:' + label, test_csv)
    for label, (path, col) in REL.items():
        def test_rel(path=path, col=col):
            count = sum(1 for _ in rows(root, path, (col,)))
            return {'path': path, 'rows': count}
        check('csv:' + label, test_rel)
    for label, (path, columns) in ADDRESS_TABLES.items():
        def test_addresses(path=path, columns=columns):
            count = sum(1 for _ in rows(root, path, columns))
            return {'path': path, 'rows': count}
        check('address_csv:' + label, test_addresses)
    check('manifest_and_section_files', lambda: {'sections_verified': len(read_extracted(root, inventory))})
    path = exe_path or root / EXE_REL
    if path.exists() or require_exe or exe_path is not None:
        check('exe', lambda: {'path': str(path), 'sha256': digest(verify_exe(root, inventory, path))})
    else:
        warnings.append(f'EXE absent: {path}; full-image byte search unavailable; use --extracted for the 31 provided sections')
    warnings.append('CSV contents are checked for required columns, not independently re-derived or hash-authenticated')
    warnings.append('Matching evidence confirms consistency, not authenticity or runtime behavior')
    return {'ok': not problems, 'checks': checks, 'warnings': warnings, 'errors': problems}


def search(root, query, sources, limit):
    needle = query.casefold()
    output = {}
    for source in sources:
        path, fields = DATA[source]
        matches = (r for r in rows(root, path, fields) if any(needle in r[field].casefold() for field in fields))
        output[source] = {'source': path, **limited(matches, limit)}
    return output


def related(root, key, expected, limit):
    path, col = REL[key]
    needle = expected.casefold()
    matches = (row for row in rows(root, path, (col,)) if row[col].casefold() == needle)
    return {'source': path, **limited(matches, limit)}


def class_profile(root, query, limit):
    path, fields = DATA['classes']
    query = query.casefold()
    matched = [r for r in rows(root, path, fields) if query in (r['display_name'].casefold(), r['decorated_name'].casefold(), r['type_descriptor_va'].casefold())]
    if len(matched) != 1:
        raise ValueError(f'Expected exactly one class by full name, decorated name or descriptor VA; found {len(matched)}. Use search to choose.')
    item = matched[0]
    td = item['type_descriptor_va']
    result = {'class_source': path, 'class': item}
    for key in ('cols', 'vtables', 'bases', 'rtti_mentions', 'rtti_outgoing', 'symbol_mentions'):
        result[key] = related(root, key, td, limit)
    if item['display_name']:
        result['api_class_comparison'] = related(root, 'api_class_comparison', item['display_name'], limit)
    return result


def api_profile(root, query, limit):
    path, fields = DATA['api']
    matches = [r for r in rows(root, path, fields) if r['api_path'].casefold() == query.casefold()]
    if not matches:
        raise ValueError('API path not found; use search to find the exact path')
    return {'api_source': path, 'api': limited(matches, limit),
            'proxy_candidates': related(root, 'api_proxy', query, limit),
            'game_registration_candidates': related(root, 'api_game', query, limit)}


def selected_sections(inventory, wanted):
    if not wanted:
        return inventory['sections']
    wanted = wanted.casefold()
    selected = [s for s in inventory['sections'] if str(s['index']) == wanted or s['name'].strip().casefold() == wanted]
    if not selected:
        raise ValueError(f'Unknown section: {wanted}')
    return selected


def location(inventory, sec, off):
    return {'section_index': sec['index'], 'section': sec['name'], 'section_offset': hexa(off),
            'file_offset': hexa(sec['raw_offset'] + off),
            'rva': hexa(sec['virtual_address'] + off),
            'preferred_va': hexa(inventory['image_base'] + sec['virtual_address'] + off),
            'region': area(sec, off)}


def section_data(source, sec):
    data = source[sec['index']] if isinstance(source, dict) else source[sec['raw_offset']:sec['raw_offset'] + sec['raw_size']]
    if len(data) != sec['raw_size']:
        raise ValueError('Section outside file or unexpected section length')
    return data


def find_bytes(raw, inventory, needle, wanted=None):
    if not needle:
        raise ValueError('Empty pattern is not allowed')
    for sec in selected_sections(inventory, wanted):
        data = section_data(raw, sec)
        start = 0
        while True:
            pos = data.find(needle, start)
            if pos < 0: break
            yield location(inventory, sec, pos)
            start = pos + 1  # overlapping hits included


def raw_refs(raw, inventory, target, wanted=None):
    if target > 0xFFFFFFFF:
        raise ValueError('Target is outside PE32 address space')
    needle = struct.pack('<I', target)
    # First return absolute 32-bit occurrences, then rel32 opcode candidates.
    by_index = {sec['index']: sec for sec in inventory['sections']}
    data_cache = {}
    for hit in find_bytes(raw, inventory, needle, wanted):
        yield dict(hit, kind='absolute_u32_le', target_preferred_va=hexa(target))
        sec = by_index[hit['section_index']]
        off = int(hit['section_offset'], 16)
        if off >= 2:
            if sec['index'] not in data_cache:
                data_cache[sec['index']] = section_data(raw, sec)
            prefix = bytes(data_cache[sec['index']][off-2:off])
            kinds = {b'\xff\x15': 'raw_ff15_indirect_call_candidate',
                     b'\xff\x25': 'raw_ff25_indirect_jump_candidate'}
            if prefix in kinds:
                yield dict(location(inventory, sec, off - 2), kind=kinds[prefix], target_preferred_va=hexa(target))
    for sec in selected_sections(inventory, wanted):
        data = section_data(raw, sec)
        # Exact x86 E8/E9 bytes can occur inside data or other instructions.
        for opcode, kind in ((b'\xe8', 'raw_e8_rel32_candidate'), (b'\xe9', 'raw_e9_rel32_candidate')):
            start = 0
            while True:
                pos = data.find(opcode, start)
                if pos < 0: break
                start = pos + 1
                if pos + 5 > len(data): continue
                disp = struct.unpack_from('<i', data, pos + 1)[0]
                site = inventory['image_base'] + sec['virtual_address'] + pos
                if (site + 5 + disp) & 0xFFFFFFFF == target:
                    yield dict(location(inventory, sec, pos), kind=kind, target_preferred_va=hexa(target))


def region_bytes(raw, inventory, kind, address, size):
    matches = map_address(inventory, kind, address)
    if len(matches) != 1 or matches[0]['file_offset'] is None:
        raise ValueError(f'Address must map to exactly one raw-backed section; got {len(matches)} mappings')
    hit = matches[0]
    sec = next(s for s in inventory['sections'] if s['index'] == hit['section_index'])
    off = int(hit['section_offset'], 16)
    if off + size > sec['raw_size']:
        raise ValueError('Requested bytes cross a raw section boundary')
    data = section_data(raw, sec)[off:off + size]
    if len(data) != size:
        raise ValueError('Requested bytes exceed the file')
    return hit, data


def read_bytes(raw, inventory, kind, address, size):
    hit, data = region_bytes(raw, inventory, kind, address, size)
    return {'location': hit, 'size': size, 'hex': data.hex(' '),
            'ascii_preview': ''.join(chr(c) if 32 <= c <= 126 else '.' for c in data)}


def imports_view(inventory, dll_filter, symbol_filter, limit):
    modules = []
    hits = []
    for lib in inventory['imports']:
        if dll_filter and dll_filter.casefold() not in lib['dll'].casefold():
            continue
        modules.append({'dll': lib['dll'], 'symbol_count': len(lib['symbols'])})
        for sym in lib['symbols']:
            name = sym.get('name') or ''
            ordinal = sym.get('ordinal')
            if symbol_filter and symbol_filter.casefold() not in name.casefold() and (ordinal is None or symbol_filter != str(ordinal)):
                continue
            hits.append({'dll': lib['dll'], 'name': name or None, 'ordinal': ordinal,
                         'iat_preferred_va': hexa(sym['iat_va'])})
    return {'source': str(INVENTORY), 'modules': modules, 'symbols': limited(hits, limit),
            'note': 'Ordinary import directory snapshot only; IAT address is a slot, not the external function address.'}


def cpp_exports(root, query, limit):
    path = 'analysis/cpp-classes/cpp-symbols.csv'
    def matches():
        for row in rows(root, path, ('origin', 'decorated_symbol', 'demangled_prototype')):
            if row['origin'] == 'export' and (not query or query.casefold() in row['decorated_symbol'].casefold()
                                               or query.casefold() in row['demangled_prototype'].casefold()):
                yield row
    return {'source': path, 'symbols': limited(matches(), limit),
            'note': 'Only MSVC-decorated named exports in the saved C++ index; not a complete generic export directory parser.'}


def address_evidence(root, inventory, kind, address, limit, radius=0):
    mappings = map_address(inventory, kind, address)
    if kind == 'va':
        va = address
    elif kind == 'rva':
        va = inventory['image_base'] + address
    else:
        if len(mappings) != 1:
            raise ValueError('File offset must map to exactly one section to look up a preferred VA')
        va = int(mappings[0]['preferred_va'], 16)
    evidence = {}
    for label, (path, columns) in ADDRESS_TABLES.items():
        def matching():
            for row in rows(root, path, columns):
                found = []
                for col in columns:
                    try:
                        value = int(row[col], 0)
                        if abs(value - va) <= radius:
                            found.append({'field': col, 'value': hexa(value), 'delta_from_query': value - va})
                    except ValueError:
                        continue
                if found:
                    yield {'matched_fields': found, 'row': row}
        evidence[label] = {'source': path, **limited(matching(), limit)}
    def import_slots():
        for lib in inventory['imports']:
            for sym in lib['symbols']:
                value = sym['iat_va']
                if abs(value - va) <= radius:
                    yield {'dll': lib['dll'], 'name': sym['name'], 'ordinal': sym['ordinal'],
                           'iat_preferred_va': hexa(value), 'delta_from_query': value - va}
    evidence['imports_iat_slots'] = {'source': str(INVENTORY), **limited(import_slots(), limit)}
    return {'preferred_va': hexa(va), 'radius_bytes': radius, 'section_mappings': mappings, 'evidence': evidence,
            'note': 'Stored address fields within radius only; no inferred instruction boundaries, object range or runtime behavior.'}


def scan_pattern(raw, inventory, pattern, wanted):
    for sec in selected_sections(inventory, wanted):
        data = section_data(raw, sec)
        for offset in extra.pattern_offsets(data, pattern):
            yield location(inventory, sec, offset)


def scan_strings(raw, inventory, encodings, minimum, contains, nul_only, wanted, limit):
    groups = {}
    for encoding in encodings:
        def matches():
            for sec in selected_sections(inventory, wanted):
                data = section_data(raw, sec)
                for hit in extra.string_hits(data, encoding, minimum, contains, nul_only):
                    offset = hit.pop('offset')
                    yield dict(location(inventory, sec, offset), **hit)
        groups[encoding] = limited(matches(), limit)
    return groups


def section_statistics(raw, inventory, wanted):
    result = []
    for sec in selected_sections(inventory, wanted):
        stats = extra.statistics(section_data(raw, sec))
        stats.update({'section_index': sec['index'], 'section': sec['name'],
                      'raw_offset': hexa(sec['raw_offset']), 'rva': hexa(sec['virtual_address']),
                      'expected_sha256': sec['sha256'], 'matches_inventory_sha256': stats['sha256'] == sec['sha256']})
        result.append(stats)
    return result


def words(raw, inventory, kind, address, width, count, map_inventory=None):
    hit, data = region_bytes(raw, inventory, kind, address, width * count)
    base = int(hit['preferred_va'], 16)
    values = []
    for i in range(count):
        part = data[i * width:(i + 1) * width]
        value = int.from_bytes(part, 'little')
        row = {'index': i, 'slot_preferred_va': hexa(base + i * width), 'raw_hex': part.hex(' '),
               'unsigned': value, 'signed': int.from_bytes(part, 'little', signed=True), 'hex': hexa(value)}
        if width == 4:
            row['preferred_va_section_matches_if_pointer'] = map_address(map_inventory or inventory, 'va', value)
        values.append(row)
    return {'location': hit, 'width': width, 'count': count, 'values': values,
            'note': 'Little-endian interpretations only; mapped values are pointer candidates, not proven pointers.'}


def vtable_view(root, raw, inventory, map_inventory, va, count, limit):
    if count > 512:
        raise ValueError('--count must be at most 512 for vtable')
    table = words(raw, inventory, 'va', va, 4, count, map_inventory)
    path = 'analysis/cpp-classes/vtable-candidates.csv'
    entries = (r for r in rows(root, path, ('vtable_va',)) if int(r['vtable_va'], 16) == va)
    table['known_vtable_candidates'] = {'source': path, **limited(entries, limit)}
    table['preceding_u32'] = None
    if va >= 4:
        try:
            prev, prev_data = region_bytes(raw, inventory, 'va', va - 4, 4)
            if prev['section_index'] == table['location']['section_index']:
                value = int.from_bytes(prev_data, 'little')
                table['preceding_u32'] = {'location': prev, 'value': hexa(value),
                                          'section_matches_if_pointer': map_address(map_inventory, 'va', value)}
        except ValueError:
            pass
    table['note'] = ('User-selected number of 32-bit words; the actual vtable length is not inferred. '
                     'Preceding u32 is only a COL candidate when independently validated.')
    return table


def compare_bytes(raw, inventory, left_va, right_va, size, limit):
    left, a = region_bytes(raw, inventory, 'va', left_va, size)
    right, b = region_bytes(raw, inventory, 'va', right_va, size)
    changes = limited(({'offset': i, 'left_hex': f'{x:02X}', 'right_hex': f'{y:02X}'}
                       for i, (x, y) in enumerate(zip(a, b)) if x != y), limit)
    return {'left': left, 'right': right, 'size': size, 'identical': a == b,
            'left_sha256': digest(a), 'right_sha256': digest(b), 'differences': changes}


def disassemble(raw, inventory, kind, address, size, count, map_inventory=None):
    # Capstone is optional; installation never happens implicitly.
    sys.path.insert(0, str(ROOT / 'tooling/python'))
    try:
        import capstone
        from capstone.x86_const import X86_OP_IMM
    except ImportError as e:
        raise ValueError('Capstone unavailable; install capstone==5.0.9 into tooling/python via Python/pip') from e
    if inventory['machine'] != 0x14c:
        raise ValueError('Only x86 PE32 disassembly is supported')
    hit, data = region_bytes(raw, inventory, kind, address, size)
    va = int(hit['preferred_va'], 16)
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    instructions = []
    for ins in engine.disasm(data, va, count=count):
        immediates = []
        for op in ins.operands:
            if op.type == X86_OP_IMM:
                value = op.imm & 0xFFFFFFFF
                immediates.append({'value': hexa(value), 'section_matches_if_address': map_address(map_inventory or inventory, 'va', value)})
        instructions.append({'preferred_va': hexa(ins.address), 'size': ins.size, 'bytes': bytes(ins.bytes).hex(' '),
                             'mnemonic': ins.mnemonic, 'operands': ins.op_str, 'immediates': immediates})
    consumed = sum(x['size'] for x in instructions)
    return {'location': hit, 'bytes_provided': len(data), 'bytes_decoded': consumed,
            'remaining_bytes': len(data) - consumed, 'instruction_limit': count,
            'limit_reached': len(instructions) == count, 'instructions': instructions,
            'note': 'Linear decoding from the user-supplied start; no instruction-boundary, function, CFG, reachability or runtime validation.'}


def class_row(root, query):
    path, fields = DATA['classes']
    q = query.casefold()
    found = [r for r in rows(root, path, fields) if q in
             (r['display_name'].casefold(), r['decorated_name'].casefold(), r['type_descriptor_va'].casefold())]
    if len(found) != 1:
        raise ValueError(f'Expected one exact class; found {len(found)}. Use search first.')
    return found[0]


def type_uses(root, name, limit):
    paths = {'rtti_mentions': ('analysis/cpp-classes/rtti-type-references.csv', 'referenced_name_candidate'),
             'symbol_mentions': ('analysis/cpp-classes/symbol-type-references.csv', 'class_name_candidate')}
    result = {}
    for label, (path, field) in paths.items():
        hits = (r for r in rows(root, path, (field,)) if r[field].casefold() == name.casefold())
        result[label] = {'source': path, **limited(hits, limit)}
    result['note'] = 'Exact saved demangled spelling only; mentions are not proof of implementation or runtime use.'
    return result


def hierarchy(root, query, limit):
    owner = class_row(root, query)
    path = 'analysis/cpp-classes/base-descriptors.csv'
    grouped = {}
    for row in rows(root, path, ('hierarchy_va', 'owner_type_descriptor_va', 'contained_bases', 'index')):
        if row['owner_type_descriptor_va'].casefold() == owner['type_descriptor_va'].casefold():
            grouped.setdefault(row['hierarchy_va'], []).append(row)
    result = []
    for va, entries in grouped.items():
        entries.sort(key=lambda r: int(r['index']))
        nodes = advanced.hierarchy_nodes(entries)
        result.append({'hierarchy_va': va, 'nodes': limited(nodes, limit)})
    return {'owner': owner, 'source': path, 'hierarchies': result,
            'note': 'Parent indices inferred from MSVC preorder contained_bases spans; static candidate relationships, not runtime evidence.'}


def derived_classes(root, query, direct_only, limit):
    target = class_row(root, query)
    path = 'analysis/cpp-classes/base-descriptors.csv'
    grouped = {}
    for row in rows(root, path, ('hierarchy_va', 'owner_type_descriptor_va', 'base_type_descriptor_va', 'index', 'contained_bases')):
        grouped.setdefault(row['hierarchy_va'], []).append(row)
    def matches():
        for va, entries in grouped.items():
            if not any(r['base_type_descriptor_va'].casefold() == target['type_descriptor_va'].casefold()
                       and int(r['index']) > 0 for r in entries):
                continue
            entries.sort(key=lambda r: int(r['index']))
            for node in advanced.hierarchy_nodes(entries):
                r = node['base']
                if node['index'] == 0 or r['base_type_descriptor_va'].casefold() != target['type_descriptor_va'].casefold():
                    continue
                direct = node['parent_index_candidate'] == 0
                if direct_only and not direct: continue
                yield {'hierarchy_va': va, 'owner_type_descriptor_va': r['owner_type_descriptor_va'],
                       'base_entry_index': node['index'], 'parent_index_candidate': node['parent_index_candidate'],
                       'direct_base_candidate': direct, 'base': r}
    return {'target': target, 'source': path, 'matches': limited(matches(), limit),
            'note': 'Relations inferred from MSVC preorder spans; repeated base occurrences remain separate; not proof of runtime behavior.'}


def pointer_chain(raw, inventory, full_inventory, start, depth):
    if depth > 32: raise ValueError('Pointer-chain depth must be at most 32')
    current, seen, hops = start, set(), []
    reason = 'depth_limit'
    for _ in range(depth):
        if current == 0:
            reason = 'null_pointer'
            break
        if current in seen:
            reason = 'cycle_detected'
            break
        seen.add(current)
        try:
            loc, data = region_bytes(raw, inventory, 'va', current, 4)
        except ValueError as e:
            reason = 'not_readable_in_selected_raw_sections'
            return {'start_preferred_va': hexa(start), 'hops': hops, 'stop_reason': reason,
                    'stop_preferred_va': hexa(current), 'stop_section_mappings': map_address(full_inventory, 'va', current),
                    'detail': str(e), 'note': 'Raw preferred-VA u32 values; not relocated runtime pointers.'}
        value = int.from_bytes(data, 'little')
        hops.append({'slot': loc, 'raw_hex': data.hex(' '), 'value': hexa(value),
                     'target_section_mappings': map_address(full_inventory, 'va', value)})
        current = value
    return {'start_preferred_va': hexa(start), 'hops': hops, 'stop_reason': reason,
            'stop_preferred_va': hexa(current), 'stop_section_mappings': map_address(full_inventory, 'va', current),
            'note': 'Raw preferred-VA u32 values; not relocated runtime pointers.'}


def section_strings(raw, inventory, kind, address, encoding, maximum):
    mappings = map_address(inventory, kind, address)
    if len(mappings) != 1 or mappings[0]['file_offset'] is None:
        raise ValueError('String start must map to one raw-backed section')
    loc = mappings[0]
    sec = next(s for s in inventory['sections'] if s['index'] == loc['section_index'])
    pos = int(loc['section_offset'], 16)
    data = section_data(raw, sec)[pos:pos+maximum]
    width = 2 if encoding in ('utf-16le', 'utf-16be') else 1
    end = None
    for i in range(0, len(data) - width + 1, width):
        if data[i:i+width] == b'\0' * width:
            end = i
            break
    content = data[:end] if end is not None else data
    try:
        text = content.decode(encoding)
        valid = True
    except UnicodeDecodeError:
        text = content.decode(encoding, 'replace')
        valid = False
    reason = 'nul_terminator' if end is not None else ('section_end' if pos + len(data) == sec['raw_size'] else 'max_bytes')
    return {'location': loc, 'encoding': encoding, 'bytes_before_terminator': len(content),
            'terminator_found': end is not None, 'stop_reason': reason, 'valid_encoding': valid,
            'text_preview': text[:512], 'preview_truncated': len(text) > 512,
            'raw_preview_hex': content[:64].hex(' '), 'content_sha256': digest(content)}


def signatures(raw, inventory, names, section, limit):
    output = {}
    for name in names:
        needle, description = advanced.SIGNATURES[name]
        output[name] = {'signature_hex': needle.hex(' '), 'description': description,
                        **limited(find_bytes(raw, inventory, needle, section), limit)}
    return output


def entropy_windows(raw, inventory, section, width, step, partial, lo, hi, limit):
    if width > 1048576 or step > 1048576: raise ValueError('Window and step must not exceed 1 MiB')
    if not (0 <= lo <= hi <= 8): raise ValueError('Entropy bounds must satisfy 0 <= min <= max <= 8')
    secs = selected_sections(inventory, section)
    count = sum(advanced.window_count(s['raw_size'], width, step, partial) for s in secs)
    if count > 100000: raise ValueError('More than 100000 windows; increase --step or restrict section')
    def hits():
        for sec in secs:
            for window in advanced.window_stats(section_data(raw, sec), width, step, partial, lo, hi):
                offset = window.pop('offset')
                yield dict(location(inventory, sec, offset), **window)
    return {'windows_evaluated': count, 'width': width, 'step': step, 'include_partial': partial,
            'entropy_min': lo, 'entropy_max': hi, 'matches': limited(hits(), limit),
            'note': 'Shannon entropy is descriptive, not proof of compression or encryption.'}


def int_search(raw, inventory, value, widths, endian, section, limit):
    output = {}
    for width, order, pattern in advanced.int_encodings(value, widths, endian):
        key = f'{width * 8}bit_{order}'
        output[key] = {'pattern_hex': pattern.hex(' '), **limited(find_bytes(raw, inventory, pattern, section), limit)}
    return {'value': value, 'groups': output, 'note': 'Unaligned raw-byte matches; not proven pointers or instructions.'}


def scan_runs(raw, inventory, section, minimum, byte_value):
    for sec in selected_sections(inventory, section):
        for run in advanced.byte_runs(section_data(raw, sec), minimum, byte_value):
            offset = run.pop('offset')
            yield dict(location(inventory, sec, offset), **run)


def overview(root, inventory):
    classes = list(rows(root, DATA['classes'][0], ('kind', 'evidence', 'demangle_status')))
    api = list(rows(root, DATA['api'][0], ('highest_observed_evidence_not_runtime_proof',)))
    return {'section_count': len(inventory['sections']), 'raw_section_bytes_sum': sum(s['raw_size'] for s in inventory['sections']),
            'imports_modules': len(inventory['imports']), 'imports_entries': sum(len(x['symbols']) for x in inventory['imports']),
            'rtti_records': len(classes), 'rtti_kind': dict(sorted(Counter(x['kind'] for x in classes).items())),
            'rtti_evidence': dict(sorted(Counter(x['evidence'] for x in classes).items())),
            'demangle_status': dict(sorted(Counter(x['demangle_status'] for x in classes).items())),
            'api_records': len(api), 'api_evidence': dict(sorted(Counter(x['highest_observed_evidence_not_runtime_proof'] for x in api).items())),
            'csv_tables': len(advanced.catalog(root)), 'sources': [str(INVENTORY), DATA['classes'][0], DATA['api'][0]],
            'note': 'Counts from saved indexes; no semantic uniqueness, completeness or runtime validation implied.'}


def compare_extracted(root, inventory, exe_path):
    raw = verify_exe(root, inventory, exe_path)
    extracted = read_extracted(root, inventory)
    result = []
    for sec in inventory['sections']:
        if sec['index'] not in extracted: continue
        data = extracted[sec['index']]
        start = sec['raw_offset']
        result.append({'section_index': sec['index'], 'section': sec['name'], 'size': len(data),
                       'matches_exe_bytes': raw[start:start+len(data)] == data})
    return {'sections_checked': len(result), 'all_equal': all(x['matches_exe_bytes'] for x in result),
            'sections': result, 'note': 'Compares supplied extracted sections against the verified EXE only.'}


def compare_sections(raw, inventory, left, right, limit):
    a, b = selected_sections(inventory, left), selected_sections(inventory, right)
    if len(a) != 1 or len(b) != 1:
        raise ValueError('Each section selector must identify exactly one section')
    result = advanced.section_diff(section_data(raw, a[0]), section_data(raw, b[0]), limit)
    result.update({'left_section_index': a[0]['index'], 'right_section_index': b[0]['index'],
                   'left_section': a[0]['name'], 'right_section': b[0]['name'],
                   'note': 'Byte comparisons by section-relative offset; different layouts can make comparisons misleading.'})
    return result


def audit_class(root, raw, inventory, query, limit):
    profile = class_profile(root, query, limit)
    owner = profile['class']
    checks = []
    class EvidenceUnavailable(Exception):
        pass
    def read(va, size):
        try:
            return region_bytes(raw, inventory, 'va', va, size)[1]
        except ValueError as e:
            raise EvidenceUnavailable(str(e)) from e
    def check(kind, va, fn):
        try:
            details = fn()
            ok = all(details.values())
            checks.append({'kind': kind, 'preferred_va': hexa(va), 'status': 'match' if ok else 'mismatch', 'fields': details})
        except EvidenceUnavailable as e:
            checks.append({'kind': kind, 'preferred_va': hexa(va), 'status': 'unavailable', 'detail': str(e)})
        except (ValueError, KeyError, struct.error) as e:
            checks.append({'kind': kind, 'preferred_va': hexa(va), 'status': 'mismatch', 'detail': 'Malformed stored field: ' + str(e)})
    td = int(owner['type_descriptor_va'], 16)
    def type_check():
        raw_header = read(td, 8)
        name = read(td + 8, len(owner['decorated_name'].encode('ascii')) + 1)
        ptr, spare = struct.unpack('<II', raw_header)
        return {'type_info_vftable': ptr == int(owner['vftable_pointer'], 16),
                'spare': spare == int(owner['spare'], 16), 'name_va': td + 8 == int(owner['name_va'], 16),
                'decorated_name_and_nul': name == owner['decorated_name'].encode('ascii') + b'\0'}
    check('type_descriptor', td, type_check)
    for row in profile['cols']['items']:
        va = int(row['col_va'], 16)
        def col_check(row=row, va=va):
            data = read(va, 20)
            sig, offset, cd, typeptr, ch = struct.unpack('<IIIII', data)
            return {'signature_zero': sig == 0, 'object_offset': offset == int(row['object_offset'], 16),
                    'cd_offset': cd == int(row['cd_offset'], 16), 'type_descriptor': typeptr == int(row['type_descriptor_va'], 16),
                    'hierarchy': ch == int(row['hierarchy_va'], 16)}
        check('col', va, col_check)
    for row in profile['vtables']['items']:
        va = int(row['vtable_va'], 16)
        def vtable_check(row=row, va=va):
            data = read(va-4, 8)
            col, first = struct.unpack('<II', data)
            return {'preceding_col': col == int(row['col_va'], 16), 'first_slot': first == int(row['first_slot_va'], 16)}
        check('vtable_candidate', va, vtable_check)
    for row in profile['bases']['items']:
        va = int(row['base_descriptor_va'], 16)
        def base_check(row=row, va=va):
            data = read(va, 24)
            fields = struct.unpack('<IIiiiI', data)
            expected = (int(row['base_type_descriptor_va'], 16), int(row['contained_bases']), int(row['mdisp']),
                        int(row['pdisp']), int(row['vdisp']), int(row['attributes'], 16))
            return {key: actual == wanted for key, actual, wanted in zip(('type', 'contained', 'mdisp', 'pdisp', 'vdisp', 'attributes'), fields, expected)}
        check('base_descriptor', va, base_check)
    counts = {status: sum(x['status'] == status for x in checks) for status in ('match', 'mismatch', 'unavailable')}
    truncated = any(profile[key]['truncated'] for key in ('cols', 'vtables', 'bases'))
    complete = not truncated and counts['unavailable'] == 0
    return {'owner': owner, 'counts': counts, 'truncated': truncated,
            'complete': complete, 'all_match': complete and counts['mismatch'] == 0, 'checks': checks,
            'note': 'Compares saved RTTI/COL/vtable/base candidate fields to raw bytes; no proof of runtime behavior or class completeness.'}


def byte_source(root, inventory, exe_path, extracted):
    if extracted:
        if exe_path is not None:
            raise ValueError('--exe and extracted byte source cannot be combined')
        raw = read_extracted(root, inventory)
        scoped = dict(inventory, sections=[s for s in inventory['sections'] if s['index'] in raw])
        coverage = {'source': 'verified extracted section files only', 'section_count': len(scoped['sections']),
                    'section_indices': [s['index'] for s in scoped['sections']], 'all_pe_sections': False}
    else:
        raw = verify_exe(root, inventory, exe_path)
        scoped = inventory
        coverage = {'source': 'SHA-256 verified EXE', 'section_count': len(scoped['sections']), 'all_pe_sections': True}
    return raw, scoped, coverage


def triage(root, inventory, query, limit, byte_mode, refs, exe_path):
    if not query:
        raise ValueError('Empty search query is not allowed')
    if refs and byte_mode == 'none':
        raise ValueError('--refs requires --bytes exe or --bytes extracted')
    result = {'query': query, 'index_search': search(root, query, list(DATA), limit),
              'exact_class_profile': None, 'exact_api_profile': None}
    cls_path, cls_fields = DATA['classes']
    matches = [r for r in rows(root, cls_path, cls_fields) if query.casefold() in
               (r['display_name'].casefold(), r['decorated_name'].casefold(), r['type_descriptor_va'].casefold())]
    if len(matches) == 1:
        result['exact_class_profile'] = class_profile(root, query, limit)
    api_path, api_fields = DATA['api']
    if any(r['api_path'].casefold() == query.casefold() for r in rows(root, api_path, api_fields)):
        result['exact_api_profile'] = api_profile(root, query, limit)
    if refs and len(matches) != 1:
        raise ValueError('--refs requires a unique exact RTTI class name or descriptor VA')
    if byte_mode != 'none':
        raw, scoped, coverage = byte_source(root, inventory, exe_path, byte_mode == 'extracted')
        result['byte_search'] = {'coverage': coverage, 'note': 'Literal non-NUL-terminated raw bytes; not proof of runtime use.', 'encodings': {}}
        for encoding in ('utf-8', 'utf-16le', 'utf-16be'):
            data = query.encode(encoding)
            result['byte_search']['encodings'][encoding] = {'pattern_hex': data.hex(' '),
                                                            **limited(find_bytes(raw, scoped, data), limit)}
        if refs:
            target = int(matches[0]['type_descriptor_va'], 16)
            result['descriptor_references'] = {'target_preferred_va': hexa(target), 'coverage': coverage,
                                               'groups': group_refs(raw_refs(raw, scoped, target), limit),
                                               'note': 'Raw candidate bytes, not verified instruction boundaries or runtime proof.'}
    return result


def parse_hex(value):
    try:
        data = bytes.fromhex(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError('Expected hexadecimal bytes, e.g. "DE AD BE EF"') from e
    if not data:
        raise argparse.ArgumentTypeError('Pattern must not be empty')
    return data


def add_address(group):
    group.add_argument('--va', type=integer, help='preferred VA, not runtime VA')
    group.add_argument('--rva', type=integer)
    group.add_argument('--file', type=integer, help='file offset')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=ROOT, help='repository root')
    p.add_argument('--exe', type=Path, help='path to known EXE (SHA-256 verified before reading bytes)')
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('doctor', help='check indexes, manifest, section files and optional EXE')
    s.add_argument('--require-exe', action='store_true')
    sub.add_parser('sections', help='list the recorded raw/virtual PE section ranges')
    sub.add_parser('overview', help='summarize saved C++ / API / PE inventory counts')
    sub.add_parser('compare-sections', help='byte-compare extracted sections against the verified EXE')
    sub.add_parser('pe-headers', help='parse PE32 headers directly from the verified EXE')
    s = sub.add_parser('pe-exports', help='parse named, ordinal-only and forwarded exports from verified PE32')
    s.add_argument('--query', help='case-insensitive name/forwarder substring or exact ordinal')
    s.add_argument('--limit', type=positive, default=50)
    s = sub.add_parser('pack', help='pack numeric values into an explicit binary layout without reading the EXE')
    s.add_argument('--layout', required=True, help='e.g. u32,i16,ptr32,pad[2],f32')
    s.add_argument('--value', action='append', default=[], help='one value per non-padding field, repeat in order')
    s.add_argument('--endian', choices=('little', 'big'), default='little')
    sub.add_parser('tables', help='list queryable CSV files under analysis/')
    s = sub.add_parser('schema', help='show column names for one analysis CSV')
    s.add_argument('table', help='exact path from tables')
    s = sub.add_parser('table', help='filter, select, sort and paginate an analysis CSV')
    s.add_argument('table', help='exact path from tables')
    s.add_argument('--where', nargs=3, action='append', default=[], metavar=('COLUMN', 'OP', 'VALUE'))
    s.add_argument('--select', action='append', default=[], help='column to return; repeat as needed')
    s.add_argument('--ignore-case', action='store_true')
    s.add_argument('--sort', help='sort column (up to 150000 matches)')
    s.add_argument('--numeric-sort', action='store_true')
    s.add_argument('--descending', action='store_true')
    s.add_argument('--offset', type=integer, default=0)
    s.add_argument('--limit', type=positive, default=50)
    s = sub.add_parser('group', help='count distinct column values of an analysis CSV')
    s.add_argument('table', help='exact path from tables')
    s.add_argument('--column', required=True)
    s.add_argument('--where', nargs=3, action='append', default=[], metavar=('COLUMN', 'OP', 'VALUE'))
    s.add_argument('--ignore-case', action='store_true')
    s.add_argument('--limit', type=positive, default=50)
    sub.add_parser('layout', help='inspect section intervals, overlaps and file gaps from metadata')
    s = sub.add_parser('int-info', help='show integer signed/unsigned, endian and bit interpretations')
    s.add_argument('value', type=signed_integer)
    s.add_argument('--width', type=int, choices=(1, 2, 4, 8), default=4)
    s = sub.add_parser('float-info', help='inspect IEEE-754 values or bit patterns')
    s.add_argument('--width', type=int, choices=(4, 8), default=4)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument('--value', type=float)
    g.add_argument('--bits', type=integer)
    s = sub.add_parser('uses', help='find exact type mentions even without a matching RTTI descriptor')
    s.add_argument('name')
    s.add_argument('--limit', type=positive, default=50)
    s = sub.add_parser('hierarchy', help='reconstruct candidate RTTI preorder parent relationships')
    s.add_argument('query', help='exact class name, decorated name, or TypeDescriptor VA')
    s.add_argument('--limit', type=positive, default=50)
    s = sub.add_parser('derived', help='find candidate derived classes for an RTTI type')
    s.add_argument('query', help='exact class name, decorated name, or TypeDescriptor VA')
    s.add_argument('--direct', action='store_true', help='only candidate direct bases')
    s.add_argument('--limit', type=positive, default=50)
    s = sub.add_parser('imports', help='browse saved ordinary DLL imports and IAT addresses')
    s.add_argument('--dll', help='case-insensitive DLL substring')
    s.add_argument('--symbol', help='case-insensitive symbol substring or exact ordinal')
    s.add_argument('--limit', type=positive, default=50)
    s = sub.add_parser('cpp-exports', help='browse MSVC-decorated exports from the saved index')
    s.add_argument('--query', help='case-insensitive substring in decorated name or prototype')
    s.add_argument('--limit', type=positive, default=50)
    s = sub.add_parser('triage', help='combine index search, exact profiles, and optional raw-byte search')
    s.add_argument('query')
    s.add_argument('--limit', type=positive, default=5, help='max results per table / byte encoding / reference kind')
    s.add_argument('--bytes', choices=('none', 'exe', 'extracted'), default='none', help='optional raw byte search source')
    s.add_argument('--refs', action='store_true', help='search references for a unique exact RTTI class; requires --bytes')
    s = sub.add_parser('search', help='case-insensitive substring search across existing evidence tables')
    s.add_argument('query')
    s.add_argument('--source', choices=tuple(DATA), action='append', help='repeat to choose sources; default all')
    s.add_argument('--limit', type=positive, default=20, help='max returned per source; total is always counted')
    s = sub.add_parser('class', help='exact RTTI class profile and related evidence')
    s.add_argument('query', help='full demangled/decorated name or descriptor VA')
    s.add_argument('--limit', type=positive, default=50, help='max returned per related table')
    s = sub.add_parser('api', help='exact API evidence and proxy/registration candidates')
    s.add_argument('path')
    s.add_argument('--limit', type=positive, default=50)
    s = sub.add_parser('map', help='convert address using the recorded section table')
    add_address(s.add_mutually_exclusive_group(required=True))
    s = sub.add_parser('at', help='look up an address in known C++/API/other evidence tables')
    add_address(s.add_mutually_exclusive_group(required=True))
    s.add_argument('--limit', type=positive, default=20, help='max results per evidence table')
    s.add_argument('--radius', type=integer, default=0, help='include stored VA values within this many bytes (max 0x100000)')
    s = sub.add_parser('signatures', help='search known magic-byte candidates or list signatures')
    s.add_argument('--list', action='store_true', help='list supported signatures without reading bytes')
    s.add_argument('--name', choices=tuple(advanced.SIGNATURES), action='append', help='repeat to select signatures')
    s.add_argument('--section')
    s.add_argument('--limit', type=positive, default=20)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('windows', help='measure entropy in raw sliding windows within one section')
    s.add_argument('--section', required=True)
    s.add_argument('--window', type=bounded_size, default=4096)
    s.add_argument('--step', type=bounded_size, default=4096)
    s.add_argument('--partial', action='store_true')
    s.add_argument('--min-entropy', type=float, default=0.0)
    s.add_argument('--max-entropy', type=float, default=8.0)
    s.add_argument('--limit', type=positive, default=50)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('int-find', help='search signed/unsigned integer byte encodings in raw sections')
    s.add_argument('value', type=signed_integer)
    s.add_argument('--width', type=int, choices=(1, 2, 4, 8), action='append', help='bytes; repeat for several widths')
    s.add_argument('--endian', choices=('little', 'big', 'both'), default='little')
    s.add_argument('--section')
    s.add_argument('--limit', type=positive, default=50)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('hash', help='hash a bounded raw byte range with multiple algorithms')
    add_address(s.add_mutually_exclusive_group(required=True))
    s.add_argument('--size', type=bounded_size, default=64)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('unpack', help='decode an explicitly specified packed binary layout')
    add_address(s.add_mutually_exclusive_group(required=True))
    s.add_argument('--layout', required=True, help='e.g. u32,i16,ptr32,pad[2],f32')
    s.add_argument('--endian', choices=('little', 'big'), default='little')
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('cstring', help='read one bounded NUL-terminated text candidate')
    add_address(s.add_mutually_exclusive_group(required=True))
    s.add_argument('--encoding', choices=('ascii', 'utf-8', 'latin-1', 'utf-16le', 'utf-16be'), default='ascii')
    s.add_argument('--max-bytes', type=bounded_size, default=4096)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('chain', help='follow bounded raw PE32 pointer candidates')
    s.add_argument('--va', type=integer, required=True)
    s.add_argument('--depth', type=positive, default=8)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('probe', help='bounded zlib/gzip/raw-DEFLATE decompression probe')
    add_address(s.add_mutually_exclusive_group(required=True))
    s.add_argument('--size', type=bounded_size, default=4096, help='maximum input bytes')
    s.add_argument('--max-output', type=bounded_size, default=65536)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('transform', help='apply bounded byte transformations without writing files')
    add_address(s.add_mutually_exclusive_group(required=True))
    s.add_argument('--size', type=positive, default=64, help='max 4096 bytes')
    s.add_argument('--operation', choices=('xor', 'not', 'rotl', 'rotr', 'reverse', 'swap16', 'swap32'), required=True)
    s.add_argument('--key', type=integer, default=0, help='byte XOR key or rotation count')
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('xor-rank', help='rank single-byte XOR keys by printable-byte frequency')
    add_address(s.add_mutually_exclusive_group(required=True))
    s.add_argument('--size', type=positive, default=64, help='max 4096 bytes')
    s.add_argument('--limit', type=positive, default=10, help='max 256 results')
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('frequencies', help='count byte frequencies within one verified raw section')
    s.add_argument('--section', required=True)
    s.add_argument('--limit', type=positive, default=32)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('runs', help='find maximal repeated-byte runs')
    s.add_argument('--section', required=True)
    s.add_argument('--min-length', type=bounded_size, default=32)
    s.add_argument('--value', type=integer, help='restrict to a byte value 0..255')
    s.add_argument('--limit', type=positive, default=50)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('section-diff', help='compare two raw sections by section-relative offset')
    s.add_argument('--left', required=True, help='left section name/index')
    s.add_argument('--right', required=True, help='right section name/index')
    s.add_argument('--limit', type=positive, default=50)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('audit-class', help='compare saved class evidence with source bytes')
    s.add_argument('query', help='exact class name or TypeDescriptor VA')
    s.add_argument('--limit', type=positive, default=50, help='max COL/vtable/base rows per category')
    s.add_argument('--require-complete', action='store_true', help='fail if source sections or results are incomplete')
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('stats', help='measure entropy and byte statistics for verified raw sections')
    s.add_argument('--section', help='name or PE section index')
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('strings', help='extract printable ASCII / UTF-16 ASCII-range runs from raw sections')
    s.add_argument('--encoding', choices=('all', 'ascii', 'utf-16le', 'utf-16be'), default='all')
    s.add_argument('--min-length', type=positive, default=4)
    s.add_argument('--contains', help='case-insensitive substring filter')
    s.add_argument('--nul', action='store_true', help='only NUL-terminated runs')
    s.add_argument('--section', help='name or PE section index')
    s.add_argument('--limit', type=positive, default=50, help='max results per encoding')
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('pattern', help='find overlapping wildcard byte patterns')
    s.add_argument('pattern', help='space-separated hex bytes and ?? wildcards, e.g. "E8 ?? ?? ?? ?? 83 C4"')
    s.add_argument('--section', help='name or PE section index')
    s.add_argument('--limit', type=positive, default=50)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('words', help='interpret little-endian values at a raw-backed address')
    add_address(s.add_mutually_exclusive_group(required=True))
    s.add_argument('--width', type=int, choices=(1, 2, 4, 8), default=4)
    s.add_argument('--count', type=positive, default=8, help='max 512 values')
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('vtable', help='inspect candidate vtable slots and any saved metadata')
    s.add_argument('--va', type=integer, required=True, help='preferred VA of first slot')
    s.add_argument('--count', type=positive, default=8, help='number of slots, max 512; actual length is not inferred')
    s.add_argument('--limit', type=positive, default=20)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('diff', help='compare two raw-backed preferred-VA byte ranges')
    s.add_argument('--left-va', type=integer, required=True)
    s.add_argument('--right-va', type=integer, required=True)
    s.add_argument('--size', type=positive, default=64)
    s.add_argument('--limit', type=positive, default=50)
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('disasm', help='linearly decode x86 from a supplied address (optional Capstone)')
    add_address(s.add_mutually_exclusive_group(required=True))
    s.add_argument('--size', type=positive, default=128, help='bytes to decode, max 4096')
    s.add_argument('--count', type=positive, default=32, help='max instructions, at most 512')
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('dump', help='read raw bytes from exactly one section of the verified EXE')
    add_address(s.add_mutually_exclusive_group(required=True))
    s.add_argument('--size', type=positive, default=64, help='number of bytes, max 10000, no cross-section reads')
    s.add_argument('--extracted', action='store_true', help='use only verified extracted section files, not the EXE')
    s = sub.add_parser('find', help='search raw section bytes of the verified EXE')
    spec = s.add_mutually_exclusive_group(required=True)
    spec.add_argument('--text', help='literal text (no implied NUL)')
    spec.add_argument('--hex', type=parse_hex, help='hexadecimal byte pattern')
    s.add_argument('--encoding', choices=('ascii', 'utf-8', 'utf-16le', 'utf-16be'), default='ascii')
    s.add_argument('--nul', action='store_true', help='append the encoding-appropriate NUL to text')
    s.add_argument('--section', help='name or PE section index')
    s.add_argument('--limit', type=positive, default=50)
    s.add_argument('--extracted', action='store_true', help='use only verified extracted section files, not the EXE')
    s = sub.add_parser('trace-string', help='find literal byte occurrences and raw references to their start addresses')
    s.add_argument('--text', required=True)
    s.add_argument('--encoding', choices=('ascii', 'utf-8', 'utf-16le', 'utf-16be'), default='ascii')
    s.add_argument('--nul', action='store_true')
    s.add_argument('--string-section', help='restrict literal search to one section')
    s.add_argument('--reference-section', help='restrict raw reference search to one section')
    s.add_argument('--max-targets', type=positive, default=3, help='number of occurrences to trace, max 10')
    s.add_argument('--limit', type=positive, default=20, help='max references per kind per occurrence')
    s.add_argument('--extracted', action='store_true')
    s = sub.add_parser('refs', help='find raw u32, E8/E9 and FF15/FF25 candidate references to a preferred VA')
    s.add_argument('target_va', type=integer)
    s.add_argument('--section', help='name or PE section index')
    s.add_argument('--limit', type=positive, default=50, help='max results per reference kind')
    s.add_argument('--extracted', action='store_true', help='use only verified extracted section files, not the EXE')
    args = p.parse_args(argv)
    try:
        root = args.root.resolve()
        inv = context(root)
        common = {'image_sha256': inv['sha256'], 'image_base': hexa(inv['image_base']),
                  'address_warning': 'preferred VAs use the recorded image base, not runtime/ASLR addresses',
                  'evidence_warning': 'Static indexes and raw hits can be incomplete, stale, or heuristic; not runtime proof.'}
        if args.command == 'doctor':
            result = status(root, inv, args.exe, args.require_exe)
        elif args.command == 'sections':
            result = {'source': str(INVENTORY), 'sections': inv['sections']}
        elif args.command == 'overview':
            result = overview(root, inv)
        elif args.command == 'compare-sections':
            result = compare_extracted(root, inv, args.exe)
        elif args.command in ('pe-headers', 'pe-exports'):
            raw = verify_exe(root, inv, args.exe)
            header = advanced.parse_pe_headers(raw)
            if args.command == 'pe-headers':
                keys = ('index', 'raw_name_hex', 'virtual_address', 'virtual_size', 'raw_offset', 'raw_size', 'characteristics')
                header['sections_match_inventory'] = len(header['sections']) == len(inv['sections']) and all(
                    all(a[k] == b[k] for k in keys) for a, b in zip(header['sections'], inv['sections']))
                header['machine_matches_inventory'] = header['machine'] == inv['machine']
                header['image_base_matches_inventory'] = header['image_base'] == inv['image_base']
                result = header
            else:
                exports = advanced.parse_pe_exports(raw, header)
                query = (args.query or '').casefold()
                matched = (x for x in exports if not query or query in (x['name'] or '').casefold()
                           or query in (x['forwarder'] or '').casefold() or query == str(x['ordinal']))
                result = {'exports': limited(matched, args.limit), 'export_records_unfiltered': len(exports),
                          'note': 'PE32 export directory only; forwarded exports are names, not local function addresses.'}
        elif args.command == 'pack':
            layout = advanced.parse_layout(args.layout)
            data = advanced.pack_layout(layout, args.value, args.endian)
            result = {'layout': args.layout, 'endian': args.endian, 'size': len(data), 'hex': data.hex(' '),
                      'sha256': digest(data), 'note': 'User-specified packed fields; padding is zero.'}
        elif args.command == 'tables':
            result = {'scope': 'analysis/**/*.csv', 'tables': advanced.catalog(root)}
        elif args.command == 'schema':
            result = {'source': args.table, 'columns': advanced.table_header(advanced.table_path(root, args.table))}
        elif args.command == 'table':
            result = advanced.table_query(root, args.table, args.where, args.select, args.ignore_case, args.sort,
                                          args.numeric_sort, args.descending, args.offset, args.limit)
        elif args.command == 'group':
            result = advanced.table_group(root, args.table, args.column, args.where, args.ignore_case, args.limit)
        elif args.command == 'layout':
            result = advanced.layout_report(inv)
        elif args.command == 'int-info':
            result = advanced.integer_info(args.value, args.width)
        elif args.command == 'float-info':
            result = advanced.float_info(args.width, args.value, args.bits)
        elif args.command == 'uses':
            if not args.name: raise ValueError('Empty name is not allowed')
            result = type_uses(root, args.name, args.limit)
        elif args.command == 'hierarchy':
            result = hierarchy(root, args.query, args.limit)
        elif args.command == 'derived':
            result = derived_classes(root, args.query, args.direct, args.limit)
        elif args.command == 'signatures' and args.list:
            selected = list(dict.fromkeys(args.name or advanced.SIGNATURES))
            result = {'signatures': [{'name': k, 'hex': advanced.SIGNATURES[k][0].hex(' '),
                                      'description': advanced.SIGNATURES[k][1]} for k in selected],
                      'note': 'Magic-byte candidates, not validated formats.'}
        elif args.command == 'imports':
            result = imports_view(inv, args.dll, args.symbol, args.limit)
        elif args.command == 'cpp-exports':
            result = cpp_exports(root, args.query, args.limit)
        elif args.command == 'triage':
            result = triage(root, inv, args.query, args.limit, args.bytes, args.refs, args.exe)
        elif args.command == 'search':
            if not args.query: raise ValueError('Empty search query is not allowed')
            result = search(root, args.query, list(dict.fromkeys(args.source or DATA)), args.limit)
        elif args.command == 'class': result = class_profile(root, args.query, args.limit)
        elif args.command == 'api': result = api_profile(root, args.path, args.limit)
        elif args.command == 'map':
            kind = next(k for k in ('va', 'rva', 'file') if getattr(args, k) is not None)
            result = {'input_kind': kind, 'input': hexa(getattr(args, kind)), 'matches': map_address(inv, kind, getattr(args, kind)),
                      'note': 'Unmapped headers/overlay and gaps produce no matches; virtual tails have no file offset.'}
        elif args.command == 'at':
            if args.radius > 0x100000: raise ValueError('--radius must be at most 0x100000')
            kind = next(k for k in ('va', 'rva', 'file') if getattr(args, k) is not None)
            result = address_evidence(root, inv, kind, getattr(args, kind), args.limit, args.radius)
        elif args.command in ('find', 'dump', 'refs', 'stats', 'strings', 'pattern', 'words', 'vtable', 'diff', 'disasm', 'trace-string',
                               'signatures', 'windows', 'int-find', 'hash', 'unpack', 'cstring', 'chain', 'probe', 'transform', 'xor-rank',
                               'frequencies', 'runs', 'section-diff', 'audit-class'):
            map_inventory = inv
            raw, inv, coverage = byte_source(root, inv, args.exe, args.extracted)
            if args.command == 'frequencies':
                secs = selected_sections(inv, args.section)
                if len(secs) != 1: raise ValueError('Select exactly one section')
                result = advanced.frequencies(section_data(raw, secs[0]), args.limit)
                result.update({'section_index': secs[0]['index'], 'section': secs[0]['name']})
            elif args.command == 'runs':
                result = {'minimum_length': args.min_length, 'byte_filter': hexa(args.value) if args.value is not None else None,
                          'runs': limited(scan_runs(raw, inv, args.section, args.min_length, args.value), args.limit)}
            elif args.command == 'section-diff':
                result = compare_sections(raw, inv, args.left, args.right, args.limit)
            elif args.command == 'audit-class':
                result = audit_class(root, raw, inv, args.query, args.limit)
            elif args.command == 'signatures':
                names = list(dict.fromkeys(args.name or advanced.SIGNATURES))
                result = {'groups': signatures(raw, inv, names, args.section, args.limit),
                          'note': 'Raw magic-byte candidates only; no embedded format or payload validation.'}
            elif args.command == 'windows':
                result = entropy_windows(raw, inv, args.section, args.window, args.step, args.partial,
                                         args.min_entropy, args.max_entropy, args.limit)
            elif args.command == 'int-find':
                result = int_search(raw, inv, args.value, list(dict.fromkeys(args.width or [4])), args.endian, args.section, args.limit)
            elif args.command in ('hash', 'unpack', 'cstring', 'probe', 'transform', 'xor-rank'):
                kind = next(k for k in ('va', 'rva', 'file') if getattr(args, k) is not None)
                address = getattr(args, kind)
                if args.command == 'cstring':
                    result = section_strings(raw, inv, kind, address, args.encoding, args.max_bytes)
                elif args.command == 'unpack':
                    layout = advanced.parse_layout(args.layout)
                    loc, data = region_bytes(raw, inv, kind, address, sum(f[2] for f in layout))
                    fields = advanced.unpack_layout(data, layout, args.endian)
                    for field in fields:
                        field['preferred_va'] = hexa(int(loc['preferred_va'], 16) + field['offset'])
                        if field['type'] == 'ptr32':
                            field['section_matches_if_pointer'] = map_address(map_inventory, 'va', field['value'])
                    result = {'location': loc, 'endian': args.endian, 'fields': fields,
                              'note': 'Packed layout supplied by user; pointer and field interpretations are not validated.'}
                else:
                    if args.command in ('transform', 'xor-rank') and args.size > 4096:
                        raise ValueError('transform/xor-rank support at most 4096 input bytes')
                    loc, data = region_bytes(raw, inv, kind, address, args.size)
                    if args.command == 'hash':
                        result = {'location': loc, 'hashes': advanced.hash_bytes(data)}
                    elif args.command == 'probe':
                        result = {'location': loc, 'input_size': len(data), 'max_output': args.max_output,
                                  'formats': advanced.compression_probe(data, args.max_output)}
                    elif args.command == 'transform':
                        output = advanced.transform(data, args.operation, args.key)
                        result = {'location': loc, 'operation': args.operation, 'key': args.key,
                                  'input_sha256': digest(data), 'output_sha256': digest(output),
                                  'output_hex': output.hex(' '), 'note': 'Byte transformation only; interpretation is unproven.'}
                    else:
                        if args.limit > 256: raise ValueError('xor-rank limit must be at most 256')
                        result = {'location': loc, 'keys_tested': 256, 'ranked': advanced.xor_rank(data, args.limit),
                                  'note': 'Printable-byte score is only a heuristic; it does not prove encryption or plaintext.'}
            elif args.command == 'chain':
                result = pointer_chain(raw, inv, map_inventory, args.va, args.depth)
            elif args.command == 'stats':
                result = {'sections': section_statistics(raw, inv, args.section),
                          'note': 'Raw-byte statistics; entropy alone does not prove compression or encryption.'}
            elif args.command == 'strings':
                encodings = ('ascii', 'utf-16le', 'utf-16be') if args.encoding == 'all' else (args.encoding,)
                result = {'groups': scan_strings(raw, inv, encodings, args.min_length, args.contains, args.nul, args.section, args.limit),
                          'note': 'Maximal non-overlapping runs per encoding using printable ASCII-range characters only; not all Unicode strings.'}
            elif args.command == 'pattern':
                pattern = extra.masked_pattern(args.pattern)
                if not any(x is not None for x in pattern):
                    raise ValueError('At least one literal byte is required in a pattern')
                result = {'pattern': args.pattern, 'hits': limited(scan_pattern(raw, inv, pattern, args.section), args.limit),
                          'note': 'Overlapping raw-byte matches; wildcard patterns do not validate instruction boundaries.'}
            elif args.command == 'words':
                if args.count > 512: raise ValueError('--count must be at most 512 for words')
                kind = next(k for k in ('va', 'rva', 'file') if getattr(args, k) is not None)
                result = words(raw, inv, kind, getattr(args, kind), args.width, args.count, map_inventory)
            elif args.command == 'vtable':
                result = vtable_view(root, raw, inv, map_inventory, args.va, args.count, args.limit)
            elif args.command == 'diff':
                result = compare_bytes(raw, inv, args.left_va, args.right_va, args.size, args.limit)
            elif args.command == 'disasm':
                if args.size > 4096 or args.count > 512:
                    raise ValueError('disasm supports --size at most 4096 and --count at most 512')
                kind = next(k for k in ('va', 'rva', 'file') if getattr(args, k) is not None)
                result = disassemble(raw, inv, kind, getattr(args, kind), args.size, args.count, map_inventory)
            elif args.command == 'dump':
                kind = next(k for k in ('va', 'rva', 'file') if getattr(args, k) is not None)
                result = read_bytes(raw, inv, kind, getattr(args, kind), args.size)
            elif args.command == 'trace-string':
                if not args.text: raise ValueError('Empty text is not allowed')
                if args.max_targets > 10: raise ValueError('--max-targets must be at most 10')
                needle = args.text.encode(args.encoding) + ('\0'.encode(args.encoding) if args.nul else b'')
                occurrences = limited(find_bytes(raw, inv, needle, args.string_section), args.max_targets)
                if args.reference_section:
                    selected_sections(inv, args.reference_section)  # validate even if no occurrences
                traces = []
                for hit in occurrences['items']:
                    va = int(hit['preferred_va'], 16)
                    traces.append({'occurrence': hit, 'groups': group_refs(raw_refs(raw, inv, va, args.reference_section), args.limit)})
                result = {'pattern_hex': needle.hex(' '), 'string_section_filter': args.string_section,
                          'reference_section_filter': args.reference_section, 'occurrences': occurrences, 'traces': traces,
                          'note': 'Literal starts and raw reference candidates only; no instruction boundaries or runtime execution proved.'}
            elif args.command == 'find':
                if args.hex is not None and args.nul:
                    raise ValueError('--nul applies only to text patterns')
                needle = args.hex if args.hex is not None else args.text.encode(args.encoding) + (('\0'.encode(args.encoding)) if args.nul else b'')
                if not needle: raise ValueError('Empty pattern is not allowed')
                result = {'pattern_hex': needle.hex(' '), 'section_filter': args.section,
                          'hits': limited(find_bytes(raw, inv, needle, args.section), args.limit),
                          'note': 'Raw on-disk section bytes only; overlapping hits included; not evidence of code or execution.'}
            else:
                result = {'target_preferred_va': hexa(args.target_va), 'section_filter': args.section,
                          'groups': group_refs(raw_refs(raw, inv, args.target_va, args.section), args.limit),
                          'note': 'Raw candidate bytes only: E8/E9/FF15/FF25 may not be instruction boundaries; u32 may be data. FF15/FF25 target a memory slot, not its runtime contents.'}
            if args.command in ('dump', 'words', 'vtable', 'disasm', 'hash', 'unpack', 'cstring', 'probe', 'transform', 'xor-rank'):
                coverage = dict(coverage, section_count=1, section_indices=[result['location']['section_index']], all_pe_sections=False)
            elif args.command == 'chain':
                indices = sorted({hop['slot']['section_index'] for hop in result['hops']})
                coverage = dict(coverage, section_count=len(indices), section_indices=indices, all_pe_sections=False)
            elif args.command in ('diff', 'section-diff'):
                if args.command == 'diff':
                    indices = sorted({result['left']['section_index'], result['right']['section_index']})
                else:
                    indices = sorted({result['left_section_index'], result['right_section_index']})
                coverage = dict(coverage, section_count=len(indices), section_indices=indices, all_pe_sections=False)
            elif args.command == 'audit-class':
                indices = sorted({m['section_index'] for c in result['checks'] if c['status'] != 'unavailable'
                                  for m in map_address(inv, 'va', int(c['preferred_va'], 16))})
                coverage = dict(coverage, section_count=len(indices), section_indices=indices, all_pe_sections=False)
            elif args.command == 'trace-string':
                coverage = dict(coverage, all_pe_sections=coverage['all_pe_sections'] and bool(result['traces']) and not (args.string_section or args.reference_section),
                                string_section_indices=[s['index'] for s in selected_sections(inv, args.string_section)],
                                reference_section_indices=[s['index'] for s in selected_sections(inv, args.reference_section)] if result['traces'] else [])
            elif getattr(args, 'section', None):
                coverage = dict(coverage, section_filter=args.section, section_count=len(selected_sections(inv, args.section)),
                                section_indices=[s['index'] for s in selected_sections(inv, args.section)], all_pe_sections=False)
            result['coverage'] = coverage
        print(json.dumps({'context': common, 'command': args.command, 'result': result}, ensure_ascii=False, indent=2))
        failed = ((args.command == 'doctor' and not result['ok']) or
                  (args.command == 'compare-sections' and not result['all_equal']) or
                  (args.command == 'audit-class' and (result['counts']['mismatch'] > 0 or (args.require_complete and not result['complete']))) or
                  (args.command == 'pe-headers' and not (result['sections_match_inventory'] and result['machine_matches_inventory'] and result['image_base_matches_inventory'])))
        return 1 if failed else 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
