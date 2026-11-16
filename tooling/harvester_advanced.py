"""Bounded, read-only analysis primitives for the FEAR3 forensic workbench."""
from collections import Counter
import csv
import hashlib
import math
from pathlib import Path
import re
import struct
import zlib


# Byte signatures are indicators, not file-carving or decompression validation.
SIGNATURES = {
    'png': (b'\x89PNG\r\n\x1a\n', 'PNG signature'),
    'jpeg': (b'\xff\xd8\xff', 'JPEG start candidate'),
    'gif87a': (b'GIF87a', 'GIF87a signature'),
    'gif89a': (b'GIF89a', 'GIF89a signature'),
    'dds': (b'DDS ', 'DirectDraw surface signature'),
    'riff': (b'RIFF', 'RIFF container candidate'),
    'ogg': (b'OggS', 'Ogg page signature'),
    'zip': (b'PK\x03\x04', 'ZIP local header candidate'),
    'gzip': (b'\x1f\x8b\x08', 'gzip header candidate'),
    'xz': (b'\xfd7zXZ\x00', 'XZ header candidate'),
    '7z': (b'7z\xbc\xaf\x27\x1c', '7-Zip header candidate'),
    'lz4-frame': (b'\x04\x22\x4d\x18', 'LZ4 frame candidate'),
    'zstd': (b'\x28\xb5\x2f\xfd', 'Zstandard frame candidate'),
    'zlib-7801': (b'\x78\x01', 'common zlib header, high false-positive risk'),
    'zlib-785e': (b'\x78\x5e', 'common zlib header, high false-positive risk'),
    'zlib-789c': (b'\x78\x9c', 'common zlib header, high false-positive risk'),
    'zlib-78da': (b'\x78\xda', 'common zlib header, high false-positive risk'),
    'mz': (b'MZ', 'DOS/PE header candidate, high false-positive risk'),
    'xml': (b'<?xml', 'XML text candidate'),
    'lua-bytecode': (b'\x1bLua', 'Lua bytecode signature'),
}


def catalog(root):
    base = (root / 'analysis').resolve()
    if not base.is_dir():
        raise ValueError('analysis directory not found')
    paths = []
    for path in base.rglob('*.csv'):
        if path.is_file() and path.resolve().is_relative_to(base):
            paths.append(path.relative_to(root.resolve()).as_posix())
    return sorted(paths)


def table_path(root, name):
    # Only exact catalog members are permitted; paths must not escape analysis/.
    if name not in catalog(root):
        raise ValueError('Unknown table; choose an exact path from tables')
    return root / name


def table_header(path):
    with path.open(encoding='utf-8', newline='') as f:
        header = next(csv.reader(f), None)
    if not header or len(set(header)) != len(header) or any(not x for x in header):
        raise ValueError(f'Invalid or duplicate CSV header: {path}')
    return header


def table_rows(path):
    columns = table_header(path)
    with path.open(encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        for number, row in enumerate(reader, 2):
            if None in row or any(row[c] is None for c in columns):
                raise ValueError(f'Malformed CSV row {number}: {path}')
            yield row


def integer_value(value):
    """Parse decimal or 0x hexadecimal; reject floats and missing values."""
    if not re.fullmatch(r'[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)', value):
        raise ValueError('not an integer')
    signless = value.lstrip('+-')
    return int(value, 16 if signless.lower().startswith('0x') else 10)


def prepare_filters(columns, filters, ignore_case):
    parsed = []
    for col, op, value in filters:
        if col not in columns:
            raise ValueError(f'Unknown column: {col}')
        if op not in ('eq', 'ne', 'contains', 'starts', 'ends', 'gt', 'ge', 'lt', 'le'):
            raise ValueError(f'Unknown filter operator: {op}')
        if op in ('gt', 'ge', 'lt', 'le'):
            try:
                value = integer_value(value)
            except ValueError as e:
                raise ValueError(f'Numeric filter needs decimal or hexadecimal integer: {value}') from e
        elif ignore_case:
            value = value.casefold()
        parsed.append((col, op, value))
    return parsed


def row_matches(row, filters, ignore_case):
    for col, op, expected in filters:
        val = row[col]
        if op in ('gt', 'ge', 'lt', 'le'):
            try: val = integer_value(val)
            except ValueError: return False
            success = {'gt': val > expected, 'ge': val >= expected, 'lt': val < expected, 'le': val <= expected}[op]
        else:
            if ignore_case: val = val.casefold()
            success = {'eq': val == expected, 'ne': val != expected, 'contains': expected in val,
                       'starts': val.startswith(expected), 'ends': val.endswith(expected)}[op]
        if not success:
            return False
    return True


def checked_columns(columns, requested):
    if not requested:
        return columns
    if len(set(requested)) != len(requested) or any(c not in columns for c in requested):
        raise ValueError('Unknown or duplicate selected column')
    return requested


def table_query(root, name, filters, selected, ignore_case, sort, numeric_sort, descending, offset, limit):
    path = table_path(root, name)
    columns = table_header(path)
    selected = checked_columns(columns, selected)
    filters = prepare_filters(columns, filters, ignore_case)
    if sort and sort not in columns:
        raise ValueError('Unknown sort column')
    if numeric_sort and not sort:
        raise ValueError('--numeric-sort requires --sort')
    if descending and not sort:
        raise ValueError('--descending requires --sort')
    matches = (r for r in table_rows(path) if row_matches(r, filters, ignore_case))
    if sort:
        bounded = []
        for row in matches:
            bounded.append(row)
            if len(bounded) > 150000:
                raise ValueError('Refusing to sort more than 150000 rows; filter first')
        matches = bounded
        def key(row):
            v = row[sort]
            if numeric_sort:
                try: return (0, integer_value(v))
                except ValueError: return (1, 0)
            return (0, v.casefold() if ignore_case else v)
        matches.sort(key=key, reverse=descending)
    total, result = 0, []
    for row in matches:
        if offset <= total < offset + limit:
            result.append({c: row[c] for c in selected})
        total += 1
    return {'source': name, 'filters': filters, 'total': total, 'offset': offset, 'returned': len(result),
            'has_more': offset + len(result) < total, 'items': result}


def table_group(root, name, column, filters, ignore_case, limit):
    path = table_path(root, name)
    columns = table_header(path)
    if column not in columns:
        raise ValueError('Unknown group column')
    filters = prepare_filters(columns, filters, ignore_case)
    counter = Counter()
    total = 0
    for row in table_rows(path):
        if row_matches(row, filters, ignore_case):
            value = row[column].casefold() if ignore_case else row[column]
            counter[value] += 1
            total += 1
    ordered = sorted(counter.items(), key=lambda v: (-v[1], v[0]))
    return {'source': name, 'column': column, 'matching_rows': total, 'distinct_values': len(counter),
            'returned': min(len(ordered), limit), 'truncated': len(ordered) > limit,
            'items': [{'value': value, 'count': count} for value, count in ordered[:limit]]}


def raw_intervals(sections):
    return sorted((s['raw_offset'], s['raw_offset'] + s['raw_size'], s['index'], s['name'])
                  for s in sections if s['raw_size'])


def virtual_intervals(sections):
    return sorted((s['virtual_address'], s['virtual_address'] + max(s['virtual_size'], s['raw_size']), s['index'], s['name'])
                  for s in sections if max(s['virtual_size'], s['raw_size']))


def overlaps(intervals):
    out = []
    for i, left in enumerate(intervals):
        for right in intervals[i + 1:]:
            if right[0] >= left[1]: break
            out.append({'left_index': left[2], 'right_index': right[2], 'start': hex(right[0]),
                        'end_exclusive': hex(min(left[1], right[1]))})
    return out


def gaps(intervals, start, end):
    out, cursor = [], start
    for low, high, _, _ in intervals:
        if low > cursor and cursor < end:
            out.append({'start': hex(cursor), 'end_exclusive': hex(min(low, end)), 'size': min(low, end) - cursor})
        cursor = max(cursor, high)
    if cursor < end:
        out.append({'start': hex(cursor), 'end_exclusive': hex(end), 'size': end - cursor})
    return [x for x in out if x['size'] > 0]


def layout_report(inventory):
    raw = raw_intervals(inventory['sections'])
    virtual = virtual_intervals(inventory['sections'])
    maximum = max((end for _, end, _, _ in raw), default=0)
    return {'section_count': len(inventory['sections']), 'file_size': inventory['size'],
            'raw_section_bytes_sum': sum(end-start for start,end,_,_ in raw),
            'raw_overlap_pairs': overlaps(raw), 'virtual_overlap_pairs_using_max_raw_virtual': overlaps(virtual),
            'raw_gaps_including_headers_and_overlay': gaps(raw, 0, inventory['size']),
            'raw_sections_beyond_file': [s['index'] for s in inventory['sections'] if s['raw_offset'] + s['raw_size'] > inventory['size']],
            'bytes_after_last_raw_section': max(0, inventory['size'] - maximum),
            'note': 'Metadata-based intervals only; gaps can contain headers, padding, certificates, or overlay; not classified by this operation.'}


def hash_bytes(data):
    return {'size': len(data), 'md5': hashlib.md5(data, usedforsecurity=False).hexdigest(),
            'sha1': hashlib.sha1(data, usedforsecurity=False).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(), 'sha512': hashlib.sha512(data).hexdigest(),
            'blake2b': hashlib.blake2b(data).hexdigest(), 'crc32': f'0x{zlib.crc32(data):08X}',
            'adler32': f'0x{zlib.adler32(data):08X}',
            'note': 'MD5, SHA-1, CRC32 and Adler-32 are not collision-resistant authenticity checks.'}


def window_count(size, width, step, partial):
    if width <= 0 or step <= 0: raise ValueError('Window width and step must be positive')
    if size <= 0: return 0
    if partial: return 1 + (size - 1) // step
    if size < width: return 0
    return 1 + (size - width) // step


def window_stats(data, width, step, partial, entropy_min, entropy_max):
    if width <= 0 or step <= 0: raise ValueError('Window width and step must be positive')
    for pos in range(0, len(data), step):
        sample = data[pos:pos + width]
        if len(sample) < width and not partial: break
        count = Counter(sample)
        n = len(sample)
        entropy = -sum((v/n)*math.log2(v/n) for v in count.values()) if n else 0.0
        if entropy_min <= entropy <= entropy_max:
            yield {'offset': pos, 'size': n, 'entropy_bits_per_byte': round(entropy, 6),
                   'zero_bytes': count.get(0, 0), 'sha256': hashlib.sha256(sample).hexdigest()}


def int_encodings(value, widths, endian):
    output = []
    for width in widths:
        for order in (('little', 'big') if endian == 'both' else (endian,)):
            try: b = value.to_bytes(width, order, signed=value < 0)
            except OverflowError as e: raise ValueError(f'{value} does not fit {width} bytes ({order})') from e
            output.append((width, order, b))
    return output


def integer_info(value, width):
    raw = int_encodings(value, [width], 'little')[0][2]
    unsigned = int.from_bytes(raw, 'little')
    return {'input': value, 'width': width, 'unsigned': unsigned,
            'signed': int.from_bytes(raw, 'little', signed=True), 'hex': f'0x{unsigned:0{width * 2}X}',
            'little_endian_hex': raw.hex(' '), 'big_endian_hex': raw[::-1].hex(' '),
            'set_bit_indices_lsb_first': [i for i in range(width * 8) if unsigned & (1 << i)],
            'set_bit_count': unsigned.bit_count()}


def float_info(width, value=None, bits=None):
    if width not in (4, 8) or (value is None) == (bits is None):
        raise ValueError('Supply exactly one of value or bits, and width 4 or 8')
    fmt = 'f' if width == 4 else 'd'
    exp_bits, mantissa_bits = (8, 23) if width == 4 else (11, 52)
    if bits is None:
        try: raw = struct.pack('<' + fmt, value)
        except (OverflowError, struct.error) as e: raise ValueError(f'Value does not fit IEEE {width * 8}-bit float') from e
        bits = int.from_bytes(raw, 'little')
    else:
        if not 0 <= bits < 1 << (width * 8): raise ValueError('Bit pattern does not fit selected width')
        raw = bits.to_bytes(width, 'little')
    decoded = struct.unpack('<' + fmt, raw)[0]
    exponent = (bits >> mantissa_bits) & ((1 << exp_bits) - 1)
    mantissa = bits & ((1 << mantissa_bits) - 1)
    category = ('nan' if mantissa else 'infinity') if exponent == (1 << exp_bits) - 1 else ('zero' if mantissa == 0 else 'subnormal') if exponent == 0 else 'normal'
    return {'width': width, 'value': json_float(decoded), 'category': category, 'sign': bits >> (width * 8 - 1),
            'exponent_bits': exponent, 'mantissa_bits_hex': f'0x{mantissa:X}', 'bits_hex': f'0x{bits:0{width*2}X}',
            'little_endian_hex': raw.hex(' '), 'big_endian_hex': raw[::-1].hex(' ')}


def parse_layout(spec):
    formats = {'u8': ('B', 1), 'i8': ('b', 1), 'u16': ('H', 2), 'i16': ('h', 2),
               'u32': ('I', 4), 'i32': ('i', 4), 'u64': ('Q', 8), 'i64': ('q', 8),
               'f32': ('f', 4), 'f64': ('d', 8), 'ptr32': ('I', 4)}
    result = []
    for token in spec.split(','):
        token = token.strip().lower()
        if token in formats:
            fmt, size = formats[token]
            result.append((token, fmt, size))
        else:
            m = re.fullmatch(r'pad\[([1-9][0-9]*)\]', token)
            if not m: raise ValueError(f'Unknown packed layout item: {token}')
            result.append((token, None, int(m.group(1))))
    if not result or len(result) > 256 or sum(x[2] for x in result) > 4096:
        raise ValueError('Layout must have at most 256 items and 4096 bytes')
    return result


def json_float(value):
    if math.isnan(value): return 'NaN'
    if math.isinf(value): return 'Infinity' if value > 0 else '-Infinity'
    return value


def unpack_layout(data, layout, endian):
    fields, offset = [], 0
    for name, fmt, size in layout:
        raw = data[offset:offset+size]
        if len(raw) != size: raise ValueError('Insufficient bytes for layout')
        row = {'field_index': len(fields), 'offset': offset, 'type': name, 'size': size, 'raw_hex': raw.hex(' ')}
        if fmt:
            value = struct.unpack(('<' if endian == 'little' else '>') + fmt, raw)[0]
            row['value'] = json_float(value) if isinstance(value, float) else value
            if name == 'ptr32': row['pointer_value_hex'] = f'0x{value:X}'
        fields.append(row)
        offset += size
    return fields


def bounded_zlib(data, wbits, limit):
    try:
        decoder = zlib.decompressobj(wbits)
        output = decoder.decompress(data, limit + 1)
        too_long = len(output) > limit
        prefix = output[:limit]
        return {'status': 'output_limit_reached' if too_long else 'complete' if decoder.eof else 'incomplete',
                'output_bytes_returned': len(prefix), 'output_prefix_sha256': hashlib.sha256(prefix).hexdigest(),
                'output_preview_hex': prefix[:64].hex(' '),
                'compressed_bytes_consumed': len(data) - len(decoder.unused_data) - len(decoder.unconsumed_tail),
                'unused_input_bytes': len(decoder.unused_data), 'unconsumed_input_bytes': len(decoder.unconsumed_tail),
                'eof': decoder.eof}
    except zlib.error as e:
        return {'status': 'decode_error', 'error': str(e)}


def compression_probe(data, limit):
    return {'zlib': bounded_zlib(data, 15, limit), 'gzip': bounded_zlib(data, 31, limit),
            'raw_deflate': bounded_zlib(data, -15, limit),
            'note': 'Bounded local probe only; incomplete/failed does not exclude other offsets, codecs or formats.'}


def transform(data, operation, key):
    if operation in ('xor', 'rotl', 'rotr') and not 0 <= key <= (255 if operation == 'xor' else 7):
        raise ValueError('xor key must be 0..255, rotation must be 0..7')
    if operation == 'xor': return bytes(b ^ key for b in data)
    if operation == 'not': return bytes(b ^ 0xff for b in data)
    if operation == 'rotl': return bytes(((b << key) | (b >> (8-key))) & 0xff for b in data)
    if operation == 'rotr': return bytes(((b >> key) | (b << (8-key))) & 0xff for b in data)
    if operation == 'reverse': return data[::-1]
    if operation in ('swap16', 'swap32'):
        width = 2 if operation == 'swap16' else 4
        if len(data) % width: raise ValueError(f'{operation} requires a multiple of {width} bytes')
        return b''.join(data[i:i+width][::-1] for i in range(0, len(data), width))
    raise ValueError('Unknown transformation')


def xor_rank(data, limit):
    result = []
    for key in range(256):
        decoded = bytes(b ^ key for b in data)
        count = sum(b in (9, 10, 13) or 32 <= b <= 126 for b in decoded)
        result.append({'key': f'0x{key:02X}', 'printable_bytes': count, 'total_bytes': len(data),
                       'printable_fraction': round(count / len(data), 6) if data else 0.0,
                       'preview_hex': decoded[:64].hex(' ')})
    return sorted(result, key=lambda x: (-x['printable_bytes'], x['key']))[:limit]


def hierarchy_nodes(entries):
    nodes, stack, n = [], [], len(entries)
    for index, row in enumerate(entries):
        if int(row['index']) != index: raise ValueError('Base entries are missing or out of order')
        while stack and index >= stack[-1][1]: stack.pop()
        contained = int(row['contained_bases'])
        if contained < 0: raise ValueError('Negative contained_bases')
        end = index + contained + 1
        if end > n or (stack and end > stack[-1][1]) or (index and not stack):
            raise ValueError('Base contained_bases spans are inconsistent')
        nodes.append({'index': index, 'parent_index_candidate': stack[-1][0] if stack else None,
                      'end_exclusive': end, 'base': row})
        stack.append((index, end))
    return nodes


def frequencies(data, limit):
    counts = Counter(data)
    ordered = sorted(counts.items(), key=lambda v: (-v[1], v[0]))
    return {'bytes': len(data), 'distinct_values': len(counts), 'returned': min(limit, len(ordered)),
            'truncated': len(ordered) > limit,
            'values': [{'byte': f'0x{v:02X}', 'count': n, 'fraction': round(n/len(data), 6) if data else 0.0}
                       for v, n in ordered[:limit]]}


def byte_runs(data, minimum, value=None):
    if minimum < 1: raise ValueError('Minimum run length must be positive')
    if value is not None and not 0 <= value <= 255: raise ValueError('Byte value must be 0..255')
    if value is None:
        pattern = re.compile(rb'(.)\1{' + str(minimum - 1).encode() + rb',}', re.DOTALL)
    else:
        pattern = re.compile(re.escape(bytes([value])) + b'{' + str(minimum).encode() + b',}')
    for match in pattern.finditer(data):
        yield {'offset': match.start(), 'length': match.end() - match.start(), 'byte': f'0x{match.group()[0]:02X}'}


def pack_layout(layout, values, endian):
    expected = sum(fmt is not None for _, fmt, _ in layout)
    if len(values) != expected: raise ValueError(f'Layout requires {expected} values, got {len(values)}')
    parts, index = [], 0
    for name, fmt, size in layout:
        if fmt is None:
            parts.append(bytes(size))
            continue
        text = values[index]
        index += 1
        try:
            value = float(text) if name in ('f32', 'f64') else integer_value(text)
            part = struct.pack(('<' if endian == 'little' else '>') + fmt, value)
        except (ValueError, OverflowError, struct.error) as e:
            raise ValueError(f'Cannot pack {name} value {text!r}: {e}') from e
        parts.append(part)
    return b''.join(parts)


def section_diff(left, right, limit):
    common = min(len(left), len(right))
    count, items = 0, []
    for i in range(common):
        if left[i] != right[i]:
            count += 1
            if len(items) < limit:
                items.append({'offset': i, 'left': f'{left[i]:02X}', 'right': f'{right[i]:02X}'})
    return {'left_size': len(left), 'right_size': len(right), 'common_bytes': common,
            'mismatching_bytes_in_common_prefix': count, 'left_extra_bytes': len(left) - common,
            'right_extra_bytes': len(right) - common, 'identical': left == right,
            'left_sha256': hashlib.sha256(left).hexdigest(), 'right_sha256': hashlib.sha256(right).hexdigest(),
            'sample': {'total': count, 'returned': len(items), 'truncated': count > len(items), 'items': items}}


def _read(data, fmt, offset):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data): raise ValueError('Truncated PE structure')
    return struct.unpack_from(fmt, data, offset)


def parse_pe_headers(data):
    if data[:2] != b'MZ': raise ValueError('Missing MZ signature')
    peoff = _read(data, '<I', 0x3c)[0]
    if peoff + 24 > len(data) or data[peoff:peoff+4] != b'PE\0\0': raise ValueError('Missing PE signature')
    machine, count, timestamp, symptr, syms, optsize, characteristics = _read(data, '<HHIIIHH', peoff+4)
    opt = peoff + 24
    if optsize < 96 or opt + optsize > len(data): raise ValueError('Invalid optional-header size')
    if _read(data, '<H', opt)[0] != 0x10b: raise ValueError('Only PE32 is supported')
    entry = _read(data, '<I', opt+16)[0]
    base = _read(data, '<I', opt+28)[0]
    section_alignment, file_alignment = _read(data, '<II', opt+32)
    image_size, header_size, checksum = _read(data, '<III', opt+56)
    subsystem, dll_flags = _read(data, '<HH', opt+68)
    directory_count = _read(data, '<I', opt+92)[0]
    if directory_count > (optsize - 96) // 8: raise ValueError('Directories exceed optional header')
    directories = []
    for i in range(directory_count):
        rva, size = _read(data, '<II', opt+96+i*8)
        directories.append({'index': i, 'address': rva, 'size': size,
                            'address_kind': 'file_offset' if i == 4 else 'rva'})
    table = opt + optsize
    if count > 4096 or table + count * 40 > len(data): raise ValueError('Invalid section table')
    sections = []
    for i in range(count):
        name, vs, va, rs, rp, reloc, line, nreloc, nline, flags = _read(data, '<8sIIIIIIHHI', table + i * 40)
        if rp + rs > len(data): raise ValueError('Section extends beyond file')
        sections.append({'index': i, 'raw_name_hex': name.hex(), 'name': name.rstrip(b'\0').decode('ascii', 'replace'),
                         'virtual_address': va, 'virtual_size': vs, 'raw_offset': rp, 'raw_size': rs,
                         'characteristics': flags})
    return {'machine': machine, 'section_count': count, 'timestamp': timestamp,
            'coff_symbol_table_file_offset': symptr, 'coff_symbol_count': syms, 'characteristics': characteristics,
            'pe_header_file_offset': peoff, 'optional_header_size': optsize, 'image_base': base,
            'entrypoint_rva': entry, 'section_alignment': section_alignment, 'file_alignment': file_alignment,
            'image_size': image_size, 'header_size': header_size, 'checksum': checksum,
            'subsystem': subsystem, 'dll_characteristics': dll_flags, 'directories': directories, 'sections': sections}


def rva_bytes(data, sections, rva, size):
    hits = []
    for sec in sections:
        offset = rva - sec['virtual_address']
        if 0 <= offset and offset + size <= sec['raw_size']:
            hits.append(sec['raw_offset'] + offset)
    if len(hits) != 1: raise ValueError('RVA is not uniquely raw-backed')
    return data[hits[0]:hits[0]+size]


def rva_string(data, sections, rva, limit=65536):
    hits = []
    for sec in sections:
        offset = rva - sec['virtual_address']
        if 0 <= offset < sec['raw_size']:
            hits.append((sec['raw_offset'] + offset, sec['raw_offset'] + sec['raw_size']))
    if len(hits) != 1: raise ValueError('String RVA is not uniquely raw-backed')
    start, end = hits[0]
    stop = data.find(b'\0', start, min(end, start + limit))
    if stop < 0: raise ValueError('Unterminated or too-long export string')
    return data[start:stop].decode('ascii', 'backslashreplace')


def parse_pe_exports(data, header):
    if not header['directories'] or header['directories'][0]['address'] == 0:
        return []
    directory = header['directories'][0]
    rva, size = directory['address'], directory['size']
    secs = header['sections']
    fields = struct.unpack('<IIHHIIIIIII', rva_bytes(data, secs, rva, 40))
    _, _, _, _, _, ordinal_base, function_count, name_count, functions_va, names_va, ordinals_va = fields
    if function_count > 1000000 or name_count > 1000000: raise ValueError('Export table exceeds safety bound')
    funcs = rva_bytes(data, secs, functions_va, function_count * 4) if function_count else b''
    names = rva_bytes(data, secs, names_va, name_count * 4) if name_count else b''
    ords = rva_bytes(data, secs, ordinals_va, name_count * 2) if name_count else b''
    named = {}
    for i in range(name_count):
        name_rva = _read(names, '<I', i*4)[0]
        index = _read(ords, '<H', i*2)[0]
        if index >= function_count: raise ValueError('Export name ordinal index outside address table')
        named.setdefault(index, []).append(rva_string(data, secs, name_rva))
    result = []
    for i in range(function_count):
        target = _read(funcs, '<I', i*4)[0]
        if not target: continue
        is_forwarder = rva <= target < rva + size
        forwarder = rva_string(data, secs, target) if is_forwarder else None
        for name in named.get(i, [None]):
            result.append({'name': name, 'ordinal': ordinal_base + i, 'target_rva': target,
                           'target_preferred_va': None if is_forwarder else header['image_base'] + target,
                           'forwarder': forwarder})
    return result
