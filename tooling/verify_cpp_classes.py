#!/usr/bin/env python3
"""Independent byte-level consistency checks of the published C++ inventory."""
import csv
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'tooling/python'))
import pefile

EXE = ROOT/'evidence/source-exe/F.E.A.R. 3.exe'
OUT = ROOT/'analysis/cpp-classes'
SHA = 'caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2'


def require(ok, message):
    if not ok: raise ValueError(message)


def read_csv(path):
    with path.open(encoding='utf-8', newline='') as f: return list(csv.DictReader(f))


def num(x): return int(x, 16)


def main():
    raw = EXE.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == SHA, 'EXE mismatch')
    pe = pefile.PE(data=raw)
    base = pe.OPTIONAL_HEADER.ImageBase
    sections = pe.sections
    def read_va(va, count):
        for s in sections:
            delta = va - base - s.VirtualAddress
            if 0 <= delta and delta + count <= s.SizeOfRawData:
                return raw[s.PointerToRawData+delta:s.PointerToRawData+delta+count]
        raise ValueError('VA not raw-backed: ' + hex(va))
    def u32(va): return struct.unpack('<I', read_va(va, 4))[0]
    def executable(va):
        return any(s.VirtualAddress <= va-base < s.VirtualAddress+s.SizeOfRawData and s.Characteristics & 0x20000000 for s in sections)
    coverage = read_csv(OUT/'section-coverage.csv')
    require(len(coverage) == len(sections), 'section count mismatch')
    prefix_locations = set()
    for i, (s, row) in enumerate(zip(sections, coverage)):
        data = raw[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        require(int(row['section_index']) == i and num(row['raw_offset']) == s.PointerToRawData and num(row['raw_size']) == len(data), 'section metadata mismatch')
        require(hashlib.sha256(data).hexdigest() == row['sha256'], 'section hash mismatch')
        count = 0
        for n in range(len(data)-2):
            if data[n:n+3] == b'.?A':
                prefix_locations.add((i, n)); count += 1
        require(count == int(row['prefix_hits']), 'prefix count mismatch')
    names = read_csv(OUT/'raw-name-candidates.csv')
    require({(int(r['section_index']), num(r['section_offset'])) for r in names} == prefix_locations, 'name coverage mismatch')
    types = read_csv(OUT/'classes.csv')
    td_set = {num(r['type_descriptor_va']) for r in types}
    require(len(types) == len(td_set), 'duplicate type descriptor')
    old = read_csv(ROOT/'analysis/script-classes/all-rtti.csv')
    require({(num(x['type_descriptor_va']), x['decorated_name']) for x in old} == {(num(x['type_descriptor_va']), x['decorated_name']) for x in types}, 'old RTTI inventory differs')
    for r in types:
        va = num(r['type_descriptor_va'])
        name = r['decorated_name'].encode('ascii') + b'\0'
        require(read_va(va + 8, len(name)) == name, 'type name mismatch ' + hex(va))
        ptr, spare = struct.unpack('<II', read_va(va, 8))
        require(spare == 0 and ptr == num(r['vftable_pointer']) and executable(u32(ptr)), 'type header mismatch')
    cols = read_csv(OUT/'complete-object-locators.csv')
    col_map = {num(c['col_va']): c for c in cols}
    require(len(cols) == len(col_map), 'duplicate COL')
    for col in cols:
        va = num(col['col_va'])
        sig, off, cd, td, ch = struct.unpack('<IIIII', read_va(va,20))
        require(sig == 0 and off == num(col['object_offset']) and cd == num(col['cd_offset']) and td in td_set and td == num(col['type_descriptor_va']) and ch == num(col['hierarchy_va']), 'bad COL')
        sig, flags, count, arr = struct.unpack('<IIII', read_va(ch, 16))
        require(sig == 0 and count == int(col['base_count']) and flags == num(col['hierarchy_attributes']) and arr == num(col['base_array_va']), 'bad hierarchy')
        for i in range(count):
            desc = u32(arr + i*4)
            btd = u32(desc)
            require(btd in td_set and (i != 0 or btd == td), 'bad base descriptor')
    tables = read_csv(OUT/'vtable-candidates.csv')
    for t in tables:
        va, col = num(t['vtable_va']), num(t['col_va'])
        require(col in col_map and u32(va-4) == col and executable(u32(va)) and u32(va) == num(t['first_slot_va']), 'bad vtable candidate')
        require(t['type_descriptor_va'] == col_map[col]['type_descriptor_va'], 'vtable type mismatch')
    bases = read_csv(OUT/'base-descriptors.csv')
    for r in bases:
        hierarchy = num(r['hierarchy_va']); arr = u32(hierarchy + 12); desc = u32(arr + int(r['index'])*4)
        fields = struct.unpack('<IIiiiI', read_va(desc,24))
        require(desc == num(r['base_descriptor_va']) and fields == (num(r['base_type_descriptor_va']), int(r['contained_bases']), int(r['mdisp']), int(r['pdisp']), int(r['vdisp']), num(r['attributes'])), 'base row mismatch')
    symbols = read_csv(OUT/'cpp-symbols.csv')
    for r in symbols:
        off = num(r['name_file_offset']); b = r['decorated_symbol'].encode('ascii')+b'\0'
        require(raw[off:off+len(b)] == b, 'symbol bytes mismatch')
    print(f'OK: {len(coverage)} raw sections, {len(names)} prefix hits, {len(types)} names vs independent previous inventory, {len(cols)} COLs, {len(tables)} vtable hits, {len(bases)} base rows, {len(symbols)} symbol names checked')

if __name__ == '__main__': main()
