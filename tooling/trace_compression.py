#!/usr/bin/env python3
"""Reproduce byte/string evidence and reviewed x86 slices; no execution of evidence."""
from pathlib import Path
import csv
import hashlib
import re
import struct
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tooling/python'))
import pefile
import capstone

EXE = ROOT / 'evidence/source-exe/F.E.A.R. 3.exe'
SNAP = ROOT / 'external/lua-api/snapshot'
OUT = ROOT / 'analysis/compression'
SHA = 'caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2'
TERMS = ('minipack', 'zlib', 'lsd', 'lzd', 'lzx')
ENCODINGS = ('ascii', 'utf-16le', 'utf-16be')
# Starts are reviewed function entries or instruction boundaries, not inferred function extents.
SPANS = [
 ('MiniPack factory',0x947780,0x947850),
 ('MiniPack object constructor',0x8e6710,0x8e6790),
 ('MiniPack initialization',0xced7b0,0xced9c7),
 ('MiniPack vtable slot 4',0x969750,0x9697ad),
 ('MiniPack vtable slot 68',0x4c31b0,0x4c3238),
 ('filesystem constructor default codec',0x8d1f40,0x8d2080),
 ('compressed stream object constructor',0xa47730,0xa477aa),
 ('filesystem header and codec selection',0xaa9ac0,0xaa9d06),
 ('filesystem header caller',0x950530,0x950610),
 ('compressed stream constructor caller from header',0x552230,0x5522ef),
 ('compressed stream constructor caller from memory',0xde20f0,0xde2184),
 ('compressed stream header parsing',0x839990,0x839b50),
 ('compressed stream copied header parsing',0x52e0d0,0x52e210),
 ('compressed stream read caller',0xc19890,0xc19940),
 ('compressed block dispatch',0xa50420,0xa50620),
 ('LZD handler',0xb44930,0xb44acc),
 ('ZLib branch wrapper',0xe5a3a0,0xe5a3e0),
 ('other branch wrapper',0x9c1250,0x9c12a8),
 ('filesystem diagnostic and codec names',0xa76b72,0xa76dc0),
]
CALL_TARGETS = (0x8e6710,0xced7b0,0xaa9ac0,0x839990,0x52e0d0,0xa50420,0xb44930,0xe5a3a0,0x9c1250)
STRING_TARGETS = (0x17edb8c,0x17edb98,0x17edbc0,0x17edc70,0x17ee1a4,0x17ee1b0,0x17ee1c8,0x17ee17c,0x17ee184,0x17ee188,0x17ee18c,0x18344b4,0x18b0fd0,0x14d0d68,0x14d7440,0x14dfb20,0x14dfb34,0x14dfb48)


def csvfile(name, header, rows):
    with (OUT / name).open('w', encoding='utf-8', newline='') as f:
        w=csv.writer(f, lineterminator='\n'); w.writerow(header); w.writerows(rows)


def main():
    blob = EXE.read_bytes()
    if hashlib.sha256(blob).hexdigest() != SHA:
        raise SystemExit('EXE SHA-256 mismatch')
    if not SNAP.is_dir():
        raise SystemExit('Missing upstream snapshot; run tooling/fetch_lua_api.py first')
    archive = ROOT / 'external/lua-api/source.zip'
    if hashlib.sha256(archive.read_bytes()).hexdigest() != '1f3aa0fb555a8e2bbb05b04b6464aa49951416baaed568e5963440b6ea2b80e6':
        raise SystemExit('Snapshot archive hash mismatch')
    prefix = 'FEAR3-DespairEngineLuaAPI-4a7a7cf3d48f09dca446441d8af427f30556280d/'
    with zipfile.ZipFile(archive) as z:
        expected = {i.filename[len(prefix):]: i for i in z.infolist() if not i.is_dir() and i.filename.startswith(prefix)}
        actual = {x.relative_to(SNAP).as_posix() for x in SNAP.rglob('*') if x.is_file()}
        if set(expected) != actual:
            raise SystemExit('Snapshot file list mismatch')
        for name, info in expected.items():
            if hashlib.sha256((SNAP / name).read_bytes()).digest() != hashlib.sha256(z.read(info)).digest():
                raise SystemExit('Snapshot mismatch: ' + name)
    p = pefile.PE(data=blob); base=p.OPTIONAL_HEADER.ImageBase
    OUT.mkdir(parents=True, exist_ok=True)
    sources = [EXE] + sorted((ROOT / 'evidence/fear3-engine-sections').glob('*.bin')) + sorted(x for x in SNAP.rglob('*') if x.is_file())
    rows=[]
    for path in sources:
        data = blob if path == EXE else path.read_bytes()
        low=data.lower()
        for term in TERMS:
            for enc in ENCODINGS:
                pattern=term.encode(enc); start=0
                while True:
                    pos=low.find(pattern,start)
                    if pos<0: break
                    section=''; va=''
                    if path == EXE:
                        try:
                            rva=p.get_rva_from_offset(pos); s=p.get_section_by_rva(rva)
                            section=s.Name.rstrip(b'\0').decode('ascii','replace').strip() if s else 'headers'
                            va=f'0x{base+rva:X}'
                        except pefile.PEFormatError: pass
                    line = data.count(b'\n',0,pos)+1 if enc=='ascii' and b'\0' not in data else ''
                    rows.append((str(path.relative_to(ROOT)),term,enc,f'0x{pos:X}',va,section,line))
                    start=pos+1
    csvfile('literal-hits.csv',['path','term_case_insensitive','encoding','file_offset','preferred_va_exe_only','pe_section','line_if_text'],rows)
    ids=[]
    for value in (0xc5735a0f, 0xc5735a10, 0xc5735a11):
        needle=struct.pack('<I',value)
        for match in re.finditer(re.escape(needle),blob):
            off=match.start()
            try:
                rva=p.get_rva_from_offset(off); s=p.get_section_by_rva(rva)
                section=s.Name.rstrip(b'\0').decode('ascii','replace').strip() if s else 'headers'
                va=f'0x{base+rva:X}'
            except pefile.PEFormatError:
                section='unmapped'; va=''
            ids.append((f'0x{value:X}',f'0x{off:X}',va,section))
    csvfile('codec-id-byte-hits.csv',['id_little_endian','file_offset','preferred_va_of_first_byte_not_instruction','section'],ids)
    tables = [
        (0x17edbec, 'MiniPackFileSystem', [(0x04,0x969750),(0x68,0x4c31b0)]),
        (0x17ee254, 'PackFileSystem', [(0x68,0xa767c0)]),
        (0x17ee3b8, 'StreamCompression', [(0x18,0xc19890)]),
        (0x17ee594, 'MiniPackFileDir', []),
    ]
    table_rows=[]
    for vtable, name, slots in tables:
        col, = struct.unpack('<I',p.get_data(vtable-base-4,4))
        sig, offset, cd, type_desc, hierarchy = struct.unpack('<IIIII',p.get_data(col-base,20))
        decorated = p.get_string_at_rva(type_desc-base+8).decode('ascii')
        if sig != 0 or offset != 0 or decorated != '.?AV'+name+'@Despair@@':
            raise ValueError('RTTI mismatch: '+name)
        table_rows.append((name,f'0x{vtable:X}',f'0x{col:X}',f'0x{type_desc:X}',decorated,'',''))
        for slot, target in slots:
            value, = struct.unpack('<I',p.get_data(vtable-base+slot,4))
            if value != target: raise ValueError('vtable slot mismatch: '+name)
            table_rows.append((name,f'0x{vtable:X}',f'0x{col:X}',f'0x{type_desc:X}',decorated,f'0x{slot:X}',f'0x{target:X}'))
    csvfile('rtti-vtables.csv',['class','vtable_va','complete_object_locator_va','type_descriptor_va','decorated_name','slot_offset','slot_target_va'],table_rows)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    lines=[f'Preferred VAs for EXE SHA-256 {SHA}. Ends are excerpts, not function boundaries.\n']
    for title,start,end in SPANS:
        # Read up to the requested end and emit only complete instructions.
        lines.append(f'\n=== {title}: {start:08X} through before {end:08X} ===')
        for ins in md.disasm(p.get_data(start-base,end-start),start):
            lines.append(f'{ins.address:08X}  {ins.bytes.hex(" "):<30} {ins.mnemonic:<8} {ins.op_str}'.rstrip())
    (OUT/'code-excerpts.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    # Raw candidates: 68 imm32 and E8 rel32 may occur inside instructions/data, hence review is required.
    candidates=[]
    for section in p.sections:
        if not section.Characteristics & 0x20000000: continue
        data=section.get_data(); origin=base+section.VirtualAddress
        name=section.Name.rstrip(b'\0').decode('ascii','replace').strip()
        for target in STRING_TARGETS:
            needle=b'\x68'+struct.pack('<I',target); start=0
            while True:
                pos=data.find(needle,start)
                if pos<0:break
                candidates.append(('push-imm32-byte-candidate',f'0x{origin+pos:X}',f'0x{target:X}',name))
                start=pos+1
        for m in re.finditer(b'\xe8',data):
            pos=m.start()
            if pos+5>len(data):continue
            target=(origin+pos+5+struct.unpack_from('<i',data,pos+1)[0]) & 0xffffffff
            if target in CALL_TARGETS:
                candidates.append(('call-rel32-byte-candidate',f'0x{origin+pos:X}',f'0x{target:X}',name))
    csvfile('xref-candidates.csv',['kind_not_proof_of_instruction_boundary','site_preferred_va','target_preferred_va','executable_section'],sorted(candidates,key=lambda r:int(r[1],16)))
    print(f'{len(sources)} files scanned; {len(rows)} literal hits; {len(candidates)} raw xref candidates; {len(SPANS)} excerpts')

if __name__=='__main__': main()
