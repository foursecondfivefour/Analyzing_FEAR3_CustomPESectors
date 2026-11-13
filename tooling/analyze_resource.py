#!/usr/bin/env python3
"""Produce a reproducible, static byte census and candidate-reference inventory."""
import collections
import csv
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tooling/python'))
import pefile
import capstone

SRC = ROOT / 'evidence/fear3-engine-sections/15_Resource.bin'
EXE = ROOT / 'evidence/source-exe/F.E.A.R. 3.exe'
OUT = ROOT / 'analysis/resource'
EXPECTED = '6e4679833292366db29855d40f4f32734028740291142b9d1ffc2e62cb7e9ec6'
EXPECTED_EXE = 'caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2'
# These are observed starts, not inferred data types. Include the newline in the diagnostic string.
STRING_STARTS = (0x60,0x78,0xf0,0xf8,0x100,0x108,0x10c,0x110,0x114,
  0x150,0x1c8,0x200,0x210,0x218,0x220,0x22c,0x234,0x318,0x330,0x388,0x398,
  0x418,0x530,0x540,0x558,0x570,0x600,0x610,0x630,0x658,0x6dc,0x6f4,0x730,0x7cc)

def hash256(b): return hashlib.sha256(b).hexdigest()
def hx(v): return f'0x{v:X}'
def signed(x): return x if x < 0x80000000 else x - 0x100000000

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data, raw = SRC.read_bytes(), EXE.read_bytes()
    if hash256(data)!=EXPECTED or hash256(raw)!=EXPECTED_EXE:
        raise SystemExit('Evidence SHA-256 mismatch; refusing to analyze')
    p = pefile.PE(data=raw)
    sec = p.sections[15]
    if sec.Name != b'Resource' or sec.SizeOfRawData != len(data) or raw[sec.PointerToRawData:sec.PointerToRawData+len(data)] != data:
        raise SystemExit('Resource section mismatch')
    imagebase = p.OPTIONAL_HEADER.ImageBase
    va = imagebase + sec.VirtualAddress
    def in_section(v):
        if v < imagebase: return None
        s = p.get_section_by_rva(v-imagebase)
        return s.Name.rstrip(b'\0').decode('ascii', 'backslashreplace') if s else None
    def read_va(v, size):
        if not in_section(v): raise ValueError('invalid VA')
        d=p.get_data(v-imagebase, size)
        if len(d)!=size: raise ValueError('truncated VA')
        return d
    def name_va(v):
        # Pointer must be file-backed; stop at NUL and bound the input.
        rva=v-imagebase
        offset=p.get_offset_from_rva(rva)
        return raw[offset:offset+256].split(b'\0',1)[0].decode('ascii','backslashreplace')
    def rtti(v):
        try:
            sig, displacement, cd, typeva, hierarchy = struct.unpack('<5I',read_va(v,20))
            if sig != 0: return None
            typename=name_va(typeva+8)
            if not typename.startswith('.?A'): return None
            hs, attrs, count, arr = struct.unpack('<4I',read_va(hierarchy,16))
            if count>64: return None
            entries=struct.unpack('<'+'I'*count,read_va(arr,4*count)) if count else []
            bases=[]
            for ptr in entries:
                td,n,md,pd,vd,attr,ch=struct.unpack('<7I',read_va(ptr,28))
                bases.append({'type':name_va(td+8),'descriptor_va':hx(ptr),'contained_bases':n,
                              'mdisp':signed(md),'pdisp':signed(pd),'vdisp':signed(vd),'attributes':hx(attr)})
            return {'locator_va':hx(v),'signature':sig,'object_offset':displacement,
                    'constructor_displacement':cd,'type_descriptor_va':hx(typeva),
                    'decorated_type':typename,'hierarchy_va':hx(hierarchy),'hierarchy_signature':hs,
                    'hierarchy_attributes':hx(attrs),'base_classes':bases}
        except (ValueError, pefile.PEFormatError, struct.error, IndexError): return None
    labels=['']*len(data); strings=[]
    for start in STRING_STARTS:
        end=data.find(b'\0',start)
        if end<start or not all(0x20<=x<=0x7e or x==10 for x in data[start:end]):
            raise ValueError(f'Invalid string at {start:#x}')
        for i in range(start,end): labels[i]='string byte'
        labels[end]='string NUL'
        strings.append({'offset':hx(start),'end_inclusive':hx(end),'value':data[start:end].decode('ascii')})
    words=[]; ptrs=[]
    for off in range(0,len(data),4):
        chunk=data[off:off+4]; val=struct.unpack('<I',chunk)[0]; section=in_section(val)
        has_string=any(labels[off:off+4])
        kind = 'string overlap' if has_string else ('zero' if not val else ('in-image candidate' if section else 'other nonzero'))
        row={'offset':hx(off),'file_offset':hx(sec.PointerToRawData+off),'rva':hx(sec.VirtualAddress+off),
             'preferred_va':hx(va+off),'bytes_le':chunk.hex(' '),'u32_le_hex':hx(val),
             'u32_le_decimal':val,'category':kind,'candidate_target_section':section or ''}
        words.append(row)
        if section and not has_string:
            record=dict(row); record['rtti']=rtti(val) if section=='.rdata' else None
            ptrs.append(record)
            for i in range(off,off+4):
                if not labels[i]: labels[i]='pointer candidate byte'
    with (OUT/'bytes.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f, lineterminator="\n");w.writerow(['section_offset','file_offset','rva','preferred_va_arithmetic','value_hex','value_decimal','interpretation','region'])
        for off,c in enumerate(data):
            label=labels[off] or ('zero (meaning undetermined)' if c==0 else 'other nonzero (meaning undetermined)')
            w.writerow([hx(off),hx(sec.PointerToRawData+off),hx(sec.VirtualAddress+off),hx(va+off),f'{c:02X}',c,label,
                        'raw beyond VirtualSize' if off>=sec.Misc_VirtualSize else 'within VirtualSize'])
    with (OUT/'words.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=words[0],lineterminator="\n");w.writeheader();w.writerows(words)
    with (OUT/'hexdump.txt').open('w',encoding='utf-8') as f:
        for off in range(0,len(data),16):
            chunk=data[off:off+16]
            f.write(f'{off:04X}  {chunk.hex(" "):<47}  '+''.join(chr(x) if 32<=x<127 else '.' for x in chunk)+'\n')
    cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);cs.detail=True
    # Search every byte offset, including unaligned occurrences; do not equate matches with proven xrefs.
    matches=[]
    for offset in range(len(raw)-3):
        if raw[offset+3] != (va >> 24): continue
        value=struct.unpack_from('<I',raw,offset)[0]
        if not va<=value<va+len(data): continue
        try:
            rva=p.get_rva_from_offset(offset); locsec=p.get_section_by_rva(rva)
            locname=locsec.Name.rstrip(b'\0').decode('ascii','backslashreplace') if locsec else 'none'
        except pefile.PEFormatError: rva=None;locname='none'
        candidates=[]
        if locname=='.text':
            for start in range(max(locsec.PointerToRawData,offset-10),offset):
                locva=imagebase+locsec.VirtualAddress+(start-locsec.PointerToRawData)
                ins=next(cs.disasm(raw[start:start+15],locva,count=1),None)
                if ins and ((ins.imm_offset==offset-start and ins.imm_size==4) or (ins.disp_offset==offset-start and ins.disp_size==4)):
                    candidates.append(f'{hx(ins.address)} {ins.mnemonic} {ins.op_str}')
        matches.append({'file_offset':hx(offset),'preferred_va':hx(imagebase+rva) if rva is not None else '',
                        'source_section':locname,'target_section_offset':hx(value-va),'target_preferred_va':hx(value),
                        'possible_instructions_unvalidated':' | '.join(candidates)})
    with (OUT/'address_matches.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=matches[0],lineterminator="\n");w.writeheader();w.writerows(matches)
    targets=sorted({int(x['u32_le_hex'],16) for x in ptrs if x['candidate_target_section']=='.text'})
    with (OUT/'text_target_previews.txt').open('w',encoding='utf-8') as f:
        f.write('Heuristic previews at candidate pointer targets; not complete functions or proven boundaries.\n\n')
        for target in targets:
            f.write(f'=== preferred VA {target:#x} ===\n')
            for ins in cs.disasm(p.get_data(target-imagebase,80),target,count=12):
                f.write(f'{ins.address:08X}  {ins.bytes.hex():<20} {ins.mnemonic:<8} {ins.op_str}\n')
                if ins.mnemonic.startswith('ret'): break
            f.write('\n')
    previews = OUT/'text_target_previews.txt'
    previews.write_text('\n'.join(line.rstrip() for line in previews.read_text(encoding='utf-8').splitlines()).rstrip() + '\n', encoding='utf-8')
    counts=collections.Counter(data)
    result={'resource_sha256':hash256(data),'exe_sha256':hash256(raw),'size':len(data),
            'virtual_size':sec.Misc_VirtualSize,'file_offset':hx(sec.PointerToRawData),
            'rva':hx(sec.VirtualAddress),'preferred_va':hx(va),
            'zeros':counts[0],'nonzeros':len(data)-counts[0],
            'last_nonzero_offset':hx(max(i for i,x in enumerate(data) if x)),
            'trailing_zero_bytes':len(data)-len(data.rstrip(b'\0')),
            'entropy_bits_per_byte':-sum((n/len(data))*math.log2(n/len(data)) for n in counts.values()),
            'byte_histogram':{f'{i:02X}':counts[i] for i in range(256)},
            'strings':strings,'aligned_pointer_candidates':ptrs,
            'candidate_pointer_counts_by_target_section':dict(collections.Counter(x['candidate_target_section'] for x in ptrs)),
            'candidate_address_matches_by_source_section':dict(collections.Counter(x['source_section'] for x in matches)),
            'unique_text_target_previews':len(targets)}
    (OUT/'inventory.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(f'{len(data)} bytes, {len(words)} aligned words, {len(strings)} strings, {len(ptrs)} aligned pointer candidates, {len(matches)} raw address matches')
    print('Pointer target sections:',result['candidate_pointer_counts_by_target_section'])
    print('Raw address matches by source section:',result['candidate_address_matches_by_source_section'])

if __name__=='__main__': main()
