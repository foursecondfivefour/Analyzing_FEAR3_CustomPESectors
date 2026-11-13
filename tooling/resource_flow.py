#!/usr/bin/env python3
"""Reproduce selected instruction excerpts anchored to known table targets and code sites."""
from pathlib import Path
import csv
import hashlib
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'tooling/python'))
import pefile
import capstone

EXE = ROOT/'evidence/source-exe/F.E.A.R. 3.exe'
SECTION = ROOT/'evidence/fear3-engine-sections/15_Resource.bin'
OUT = ROOT/'analysis/resource'
# Each interval starts at a verified table target or independently reviewed instruction boundary.
# Intervals can be excerpts; their ends do not imply end of function.
SPANS = [
 ('ResourceMgr2 object initialization excerpt',0xAFF210,0xAFF2BB),
 ('ResourceMgr2 byte setter',0x6AA760,0x6AA76A),
 ('ResourceMgr2 byte getter',0x69E000,0x69E004),
 ('ResourceMgr2 nested byte setter 1D',0x6CEDB0,0x6CEDC0),
 ('ResourceMgr2 nested byte getter 1D',0x9F80E0,0x9F80EA),
 ('ResourceMgr2 nested byte setter 1E',0xCFC250,0xCFC260),
 ('ResourceMgr2 nested byte getter 1E',0x67B130,0x67B13A),
 ('ResourceMgr2 address-of-field accessor',0xC2D6F0,0xC2D6F4),
 ('ResourceJobWrapper dispatch',0x6EFE90,0x6EFE98),
 ('Job dispatch target excerpt',0xE3D9F0,0xE3DA61),
 ('Job diagnostic branch excerpt',0xE3DA61,0xE3DAA0),
 ('FlexML path formatting excerpt',0x8DD489,0x8DD4D4),
 ('Variadic formatting helper',0x942E50,0x942E84),
 ('RenameStream name-holder initialization',0x552F80,0x552FDB),
 ('RenameStream creation excerpt',0x8C6870,0x8C68CA),
 ('RenameStream destructor first slot',0xA2E4A0,0xA2E4F3),
 ('RenameStream local accessor',0x52D1A0,0x52D1A7),
 ('FlexMLWrapperLoadResource output pointer',0x861060,0x86106D),
 ('FlexMLWrapperLoadResource field setter',0xBEEDC0,0xBEEDCA),
 ('FlexMLWrapperLoadResource field getter',0xB530C0,0xB530C4),
 ('FlexMLWrapperLoadResource constant zero',0xA71E30,0xA71E33),
]
WRAPPERS = [
 (0x7F8,0x56ED90,0x08), (0x7FC,0x6DDBC0,0x0C), (0x800,0x973F00,0x10),
 (0x804,0xDCD1B0,0x14), (0x808,0xC99A60,0x18), (0x80C,0x4D61C0,0x1C),
 (0x810,0x554430,0x20), (0x814,0xD1B030,0x24), (0x818,0xC77180,0x28),
 (0x81C,0xA58840,0x2C), (0x820,0x6A0110,0x30),
]

def main():
    data=EXE.read_bytes(); sec=SECTION.read_bytes()
    if hashlib.sha256(data).hexdigest()!='caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2' or hashlib.sha256(sec).hexdigest()!='6e4679833292366db29855d40f4f32734028740291142b9d1ffc2e62cb7e9ec6':
        raise SystemExit('Evidence SHA-256 mismatch')
    p=pefile.PE(data=data); base=p.OPTIONAL_HEADER.ImageBase
    imports={i.address: (dll.dll, i.name) for dll in p.DIRECTORY_ENTRY_IMPORT for i in dll.imports}
    for address, expected in {0x13F0250:(b'KERNEL32.dll',b'InterlockedDecrement'),
                              0x13F025C:(b'KERNEL32.dll',b'InterlockedIncrement'),
                              0x13F0448:(b'MSVCP90.dll',b'?length@?$char_traits@D@std@@SAIPBD@Z'),
                              0x13F066C:(b'MSVCR90.dll',b'_vsnprintf')}.items():
        if imports.get(address)!=expected:
            raise ValueError(f'Unexpected import at {address:X}')
    slots={0x5CC:0x6AA760, 0x5D0:0x69E000, 0x5D4:0x6CEDB0, 0x5D8:0x9F80E0,
           0x5DC:0xCFC250, 0x5E0:0x67B130, 0x5F4:0xC2D6F0, 0x62C:0x6EFE90,
           0x71C:0x861060, 0x720:0xBEEDC0, 0x724:0xB530C0, 0x72C:0xA71E30,
           0x7F0:0xA2E4A0, 0x7F4:0x52D1A0}
    for offset, target in slots.items():
        if struct.unpack_from('<I',sec,offset)[0] != target:
            raise ValueError(f'Unexpected table target at {offset:X}')
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    md.detail=True
    lines=['Selected static x86 instruction excerpts; end of excerpt is not necessarily end of function.\n',
           'All addresses are preferred VA for SHA-256 caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2.\n\n']
    spans=SPANS + [(f'RenameStream slot +0x{offset:X}, delegated slot +0x{inner:X}',va,va+10)
                   for offset,va,inner in WRAPPERS]
    for title,start,end in spans:
        blob=p.get_data(start-base,end-start)
        ins=list(md.disasm(blob,start))
        if sum(i.size for i in ins)!=end-start:
            raise ValueError(f'Invalid instruction interval {title}: {start:X}-{end:X}')
        lines.append(f'=== {title}: {start:08X}-{end:08X} (end exclusive) ===\n')
        for i in ins:
            lines.append(f'{i.address:08X}  {i.bytes.hex(" "):<29} {i.mnemonic:<8} {i.op_str}\n')
        lines.append('\n')
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'flow-snippets.txt').write_text('\n'.join(line.rstrip() for line in ''.join(lines).splitlines()).rstrip() + '\n',encoding='utf-8')
    with (OUT/'rename-stream-slots.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f, lineterminator="\n");w.writerow(['section_offset','vtable_slot_index','target_preferred_va','delegated_object_field','delegated_vtable_offset'])
        for offset,target,inner in WRAPPERS:
            if struct.unpack_from('<I',sec,offset)[0]!=target:
                raise ValueError('Unexpected vtable entry')
            # Verify opcode structure, including the encoded displacement in the third instruction.
            blob=p.get_data(target-base,10)
            ins=list(md.disasm(blob,target))
            expected=[('mov','ecx, dword ptr [ecx + 8]'),('mov','eax, dword ptr [ecx]')]
            if (len(ins)!=4 or [(i.mnemonic,i.op_str) for i in ins[:2]] != expected
                or ins[2].mnemonic!='mov' or len(ins[2].operands)!=2
                or ins[2].operands[1].type != capstone.x86.X86_OP_MEM
                or ins[2].operands[1].mem.base != capstone.x86.X86_REG_EAX
                or ins[2].operands[1].mem.disp != inner or ins[3].mnemonic!='jmp'
                or ins[3].operands[0].reg != ins[2].operands[0].reg):
                raise ValueError(f'Unexpected delegation code at {target:X}')
            w.writerow([f'0x{offset:X}',(offset-0x7F0)//4,f'0x{target:X}','+0x8',f'0x{inner:X}'])
    print(f'{len(spans)} verified instruction intervals; {len(WRAPPERS)} delegation wrappers')

if __name__=='__main__': main()
