#!/usr/bin/env python3
"""Compare PE script RTTI, code patterns and the pinned upstream API catalog."""
from pathlib import Path
from collections import Counter, defaultdict
import csv
import hashlib
import json
import re
import struct
import sys
import zipfile

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tooling/python'))
import pefile
import capstone

EXE=ROOT/'evidence/source-exe/F.E.A.R. 3.exe'
SNAP=ROOT/'external/lua-api/snapshot'
ZIP=ROOT/'external/lua-api/source.zip'
OUT=ROOT/'analysis/script-api-comparison'
REV='4a7a7cf3d48f09dca446441d8af427f30556280d'
EXE_SHA='caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2'
ZIP_SHA='1f3aa0fb555a8e2bbb05b04b6464aa49951416baaed568e5963440b6ea2b80e6'
DOC_SHA='6f6e8143cf8374ac24e7dd9301372a013b2be86fc3692bf8d29a83f76c902b58'
REGISTRATION=re.compile(rb'\x33\xc0\x50\xb8(.{4})\x50\x68(.{4})\xe8(.{4})\x83\xc4\x0c\x50(?:\x8b[\xc8-\xcf]|\xb9.{4})\xe8(.{4})',re.S)
# Whole, common builder shape; wildcard operands retained but not interpreted as code.
BUILDER=re.compile(rb'\x56\x6a\x28\xe8....\x8b\xf0\x83\xc4\x04\x85\xf6\x74\x3b\x8d\x4e\x04\xc7\x06....\xe8....\x8b\x44\x24\x08\x89\x46\x10\xc7\x46\x14....\xc7\x46\x18\x00\x00\x00\x00\xc7\x06(.{4})\x8b\x4c\x24\x0c\x89\x4e\x20\x8b\x54\x24\x10\x89\x56\x24\x8b\xc6\x5e\xc3',re.S)


def sha(b): return hashlib.sha256(b).hexdigest()
def hx(n): return f'0x{n:X}'
def csvfile(name,fields,rows):
    with (OUT/name).open('w',encoding='utf-8',newline='') as f:
        w=csv.writer(f,lineterminator='\n');w.writerow(fields);w.writerows(rows)


def main():
    exe=EXE.read_bytes()
    if sha(exe)!=EXE_SHA:raise SystemExit('EXE SHA-256 mismatch')
    if sha(ZIP.read_bytes())!=ZIP_SHA:raise SystemExit('ZIP SHA-256 mismatch')
    prefix='FEAR3-DespairEngineLuaAPI-'+REV+'/'
    with zipfile.ZipFile(ZIP) as z:
        expected={i.filename[len(prefix):]:i for i in z.infolist() if not i.is_dir() and i.filename.startswith(prefix)}
        actual={x.relative_to(SNAP).as_posix() for x in SNAP.rglob('*') if x.is_file()}
        if set(expected)!=actual:raise SystemExit('Snapshot file list mismatch')
        for name,info in expected.items():
            if sha((SNAP/name).read_bytes())!=sha(z.read(info)):raise SystemExit('Snapshot file differs: '+name)
    doc=(SNAP/'docs/API.md').read_bytes()
    if sha(doc)!=DOC_SHA:raise SystemExit('API.md SHA mismatch')
    docrows=re.findall(r'^\| \[([^\]]+)\]\(reference/[^)]+\) \| (\d+) \|$',doc.decode('utf-8'),re.M)
    entries=json.loads((SNAP/'api/despair-api.json').read_text(encoding='utf-8'))['entries']
    ns_counts=Counter(e['namespace'] for e in entries)
    if len(docrows)!=len(ns_counts) or dict((x,int(y)) for x,y in docrows)!=dict(ns_counts):raise ValueError('API.md index disagrees with JSON')
    with (ROOT/'analysis/script-classes/script-classes.csv').open(encoding='utf-8',newline='') as f:
        classes=list(csv.DictReader(f))
    if len(classes)!=149:raise ValueError('Expected 149 input class rows; rerun extractor')
    pe=pefile.PE(data=exe);base=pe.OPTIONAL_HEADER.ImageBase
    OUT.mkdir(parents=True,exist_ok=True)
    # Cross-check each extracted type descriptor and decorated string against EXE.
    for cls in classes:
        addr=int(cls['name_preferred_va'],16)
        if pe.get_string_at_rva(addr-base).decode('ascii')!=cls['decorated_name']:
            raise ValueError('RTTI input differs from EXE: '+cls['plain_name_if_simple'])
    by_ns=defaultdict(list)
    for entry in entries:by_ns[entry['namespace']].append(entry)
    game_ns=sorted(n for n in ns_counts if n.startswith('GameScript.'))
    entry_names={e['name'] for e in entries}
    # Every simple class gets a row; namespace mapping is strictly name-based, not a proof of binding.
    crows=[]; candidate_map={}
    for cls in classes:
        full=cls['plain_name_if_simple'];leaf=full.split('::')[-1]
        direct=[e['name'] for e in entries if leaf in e['name'].split('.')]
        suffix=leaf[len('GameScript'):] if leaf.startswith('GameScript') else ''
        matched=[n for n in game_ns if suffix and n.split('.')[-1]==suffix]
        if matched:candidate_map[leaf]=matched
        alias= suffix if suffix in by_ns else ''
        same=''
        if alias and len(matched)==1:
            same=str({e['name'].split('.')[-1] for e in by_ns[alias]}=={e['name'].split('.')[-1] for e in by_ns[matched[0]]}).lower()
        crows.append((full,cls['name_preferred_va'],len(direct),' | '.join(direct),' | '.join(matched),sum(ns_counts[n] for n in matched),alias,same))
    csvfile('class-namespace-comparison.csv',['native_rtti_class','native_rtti_name_va','exact_api_path_component_count','exact_api_paths','possible_gamescript_namespaces_by_suffix','namespace_entries','short_alias_namespace_if_present','alias_member_names_equal'],crows)
    # Whole NUL-terminated strings preceded by NUL or section boundary. Stronger than substring;
    # this deliberately misses legitimate strings preceded by a nonzero byte.
    index=defaultdict(list)
    for i,s in enumerate(pe.sections):
        data=exe[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        for m in re.finditer(rb'[\x20-\x7e]{1,}\x00',data):
            pos=m.start()
            if pos and data[pos-1]!=0:continue
            val=m.group()[:-1].decode('ascii')
            index[val].append((i,s.Name.rstrip(b'\0').decode('ascii','replace').strip(),base+s.VirtualAddress+pos,s.PointerToRawData+pos))
    rows=[]
    for entry in entries:
        name=entry['name'];leaf=name.split('.')[-1];matches=index.get(leaf,[])
        rows.append((name,entry['namespace'],leaf,len(matches),' | '.join(f'{sec}:{hx(va)}' for _,sec,va,_ in matches),str(entry['signature'] is not None).lower(),str(entry['calltip'] is not None).lower()))
    csvfile('api-entry-exact-leaf-strings.csv',['api_full_name','api_namespace','api_leaf','pe_literal_occurrences','pe_section_and_preferred_va','has_stub_signature','has_calltip'],rows)
    # Fixed x86 patterns are still candidates: no proof all 181 sites are instruction boundaries.
    text=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
    data=exe[text.PointerToRawData:text.PointerToRawData+text.SizeOfRawData];origin=base+text.VirtualAddress
    typed=[]
    def code(va):
        sec=pe.get_section_by_rva(va-base)
        return bool(sec and sec.Characteristics & 0x20000000)
    for m in REGISTRATION.finditer(data):
        site=origin+m.start();func=struct.unpack('<I',m.group(1))[0];nameva=struct.unpack('<I',m.group(2))[0]
        builder=(site+19+struct.unpack('<i',m.group(3))[0]) & 0xffffffff
        sink=(site+len(m.group(0))+struct.unpack('<i',m.group(4))[0]) & 0xffffffff
        try:
            if not code(func) or not code(builder) or not code(sink):continue
            leaf=pe.get_string_at_rva(nameva-base).decode('ascii')
            b=BUILDER.match(pe.get_data(builder-base,100))
            if not b:continue
            vt=struct.unpack('<I',b.group(1))[0]
            col=struct.unpack('<I',pe.get_data(vt-base-4,4))[0]
            sig,obj_off,cd,td,hierarchy=struct.unpack('<IIIII',pe.get_data(col-base,20))
            if sig!=0 or obj_off!=0:continue
            decorated=pe.get_string_at_rva(td-base+8).decode('ascii')
            match=re.search(r'^\.\?AV\?\$ClassMethodProxy[^@]*@[^@]*V(GameScript[A-Za-z0-9_]+)@Despair@@',decorated)
            if not match:continue
            classname=match.group(1)
            for namespace in candidate_map.get(classname,[]):
                full=namespace+'.'+leaf
                if full not in entry_names:continue
                typed.append((full,classname,leaf,hx(nameva),hx(site),hx(func),hx(builder),hx(vt),hx(col),hx(td),hx(sink),decorated))
        except (ValueError,UnicodeDecodeError,pefile.PEFormatError,struct.error):
            continue
    csvfile('typed-proxy-pattern-candidates.csv',['api_name_name_based','cpp_class_from_proxy_rtti','method_leaf','method_string_va','raw_pattern_site_va','native_function_va','builder_va','builder_vtable_va','col_va','proxy_type_descriptor_va','post_builder_call_va','decorated_proxy_type'],typed)
    reviewed=[
        ('Game.StreamWorlds registration',0x127f9ce,0x127f9ef),
        ('Game.StreamWorlds proxy constructor',0x82c4a0,0x82c4ec),
        ('Game.SetAnimationGraphResource registration',0x127f197,0x127f1b8),
        ('Game.SetAnimationGraphResource proxy constructor',0x67b820,0x67b86c),
        ('Player.RevivePlayerInstant registration',0x1272f2d,0x1272f4b),
        ('Player.RevivePlayerInstant proxy constructor',0xa82000,0xa8204c),
        ('Support.RegisterAnimationGraphResourceVariable registration',0x1275094,0x12750b2),
        ('Support.RegisterAnimationGraphResourceVariable proxy constructor',0x981300,0x98134c),
    ]
    required={'GameScript.Game.StreamWorlds','GameScript.Game.SetAnimationGraphResource','GameScript.Game.Player.RevivePlayerInstant','GameScript.Support.RegisterAnimationGraphResourceVariable'}
    if not required.issubset({x[0] for x in typed}):raise ValueError('Reviewed patterns missing')
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    lines=['Reviewed x86 instruction excerpts. Preferred VAs. Excerpt ends are exclusive.']
    for label,start,end in reviewed:
        ins=list(md.disasm(pe.get_data(start-base,end-start),start))
        if sum(x.size for x in ins)!=end-start:raise ValueError('Bad instruction boundary: '+label)
        lines.append(f'\n=== {label}: {start:08X}-{end:08X} ===')
        lines.extend(f'{x.address:08X}  {x.bytes.hex(" "):<28} {x.mnemonic:<8} {x.op_str}'.rstrip() for x in ins)
    (OUT/'reviewed-bridges-asm.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    stats={'revision':REV,'api_md_sha256':DOC_SHA,'archive_sha256':ZIP_SHA,'exe_sha256':EXE_SHA,
           'snapshot_files':len(expected),'doc_index_namespaces':len(docrows),'api_entries':len(entries),
           'game_script_api_entries':sum(1 for e in entries if e['namespace']=='GameScript' or e['namespace'].startswith('GameScript.')),
           'native_simple_script_classes':len(classes), 'classes_exact_api_path_component':sum(int(x[2])>0 for x in crows),
           'classes_with_suffix_namespace_candidates':sum(bool(x[4]) for x in crows),
           'api_entries_with_exact_pe_leaf_string':sum(int(x[3])>0 for x in rows),
           'game_script_entries_with_exact_pe_leaf_string':sum(int(x[3])>0 and (x[1]=='GameScript' or x[1].startswith('GameScript.')) for x in rows),
           'typed_proxy_pattern_candidates':len(typed),
           'typed_proxy_candidate_classes':dict(sorted(Counter(x[1] for x in typed).items())),
           'game_debug_dump_raw_case_insensitive_exe_hits':{enc:exe.lower().count('gamedebugdump'.encode(enc)) for enc in ('ascii','utf-16le','utf-16be')}}
    (OUT/'stats.json').write_text(json.dumps(stats,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps(stats,indent=2,ensure_ascii=False))

if __name__=='__main__':main()
