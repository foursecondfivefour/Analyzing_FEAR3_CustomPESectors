#!/usr/bin/env python3
"""Correlate every Resource string and RTTI class with the pinned Lua repository."""
from pathlib import Path
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
REV='4a7a7cf3d48f09dca446441d8af427f30556280d'
ZIP_SHA='1f3aa0fb555a8e2bbb05b04b6464aa49951416baaed568e5963440b6ea2b80e6'
EXE_SHA='caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2'
SECTION_SHA='6e4679833292366db29855d40f4f32734028740291142b9d1ffc2e62cb7e9ec6'
REPO=ROOT/'external/lua-api/snapshot'; ZIP=ROOT/'external/lua-api/source.zip'; OUT=ROOT/'analysis/resource/lua-correlation'

def sha(x):return hashlib.sha256(x).hexdigest()
def csv_write(path,fields,rows):
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,lineterminator="\n");w.writeheader();w.writerows(rows)

def main():
    if sha(ZIP.read_bytes())!=ZIP_SHA:raise SystemExit('Snapshot ZIP hash mismatch')
    with zipfile.ZipFile(ZIP) as z:
        prefix='FEAR3-DespairEngineLuaAPI-'+REV+'/'
        expected_files={i.filename[len(prefix):]:i for i in z.infolist() if not i.is_dir() and i.filename.startswith(prefix)}
        actual_files={str(p.relative_to(REPO)).replace('\\','/') for p in REPO.rglob('*') if p.is_file()}
        if set(expected_files)!=actual_files:raise SystemExit('Snapshot file list mismatch')
        for path,info in expected_files.items():
            if sha((REPO/path).read_bytes())!=sha(z.read(info)):raise SystemExit('Snapshot file differs: '+path)
    files=sorted((REPO/'recovered').rglob('*.lua'));recovered={}
    for folder in ['boot','resources']:
        manifest=json.loads((REPO/'recovered'/folder/'manifest.json').read_text(encoding='utf-8'))
        for e in manifest['files']:
            path=REPO/'recovered'/folder/e['path']
            if not path.is_file() or sha(path.read_bytes())!=e['recovered_sha256']:raise SystemExit('Recovered hash mismatch: '+str(path))
            recovered[path]=e
    if set(recovered)!=set(files):raise SystemExit('Recovered Lua file list mismatch')
    inventory=json.loads((ROOT/'analysis/resource/inventory.json').read_text(encoding='utf-8'))
    exe=(ROOT/'evidence/source-exe/F.E.A.R. 3.exe').read_bytes()
    sec=(ROOT/'evidence/fear3-engine-sections/15_Resource.bin').read_bytes()
    if sha(exe)!=EXE_SHA or sha(sec)!=SECTION_SHA or inventory['resource_sha256']!=SECTION_SHA:raise SystemExit('Evidence SHA-256 mismatch')
    api=json.loads((REPO/'api/despair-api.json').read_text(encoding='utf-8'))['entries']
    corpus={str(f.relative_to(REPO)).replace('\\','/'):f.read_bytes() for f in files}
    hitrows=[];summaries=[]
    for item in inventory['strings']:
        term=item['value'].encode('ascii'); count=0; filecount=0
        for path,data in corpus.items():
            pos=0; found=False
            while True:
                i=data.find(term,pos)
                if i<0:break
                found=True;count+=1
                hitrows.append({'resource_offset':item['offset'],'literal_repr':repr(item['value']),
                                'path':path,'line':data.count(b'\n',0,i)+1,'file_byte_offset':i})
                pos=i+1
            filecount+=found
        summaries.append({'resource_offset':item['offset'],'literal_repr':repr(item['value']),
                          'length':len(term),'occurrences':count,'files':filecount})
    classes=sorted({ptr['rtti']['decorated_type'][4:].split('@')[0] for ptr in inventory['aligned_pointer_candidates'] if ptr['rtti']})
    classrows=[]
    for term in classes:
        literal=term.lower().encode('ascii');hits=[path for path,data in corpus.items() if literal in data.lower()]
        api_hits=[e['name'] for e in api if term.lower() in json.dumps(e,ensure_ascii=False).lower()]
        classrows.append({'rtti_class':term,'recovered_files':len(hits),'recovered_paths':' | '.join(hits),
                          'api_entries':len(api_hits),'api_names':' | '.join(api_hits)})
    broad=[]
    for path,data in corpus.items():
        for line_number,line in enumerate(data.splitlines(),1):
            matches=sorted(set(m.group(0).decode('ascii').lower() for m in re.finditer(rb'resource|stream|flexml',line,re.I)))
            if matches:broad.append({'path':path,'line':line_number,'matched_terms':' | '.join(matches)})
    apirows=[]
    for e in api:
        if re.search(r'resource|stream|flexml',e['name'],re.I):
            apirows.append({'name':e['name'],'namespace':e['namespace'],
                            'stub_line':e['signature']['line'] if e['signature'] else '',
                            'category':'editor' if e['name'].startswith('Despair.') else ('GameScript' if e['name'].startswith('GameScript.') else 'other')})
    OUT.mkdir(parents=True,exist_ok=True)
    csv_write(OUT/'literal-summary.csv',['resource_offset','literal_repr','length','occurrences','files'],summaries)
    csv_write(OUT/'literal-hits.csv',['resource_offset','literal_repr','path','line','file_byte_offset'],hitrows)
    csv_write(OUT/'rtti-class-matches.csv',['rtti_class','recovered_files','recovered_paths','api_entries','api_names'],classrows)
    csv_write(OUT/'related-script-lines.csv',['path','line','matched_terms'],broad)
    csv_write(OUT/'api-name-candidates.csv',['name','namespace','stub_line','category'],apirows)
    # Manually reviewed instruction boundaries, not blind whole-section linear sweep.
    p=pefile.PE(data=exe); base=p.OPTIONAL_HEADER.ImageBase;md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    snippets=[('Registration pair: StreamWorlds',0x127F9CE,0x127F9E4),
              ('Registration pair: StreamWorldsWithSaveOverride',0x127FA01,0x127FA17),
              ('StreamWorlds descriptor builder',0x82C4A0,0x82C4EC),
              ('StreamWorldsWithSaveOverride descriptor builder',0x4A2D30,0x4A2D7C),
              ('StreamWorlds wrapper',0xC316A0,0xC316B4),
              ('Early branches and provenance of EBX',0x9DA0AD,0x9DA12D),
              ('Conditional path to shared accessor',0x9DA1D6,0x9DA1F4),
              ('Shared accessor in ResourceMgr2 vtable',0xC2D6F0,0xC2D6F4),
              ('Registration pair: SetAnimationGraphResource',0x127F197,0x127F1AD),
              ('SetAnimationGraphResource descriptor builder',0x67B820,0x67B86C),
              ('SetAnimationGraphResource wrapper',0x93CC90,0x93CCAE),
              ('Registration pair: RemoveAnimationGraphResource',0x127F1F7,0x127F20D),
              ('RemoveAnimationGraphResource wrapper',0x436020,0x436037)]
    lines=[]; decoded={}
    for label,start,end in snippets:
        ins=list(md.disasm(p.get_data(start-base,end-start),start))
        if sum(i.size for i in ins)!=end-start:raise ValueError('instruction boundary: '+label)
        decoded[start]=ins
        lines.append(f'=== {label}: {start:08X}-{end:08X} exclusive ===\n')
        lines.extend(f'{x.address:08X}  {x.bytes.hex(" "):<29} {x.mnemonic:<8} {x.op_str}\n' for x in ins)
        lines.append('\n')
    assert p.get_data(0x18788A8-base,len('StreamWorlds')+1)==b'StreamWorlds\0'
    assert p.get_data(0x1878888-base,len('StreamWorldsWithSaveOverride')+1)==b'StreamWorldsWithSaveOverride\0'
    assert p.get_data(0x1878CBC-base,len('SetAnimationGraphResource')+1)==b'SetAnimationGraphResource\0'
    assert p.get_data(0x1878C78-base,len('RemoveAnimationGraphResource')+1)==b'RemoveAnimationGraphResource\0'
    float_bytes=p.get_data(0x145B2D0-base,4)
    assert float_bytes==bytes.fromhex('CD CC 4C 3E')
    lines.append(f'Float constant 0x145B2D0: {float_bytes.hex(" ")} = {struct.unpack("<f",float_bytes)[0]} (IEEE-754 binary32)\n')
    assert int.from_bytes(sec[0x5f4:0x5f8],'little')==0xC2D6F0
    for start,function_va,name_va in [(0x127F9CE,0xC316A0,0x18788A8),
                                       (0x127FA01,0x9DA070,0x1878888),
                                       (0x127F197,0x93CC90,0x1878CBC),
                                       (0x127F1F7,0x436020,0x1878C78)]:
        ins=decoded[start]
        assert ins[2].mnemonic=='mov' and ins[2].operands[1].imm==function_va
        assert ins[3].mnemonic=='push' and ins[4].mnemonic=='push' and ins[4].operands[0].imm==name_va
        assert ins[5].mnemonic=='call'
    assert any(i.address==0xC316AC and i.operands[0].imm==0x9DA070 for i in decoded[0xC316A0])
    assert any(i.address==0x9DA1DC and i.operands[0].imm==0xC2D6F0 for i in decoded[0x9DA1D6])
    assert any(i.address==0x93CCA6 and i.operands[0].imm==0x7681F0 for i in decoded[0x93CC90])
    assert any(i.address==0x43602F and i.operands[0].imm==0xA34E10 for i in decoded[0x436020])
    (OUT/'native-bridge-asm.txt').write_text('\n'.join(line.rstrip() for line in ''.join(lines).splitlines()).rstrip() + '\n',encoding='utf-8')
    # Raw E8 relative-call byte patterns, not necessarily valid instruction boundaries.
    text=p.sections[0]; textva=base+text.VirtualAddress
    code=exe[text.PointerToRawData:text.PointerToRawData+text.SizeOfRawData]
    calls=[]; pos=0
    while True:
        pos=code.find(b'\xe8',pos)
        if pos<0 or pos+5>len(code): break
        if textva+pos+5+struct.unpack_from('<i',code,pos+1)[0]==0xC2D6F0:
            calls.append({'candidate_call_va':f'0x{textva+pos:X}','file_offset':f'0x{text.PointerToRawData+pos:X}'})
        pos+=1
    csv_write(OUT/'shared-accessor-e8-candidates.csv',['candidate_call_va','file_offset'],calls)
    # Literal u32 occurrences are likewise only byte matches.
    occurrences=[];pos=0;needle=struct.pack('<I',0xC2D6F0)
    while True:
        pos=exe.find(needle,pos)
        if pos<0:break
        try:
            rva=p.get_rva_from_offset(pos); section=p.get_section_by_rva(rva)
            name=section.Name.rstrip(b'\0').decode('ascii','backslashreplace') if section else ''
            va=f'0x{base+rva:X}'
        except pefile.PEFormatError: name='';va=''
        occurrences.append({'file_offset':f'0x{pos:X}','preferred_va':va,'section':name})
        pos+=1
    csv_write(OUT/'shared-accessor-u32-occurrences.csv',['file_offset','preferred_va','section'],occurrences)
    stats={'repository':'https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI',
           'commit':REV,'codeload_sha256':ZIP_SHA,'snapshot_files':len(actual_files),
           'recovered_lua_files':len(files),'manifest_hashes_verified':len(recovered),
           'original_bytecode_and_claimed_tree_comparison_independently_verified':False,
           'resource_string_count':len(summaries),'rtti_class_count':len(classes),
           'resource_literal_occurrences':len(hitrows),'resource_related_lines':len(broad),
           'api_candidates':len(apirows),'shared_accessor_raw_e8_candidates':len(calls),
           'shared_accessor_raw_u32_occurrences':len(occurrences),
           'exe_sha256':EXE_SHA,'resource_sha256':SECTION_SHA}
    (OUT/'provenance.json').write_text(json.dumps(stats,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(stats,indent=2))

if __name__=='__main__':main()
