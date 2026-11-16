#!/usr/bin/env python3
"""Run one evidence-valued integration case for each CLI command on the real PE.

Requires the local checked EXE, pefile and capstone.  This is not exhaustive testing.
"""
import contextlib
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tooling/python'))
import pefile
import capstone
import forensic_harvester as h

cmds=[['doctor','--require-exe'],['sections'],['overview'],['compare-sections'],['pe-headers'],['pe-exports','--limit','1'],['pack','--layout','u32','--value','0x6c2d50'],['tables'],['schema','analysis/cpp-classes/classes.csv'],['table','analysis/cpp-classes/classes.csv','--where','type_descriptor_va','eq','0x169B418'],['group','analysis/cpp-classes/classes.csv','--column','kind'],['layout'],['int-info','0x6c2d50'],['float-info','--bits','0x3f800000'],['uses','Despair::GameScriptPlayer'],['hierarchy','Despair::GameScriptPlayer'],['derived','Despair::Reflection::Object','--direct','--limit','1'],['imports','--dll','MSVCR90.dll','--limit','1'],['cpp-exports','--limit','1'],['triage','Despair::GameScriptPlayer','--bytes','exe','--limit','1'],['search','GameScriptPlayer','--limit','1'],['class','Despair::GameScriptPlayer'],['api','GameScript.Game.ShowMovie'],['map','--va','0x1870e7c'],['at','--va','0x1870e7c'],['signatures','--name','png','--limit','1'],['windows','--section','Game_dat','--window','4096','--step','4096','--limit','1'],['int-find','0x6c2d50','--section','Game_dat','--limit','1'],['hash','--va','0x1870e7c','--size','8'],['unpack','--va','0x1870e7c','--layout','ptr32,u32'],['cstring','--va','0x1878b4c'],['chain','--va','0x1870e7c'],['probe','--va','0x1870e7c','--size','8'],['transform','--va','0x1870e7c','--size','8','--operation','xor','--key','255'],['xor-rank','--va','0x1870e7c','--size','8'],['frequencies','--section','Game_dat','--limit','1'],['runs','--section','Game_dat','--min-length','1000','--limit','1'],['section-diff','--left','Game_dat','--right','Game_dat','--limit','1'],['audit-class','Despair::GameScriptPlayer','--require-complete'],['stats','--section','Game_dat'],['strings','--section','Game_dat','--limit','1'],['pattern','50 2D 6C 00','--section','Game_dat','--limit','1'],['words','--va','0x1870e7c','--count','2'],['vtable','--va','0x1870e7c','--count','2'],['diff','--left','0x1870e7c','--right','0x1870e7c','--size','8'],['disasm','--va','0x6c2d50','--size','8'],['dump','--va','0x1870e7c','--size','8'],['find','--text','ShowMovie','--nul','--limit','1'],['trace-string','--text','ShowMovie','--nul','--limit','1'],['refs','0x1878b4c','--limit','1']]


def run(args):
    out,err=io.StringIO(),io.StringIO()
    with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
        try: code=h.main(args)
        except SystemExit as exc: code=exc.code
    if code != 0:raise AssertionError(f"{args}: exit {code}, {err.getvalue()}")
    response=json.loads(out.getvalue())
    assert response['command']==args[0]
    return response['result']


def main():
    path=ROOT/h.EXE_REL;data=path.read_bytes()
    assert hashlib.sha256(data).hexdigest()=='caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2'
    pe=pefile.PE(data=data); base=pe.OPTIONAL_HEADER.ImageBase
    def raw(va,n):return pe.get_data(va-base,n)
    vt=0x1870e7c;slot=raw(vt,8);word=struct.unpack('<I',slot[:4])[0]
    s=next(x for x in pe.sections if x.Name.rstrip(b'\0')==b'Game_dat')
    game=data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
    results={}
    for args in cmds:
        name=args[0]
        assert name not in results
        r=run(args)
        if name=='doctor': assert r['ok']
        elif name=='sections':assert len(r['sections'])==len(pe.sections)==35
        elif name=='overview':assert r['rtti_records']==11951 and r['section_count']==35
        elif name=='compare-sections':assert r['all_equal'] and r['sections_checked']==31
        elif name=='pe-headers':assert r['section_count']==len(pe.sections) and r['image_base']==base
        elif name=='pe-exports':assert r['exports']['total']==len(pe.DIRECTORY_ENTRY_EXPORT.symbols)==199
        elif name=='pack':assert bytes.fromhex(r['hex'])==slot[:4]
        elif name=='tables':assert 'analysis/cpp-classes/classes.csv' in r['tables']
        elif name=='schema':assert 'type_descriptor_va' in r['columns']
        elif name=='table':assert r['total']==1 and r['items'][0]['display_name']=='Despair::GameScriptPlayer'
        elif name=='group':assert {x['value']:x['count'] for x in r['items']}=={'class':11832,'struct':119}
        elif name=='layout':assert r['section_count']==35 and r['file_size']==len(data)
        elif name=='int-info':assert bytes.fromhex(r['little_endian_hex'])==slot[:4]
        elif name=='float-info':assert r['value']==struct.unpack('<f',bytes.fromhex('00 00 80 3f'))[0]
        elif name=='uses':assert r['rtti_mentions']['total']>0
        elif name=='hierarchy':assert r['owner']['type_descriptor_va']=='0x169B418' and r['hierarchies']
        elif name=='derived':assert r['matches']['total']>0 and r['matches']['items'][0]['direct_base_candidate']
        elif name=='imports':
            dll=next(x for x in pe.DIRECTORY_ENTRY_IMPORT if x.dll.lower()==b'msvcr90.dll')
            assert r['symbols']['total']==len(dll.imports)
        elif name=='cpp-exports':assert r['symbols']['total']==199
        elif name=='triage':assert r['exact_class_profile']['class']['type_descriptor_va']=='0x169B418' and r['byte_search']['coverage']['all_pe_sections']
        elif name=='search':assert r['classes']['total']>0
        elif name=='class':assert r['class']['type_descriptor_va']=='0x169B418' and r['vtables']['total']==2
        elif name=='api':assert r['api']['items'][0]['api_path']=='GameScript.Game.ShowMovie'
        elif name=='map':assert int(r['matches'][0]['file_offset'],16)==pe.get_offset_from_rva(vt-base)
        elif name=='at':assert r['section_mappings'][0]['section']=='Game_dat' and r['evidence']['vtables']['total']==1
        elif name=='signatures':
            hit=r['groups']['png']['items'][0];assert raw(int(hit['preferred_va'],16),8)==bytes.fromhex('89504e470d0a1a0a')
        elif name=='windows':assert r['windows_evaluated']==len(game)//4096
        elif name=='int-find':assert int(r['groups']['32bit_little']['items'][0]['preferred_va'],16)==vt and game.count(slot[:4])==1
        elif name=='hash':assert r['hashes']['sha256']==hashlib.sha256(slot).hexdigest()
        elif name=='unpack':assert [x['value'] for x in r['fields']]==list(struct.unpack('<II',slot))
        elif name=='cstring':assert r['text_preview']=='ShowMovie' and raw(0x1878b4c,10)==b'ShowMovie\0'
        elif name=='chain':assert r['hops'][0]['value']==hex(word).upper().replace('0X','0x')
        elif name=='probe':assert r['input_size']==len(slot) and r['formats']['zlib']['status']=='decode_error'
        elif name=='transform':assert r['output_sha256']==hashlib.sha256(bytes(x^255 for x in slot)).hexdigest()
        elif name=='xor-rank':assert r['keys_tested']==256 and r['ranked'][0]['printable_bytes']==max(sum((x^k) in (9,10,13) or 32<=(x^k)<=126 for x in slot) for k in range(256))
        elif name=='frequencies':assert r['values'][0]['count']==Counter(game).most_common(1)[0][1]
        elif name=='runs':
            x=r['runs']['items'][0];off=int(x['section_offset'],16);length=x['length'];b=int(x['byte'],16)
            assert game[off:off+length]==bytes([b])*length and (off==0 or game[off-1]!=b) and (off+length==len(game) or game[off+length]!=b)
        elif name=='section-diff':assert r['identical'] and r['left_sha256']==hashlib.sha256(game).hexdigest()
        elif name=='audit-class':assert r['counts']=={'match':10,'mismatch':0,'unavailable':0} and r['all_match']
        elif name=='stats':assert r['sections'][0]['sha256']==hashlib.sha256(game).hexdigest() and r['sections'][0]['zero_bytes']==game.count(0)
        elif name=='strings':
            x=r['groups']['ascii']['items'][0];assert raw(int(x['preferred_va'],16),x['byte_length'])==x['text_preview'].encode('ascii')
        elif name=='pattern':assert int(r['hits']['items'][0]['preferred_va'],16)==vt
        elif name in ('words','vtable'):
            assert [x['unsigned'] for x in r['values']]==list(struct.unpack('<II',slot))
            if name=='vtable':assert r['known_vtable_candidates']['items'][0]['type_descriptor_va']=='0x169B418'
        elif name=='diff':assert r['identical'] and r['left_sha256']==hashlib.sha256(slot).hexdigest()
        elif name=='disasm':
            md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);first=next(md.disasm(raw(word,8),word))
            assert r['instructions'][0]['mnemonic']==first.mnemonic
        elif name=='dump':assert bytes.fromhex(r['hex'])==slot
        elif name=='find':assert r['hits']['total']==1 and int(r['hits']['items'][0]['preferred_va'],16)==0x1878b4c and r['coverage']['section_count']==35
        elif name=='trace-string':assert r['occurrences']['total']==1
        elif name=='refs':assert int(r['groups']['absolute_u32_le']['items'][0]['preferred_va'],16)==0x127f4dd and r['coverage']['section_count']==35
        else:raise AssertionError('unhandled command '+name)
        results[name]={'status':'pass','arguments':args[1:]}
    assert len(results)==50
    # Exercise section-restricted raw-byte search against a separate pefile oracle in every section.
    coverage=[]
    for index,sec in enumerate(pe.sections):
        chunk=data[sec.PointerToRawData:sec.PointerToRawData+sec.SizeOfRawData]
        assert chunk
        pat=chunk[:12]; offsets=[];p=0
        while True:
            p=chunk.find(pat,p)
            if p<0:break
            offsets.append(p);p+=1
        r=run(['find','--hex',pat.hex(),'--section',str(index),'--limit',str(min(len(offsets),1000))])
        assert r['hits']['total']==len(offsets)
        for result,offset in zip(r['hits']['items'],offsets):
            assert int(result['file_offset'],16)==sec.PointerToRawData+offset
        coverage.append({'section_index':index,'bytes':len(chunk),'pattern_length':len(pat),'matches':len(offsets)})
    # Negative checks exercise expected failures, never modifying the source EXE.
    negative=[['dump','--va','0x1','--size','4'],['pack','--layout','u8','--value','256'],
              ['pattern','GG'],['table','../outside.csv'],['int-info','256','--width','1'],
              ['audit-class','Despair::GameScriptPlayer','--extracted','--require-complete']]
    for args in negative:
        out,err=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            try:code=h.main(args)
            except SystemExit as exc:code=exc.code
        assert code!=0,(args,out.getvalue())
    report={'exe_sha256':hashlib.sha256(data).hexdigest(),'commands':results,'commands_passed':len(results),
            'section_find_crosschecks':coverage,'negative_cases_passed':len(negative),
            'limitations':['One integration case per command is not exhaustive correctness proof.',
             'Index-only commands and numeric pack/representation commands do not read PE bytes directly.',
             'The per-section check samples a pattern from each section; it is not a full scan of all possible inputs.']}
    out=ROOT/'analysis/harvester-validation/command-validation.json'
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(f"{len(results)} command cases passed; {len(coverage)} section find cross-checks; {len(negative)} negative cases")

if __name__=='__main__':main()
