#!/usr/bin/env python3
"""Independently validate saved candidate evidence against the verified PE, not runtime.

The bounded CFG reachability is not independently reproduced; decoded call sites are
rechecked as instructions. All E8 raw matches and padding runs are checked for coverage.
"""
from collections import Counter
import csv
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tooling/python'))
import pefile
import capstone
from capstone import x86

EXE=ROOT/'evidence/source-exe/F.E.A.R. 3.exe'
OUT=ROOT/'analysis/cpp-functions'
SRC=ROOT/'analysis/cpp-classes'
SHA='caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2'


def need(ok,msg):
    if not ok:raise ValueError(msg)
def rows(path):
    with path.open(encoding='utf8',newline='') as f:yield from csv.DictReader(f)
def number(v):return int(v,16)
def main():
    data=EXE.read_bytes();need(hashlib.sha256(data).hexdigest()==SHA,'EXE mismatch')
    pe=pefile.PE(data=data);base=pe.OPTIONAL_HEADER.ImageBase;secs=pe.sections
    def section(addr,size=1):
        matches=[s for s in secs if 0<=addr-base-s.VirtualAddress and addr-base-s.VirtualAddress+size<=s.SizeOfRawData]
        need(len(matches)==1,'unmapped or ambiguous VA '+hex(addr))
        return matches[0]
    def get(addr,size):
        s=section(addr,size);o=s.PointerToRawData+addr-base-s.VirtualAddress
        return data[o:o+size]
    def executable(addr):
        for s in secs:
            if s.VirtualAddress<=addr-base<s.VirtualAddress+s.SizeOfRawData and s.Characteristics&0x20000000:return True
        return False
    expected=json.loads((OUT/'summary.json').read_text(encoding='utf8'))
    need(len(expected['section_coverage'])==len(secs)==35,'section count')
    for i,(s,r) in enumerate(zip(secs,expected['section_coverage'])):
        chunk=data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        need(r['index']==i and r['raw_size']==len(chunk) and r['sha256']==hashlib.sha256(chunk).hexdigest(),'section '+str(i))
    candidates={};tiers=Counter();tags=Counter()
    for r in rows(OUT/'function-candidates.csv'):
        a=number(r['preferred_va']);need(a not in candidates and executable(a),'bad or duplicate candidate')
        sec=section(a);need(number(r['file_offset'])==sec.PointerToRawData+a-base-sec.VirtualAddress,'file offset mismatch')
        candidates[a]=r;tiers[r['evidence_tier']]+=1;tags.update(r['category_tags'].split('|'))
    need(len(candidates)==expected['function_candidate_addresses'] and dict(tiers)==expected['candidate_tiers']
         and dict(tags)==expected['category_counts_multilabel'],'candidate summary mismatch')
    # Independently enumerate every byte alignment, compare as ordered streams.
    def e8_source():
        for sec in secs:
            if not sec.Characteristics&0x20000000:continue
            buf=data[sec.PointerToRawData:sec.PointerToRawData+sec.SizeOfRawData]
            for i in range(len(buf)-4):
                if buf[i]!=0xe8:continue
                site=base+sec.VirtualAddress+i;target=(site+5+int.from_bytes(buf[i+1:i+5],'little',signed=True))&0xffffffff
                if executable(target):yield site,target
    raw_counts=Counter();raw_n=0
    actual=((number(r['site_va']),number(r['target_va'])) for r in rows(OUT/'raw-e8-calls.csv'))
    for got,want in itertools.zip_longest(actual,e8_source()):
        need(got==want,'raw E8 list differs '+repr((got,want)))
        raw_n+=1;raw_counts[got[1]]+=1
    need(raw_n==expected['raw_e8_sites_with_executable_targets'],'raw E8 count')
    for a,r in candidates.items():need(int(r['raw_e8_calls'])==raw_counts[a],'raw count for '+hex(a))
    iat={x.address:d.dll.decode('ascii','replace')+'!'+(x.name.decode('ascii','replace') if x.name else '#'+str(x.ordinal))
         for d in pe.DIRECTORY_ENTRY_IMPORT for x in d.imports}
    imp=list(rows(OUT/'imports.csv'));need(len(imp)==len(iat)==expected['external_import_slots'],'import count')
    need({number(x['iat_va']):x['dll']+'!'+x['symbol'] for x in imp}==iat,'import mismatch')
    # Saved CFG edges: independently re-decode each starting byte and its operand.
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    edge_counts=Counter();call_counts=Counter();iat_jumps=set();prev=-1
    for r in rows(OUT/'cfg-call-edges.csv'):
        va=number(r['site_va']);target=number(r['target_va']);need(va>=prev and executable(va),'edge order/section');prev=va
        sec=section(va);available=min(15,sec.SizeOfRawData-(va-base-sec.VirtualAddress))
        ins=next(md.disasm(get(va,available),va,count=1),None);need(ins is not None,'bad edge decode '+hex(va))
        if r['kind']=='direct_call':
            need(ins.group(capstone.CS_GRP_CALL) and ins.operands[0].type==x86.X86_OP_IMM and ins.operands[0].imm&0xffffffff==target,'bad call '+hex(va))
            if executable(target):call_counts[target]+=1
        else:
            need(ins.operands and ins.operands[0].type==x86.X86_OP_MEM,'bad IAT operand')
            mem=ins.operands[0].mem
            need(not mem.base and not mem.index and mem.disp&0xffffffff==target and r['iat_symbol']==iat.get(target),'bad IAT edge')
            if r['kind']=='indirect_call_iat':need(ins.group(capstone.CS_GRP_CALL),'not IAT call')
            elif r['kind']=='indirect_jump_iat':need(ins.group(capstone.CS_GRP_JUMP),'not IAT jump');iat_jumps.add(va)
            else:raise ValueError('unknown edge')
        edge_counts[r['kind']]+=1
    need(dict(edge_counts)==expected['cfg_edge_kinds'],'edge totals mismatch')
    for a,r in candidates.items():need(int(r['cfg_decoded_direct_calls'])==call_counts[a],'call count '+hex(a))
    # Every known first slot must occur once; every later word must read exactly as stored.
    known={number(r['vtable_va']):r for r in rows(SRC/'vtable-candidates.csv') if r['status']=='candidate'}
    first=set();slots_n=0;firstcounts=Counter();latercounts=Counter()
    for r in rows(OUT/'vtable-word-evidence.csv'):
        table=number(r['vtable_va']);index=int(r['slot_index']);slot=number(r['slot_va']);target=number(r['target_va'])
        need(table in known and index in range(256) and slot==table+4*index and executable(target),'bad vtable association')
        need(int.from_bytes(get(slot,4),'little')==target and known[table]['type_descriptor_va']==r['type_descriptor_va'],'bad vtable word')
        if index==0:
            need(table not in first and number(known[table]['first_slot_va'])==target and r['confidence']=='validated_first_slot','bad first slot')
            first.add(table);firstcounts[target]+=1
        else:
            need(r['confidence']=='later_word_not_proven_slot','bad later label');latercounts[target]+=1
        slots_n+=1
    need(first==set(known) and slots_n==expected['vtable_word_evidence_rows'],'vtable totals')
    for a,r in candidates.items():
        need(int(r['vtable_first_slot_references'])==firstcounts[a] and int(r['vtable_later_word_references'])==latercounts[a],'slot count mismatch')
    pads=set()
    for r in rows(OUT/'padding-entry-candidates.csv'):
        start=number(r['padding_start_va']);a=number(r['candidate_va']);n=int(r['padding_bytes']);b=bytes.fromhex(r['first_instruction_bytes'])
        need(n>=4 and a==start+n and get(start,n)==b'\xcc'*n and get(a,len(b))==b,'bad padding entry')
        ins=next(md.disasm(b,a,count=1),None)
        need(ins is not None and ins.size==len(b) and ins.mnemonic==r['first_mnemonic'] and ins.op_str==r['first_operands'],'bad padding decode')
        need(a not in pads and a in candidates and 'post_int3_padding' in candidates[a]['evidence_sources'].split('|'),'duplicate/missing padding candidate')
        pads.add(a)
    # Count all maximal runs separately; code uses regex, verifier scans the bytes.
    all_pads=set()
    for sec in secs:
        if not sec.Characteristics&0x20000000:continue
        buf=data[sec.PointerToRawData:sec.PointerToRawData+sec.SizeOfRawData];i=0
        while i<len(buf):
            if buf[i]!=0xcc:i+=1;continue
            start=i
            while i<len(buf) and buf[i]==0xcc:i+=1
            if i-start>=4 and i<len(buf):
                va=base+sec.VirtualAddress+i
                if next(md.disasm(buf[i:i+15],va,count=1),None) is not None:all_pads.add(va)
    need(pads==all_pads and len(pads)==expected['post_int3_padding_candidates'],'padding coverage mismatch')
    thunks=set()
    for r in rows(OUT/'iat-jump-patterns.csv'):
        va=number(r['site_va']);slot=number(r['iat_va'])
        need(get(va,6)==b'\xff\x25'+struct.pack('<I',slot) and r['import_symbol']==iat.get(slot),'bad thunk bytes')
        need((r['cfg_reached']=='true')==(va in iat_jumps),'thunk reachability mismatch')
        need(va not in thunks,'duplicate IAT jump');thunks.add(va)
    all_thunks=set()
    for sec in secs:
        if not sec.Characteristics&0x20000000:continue
        buf=data[sec.PointerToRawData:sec.PointerToRawData+sec.SizeOfRawData]
        for i in range(len(buf)-5):
            if buf[i:i+2]==b'\xff\x25' and int.from_bytes(buf[i+2:i+6],'little') in iat:
                all_thunks.add(base+sec.VirtualAddress+i)
    need(thunks==all_thunks and len(thunks)==expected['iat_jump_patterns'],'thunk coverage mismatch')
    # Check each exported address/name directly against PE export directory.
    exports={(base+x.address,x.name.decode('ascii','replace')) for x in pe.DIRECTORY_ENTRY_EXPORT.symbols if x.name and not x.forwarder and executable(base+x.address)}
    for addr,name in exports:
        need(addr in candidates and 'pe_export' in candidates[addr]['evidence_sources'].split('|'),'export missing '+name)
    named=list(rows(OUT/'named-evidence.csv'))
    stored={(number(r['address']),r['decorated']) for r in named if r['evidence']=='PE named export'}
    need(stored==exports,'export name mismatch')
    result={'exe_sha256':SHA,'sections_checked':len(secs),'candidate_addresses_checked':len(candidates),
      'raw_e8_sites_checked':raw_n,'decoded_edges_checked':sum(edge_counts.values()),
      'vtable_words_checked':slots_n,'vtable_first_slots_checked':len(first),'padding_candidates_checked':len(pads),
      'iat_jump_patterns_checked':len(thunks),'named_exports_checked':len(exports),'import_slots_checked':len(imp),
      'limits':'Verifies bytes and saved edge decodes, not global CFG reachability, function boundaries, names from runtime, or exhaustive functions.'}
    (OUT/'verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
