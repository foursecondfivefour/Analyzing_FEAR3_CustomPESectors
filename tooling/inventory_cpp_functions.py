#!/usr/bin/env python3
"""Build a reproducible, evidence-labelled static x86 function-candidate inventory.

A candidate target is not a proven function boundary, C++ method, or executed code.
No full vtable lengths, compiler ownership, or exhaustive function coverage are inferred.
"""
import argparse
from collections import Counter, defaultdict, deque
import csv
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tooling/python'))
import pefile
import capstone
from capstone import x86

SHA='caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2'
EXE=ROOT/'evidence/source-exe/F.E.A.R. 3.exe'
OUT=ROOT/'analysis/cpp-functions'
SRC=ROOT/'analysis/cpp-classes'
API=ROOT/'analysis/script-api-audit'


def hx(n):return f'0x{n:X}'
def require(ok,msg):
    if not ok:raise ValueError(msg)
def read_csv(path):
    with path.open(encoding='utf8',newline='') as f:return list(csv.DictReader(f))
def writer(path,fields,rows):
    with path.open('w',encoding='utf8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,lineterminator='\n',extrasaction='ignore');w.writeheader();w.writerows(rows)


class PE:
    def __init__(self,data):
        self.data=data;self.pe=pefile.PE(data=data);self.base=self.pe.OPTIONAL_HEADER.ImageBase
        require(self.pe.FILE_HEADER.Machine==0x14c and self.pe.OPTIONAL_HEADER.Magic==0x10b,'not x86 PE32')
        self.sections=[]
        for i,s in enumerate(self.pe.sections):
            raw,size=s.PointerToRawData,s.SizeOfRawData
            require(raw+size<=len(data),'truncated section')
            self.sections.append({'index':i,'name':s.Name.rstrip(b'\0').decode('ascii','replace').strip(),
              'va':self.base+s.VirtualAddress,'raw':raw,'size':size,'flags':s.Characteristics,'bytes':data[raw:raw+size]})
        intervals=sorted((s['va'],s['va']+s['size']) for s in self.sections if s['size'])
        require(all(b[0]>=a[1] for a,b in zip(intervals,intervals[1:])), 'ambiguous section VA')
    def locate(self,addr,size=1):
        for s in self.sections:
            off=addr-s['va']
            if 0<=off and off+size<=s['size']:return s,off
        return None
    def read(self,addr,size):
        hit=self.locate(addr,size)
        return hit[0]['bytes'][hit[1]:hit[1]+size] if hit else None
    def executable(self,addr):
        hit=self.locate(addr)
        return bool(hit and hit[0]['flags'] & 0x20000000)


# Classification uses observed names, NOT implementation analysis. Multiple tags allowed.
RULES=[('script_api',r'gamescript|script|lua|classmethodproxy'),
       ('graphics_rendering',r'graphics|render|shader|texture|material|mesh|vertex|pixel|display|gfx|\bimage'),
       ('audio_video',r'audio|sound|movie|music|video|voice|wave'),
       ('physics_animation',r'physics|collision|rigidbody|animation|animator|ragdoll'),
       ('network_multiplayer',r'network|multiplayer|socket|packet|peer|session'),
       ('gameplay_ai',r'gameplay|player|weapon|damage|enemy|ai::|combat|character|actor'),
       ('ui_menu',r'menu|\bui\b|dialog|widget|hud|frontend|button|scaleform'),
       ('resource_io',r'resource|archive|stream|filesystem|file|buffer|serializ|compression|zip'),
       ('math_geometry',r'\bvector|matrix|quaternion|geometry|transform|euler|bounds|math'),
       ('memory_containers',r'allocat|heap|memory|container|std::|boost::|array|hash|\blist|\bmap'),
       ('threading_sync',r'thread|mutex|lock|criticalsection|semaphore|atomic|sync'),
       ('platform_system',r'windows|winapi|kernel|system|platform|timer|clock|process'),
       ('reflection_rtti',r'reflection|type_info|rtti|\bclassfield|\bvftable')]
COMPILED=[(name,re.compile(pattern,re.I)) for name,pattern in RULES]
def categories(text):return [name for name,pat in COMPILED if pat.search(text)]


def raw_calls(image):
    """Every E8 byte alignment in executable sections, target must be raw-backed executable."""
    for s in image.sections:
        if not s['flags'] & 0x20000000:continue
        data=s['bytes'];pos=-1
        while True:
            pos=data.find(b'\xe8',pos+1)
            if pos<0 or pos+5>len(data):break
            site=s['va']+pos;target=(site+5+struct.unpack_from('<i',data,pos+1)[0]) & 0xffffffff
            if image.executable(target):yield site,target


def walk_cfg(image,seeds,iat):
    """Follow a multi-seed global heuristic CFG. Does not establish function boundaries.

    First-visited byte ownership rejects overlapping decodes; this ordering is deterministic,
    but can suppress alternative legitimate paths. Calls enqueue target and fallthrough.
    """
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    covered={s['index']:bytearray(s['size']) for s in image.sections if s['flags']&0x20000000}
    queue=deque(seeds); seen=set(); edges=[]; failures=0;overlap=0;indirect_jumps=0; indirect_calls=0; decoded=0
    while queue:
        va=queue.popleft()
        if va in seen:continue
        found=image.locate(va)
        if not found or not found[0]['flags']&0x20000000:continue
        sec,off=found;bits=covered[sec['index']]
        seen.add(va)
        if bits[off]:overlap+=1;continue
        ins=next(md.disasm(sec['bytes'][off:off+15],va,count=1),None)
        if ins is None or off+ins.size>sec['size']:
            failures+=1;continue
        if any(bits[off:off+ins.size]):overlap+=1;continue
        bits[off:off+ins.size]=b'\1'*ins.size
        decoded+=1
        nxt=(va+ins.size)&0xffffffff
        if ins.group(capstone.CS_GRP_RET) or ins.mnemonic in ('int3','int','ud2','hlt','iret','iretd'):continue
        if ins.group(capstone.CS_GRP_CALL):
            if ins.operands and ins.operands[0].type==x86.X86_OP_IMM:
                dest=ins.operands[0].imm&0xffffffff
                edges.append({'site_va':hx(va),'kind':'direct_call','target_va':hx(dest), 'iat_symbol':''})
                if image.executable(dest):queue.append(dest)
            else:
                indirect_calls+=1
                if ins.operands and ins.operands[0].type==x86.X86_OP_MEM:
                    op=ins.operands[0].mem
                    if not op.base and not op.index and (op.disp&0xffffffff) in iat:
                        slot=op.disp&0xffffffff
                        edges.append({'site_va':hx(va),'kind':'indirect_call_iat','target_va':hx(slot),'iat_symbol':iat[slot]})
            queue.append(nxt);continue
        if ins.group(capstone.CS_GRP_JUMP):
            if ins.operands and ins.operands[0].type==x86.X86_OP_IMM:
                dest=ins.operands[0].imm&0xffffffff
                if image.executable(dest):queue.append(dest)
            else:
                indirect_jumps+=1
                if ins.operands and ins.operands[0].type==x86.X86_OP_MEM:
                    op=ins.operands[0].mem
                    if not op.base and not op.index and (op.disp&0xffffffff) in iat:
                        slot=op.disp&0xffffffff
                        edges.append({'site_va':hx(va),'kind':'indirect_jump_iat','target_va':hx(slot),'iat_symbol':iat[slot]})
            if ins.mnemonic in ('jmp','ljmp'):continue
        queue.append(nxt)
    return edges,{'decoded_instructions':decoded,
                  'visited_addresses_including_failures':len(seen),'decode_failures':failures,
                  'overlapping_instruction_starts_rejected':overlap,'indirect_calls_unresolved_including_iat':indirect_calls,
                  'indirect_jumps_not_followed_including_iat':indirect_jumps,
                  'decoded_byte_coverage_per_executable_section':{str(i):sum(v) for i,v in covered.items()}}


def build(image,out):
    classes={r['type_descriptor_va']:r for r in read_csv(SRC/'classes.csv')}
    vtables=sorted((int(r['vtable_va'],16),r) for r in read_csv(SRC/'vtable-candidates.csv') if r['status']=='candidate')
    symbols=read_csv(SRC/'cpp-symbols.csv')
    candidates=defaultdict(lambda:{'sources':set(),'names':set(),'owners':set(),'api':set(),'tags':set(), 'first_slots':0,'later_slots':0,'raw_calls':0,'cfg_calls':0})
    named=[]; slots=[]; imports=[];iat={};entry=image.base+image.pe.OPTIONAL_HEADER.AddressOfEntryPoint
    require(image.executable(entry),'entrypoint not executable');candidates[entry]['sources'].add('pe_entry')
    for dll in image.pe.DIRECTORY_ENTRY_IMPORT:
        mod=dll.dll.decode('ascii','replace')
        for x in dll.imports:
            name=x.name.decode('ascii','replace') if x.name else '#'+str(x.ordinal)
            iat[x.address]=mod+'!'+name
            imports.append({'dll':mod,'symbol':name,'ordinal':x.ordinal if x.ordinal is not None else '',
                            'iat_va':hx(x.address),'category_tags':'|'.join(categories(mod+' '+name))})
    for s in symbols:
        if s['origin']!='export' or not s['target_or_iat_va'] or s['forwarder']:continue
        addr=int(s['target_or_iat_va'],16)
        if not image.executable(addr):continue
        x=candidates[addr];x['sources'].add('pe_export');label=s['demangled_prototype'] or s['decorated_symbol']
        x['names'].add(label);x['tags'].update(categories(label))
        named.append({'address':hx(addr),'evidence':'PE named export','name':label,'decorated':s['decorated_symbol']})
    for fn in ['proxy-cfg-candidates.csv','gamescript-game-all-methods.csv']:
        for r in read_csv(API/fn):
            label=r['api_path_name_correspondence_not_runtime_proof']
            values=[('native_function_va','script_api_target'),('target_va_only_if_immediate_eax','script_api_target'),('builder_va','proxy_builder'),('proxy_builder_va','proxy_builder')]
            for key,source in values:
                if not r.get(key):continue
                if fn=='proxy-cfg-candidates.csv' and r.get('cfg_reachable_sequence')!='true':continue
                addr=int(r[key],16)
                if not image.executable(addr):continue
                x=candidates[addr];x['sources'].add(source);x['api'].add(label);x['tags'].add('script_api')
                named.append({'address':hx(addr),'evidence':source+' (name correspondence only)','name':label,'decorated':''})
    # Scan bounded runs of executable-valued words after validated COL-linked table candidates.
    # They are not inferred vtable lengths: subsequent slots can be adjacent data/other tables.
    for n,(addr,row) in enumerate(vtables):
        td=row['type_descriptor_va'];owner=classes[td]['display_name'] or classes[td]['decorated_name']
        limit=vtables[n+1][0]-4 if n+1<len(vtables) else 0x100000000
        for index in range(256):
            slot=addr+index*4
            if slot>=limit:break
            data=image.read(slot,4)
            if data is None:break
            target=struct.unpack('<I',data)[0]
            if not image.executable(target):break
            if index==0:require(target==int(row['first_slot_va'],16),'vtable first slot mismatch')
            x=candidates[target];x['sources'].add('vtable_first_slot' if index==0 else 'vtable_later_word_candidate')
            x['owners'].add(owner);x['tags'].update(categories(owner))
            x['first_slots' if index==0 else 'later_slots']+=1
            slots.append({'vtable_va':hx(addr),'slot_index':index,'slot_va':hx(slot),'target_va':hx(target),
                          'type_descriptor_va':td,'owner_name_candidate':owner,'confidence':'validated_first_slot' if index==0 else 'later_word_not_proven_slot'})
    seeds=sorted(candidates,key=lambda a:(0 if 'pe_entry' in candidates[a]['sources'] else 1 if 'pe_export' in candidates[a]['sources'] else 2 if 'script_api_target' in candidates[a]['sources'] else 3 if 'proxy_builder' in candidates[a]['sources'] else 4 if 'vtable_first_slot' in candidates[a]['sources'] else 5,a))
    edges,cfg=walk_cfg(image,seeds,iat)
    for r in edges:
        if r['kind']!='direct_call':continue
        addr=int(r['target_va'],16)
        if image.executable(addr):
            x=candidates[addr];x['sources'].add('cfg_decoded_direct_call');x['cfg_calls']+=1
    # Additional weak evidence: the byte following a run of at least four INT3s,
    # and all FF25 absolute-indirect patterns targeting imported IAT slots. Neither
    # is used as a CFG seed: both can be embedded data or interior instructions.
    pads=[];thunks=[]
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    cfg_iat_jump_sites={int(e['site_va'],16) for e in edges if e['kind']=='indirect_jump_iat'}
    for sec in image.sections:
        if not sec['flags'] & 0x20000000:continue
        data=sec['bytes'];origin=sec['va']
        for m in re.finditer(rb'\xcc{4,}',data):
            off=m.end()
            if off>=len(data):continue
            ins=next(md.disasm(data[off:off+15],origin+off,count=1),None)
            if not ins:continue
            addr=origin+off;x=candidates[addr];x['sources'].add('post_int3_padding')
            pads.append({'candidate_va':hx(addr),'padding_start_va':hx(origin+m.start()),
                         'padding_bytes':m.end()-m.start(),'first_instruction_bytes':ins.bytes.hex(' '),
                         'first_mnemonic':ins.mnemonic,'first_operands':ins.op_str})
        pos=-1
        while True:
            pos=data.find(b'\xff\x25',pos+1)
            if pos<0 or pos+6>len(data):break
            slot=struct.unpack_from('<I',data,pos+2)[0]
            if slot not in iat:continue
            addr=origin+pos;x=candidates[addr];x['sources'].add('raw_iat_jmp_pattern')
            x['tags'].update(categories(iat[slot]))
            if addr in cfg_iat_jump_sites:x['sources'].add('cfg_iat_jmp')
            thunks.append({'site_va':hx(addr),'iat_va':hx(slot),'import_symbol':iat[slot],
                           'cfg_reached':str(addr in cfg_iat_jump_sites).lower()})
    out.mkdir(parents=True,exist_ok=True)
    raw_path=out/'raw-e8-calls.csv';raw_count=0
    with raw_path.open('w',encoding='utf8',newline='') as f:
        w=csv.writer(f,lineterminator='\n');w.writerow(['site_va','target_va'])
        for site,target in raw_calls(image):
            w.writerow((hx(site),hx(target)));raw_count+=1
            x=candidates[target];x['sources'].add('raw_e8_target');x['raw_calls']+=1
    output=[]
    for addr,x in sorted(candidates.items()):
        sec,off=image.locate(addr);sources=x['sources']
        if 'pe_export' in sources:strength='named_export'
        elif 'script_api_target' in sources:strength='script_registration_candidate'
        elif 'pe_entry' in sources:strength='pe_entry_point'
        elif 'vtable_first_slot' in sources:strength='validated_vtable_first_slot'
        elif 'proxy_builder' in sources:strength='script_proxy_builder_candidate'
        elif 'cfg_decoded_direct_call' in sources:strength='cfg_direct_call_target_candidate'
        elif 'vtable_later_word_candidate' in sources:strength='vtable_later_word_candidate'
        elif 'cfg_iat_jmp' in sources:strength='cfg_iat_jump_site_candidate'
        elif 'post_int3_padding' in sources:strength='post_int3_padding_candidate'
        elif 'raw_iat_jmp_pattern' in sources:strength='raw_iat_jmp_pattern_only'
        else:strength='raw_e8_target_only'
        output.append({'preferred_va':hx(addr),'section_index':sec['index'],'section':sec['name'],'file_offset':hx(sec['raw']+off),
          'evidence_tier':strength,'evidence_sources':'|'.join(sorted(sources)),
          'export_names':' | '.join(sorted(x['names'])),'script_api_names':' | '.join(sorted(x['api'])),
          'vtable_owner_count':len(x['owners']),'category_tags':'|'.join(sorted(x['tags'])) or 'unknown',
          'vtable_first_slot_references':x['first_slots'],'vtable_later_word_references':x['later_slots'],
          'cfg_decoded_direct_calls':x['cfg_calls'],'raw_e8_calls':x['raw_calls']})
    output.sort(key=lambda r:(r['category_tags'],r['evidence_tier'],int(r['preferred_va'],16)))
    writer(out/'function-candidates.csv',list(output[0]),output)
    writer(out/'vtable-word-evidence.csv',['vtable_va','slot_index','slot_va','target_va','type_descriptor_va','owner_name_candidate','confidence'],slots)
    writer(out/'named-evidence.csv',['address','evidence','name','decorated'],sorted(named,key=lambda r:(int(r['address'],16),r['evidence'],r['name'])))
    writer(out/'imports.csv',['dll','symbol','ordinal','iat_va','category_tags'],imports)
    writer(out/'padding-entry-candidates.csv',['candidate_va','padding_start_va','padding_bytes','first_instruction_bytes','first_mnemonic','first_operands'],pads)
    writer(out/'iat-jump-patterns.csv',['site_va','iat_va','import_symbol','cfg_reached'],thunks)
    edges.sort(key=lambda r:(int(r['site_va'],16),r['kind'],int(r['target_va'],16)))
    writer(out/'cfg-call-edges.csv',['site_va','kind','target_va','iat_symbol'],edges)
    percat=Counter();tiers=Counter(r['evidence_tier'] for r in output)
    for r in output:percat.update(r['category_tags'].split('|'))
    writer(out/'category-summary.csv',['category','candidate_addresses'],[{'category':k,'candidate_addresses':v} for k,v in sorted(percat.items())])
    sections=[{'index':s['index'],'name':s['name'],'raw_size':s['size'],'sha256':hashlib.sha256(s['bytes']).hexdigest(),
               'executable':bool(s['flags']&0x20000000)} for s in image.sections]
    summary={'exe_sha256':SHA,'image_base':hx(image.base),'pe_entry':hx(entry),'section_coverage':sections,
      'function_candidate_addresses':len(output),'candidate_tiers':dict(sorted(tiers.items())),
      'category_counts_multilabel':dict(sorted(percat.items())),'named_evidence_rows':len(named),'external_import_slots':len(imports),
      'vtable_word_evidence_rows':len(slots),'vtable_first_slot_rows':sum(x['slot_index']==0 for x in slots),
      'raw_e8_sites_with_executable_targets':raw_count,'post_int3_padding_candidates':len(pads),
      'iat_jump_patterns':len(thunks),'iat_jump_patterns_cfg_reached':sum(x['cfg_reached']=='true' for x in thunks),
      'cfg_seeds':len(seeds),'cfg':cfg,
      'cfg_edge_kinds':dict(sorted(Counter(r['kind'] for r in edges).items())),
      'limitations':['Functions cannot be enumerated completely from this stripped PE alone.',
       'Raw E8 and FF25 can be embedded data, misaligned, or part of another instruction.',
       'INT3 runs and following decoded instructions do not prove function entries.',
       'Vtable later words are candidates, not proven table members or boundaries.',
       'CFG seeds are heuristic; overlapping decodes and indirect branches are not exhaustively explored.',
       'A vtable owner is a type association, not proof the target is implemented by that class.',
       'Names and category tags are associations or pattern-based labels, not verified semantics.',
       'External imports list IAT slots and do not contain external implementations.']}
    (out/'summary.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
    return summary


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--exe',type=Path,default=EXE);ap.add_argument('--out',type=Path,default=OUT)
    a=ap.parse_args();raw=a.exe.read_bytes();require(hashlib.sha256(raw).hexdigest()==SHA,'EXE SHA-256 mismatch')
    result=build(PE(raw),a.out)
    print(json.dumps({k:v for k,v in result.items() if k!='section_coverage'},indent=2))

if __name__=='__main__':main()
