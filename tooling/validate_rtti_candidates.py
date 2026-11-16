#!/usr/bin/env python3
"""Independently recheck all RTTI candidates and characterize the no-COL remainder.

Static evidence only; does not execute the PE or prove function entry points or runtime use.
"""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'tooling/python'))
import capstone
import pefile

EXE = ROOT/'evidence/source-exe/F.E.A.R. 3.exe'
SRC = ROOT/'analysis/cpp-classes'
OUT = ROOT/'analysis/harvester-validation'
SHA = 'caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2'


def hx(n): return f'0x{n:X}'
def need(ok, reason):
    if not ok: raise ValueError(reason)
def load_csv(name):
    with (SRC/name).open(encoding='utf-8', newline='') as f: return list(csv.DictReader(f))
def output_csv(path, fields, data):
    with path.open('w', encoding='utf-8', newline='') as f:
        w=csv.DictWriter(f, fields, lineterminator='\n');w.writeheader();w.writerows(data)


class Image:
    def __init__(self, data):
        self.data = data
        self.pe = pefile.PE(data=data)
        need(self.pe.FILE_HEADER.Machine == 0x14c and self.pe.OPTIONAL_HEADER.Magic == 0x10b, 'not PE32 x86')
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.sections = []
        for index, s in enumerate(self.pe.sections):
            off, size = s.PointerToRawData, s.SizeOfRawData
            need(off + size <= len(data), 'truncated PE section')
            self.sections.append({'index':index, 'name':s.Name.rstrip(b'\0').decode('ascii','replace').strip(),
                                  'rva':s.VirtualAddress, 'offset':off, 'size':size, 'flags':s.Characteristics,
                                  'data':data[off:off+size]})
    def locate(self, va, size):
        found=[]
        for s in self.sections:
            offset = va-self.base-s['rva']
            if 0 <= offset and offset+size <= s['size']: found.append((s,offset))
        need(len(found)==1, 'unmapped or ambiguous raw VA '+hx(va))
        return found[0]
    def read(self, va, size):
        s, offset = self.locate(va,size)
        return s['data'][offset:offset+size]
    def unpack(self, fmt, va): return struct.unpack(fmt,self.read(va,struct.calcsize(fmt)))
    def executable(self, va):
        try: s,_ = self.locate(va,1)
        except ValueError: return False
        return bool(s['flags'] & 0x20000000)
    def imported_iat(self, dll, symbol):
        hits=[x.address for d in self.pe.DIRECTORY_ENTRY_IMPORT if d.dll.lower()==dll.lower()
              for x in d.imports if x.name==symbol]
        need(len(hits)==1,'missing or ambiguous import '+repr(symbol))
        return hits[0]


def cfg_check(data, origin, start, end, md):
    """Bounded CFG from guessed entry after int3; never assumes runtime reachability."""
    anchor=data.rfind(b'\xcc'*4,max(0,start-2048),start)
    if anchor<0: return {'status':'no_anchor'}
    entry=anchor+4
    while entry<start and data[entry]==0xcc:entry+=1
    finish=data.find(b'\xcc'*4,end,min(len(data),end+2048))
    if finish<0: return {'status':'no_end','entry':origin+entry}
    todo=[entry];seen={};bad=0;indirect=0
    while todo:
        off=todo.pop()
        if off in seen or not entry<=off<finish:continue
        ins=next(md.disasm(data[off:min(off+15,finish)],origin+off,count=1),None)
        if ins is None or off+ins.size>finish:bad+=1;continue
        seen[off]=ins
        if ins.group(capstone.CS_GRP_RET) or ins.mnemonic in ('int3','int','ud2','hlt'):continue
        if ins.group(capstone.CS_GRP_JUMP):
            if ins.operands and ins.operands[0].type==capstone.x86.X86_OP_IMM:todo.append(ins.operands[0].imm-origin)
            else:indirect+=1
            if ins.mnemonic=='jmp':continue
        todo.append(off+ins.size)
    pos=start; seq=[]
    while pos<end and pos in seen:
        seq.append(pos);pos+=seen[pos].size
    valid=pos==end
    # Reject if any other reachable decoding overlaps the target sequence.
    conflict=any(off not in seq and off < end and off+ins.size > start for off,ins in seen.items())
    return {'status':'reachable' if valid and not conflict else 'ambiguous' if conflict else 'not_reached',
            'entry':origin+entry,'end':origin+finish,'decode_errors':bad,'indirect_jumps_not_followed':indirect,
            'decoded_instructions':len(seen)}


def exception_witness(image, md):
    """Validate the separate std::bad_cast x86 exception-metadata chain in this build."""
    td,ct,arr,ti,site,thunk = 0x164167c,0x16103e0,0x16103d4,0x16103c4,0x887214,0xf3b346
    iat=image.imported_iat(b'MSVCR90.dll',b'_CxxThrowException')
    props,ct_td,mdisp,pdisp,vdisp,size,copy=image.unpack('<IIiiiII',ct)
    need((props,ct_td,mdisp,pdisp,vdisp,size,copy)==(0,td,0,-1,0,12,0xf3b754),'bad_cast CatchableType differs')
    need(image.unpack('<III',arr)==(2,ct,0x1610198),'bad_cast CatchableTypeArray differs')
    attrs,unwind,forward,catchables=image.unpack('<IIII',ti)
    need(attrs==0 and forward==0 and catchables==arr and image.executable(unwind),'bad_cast ThrowInfo differs')
    need(image.read(thunk,6)==b'\xff\x25'+struct.pack('<I',iat),'throw thunk differs')
    seq=image.read(site,15)
    need(seq[:5]==b'\x68'+struct.pack('<I',ti) and seq[5:10]==b'\x8d\x54\x24\x14\x52' and seq[10]==0xe8,'throw-site sequence differs')
    call_target=(site+15+struct.unpack('<i',seq[11:15])[0])&0xffffffff
    need(call_target==thunk,'throw-site target differs')
    sec,off=image.locate(site,15);cfg=cfg_check(sec['data'],image.base+sec['rva'],off,off+15,md)
    return {'type_descriptor_va':hx(td),'catchable_type_va':hx(ct),'catchable_array_va':hx(arr),
            'throw_info_va':hx(ti),'throw_site_va':hx(site),'throw_thunk_va':hx(thunk),'iat_va':hx(iat),
            'cfg_status':cfg['status'],'cfg_entry_va':hx(cfg['entry']) if 'entry' in cfg else '',
            'note':'Structure and candidate instructions checked statically; no runtime throw demonstrated.'}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--exe',type=Path,default=EXE)
    ap.add_argument('--out',type=Path,default=OUT)
    args=ap.parse_args()
    raw=args.exe.read_bytes()
    need(hashlib.sha256(raw).hexdigest()==SHA,'EXE SHA-256 mismatch')
    image=Image(raw);md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    inventory=json.loads((ROOT/'evidence/pe-inventory.json').read_text(encoding='utf-8'))
    need(len(image.sections)==len(inventory['sections'])==35,'section count mismatch')
    section_report=[]
    for s,orig in zip(image.sections,inventory['sections']):
        digest=hashlib.sha256(s['data']).hexdigest()
        need((s['index'],s['rva'],s['offset'],s['size'],s['flags'],digest)==
             (orig['index'],orig['virtual_address'],orig['raw_offset'],orig['raw_size'],orig['characteristics'],orig['sha256']),'PE section mismatch')
        section_report.append({'index':s['index'],'name':s['name'],'raw_size':s['size'],'sha256':digest,
                               'rtti_descriptors':0,'vtable_candidates':0})
    rows=load_csv('classes.csv');classes={int(r['type_descriptor_va'],16):r for r in rows}
    need(len(classes)==len(rows),'duplicate type descriptors')
    for td,row in classes.items():
        name=row['decorated_name'].encode('ascii')+b'\0'
        need(image.read(td+8,len(name))==name,'type name mismatch '+hx(td))
        vft,spare=image.unpack('<II',td)
        need(vft==int(row['vftable_pointer'],16) and spare==0 and image.executable(image.unpack('<I',vft)[0]),'bad type header '+hx(td))
        sec,_=image.locate(td+8,len(name));need(sec['index']==int(row['section_index']),'type section mismatch')
        section_report[sec['index']]['rtti_descriptors']+=1
    cols=load_csv('complete-object-locators.csv'); colmap={int(r['col_va'],16):r for r in cols}
    need(len(cols)==len(colmap),'duplicate COL')
    for va,row in colmap.items():
        sig,off,cd,td,ch=image.unpack('<IIIII',va)
        need(sig==0 and td in classes and td==int(row['type_descriptor_va'],16) and ch==int(row['hierarchy_va'],16)
             and off==int(row['object_offset'],16) and cd==int(row['cd_offset'],16),'COL mismatch '+hx(va))
    bases=load_csv('base-descriptors.csv');groups=defaultdict(list);base_counts=Counter();base_hier=defaultdict(set)
    for r in bases:
        groups[int(r['hierarchy_va'],16)].append(r)
        td=int(r['base_type_descriptor_va'],16);base_counts[td]+=1;base_hier[td].add(r['hierarchy_va'])
    need(set(groups)=={int(c['hierarchy_va'],16) for c in cols},'hierarchy set mismatch')
    for ch,entries in groups.items():
        sig,flags,count,arr=image.unpack('<IIII',ch)
        need(sig==0 and count==len(entries) and count>0,'invalid hierarchy '+hx(ch))
        owner=int(entries[0]['owner_type_descriptor_va'],16)
        need(image.unpack('<I',image.unpack('<I',arr)[0])[0]==owner,'hierarchy self mismatch')
        for index,r in enumerate(entries):
            need(int(r['index'])==index and int(r['owner_type_descriptor_va'],16)==owner,'hierarchy order mismatch')
            bcd=image.unpack('<I',arr+index*4)[0]
            fields=image.unpack('<IIiiiI',bcd)
            exp=(int(r['base_type_descriptor_va'],16),int(r['contained_bases']),int(r['mdisp']),int(r['pdisp']),int(r['vdisp']),int(r['attributes'],16))
            need(bcd==int(r['base_descriptor_va'],16) and fields==exp and fields[0] in classes,'bad base descriptor '+hx(bcd))
            need(classes[fields[0]]['decorated_name']==r['base_decorated_name'],'base name mismatch')
    for row in cols:
        sig,flags,count,arr=image.unpack('<IIII',int(row['hierarchy_va'],16))
        need(count==int(row['base_count']) and flags==int(row['hierarchy_attributes'],16) and arr==int(row['base_array_va'],16),'COL hierarchy mismatch')
    vt=load_csv('vtable-candidates.csv');vtdesc=Counter();decoded=0;first_targets=set();invalid=[];rejected=[]
    for row in vt:
        va=int(row['vtable_va'],16);col,first=image.unpack('<II',va-4);sec,_=image.locate(va-4,8)
        need(col in colmap and col==int(row['col_va'],16) and first==int(row['first_slot_va'],16)
             and colmap[col]['type_descriptor_va']==row['type_descriptor_va'] and image.executable(first),'vtable linkage mismatch '+hx(va))
        if row['status']=='candidate':
            need(va%4==0 and not(sec['flags'] & 0x20000000),'candidate in wrong section or unaligned')
            vtdesc[int(row['type_descriptor_va'],16)]+=1;section_report[sec['index']]['vtable_candidates']+=1
            target_sec,off=image.locate(first,1);sample=target_sec['data'][off:off+15]
            ins=next(md.disasm(sample,first,count=1),None)
            if ins: decoded+=1
            else: invalid.append(hx(first))
            first_targets.add(first)
        else:
            need(row['status']=='rejected_unaligned_and_in_executable_section' and va%4!=0 and sec['flags'] & 0x20000000,'unexplained rejected vtable')
            rejected.append({'vtable_va':hx(va),'col_va':hx(col),'section':sec['name'],'status':row['status']})
    colcounts=Counter(int(x['type_descriptor_va'],16) for x in cols)
    for td,row in classes.items():
        need(colcounts[td]==int(row['col_count']) and vtdesc[td]==int(row['vtable_candidate_count']),'type linkage counts mismatch')
    no_col={td for td,row in classes.items() if colcounts[td]==0}
    need(all(classes[td]['evidence']=='type_descriptor_candidate_only' for td in no_col),'unexpected no-COL classification')
    # Entire raw section byte streams, all alignments. High byte filter only accelerates
    # matching exact LE32 values and is built from the actual descriptor set.
    high=sorted({v>>24 for v in no_col})
    pattern=re.compile(b'['+b''.join(b'\\x%02x'%v for v in high)+b']')
    refs=Counter();exec_refs=Counter();firstref={}
    for sec in image.sections:
        data=sec['data'];origin=image.base+sec['rva']
        for m in pattern.finditer(data):
            off=m.start()-3
            if off<0:continue
            value=struct.unpack_from('<I',data,off)[0]
            if value not in no_col:continue
            refs[value]+=1
            if sec['flags']&0x20000000:exec_refs[value]+=1
            firstref.setdefault(value,(origin+off,sec['name']))
    eq_iat=image.imported_iat(b'MSVCR90.dll',b'??8type_info@@QBE_NABV0@@Z')
    eq_pattern=re.compile(rb'\x68(.{4})\xff\x15'+re.escape(struct.pack('<I',eq_iat)),re.S)
    init_pattern=re.compile(rb'\x8b\x44\x24\x08\x32\xc9\xc7\x00(.{4})\x88\x48\x04\x88\x48\x05\xc3',re.S)
    matches=defaultdict(lambda:defaultdict(list))
    for sec in image.sections:
        if not sec['flags']&0x20000000:continue
        origin=image.base+sec['rva'];data=sec['data']
        for kind,pattern in [('typeinfo_compare',eq_pattern),('initializer_store',init_pattern)]:
            for m in pattern.finditer(data):
                td=struct.unpack('<I',m.group(1))[0]
                if td not in no_col or td in base_counts:continue
                cfg=cfg_check(data,origin,m.start(),m.end(),md)
                matches[td][kind].append({'site_va':origin+m.start(),'cfg':cfg})
    witness=exception_witness(image,md);badcast=int(witness['type_descriptor_va'],16)
    need(badcast in no_col,'bad_cast was not no-COL')
    result=[]
    for td in sorted(no_col):
        row=classes[td];records=matches[td];eq=records['typeinfo_compare'];init=records['initializer_store']
        eq_cfg=[x for x in eq if x['cfg']['status']=='reachable'];init_cfg=[x for x in init if x['cfg']['status']=='reachable']
        if base_counts[td]: tier='validated_base_descriptor_in_col_hierarchy'
        elif eq_cfg: tier='typeinfo_comparison_cfg_heuristic'
        elif init_cfg: tier='initializer_store_cfg_heuristic'
        elif eq or init: tier='code_byte_pattern_only'
        elif td==badcast: tier='exception_metadata_and_throw_sequence'
        else:tier='type_descriptor_and_raw_reference_only'
        first,section=firstref.get(td,(None,''))
        def witness_site(items):return hx(items[0]['site_va']) if items else ''
        def cfg_entry(items):return hx(items[0]['cfg']['entry']) if items else ''
        result.append({'type_descriptor_va':hx(td),'display_name':row['display_name'],'decorated_name':row['decorated_name'],
                       'base_descriptor_rows':base_counts[td], 'base_hierarchy_count':len(base_hier[td]),
                       'raw_u32_references_all_sections':refs[td],'raw_u32_references_executable_sections':exec_refs[td],
                       'first_raw_reference_va':hx(first) if first is not None else '', 'first_raw_reference_section':section,
                       'typeinfo_compare_raw_sites':len(eq),'typeinfo_compare_cfg_sites':len(eq_cfg),
                       'typeinfo_compare_first_site':witness_site(eq),'typeinfo_compare_first_cfg_site':witness_site(eq_cfg),
                       'typeinfo_compare_cfg_entry':cfg_entry(eq_cfg),'initializer_raw_sites':len(init),'initializer_cfg_sites':len(init_cfg),
                       'initializer_first_site':witness_site(init),'initializer_first_cfg_site':witness_site(init_cfg),
                       'initializer_cfg_entry':cfg_entry(init_cfg),'bad_cast_exception_chain':str(td==badcast).lower(),
                       'static_evidence_tier':tier})
    summary={'exe_sha256':SHA,'section_count':len(image.sections),'type_descriptors_checked':len(classes),
             'col_records_checked':len(cols),'hierarchies_checked':len(groups),'base_rows_checked':len(bases),
             'vtable_candidates_checked':sum(r['status']=='candidate' for r in vt),'vtable_rejected_checked':len(rejected),
             'candidate_first_slots_decoded_one_instruction':decoded,'unique_candidate_first_slot_targets':len(first_targets),
             'undecoded_first_slots':invalid,'no_col_types':len(no_col),
             'no_col_with_base_hierarchy':sum(base_counts[x]>0 for x in no_col),
             'no_col_with_raw_absolute_refs':sum(refs[x]>0 for x in no_col),
             'no_col_without_base':sum(base_counts[x]==0 for x in no_col),
             'no_base_with_typeinfo_compare_raw':sum(bool(matches[x]['typeinfo_compare']) for x in no_col if not base_counts[x]),
             'no_base_with_typeinfo_compare_cfg':sum(any(m['cfg']['status']=='reachable' for m in matches[x]['typeinfo_compare']) for x in no_col if not base_counts[x]),
             'no_base_with_initializer_raw':sum(bool(matches[x]['initializer_store']) for x in no_col if not base_counts[x]),
             'no_base_with_initializer_cfg':sum(any(m['cfg']['status']=='reachable' for m in matches[x]['initializer_store']) for x in no_col if not base_counts[x]),
             'evidence_tiers':dict(sorted(Counter(r['static_evidence_tier'] for r in result).items())),
             'rejected_vtable':rejected,'bad_cast_witness':witness,
             'limitations':['Raw byte matches are not automatically instruction boundaries.',
               'CFG entry is heuristic INT3 padding; indirect jumps, calls and external control flow are not followed.',
               'A decoded first instruction does not establish a real function boundary or execution.',
               'A missing COL under the existing rules does not prove a type has no vtable or implementation.',
               'No static result proves runtime execution or covers every C++ class.']}
    args.out.mkdir(parents=True,exist_ok=True)
    fields=list(result[0]) if result else []
    output_csv(args.out/'no-col-evidence.csv',fields,result)
    output_csv(args.out/'section-validation.csv',['index','name','raw_size','sha256','rtti_descriptors','vtable_candidates'],section_report)
    (args.out/'rtti-validation-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
