#!/usr/bin/env python3
"""Audit the pinned API against PE sections and control-flow-anchored proxy patterns."""
from pathlib import Path
from collections import defaultdict, Counter
import csv
import hashlib
import json
import re
import struct
import sys

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tooling/python'))
sys.path.insert(0,str(ROOT/'tooling'))
import pefile
import capstone
import compare_script_api as prior

OUT=ROOT/'analysis/script-api-audit'
REG=re.compile(rb'\xb8(.{4})\x50\x68(.{4})\xe8(.{4})\x83\xc4\x0c\x50(?:\x8b[\xc8-\xcf]|\xb9.{4})\xe8(.{4})',re.S)
PROXY=re.compile(r'^\.\?AV\?\$ClassMethodProxy([^@]*)@.*?V(GameScript[A-Za-z0-9_]+)@(?:(Despair)@@|([0-9])@)')

def h(x):return f'0x{x:X}'
def dump(name,fields,rows):
    with (OUT/name).open('w',encoding='utf-8',newline='') as f:
        w=csv.writer(f,lineterminator='\n');w.writerow(fields);w.writerows(rows)

def main():
    # Revalidates EXE and the entire pinned API snapshot, index and RTTI inputs.
    prior.main()
    exe=prior.EXE.read_bytes();p=pefile.PE(data=exe);base=p.OPTIONAL_HEADER.ImageBase
    api=json.loads((prior.SNAP/'api/despair-api.json').read_text(encoding='utf-8'))['entries']
    with (ROOT/'analysis/script-classes/script-classes.csv').open(encoding='utf-8',newline='') as f:
        classes=list(csv.DictReader(f))
    OUT.mkdir(parents=True,exist_ok=True)
    namespaces=sorted({e['namespace'] for e in api})
    # Compare every individual documentation heading, not just counts in the index.
    docrows=[]
    for ns in namespaces:
        f=prior.SNAP/'docs/reference'/f'{ns}.md'
        expected=[e['name'] for e in api if e['namespace']==ns]
        actual=re.findall(r'^## (.+)$',f.read_text(encoding='utf-8'),re.M)
        identical=Counter(actual)==Counter(expected)
        docrows.append((ns,len(expected),len(actual),str(identical).lower()))
        if not identical:raise ValueError('Reference headings differ: '+ns)
    dump('reference-index-check.csv',['namespace','api_entries','reference_headings','multiset_equal'],docrows)
    by_name={e['name']:e for e in api}
    # Independently count complete, strictly delimited ASCII API leaf strings in every PE section.
    leaves={e['name'].split('.')[-1] for e in api}
    coverage=[]
    for idx,s in enumerate(p.sections):
        chunk=exe[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        hits=[]
        for m in re.finditer(rb'[\x20-\x7e]{1,}\x00',chunk):
            if m.start() and chunk[m.start()-1]!=0:continue
            value=m.group()[:-1].decode('ascii')
            if value in leaves:hits.append(value)
        coverage.append((idx,s.Name.rstrip(b'\0').decode('ascii','replace').strip(),h(s.PointerToRawData),h(s.SizeOfRawData),h(s.VirtualAddress),hashlib.sha256(chunk).hexdigest(),len(hits),len(set(hits))))
    dump('all-section-coverage.csv',['pe_index','section','file_offset','raw_size','rva','raw_sha256','strict_api_leaf_string_occurrences','distinct_matching_leaves'],coverage)
    candmap={}
    for row in classes:
        leaf=row['plain_name_if_simple'].split('::')[-1]
        if leaf.startswith('GameScript'):
            suffix=leaf[len('GameScript'):]
            candmap[leaf]=[n for n in namespaces if n.startswith('GameScript.') and n.split('.')[-1]==suffix]
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    # Proxy constructor is a fixed byte template, independently inspect its RTTI locator.
    def readva(va,n):
        if va<base:return b''
        try:return p.get_data(va-base,n)
        except (pefile.PEFormatError,ValueError):return b''
    def strva(va):
        if va<base:raise ValueError('unmapped')
        raw=p.get_string_at_rva(va-base)
        if raw is None:raise ValueError('unmapped string')
        return raw.decode('ascii')
    def execva(va):
        s=p.get_section_by_rva(va-base) if va>=base else None
        return bool(s and s.Characteristics&0x20000000)
    def builderinfo(addr):
        match=prior.BUILDER.match(readva(addr,100))
        if not match:return None
        vt=struct.unpack('<I',match.group(1))[0]
        col=struct.unpack('<I',readva(vt-4,4))[0]
        sig,offset,cd,td,hi=struct.unpack('<IIIII',readva(col,20))
        if sig!=0 or offset!=0:return None
        decorated=strva(td+8);pm=PROXY.match(decorated)
        if not pm:return None
        return (pm.group(2),pm.group(3) or '@'+pm.group(4),h(vt),h(col),h(td),decorated,pm.group(1))
    # Raw executable-section patterns. They need control-flow boundary anchoring below.
    raw=[]; secdata={}
    for index,s in enumerate(p.sections):
        data=exe[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        if not(s.Characteristics&0x20000000):continue
        origin=base+s.VirtualAddress;secdata[index]=(s,data,origin)
        for m in REG.finditer(data):
            site=origin+m.start();fn=int.from_bytes(m.group(1),'little');nameva=int.from_bytes(m.group(2),'little')
            builder=(site+16+int.from_bytes(m.group(3),'little',signed=True))&0xffffffff
            sink=(site+len(m.group(0))+int.from_bytes(m.group(4),'little',signed=True))&0xffffffff
            try:
                if not all(map(execva,(fn,builder,sink))):continue
                leaf=strva(nameva);info=builderinfo(builder)
                if not info:continue
                cls,qual,vt,col,td,decorated,proxy_kind=info
                for ns in candmap.get(cls,[]):
                    full=ns+'.'+leaf
                    if full in by_name:raw.append({'api':full,'cls':cls,'leaf':leaf,'site':site,'name':nameva,'fn':fn,'builder':builder,'sink':sink,'vt':vt,'col':col,'td':td,'decorated':decorated,'qualifier':qual,'kind':proxy_kind,'index':index})
            except (ValueError,UnicodeDecodeError,struct.error,pefile.PEFormatError):continue
    # Candidate entry is first byte following preceding int3 padding; recursively follow
    # immediate conditional/unconditional branches and fallthrough in that bounded interval.
    groups=defaultdict(list)
    for x in raw:
        s,data,origin=secdata[x['index']];off=x['site']-origin
        pos=data.rfind(b'\xcc'*4,0,off)
        if pos<0:x['anchor']=None;continue
        pos+=4
        while pos<off and data[pos]==0xcc:pos+=1
        x['anchor']=origin+pos;groups[(x['index'],pos)].append(x)
    reachable={}; summaries=[]
    for (index,start),items in sorted(groups.items()):
        s,data,origin=secdata[index];last=max(x['site'] for x in items)-origin
        end=data.find(b'\xcc'*4,last)
        if end<0:end=len(data)
        lo=origin+start;hi=origin+end;todo=[lo];seen={};bad=[];indirect=[]
        while todo:
            addr=todo.pop()
            if addr in seen or not(lo<=addr<hi):continue
            ins=next(md.disasm(data[addr-origin:addr-origin+15],addr,count=1),None)
            if not ins:bad.append(addr);continue
            seen[addr]=ins
            if ins.group(capstone.CS_GRP_RET) or ins.mnemonic in ('int3','int','ud2','hlt'):continue
            if ins.group(capstone.CS_GRP_JUMP):
                op=ins.operands[0]
                if op.type==capstone.x86.X86_OP_IMM:todo.append(op.imm)
                else:indirect.append(addr)
                if ins.mnemonic=='jmp':continue
            todo.append(addr+ins.size)
        reachable[(index,lo)]=seen
        summaries.append((index,h(lo),h(hi),len(items),sum(x['site'] in seen for x in items),len(seen),len(bad),len(indirect)))
    dump('cfg-anchor-summary.csv',['section_index','entry_after_int3_candidate_va','scan_end_va','matching_sites','sites_reached','decoded_instructions','decode_errors','indirect_jumps_not_followed'],summaries)
    for x in raw:
        seen=reachable.get((x['index'],x['anchor']),{})
        site=x['site']; inst=seen.get(site)
        # Verify every instruction boundary through the handoff, not only first byte.
        pos=site; seq=[]
        while pos < site+len(REG.match(readva(site,40)).group(0)):
            ins=seen.get(pos)
            if ins is None:break
            seq.append(ins);pos+=ins.size
        expected_end=site+len(REG.match(readva(site,40)).group(0))
        x['cfg_reached']=pos==expected_end
    # Exhaustively inspect the one GameScriptGame registration routine from its observed
    # entry, including methods whose target is passed in a register rather than mov eax,imm.
    secidx=next(i for i,s in enumerate(p.sections) if s.Name.rstrip(b'\0')==b'.text')
    game_entry=0x127dd20; seen=reachable[(secidx,game_entry)];ordered=sorted(seen.values(),key=lambda i:i.address)
    game_want={e['name'].split('.')[-1]:e for e in api if e['namespace']=='GameScript.Game'}
    game=[]
    for n,i in enumerate(ordered):
        if i.mnemonic!='push' or not i.operands or i.operands[0].type!=capstone.x86.X86_OP_IMM:continue
        try:leaf=strva(i.operands[0].imm)
        except (ValueError,UnicodeDecodeError,pefile.PEFormatError):continue
        if leaf not in game_want:continue
        tail=ordered[n+1:n+6]
        if len(tail)<5 or any(tail[k].address != ([i]+tail)[k].address+([i]+tail)[k].size for k in range(5)):continue
        if tail[0].mnemonic!='call' or tail[0].operands[0].type!=capstone.x86.X86_OP_IMM:continue
        if [x.mnemonic for x in tail[1:]]!=['add','push','mov','call']:continue
        try:info=builderinfo(tail[0].operands[0].imm)
        except (ValueError,UnicodeDecodeError,struct.error,pefile.PEFormatError):continue
        if not info or info[0]!='GameScriptGame':continue
        prev=ordered[n-1];prev2=ordered[n-2];fn=''
        if (prev.mnemonic=='push' and prev.op_str=='eax' and prev2.mnemonic=='mov' and len(prev2.operands)==2 and prev2.operands[0].reg==capstone.x86.X86_REG_EAX and prev2.operands[1].type==capstone.x86.X86_OP_IMM and prev2.address+prev2.size==prev.address and prev.address+prev.size==i.address):fn=h(prev2.operands[1].imm)
        proxy=info[6];mm=re.search(r'(?:const)?(\d+)$',proxy)
        arity=int(mm.group(1)) if mm else None
        sig=game_want[leaf]['signature'];stub=len(sig['parameters']) if sig is not None else None
        game.append((game_want[leaf]['name'],h(i.address),h(i.operands[0].imm),h(tail[0].operands[0].imm),fn,prev.op_str,info[1],info[2],info[3],info[4],arity if arity is not None else '',stub if stub is not None else '',str(arity==stub).lower() if arity is not None and stub is not None else 'unknown',info[5]))
    game.sort()
    # Excerpts are manually selected, independently verified instruction boundaries.
    selected=[('AdjustPossessionVisionModeForCinema',0x12800e1,0x12800fb,0xc37430),
              ('DataMinerCheckpoint',0x12800b5,0x12800cf,0x853d50),
              ('KillAllObjectsInWeaponInventory',0x127fb66,0x127fb87,0x8f4cb0),
              ('ShowLoadingScreenMovieStreamHint',0x127f56c,0x127f58d,0xa18740),
              ('ShowLoadingScreenMovieStreamHintWithMenu',0x127f59f,0x127f5c0,0xc19a20),
              ('ShowMovie',0x127f4d3,0x127f4f4,0xe775c0)]
    lines=['Reviewed instruction excerpts for six differing proxy/stub argument counts. Preferred VAs.']
    for label,start,end,builder in selected:
        for desc,first,last in [('registration',start,end),('proxy builder',builder,builder+0x4c)]:
            instructions=list(md.disasm(readva(first,last-first),first))
            if sum(i.size for i in instructions)!=last-first:raise ValueError('Bad boundary: '+label+' '+desc)
            lines.append(f'\n=== {label} {desc}: {h(first)}-{h(last)} ===')
            lines.extend(f'{i.address:08X}  {i.bytes.hex(" "):<28} {i.mnemonic:<8} {i.op_str}'.rstrip() for i in instructions)
        info=builderinfo(builder)
        if not info:raise ValueError('Missing proxy RTTI: '+label)
        lines.append(f'vtable {info[2]}, COL {info[3]}, type descriptor {info[4]}: {info[5]}')
    lines.append('\n=== ShowMovie target wrapper: 0x43E8A0-0x43E8B4 ===')
    instructions=list(md.disasm(readva(0x43e8a0,0x14),0x43e8a0))
    if sum(i.size for i in instructions)!=0x14:raise ValueError('Bad ShowMovie wrapper boundary')
    lines.extend(f'{i.address:08X}  {i.bytes.hex(" "):<28} {i.mnemonic:<8} {i.op_str}'.rstrip() for i in instructions)
    for title,first,last in [('Game registration entry and saved registers',0x127dd20,0x127dd4f),('Potential DataMiner target',0xb7f4c0,0xb7f4c3)]:
        instructions=list(md.disasm(readva(first,last-first),first))
        if sum(i.size for i in instructions)!=last-first:raise ValueError('Bad boundary: '+title)
        lines.append(f'\n=== {title}: {h(first)}-{h(last)} ===')
        lines.extend(f'{i.address:08X}  {i.bytes.hex(" "):<28} {i.mnemonic:<8} {i.op_str}'.rstrip() for i in instructions)
    (OUT/'manual-review-excerpts.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    dump('gamescript-game-all-methods.csv',['api_path_name_correspondence_not_runtime_proof','name_push_va','method_string_va','proxy_builder_va','target_va_only_if_immediate_eax','preceding_push_operand','owner_qualifier_in_decorated_name','vtable_va','col_va','type_descriptor_va','proxy_arity_suffix','stub_parameter_count','arity_numbers_equal_not_abi_proof','decorated_proxy_rtti'],game)
    typed=[]
    for x in raw:
        sig=by_name[x['api']]['signature'];m=re.search(r'(?:const)?(\d+)$',x['kind'])
        par=int(m.group(1)) if m else None; count=len(sig['parameters']) if sig is not None else None
        typed.append((x['api'],x['cls'],x['qualifier'],h(x['site']),h(x['name']),h(x['fn']),h(x['builder']),x['vt'],x['col'],x['td'],h(x['sink']),h(x['anchor']) if x['anchor'] else '',str(x['cfg_reached']).lower(),par if par is not None else '',count if count is not None else '',str(par==count).lower() if par is not None and count is not None else 'unknown',x['decorated']))
    typed.sort()
    dump('proxy-cfg-candidates.csv',['api_path_name_correspondence_not_runtime_proof','cpp_owner_token','qualifier_msvc_raw','mov_site_va','method_string_va','native_function_va','builder_va','vtable_va','col_va','type_descriptor_va','next_call_va','heuristic_entry_va','cfg_reachable_sequence','proxy_arity_suffix','stub_parameter_count','arity_numbers_equal_not_abi_proof','decorated_proxy_rtti'],typed)
    covered={x['api'] for x in raw if x['cfg_reached']}; game_extra={x[0] for x in game}
    with (ROOT/'analysis/script-api-comparison/api-entry-exact-leaf-strings.csv').open(encoding='utf-8',newline='') as f:
        literals=list(csv.DictReader(f))
    output=[]
    for row in literals:
        name=row['api_full_name'];status='proxy-cfg-candidate' if name in covered else ('game-cfg-registration' if name in game_extra else ('exact-leaf-string-only' if int(row['pe_literal_occurrences']) else 'no-exact-nul-leaf'))
        output.append((name,row['api_namespace'],status,row['pe_literal_occurrences'],row['pe_section_and_preferred_va']))
    dump('all-api-evidence.csv',['api_path','namespace','highest_observed_evidence_not_runtime_proof','exact_leaf_string_occurrences','locations'],output)
    summary={'all_api_paths':len(api),'reference_docs_verified':len(docrows),'all_pe_sections':len(p.sections),
             'api_evidence_tiers':dict(sorted(Counter(x[2] for x in output).items())),
             'pattern_candidates':len(raw),'cfg_anchored_pattern_candidates':sum(x['cfg_reached'] for x in raw),
             'cfg_groups':len(groups),'by_class':dict(sorted(Counter(x['cls'] for x in raw if x['cfg_reached']).items())),
             'game_api_names':len(game_want),'game_registration_matches':len(game),'game_missing_api_names':sorted(set('GameScript.Game.'+x for x in game_want)-set(x[0] for x in game)),
             'game_proxy_vs_stub_arity_equal':sum(x[12]=='true' for x in game),'game_proxy_vs_stub_arity_different':sum(x[12]=='false' for x in game),
             'game_proxy_vs_stub_arity_unknown':sum(x[12]=='unknown' for x in game)}
    (OUT/'stats.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps(summary,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
