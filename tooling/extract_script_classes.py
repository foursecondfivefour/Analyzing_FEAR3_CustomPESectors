#!/usr/bin/env python3
"""Inventory script-related literals and MSVC RTTI in every on-disk PE section.

No evidence is executed. Exact byte searches and conservative label-based selection;
RTTI and vtable candidates are not evidence of runtime reachability or Lua exposure.
"""
from pathlib import Path
from collections import Counter, defaultdict
import csv
import hashlib
import json
import re
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tooling/python'))
import pefile

EXE = ROOT / 'evidence/source-exe/F.E.A.R. 3.exe'
MANIFEST = ROOT / 'evidence/fear3-engine-sections/manifest.json'
OUT = ROOT / 'analysis/script-classes'
SHA = 'caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2'
RTTI = re.compile(rb'\.\?A[UV][\x21-\x7e]{3,}\x00')
SIMPLE = re.compile(r'^\.\?A([UV])([A-Za-z_][A-Za-z0-9_]*(?:@[A-Za-z_][A-Za-z0-9_]*)*)@@$')
CSTRING = re.compile(rb'[\x20-\x7e]{4,}\x00')
TERMS = ('script', 'lua')
ENCODINGS = ('ascii', 'utf-16le', 'utf-16be')


def write_csv(name, fields, rows, quoting=csv.QUOTE_MINIMAL):
    with (OUT / name).open('w', encoding='utf-8', newline='') as f:
        writer=csv.writer(f, lineterminator='\n', quoting=quoting); writer.writerow(fields); writer.writerows(rows)


def h(n): return f'0x{n:X}'


def main():
    raw=EXE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA: raise SystemExit('EXE SHA-256 mismatch')
    p=pefile.PE(data=raw); base=p.OPTIONAL_HEADER.ImageBase
    manifest=json.loads(MANIFEST.read_text(encoding='utf-8'))
    for e in manifest['sections']:
        part=ROOT/'evidence/fear3-engine-sections'/e['file']; data=part.read_bytes()
        if (hashlib.sha256(data).hexdigest()!=e['sha256'] or data!=raw[e['raw_offset']:e['raw_offset']+e['raw_size']]):
            raise SystemExit('Section mismatch: '+str(part))
    OUT.mkdir(parents=True,exist_ok=True)
    secs=[]
    for i,s in enumerate(p.sections):
        start=s.PointerToRawData; size=s.SizeOfRawData
        if start+size>len(raw):raise ValueError('Truncated PE section')
        secs.append((i,s,raw[start:start+size]))
    def loc(index,pos):
        _,s,_=secs[index]; return (index,s.Name.rstrip(b'\0').decode('ascii','replace').strip(),h(pos),h(s.PointerToRawData+pos),h(base+s.VirtualAddress+pos))
    sections=[]; rawhits=[]; literals=[]; types=[]; token_counts=defaultdict(Counter)
    for index,s,data in secs:
        name=s.Name.rstrip(b'\0').decode('ascii','replace').strip()
        low=data.lower()
        for term in TERMS:
            for enc in ENCODINGS:
                start=0; needle=term.encode(enc)
                while True:
                    pos=low.find(needle,start)
                    if pos<0:break
                    rawhits.append((*loc(index,pos),term,enc));token_counts[index][(term,enc)]+=1;start=pos+1
        for m in CSTRING.finditer(data):
            val=m.group()[:-1]
            if b'script' not in val.lower() and b'lua' not in val.lower():continue
            text=val.decode('ascii'); kind=('rtti' if text.startswith(('.?AV','.?AU')) else
                   'identifier' if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_:.$]*',text) else 'other_string')
            literals.append((*loc(index,m.start()),kind,text))
        for m in RTTI.finditer(data):
            pos=m.start()
            if pos<8:continue
            vft,zero=struct.unpack_from('<II',data,pos-8)
            if zero != 0 or vft != 0x14AA224:continue
            text=m.group()[:-1].decode('ascii');simple=SIMPLE.fullmatch(text)
            full='::'.join(reversed(simple.group(2).split('@'))) if simple else ''
            kind=('class' if simple and simple.group(1)=='V' else 'struct' if simple else 'complex_decorated')
            relevant=('Script' in text or 'Lua' in text)
            types.append({'index':index,'pos':pos,'td_va':base+s.VirtualAddress+pos-8,'name_va':base+s.VirtualAddress+pos,
                          'kind':kind,'full':full,'decorated':text,'related':relevant})
        sections.append((index,name,h(s.PointerToRawData),h(s.SizeOfRawData),h(s.VirtualAddress),
                         *(token_counts[index][(t,e)] for t in TERMS for e in ENCODINGS)))
    write_csv('section-scan.csv',['pe_index','section_name','file_offset','raw_size','rva']+[f'{t}_{e}' for t in TERMS for e in ENCODINGS],sections)
    write_csv('raw-term-hits.csv',['pe_index','section_name','section_offset','file_offset','preferred_va','term_case_insensitive','encoding'],rawhits)
    # Quote even trailing spaces so CSV preserves literal bytes without trailing whitespace in the source file.
    write_csv('script-literals.csv',['pe_index','section_name','section_offset','file_offset','preferred_va','heuristic_kind','ascii_nul_terminated'],literals,quoting=csv.QUOTE_ALL)
    write_csv('all-rtti.csv',['pe_index','section_name','name_section_offset','name_file_offset','name_preferred_va','type_descriptor_va','kind','plain_name_if_simple','decorated_name','script_or_lua_case_sensitive'],
              [(*loc(t['index'],t['pos']),h(t['td_va']),t['kind'],t['full'],t['decorated'],str(t['related']).lower()) for t in types])
    related=[t for t in types if t['related']]
    type_by_addr={t['td_va']:t for t in related}
    # Collect aligned references to script-related type descriptors and validate MSVC COL shape.
    cols={}
    def readva(va,n):
        try: return p.get_data(va-base,n)
        except (pefile.PEFormatError,ValueError):return b''
    for index,s,data in secs:
        if s.Characteristics & 0x20000000:continue
        for off in range(12,len(data)-8,4):
            val=struct.unpack_from('<I',data,off)[0]
            if val not in type_by_addr:continue
            sig,obj_off,cd,td,ch=struct.unpack_from('<IIIII',data,off-12)
            if sig!=0 or obj_off>0x10000 or cd>0x10000:continue
            hdr=readva(ch,16)
            if len(hdr)!=16:continue
            chsig,attrs,nbase,arr=struct.unpack('<IIII',hdr)
            if chsig!=0 or not 1<=nbase<=1024 or len(readva(arr,4))!=4:continue
            va=base+s.VirtualAddress+off-12
            cols[va]=(type_by_addr[val],obj_off,cd,ch,index,off-12)
    tables=[]; numtables=Counter(); numcols=Counter()
    for _,(t,*_) in cols.items():numcols[t['td_va']]+=1
    def executable(va):
        sec=p.get_section_by_rva(va-base)
        return bool(sec and sec.Characteristics & 0x20000000)
    for index,s,data in secs:
        if s.Characteristics & 0x20000000:continue
        for off in range(0,len(data)-8,4):
            val,entry=struct.unpack_from('<II',data,off)
            if val not in cols or not executable(entry):continue
            t,obj_off,cd,ch,_,_=cols[val]
            numtables[t['td_va']]+=1
            tables.append((t['full'],t['decorated'],h(t['td_va']),h(val),h(obj_off),h(cd),h(ch),h(base+s.VirtualAddress+off+4),h(entry),index,s.Name.rstrip(b'\0').decode('ascii','replace').strip(),h(off+4)))
    write_csv('rtti-vtable-candidates.csv',['plain_name_if_simple','decorated_name','type_descriptor_va','col_va','object_offset','constructor_displacement','hierarchy_va','candidate_vtable_va','first_entry_va','pe_index','section_name','vtable_section_offset'],tables)
    counts=Counter(row[-1] for row in literals if row[-2]=='identifier')
    fields=['pe_index','section_name','name_section_offset','name_file_offset','name_preferred_va','type_descriptor_va','kind','plain_name_if_simple','decorated_name','col_candidates','vtable_candidates','matching_simple_identifier_literals']
    def typerow(t):
        leaf=t['full'].split('::')[-1] if t['full'] else ''
        return (*loc(t['index'],t['pos']),h(t['td_va']),t['kind'],t['full'],t['decorated'],numcols[t['td_va']],numtables[t['td_va']],counts[leaf])
    write_csv('script-related-rtti.csv',fields,[typerow(t) for t in related])
    simple=sorted((t for t in related if t['kind'] in ('class','struct')),key=lambda t:t['full'].lower())
    write_csv('script-classes.csv',fields,[typerow(t) for t in simple])
    identifiers=[]
    for row in literals:
        *where,kind,text=row
        if kind != 'identifier': continue
        matches=[t['full'] for t in simple if text==t['full'] or t['full'].endswith('::'+text)]
        shape=bool(re.fullmatch(r'(?:[A-Z][A-Za-z0-9_]*::)*[A-Z][A-Za-z0-9_]*',text))
        identifiers.append((*where,text,str(shape).lower(),len(matches),' | '.join(matches)))
    write_csv('identifier-candidates.csv',['pe_index','section_name','section_offset','file_offset','preferred_va','identifier','capitalized_cpp_style_only_not_class_proof','matching_simple_rtti_count','matching_simple_rtti_names'],identifiers)
    leaves={t['full'].split('::')[-1] for t in simple}
    tokens=[]
    for t in related:
        if t['kind'] != 'complex_decorated': continue
        for m in re.finditer(r'(?<![a-z])([VU])([A-Za-z_][A-Za-z0-9_]*)@',t['decorated']):
            marker, name=m.groups()
            if 'Script' not in name and 'Lua' not in name: continue
            tokens.append((name,marker,str(name in leaves).lower(),h(t['name_va']),m.start(),t['decorated']))
    write_csv('template-type-token-candidates.csv',['possible_type_name','raw_v_or_u_marker','matches_simple_rtti_leaf','parent_rtti_name_va','byte_offset_in_decorated_name','parent_decorated_name'],tokens)
    groups=defaultdict(list)
    for t in simple:
        name=t['full']; leaf=name.split('::')[-1]
        if 'Scaleform' in name or 'ActionScript' in name: group='ActionScript / Scaleform / UI'
        elif 'Lua' in name: group='Lua'
        elif leaf.startswith('GameAIScript'): group='GameAIScript'
        elif leaf.startswith('GameScript'): group='GameScript'
        else: group='Script и связанные типы'
        groups[group].append(t)
    doc=['# Найденные классы и структуры, связанные со скриптами','',
         'Основной [отчёт и методика](REPORT.md). Это извлечённые имена RTTI C++, не исходный код Lua. '
         'Выборка включает простые имена с точным фрагментом `Script` или `Lua`, в том числе вложенные имена; '
         'ActionScript вынесен отдельно. Имена не гарантируют наличие в Lua или выполнение в игре. '
         'Прочие 949 шаблонных и сложных RTTI, где упоминаются `Script`/`Lua`, см. `script-related-rtti.csv`; '
         'они не добавляются сюда как отдельные классы их параметров.','',
         f'Всего простых RTTI-типов: **{len(simple)}**. Адрес — preferred VA строки имени; '
         'type descriptor находится на 8 байтов раньше. `COL / vtable` — числа структурных кандидатов, не подтверждение runtime-использования.','']
    for group in ('GameScript','GameAIScript','Lua','Script и связанные типы','ActionScript / Scaleform / UI'):
        doc.extend([f'## {group} ({len(groups[group])})','','| Имя | Тип | VA строки RTTI | COL / vtable кандидаты |','|---|---|---:|---:|'])
        for t in groups[group]:doc.append(f"| `{t['full']}` | {t['kind']} | `{h(t['name_va'])}` | {numcols[t['td_va']]} / {numtables[t['td_va']]} |")
        doc.append('')
    extra=defaultdict(list)
    for name,marker,has,va,offset,decorated in tokens:
        if has=='false': extra[name].append((marker,va))
    doc.extend(['## Дополнительные кандидаты из имён шаблонов','',
                'Ниже только имена, извлечённые эвристикой из декорированных RTTI других типов; '
                'отдельный простой type descriptor с тем же коротким именем не найден. '
                'Пространство имён и даже границы типа могут требовать ручного подтверждения; '
                '`V`/`U` — сырой маркер в сигнатуре, не доказательство определённого класса.','',
                '| Возможное имя | Маркер | Вхождения | Пример VA родительского RTTI |','|---|---|---:|---:|'])
    for name,items in sorted(extra.items()):
        doc.append(f"| `{name}` | `{', '.join(sorted({v[0] for v in items}))}` | {len(items)} | `{items[0][1]}` |")
    doc.append('')
    (OUT/'CLASSES.md').write_text('\n'.join(doc),encoding='utf-8')
    print(f'{len(secs)} PE sections, {len(rawhits)} term hits, {len(literals)} candidate strings, {len(types)} RTTI; {len(related)} related, {len(simple)} simple, {len(cols)} COL and {len(tables)} vtable candidates')
    print('groups:',{k:len(v) for k,v in groups.items()})

if __name__=='__main__':main()
