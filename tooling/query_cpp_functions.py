#!/usr/bin/env python3
"""Filter static function candidates by tag, evidence, name, or preferred VA."""
import argparse
import csv
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'analysis/cpp-functions'


def get_rows(path):
    with path.open(encoding='utf8',newline='') as f:yield from csv.DictReader(f)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--category',help='exact category tag, e.g. script_api or unknown')
    p.add_argument('--source',help='exact evidence source, e.g. vtable_first_slot')
    p.add_argument('--tier',help='exact evidence tier')
    p.add_argument('--query',help='case-insensitive substring of name, API path, or address')
    p.add_argument('--owner',help='case-insensitive substring of associated vtable type name')
    p.add_argument('--va',help='exact preferred VA, e.g. 0x43E8A0')
    p.add_argument('--limit',type=int,default=50);p.add_argument('--offset',type=int,default=0)
    p.add_argument('--owners',action='store_true',help='include all vtable owner associations for returned addresses')
    p.add_argument('--format',choices=('json','csv'),default='json')
    a=p.parse_args(argv)
    if a.limit<0 or a.limit>10000 or a.offset<0:p.error('limit must be 0..10000 and offset nonnegative')
    try:va=int(a.va,0) if a.va else None
    except ValueError:p.error('invalid VA')
    query=a.query.casefold() if a.query else None
    owners=None
    if a.owner:
        needle=a.owner.casefold()
        owners={row['target_va'] for row in get_rows(OUT/'vtable-word-evidence.csv')
                if needle in row['owner_name_candidate'].casefold()}
    found=[];total=0
    for row in get_rows(OUT/'function-candidates.csv'):
        if a.category and a.category not in row['category_tags'].split('|'):continue
        if a.source and a.source not in row['evidence_sources'].split('|'):continue
        if a.tier and a.tier!=row['evidence_tier']:continue
        if owners is not None and row['preferred_va'] not in owners:continue
        if va is not None and int(row['preferred_va'],16)!=va:continue
        if query and query not in ' '.join((row['preferred_va'],row['export_names'],row['script_api_names'])).casefold():continue
        if a.offset<=total<a.offset+a.limit:found.append(row)
        total+=1
    if a.owners:
        if a.format=='csv':p.error('--owners requires --format json')
        selected={row['preferred_va']:row for row in found}
        for row in found:row['vtable_associations']=[]
        for evidence in get_rows(OUT/'vtable-word-evidence.csv'):
            if evidence['target_va'] in selected:selected[evidence['target_va']]['vtable_associations'].append(evidence)
    if a.format=='json':
        print(json.dumps({'total':total,'offset':a.offset,'returned':len(found),'has_more':a.offset+len(found)<total,
                          'warning':'Static candidate evidence, not complete function inventory or runtime proof.',
                          'items':found},ensure_ascii=False,indent=2))
    else:
        fields=['preferred_va','section_index','section','file_offset','evidence_tier','evidence_sources','export_names','script_api_names',
                'vtable_owner_count','category_tags','vtable_first_slot_references','vtable_later_word_references','cfg_decoded_direct_calls','raw_e8_calls']
        w=csv.DictWriter(sys.stdout,fieldnames=fields,lineterminator='\n');w.writeheader();w.writerows(found)
        print(f'matches={total} returned={len(found)}',file=sys.stderr)
    return 0

if __name__=='__main__':sys.exit(main())
