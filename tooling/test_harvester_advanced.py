#!/usr/bin/env python3
"""Advanced workbench tests; real EXE and pefile used only in optional integration tests."""
import contextlib
import csv
import hashlib
import io
import json
from pathlib import Path
import random
import struct
import tempfile
import unittest
import zlib

import forensic_harvester as h
import harvester_advanced as a


def fake_pe():
    data = bytearray(0x600)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x14c, 1, 123, 0, 0, 0xe0, 0x102)
    opt = 0x98
    struct.pack_into('<H', data, opt, 0x10b)
    struct.pack_into('<I', data, opt+16, 0x1000)
    struct.pack_into('<I', data, opt+28, 0x400000)
    struct.pack_into('<II', data, opt+32, 0x1000, 0x200)
    struct.pack_into('<III', data, opt+56, 0x2000, 0x200, 0)
    struct.pack_into('<HH', data, opt+68, 3, 0x140)
    struct.pack_into('<I', data, opt+92, 16)
    struct.pack_into('<II', data, opt+96, 0x1100, 0x80)
    struct.pack_into('<8sIIIIIIHHI', data, opt+0xe0, b'.rdata\0\0', 0x400, 0x1000, 0x400, 0x200, 0, 0, 0, 0, 0x40000040)
    # export directory + three functions, two names and one forwarder
    struct.pack_into('<IIHHIIIIIII', data, 0x300, 0, 0, 0, 0, 0, 10, 3, 2, 0x1140, 0x114c, 0x1154)
    struct.pack_into('<III', data, 0x340, 0x1200, 0x1160, 0x1210)
    struct.pack_into('<II', data, 0x34c, 0x1170, 0x1178)
    struct.pack_into('<HH', data, 0x354, 0, 1)
    data[0x360:0x369] = b'DLL.func\0'
    data[0x370:0x374] = b'foo\0'
    data[0x378:0x37c] = b'bar\0'
    return bytes(data)


class TableTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        folder = self.root/'analysis'; folder.mkdir()
        self.path = folder/'data.csv'
        with self.path.open('w', newline='', encoding='utf-8') as f:
            w=csv.writer(f); w.writerow(['name','number','group'])
            w.writerows([['Alpha','0x10','a'], ['beta','2','a'], ['GAMMA','001','b'], ['bad','abc','b']])
    def tearDown(self): self.temp.cleanup()

    def test_catalog_and_path_traversal_rejected(self):
        self.assertEqual(a.catalog(self.root), ['analysis/data.csv'])
        with self.assertRaises(ValueError): a.table_path(self.root, '../data.csv')
        outside = self.root/'outside.csv'; outside.write_text('x\n')
        try: (self.root/'analysis/link.csv').symlink_to(outside)
        except OSError: self.skipTest('symlinks unsupported')
        self.assertNotIn('analysis/link.csv', a.catalog(self.root))
        with self.assertRaises(ValueError): a.table_path(self.root, 'analysis/link.csv')

    def test_query_filters_numeric_sort_and_pagination(self):
        r = a.table_query(self.root,'analysis/data.csv',[('number','ge','2')],['name','number'],False,'number',True,False,0,1)
        self.assertEqual((r['total'],r['returned'],r['has_more']),(2,1,True))
        self.assertEqual(r['items'][0]['name'],'beta')
        r = a.table_query(self.root,'analysis/data.csv',[('name','contains','A')],[],True,None,False,False,1,2)
        self.assertEqual(r['total'],4)
        self.assertEqual([x['name'] for x in r['items']], ['beta','GAMMA'])
        r = a.table_query(self.root,'analysis/data.csv',[('name','starts','Al')],[],False,None,False,False,0,10)
        self.assertEqual(r['total'],1)
        for filters in ([('missing','eq','x')], [('name','wrong','x')], [('number','gt','nan')]):
            with self.assertRaises(ValueError): a.table_query(self.root,'analysis/data.csv',filters,[],False,None,False,False,0,10)

    def test_group_invalid_headers_and_numeric_parsing(self):
        g = a.table_group(self.root,'analysis/data.csv','group',[],False,1)
        self.assertEqual((g['matching_rows'],g['distinct_values'],g['truncated']),(4,2,True))
        self.assertEqual(g['items'][0], {'value':'a','count':2})
        self.assertEqual(a.integer_value('001'),1)
        self.assertEqual(a.integer_value('-0x10'),-16)
        with self.assertRaises(ValueError): a.integer_value('1.5')
        self.path.write_text('a,a\n1,2\n')
        with self.assertRaises(ValueError): a.table_header(self.path)


class BinaryPrimitiveTests(unittest.TestCase):
    def test_pe_headers_and_exports_named_ordinal_forwarder(self):
        raw=fake_pe(); header=a.parse_pe_headers(raw); exports=a.parse_pe_exports(raw,header)
        self.assertEqual(header['image_base'],0x400000)
        self.assertEqual(header['directories'][4]['address_kind'],'file_offset')
        self.assertEqual([(x['name'],x['ordinal'],x['forwarder']) for x in exports], [('foo',10,None),('bar',11,'DLL.func'),(None,12,None)])
        self.assertEqual(exports[0]['target_preferred_va'],0x401200)
        self.assertIsNone(exports[1]['target_preferred_va'])
        for bad in (b'',b'MZ', raw[:0x200]):
            with self.assertRaises(ValueError): a.parse_pe_headers(bad)
        aliases=bytearray(raw); struct.pack_into('<H',aliases,0x356,0)
        alias_exports=a.parse_pe_exports(bytes(aliases),a.parse_pe_headers(bytes(aliases)))
        self.assertEqual([(v['name'],v['ordinal']) for v in alias_exports], [('foo',10),('bar',10),(None,11),(None,12)])
        broken=bytearray(raw); struct.pack_into('<H',broken,0x354,99)
        with self.assertRaises(ValueError): a.parse_pe_exports(bytes(broken),a.parse_pe_headers(bytes(broken)))

    def test_pe_rva_overlap_and_unterminated(self):
        raw=fake_pe(); hdr=a.parse_pe_headers(raw); secs=hdr['sections']
        self.assertEqual(a.rva_string(raw,secs,0x1170),'foo')
        with self.assertRaises(ValueError): a.rva_string(raw,secs,0x1170,limit=2)
        with self.assertRaises(ValueError): a.rva_bytes(raw,secs+[dict(secs[0])],0x1170,1)
        with self.assertRaises(ValueError): a.rva_bytes(raw,secs,0x13fe,4)

    def test_layout_overlap_nested_gap(self):
        inv={'size':30,'sections':[{'index':0,'name':'a','raw_offset':5,'raw_size':10,'virtual_address':100,'virtual_size':10},
                                  {'index':1,'name':'b','raw_offset':10,'raw_size':3,'virtual_address':104,'virtual_size':3},
                                  {'index':2,'name':'c','raw_offset':20,'raw_size':2,'virtual_address':120,'virtual_size':2}]}
        r=a.layout_report(inv)
        self.assertEqual(len(r['raw_overlap_pairs']),1)
        self.assertEqual([(g['start'],g['end_exclusive']) for g in r['raw_gaps_including_headers_and_overlay']], [('0x0','0x5'),('0xf','0x14'),('0x16','0x1e')])
        self.assertEqual(r['bytes_after_last_raw_section'],8)

    def test_hashes_frequencies_and_runs(self):
        data=b'\0'*5+b'A'*3+b'BC'
        self.assertEqual(a.hash_bytes(data)['sha256'],hashlib.sha256(data).hexdigest())
        self.assertEqual(a.hash_bytes(data)['crc32'],f'0x{zlib.crc32(data):08X}')
        self.assertEqual(a.frequencies(data,1)['values'][0]['count'],5)
        self.assertTrue(a.frequencies(data,1)['truncated'])
        self.assertEqual([(x['offset'],x['length'],x['byte']) for x in a.byte_runs(data,3)], [(0,5,'0x00'),(5,3,'0x41')])
        self.assertEqual(len(list(a.byte_runs(data,3,65))),1)
        with self.assertRaises(ValueError): list(a.byte_runs(data,1,256))

    def test_entropy_windows_bounds_and_partial(self):
        self.assertEqual(a.window_count(10,4,3,False),3)
        self.assertEqual(a.window_count(10,4,3,True),4)
        windows=list(a.window_stats(b'ABABABABAB',4,3,True,0,8))
        self.assertEqual([r['offset'] for r in windows],[0,3,6,9])
        self.assertEqual(windows[0]['entropy_bits_per_byte'],1.0)
        self.assertEqual(windows[-1]['size'],1)
        self.assertEqual(len(list(a.window_stats(b'AAAA',4,4,False,1,8))),0)

    def test_integer_encodings_and_packed_layout(self):
        self.assertEqual(a.integer_info(-1,4)['unsigned'],0xffffffff)
        self.assertEqual(a.int_encodings(-2,[2],'big')[0][2],b'\xff\xfe')
        with self.assertRaises(ValueError): a.int_encodings(256,[1],'little')
        layout=a.parse_layout('u32, i16, ptr32, pad[2], f32')
        packed=a.pack_layout(layout,['0x1234','-4','0x400000','1.5'],'little')
        fields=a.unpack_layout(packed,layout,'little')
        self.assertEqual([r.get('value') for r in fields],[0x1234,-4,0x400000,None,1.5])
        with self.assertRaises(ValueError): a.pack_layout(layout,['1'],'little')
        for bad in ('', 'pad[0]', 'u8,' , 'pad[5000]', 'u128'):
            with self.assertRaises(ValueError): a.parse_layout(bad)
        self.assertEqual(a.unpack_layout(struct.pack('<f',float('nan')),a.parse_layout('f32'),'little')[0]['value'],'NaN')

    def test_float_info(self):
        self.assertEqual(a.float_info(4, value=1.0)['bits_hex'], '0x3F800000')
        self.assertEqual(a.float_info(4, bits=0x7f800000)['category'], 'infinity')
        self.assertEqual(a.float_info(4, bits=0x7fc00000)['value'], 'NaN')
        self.assertEqual(a.float_info(4, bits=1)['category'], 'subnormal')
        self.assertEqual(a.float_info(4, bits=0x80000000)['sign'], 1)
        self.assertEqual(a.float_info(4, bits=0x80000000)['category'], 'zero')
        with self.assertRaises(ValueError): a.float_info(4, bits=1<<32)
        with self.assertRaises(ValueError): a.float_info(4, value=1e100)

    def test_safe_decompression_complete_incomplete_and_limit(self):
        plain=b'Z'*100000
        z=zlib.compress(plain)
        result=a.compression_probe(z,128)['zlib']
        self.assertEqual((result['status'],result['output_bytes_returned']),('output_limit_reached',128))
        self.assertLessEqual(len(result['output_preview_hex'].split()),64)
        self.assertEqual(a.compression_probe(z,200000)['zlib']['status'],'complete')
        self.assertEqual(a.compression_probe(z[:2],128)['zlib']['status'],'incomplete')
        gzip=zlib.compressobj(wbits=31); gz=gzip.compress(b'hello')+gzip.flush()
        self.assertEqual(a.compression_probe(gz,100)['gzip']['status'],'complete')
        raw=zlib.compressobj(wbits=-15); data=raw.compress(b'hello')+raw.flush()
        self.assertEqual(a.compression_probe(data,100)['raw_deflate']['status'],'complete')
        self.assertEqual(a.bounded_zlib(b'bad header',15,100)['status'],'decode_error')

    def test_transforms_and_xor_rank(self):
        value=b'\x01\x23\x45\x67'
        self.assertEqual(a.transform(a.transform(value,'xor',0x9a),'xor',0x9a),value)
        self.assertEqual(a.transform(a.transform(value,'rotl',3),'rotr',3),value)
        self.assertEqual(a.transform(value,'swap16',0),b'\x23\x01\x67\x45')
        self.assertEqual(a.transform(value,'swap32',0),value[::-1])
        self.assertEqual(a.transform(value,'not',0),bytes(b^255 for b in value))
        self.assertEqual(a.transform(value,'reverse',0),value[::-1])
        with self.assertRaises(ValueError): a.transform(b'123','swap16',0)
        with self.assertRaises(ValueError): a.transform(value,'rotl',8)
        self.assertEqual(len(a.xor_rank(value,10)),10)

    def test_hierarchy_preorder_validation(self):
        rows=[{'index':str(i),'contained_bases':str(n)} for i,n in enumerate([4,3,2,0,0])]
        nodes=a.hierarchy_nodes(rows)
        self.assertEqual([n['parent_index_candidate'] for n in nodes],[None,0,1,2,2])
        rows[1]['contained_bases']='5'
        with self.assertRaises(ValueError): a.hierarchy_nodes(rows)
        with self.assertRaises(ValueError): a.hierarchy_nodes([{'index':'1','contained_bases':'0'}])
        with self.assertRaises(ValueError): a.hierarchy_nodes([{'index':'0','contained_bases':'-1'}])

    def test_pointer_chain_and_cstring(self):
        sec={'index':0,'name':'.data','raw_offset':0,'raw_size':32,'virtual_address':0x1000,'virtual_size':32,'characteristics':0x40000040}
        inv={'image_base':0x400000,'sections':[sec]}
        data=bytearray(32);struct.pack_into('<II',data,0,0x401004,0x401000);data[8:14]=b'Hello\0'
        self.assertEqual(h.pointer_chain(bytes(data),inv,inv,0x401000,5)['stop_reason'],'cycle_detected')
        self.assertEqual(h.pointer_chain(bytes(data),inv,inv,0,5)['stop_reason'],'null_pointer')
        self.assertEqual(h.pointer_chain(bytes(data),inv,inv,0x402000,5)['stop_reason'],'not_readable_in_selected_raw_sections')
        self.assertEqual(h.section_strings(bytes(data),inv,'va',0x401008,'ascii',20)['text_preview'],'Hello')
        r=h.section_strings(bytes(data),inv,'va',0x401008,'ascii',3)
        self.assertFalse(r['terminator_found']);self.assertEqual(r['stop_reason'],'max_bytes')
        data[16:24]='abc'.encode('utf-16le')+b'\0\0'
        self.assertEqual(h.section_strings(bytes(data),inv,'va',0x401010,'utf-16le',8)['text_preview'],'abc')


class RepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=h.ROOT;cls.inv=h.context(cls.root);cls.raw,cls.scoped,_=h.byte_source(cls.root,cls.inv,None,True)

    def test_table_cli_and_overview(self):
        path='analysis/cpp-classes/classes.csv'
        r=a.table_group(self.root,path,'kind',[],False,10)
        self.assertEqual({x['value']:x['count'] for x in r['items']},{'class':11832,'struct':119})
        self.assertEqual(h.overview(self.root,self.inv)['api_records'],3879)
        r=a.table_query(self.root,path,[('kind','eq','struct')],['type_descriptor_va'],False,None,False,False,0,1)
        self.assertEqual((r['total'],r['returned']),(119,1))

    def test_hierarchy_uses_and_derived(self):
        r=h.hierarchy(self.root,'Despair::GameScriptPlayer',20)
        nodes=r['hierarchies'][0]['nodes']['items']
        self.assertEqual([x['parent_index_candidate'] for x in nodes],[None,0,1,2,2])
        self.assertEqual(h.type_uses(self.root,'Despair::Vector3d',1)['rtti_mentions']['total'],111)
        d=h.derived_classes(self.root,'Despair::Reflection::Object',True,2)
        self.assertGreater(d['matches']['total'],0)
        self.assertTrue(all(x['direct_base_candidate'] for x in d['matches']['items']))

    def test_audit_partial_and_full_when_available(self):
        r=h.audit_class(self.root,self.raw,self.scoped,'Despair::GameScriptPlayer',50)
        self.assertEqual(r['counts'],{'match':2,'mismatch':0,'unavailable':8})
        self.assertFalse(r['complete']);self.assertFalse(r['all_match'])
        out=io.StringIO()
        with contextlib.redirect_stdout(out): code=h.main(['audit-class','Despair::GameScriptPlayer','--extracted','--require-complete'])
        self.assertEqual(code,1)
        exe=self.root/h.EXE_REL
        if exe.exists():
            raw=h.verify_exe(self.root,self.inv)
            full=h.audit_class(self.root,raw,self.inv,'Despair::GameScriptPlayer',50)
            self.assertEqual(full['counts'],{'match':10,'mismatch':0,'unavailable':0})
            self.assertTrue(full['all_match'])
            bad=bytearray(raw);bad[int(full['owner']['file_offset'],16)]^=1
            corrupt=h.audit_class(self.root,bytes(bad),self.inv,'Despair::GameScriptPlayer',50)
            self.assertGreater(corrupt['counts']['mismatch'],0)

    def test_all_saved_hierarchy_spans_are_well_formed(self):
        from collections import defaultdict
        grouped = defaultdict(list)
        for row in h.rows(self.root, 'analysis/cpp-classes/base-descriptors.csv', ('hierarchy_va', 'index', 'contained_bases')):
            grouped[row['hierarchy_va']].append(row)
        self.assertEqual(len(grouped), 9656)
        for entries in grouped.values():
            entries.sort(key=lambda row: int(row['index']))
            self.assertEqual(len(a.hierarchy_nodes(entries)), len(entries))

    def test_extracted_signature_int_and_windows(self):
        r=h.int_search(self.raw,self.scoped,0x6c2d50,[4],'both','Game_dat',5)
        self.assertEqual(r['groups']['32bit_little']['total'],1)
        self.assertEqual(r['groups']['32bit_little']['items'][0]['preferred_va'],'0x1870E7C')
        s=h.signatures(self.raw,self.scoped,['png'],'Game_dat',5)
        self.assertEqual(s['png']['total'],0)
        w=h.entropy_windows(self.raw,self.scoped,'Game_dat',4096,4096,False,0,8,1)
        self.assertEqual(w['windows_evaluated'],181)
        self.assertTrue(w['matches']['truncated'])
        with self.assertRaises(ValueError): h.entropy_windows(self.raw,self.scoped,'Game_dat',4,1,False,0,8,1)

    def test_new_cli_commands_smoke(self):
        cmds = [
            ['overview'], ['layout'], ['int-info','-1'], ['float-info','--bits','0x3f800000'],
            ['tables'], ['schema','analysis/cpp-classes/classes.csv'],
            ['table','analysis/cpp-classes/classes.csv','--where','kind','eq','struct','--limit','2'],
            ['group','analysis/cpp-classes/classes.csv','--column','kind'],
            ['uses','Despair::Vector3d','--limit','2'], ['hierarchy','Despair::GameScriptPlayer','--limit','2'],
            ['derived','Despair::Reflection::Object','--direct','--limit','2'],
            ['pack','--layout','u32,pad[2],i16','--value','1','--value','-2'],
            ['signatures','--list'], ['signatures','--name','png','--section','Game_dat','--extracted'],
            ['windows','--section','Game_dat','--window','4096','--step','4096','--limit','1','--extracted'],
            ['int-find','0x6c2d50','--section','Game_dat','--limit','1','--extracted'],
            ['hash','--va','0x1870e7c','--size','8','--extracted'],
            ['unpack','--va','0x1870e7c','--layout','ptr32,u32','--extracted'],
            ['cstring','--va','0x1878b4c','--extracted'], ['chain','--va','0x1870e7c','--extracted'],
            ['probe','--va','0x1870e7c','--size','8','--extracted'],
            ['transform','--va','0x1870e7c','--size','8','--operation','xor','--key','255','--extracted'],
            ['xor-rank','--va','0x1870e7c','--size','8','--extracted'],
            ['frequencies','--section','Game_dat','--limit','1','--extracted'],
            ['runs','--section','Game_dat','--min-length','1000','--limit','1','--extracted'],
            ['section-diff','--left','Game_dat','--right','Game_dat','--limit','1','--extracted'],
            ['audit-class','Despair::GameScriptPlayer','--limit','2','--extracted'],
        ]
        if (self.root/h.EXE_REL).is_file(): cmds += [['compare-sections'], ['pe-headers'], ['pe-exports','--limit','2']]
        for command in cmds:
            with self.subTest(command=command):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    status=h.main(command)
                self.assertEqual(status,0,err.getvalue())
                self.assertEqual(json.loads(out.getvalue())['command'],command[0])

    def test_real_pe_and_external_independent_parser_if_available(self):
        exe=self.root/h.EXE_REL
        if not exe.is_file(): self.skipTest('user EXE absent')
        raw=h.verify_exe(self.root,self.inv); header=a.parse_pe_headers(raw)
        self.assertEqual((header['section_count'],header['image_base']),(35,0x400000))
        exports=a.parse_pe_exports(raw,header)
        self.assertEqual(len(exports),199)
        try:
            import sys
            sys.path.insert(0,str(h.ROOT/'tooling/python'))
            import pefile
        except ImportError:
            return
        reference=pefile.PE(data=raw).DIRECTORY_ENTRY_EXPORT.symbols
        actual={(x['ordinal'],x['name'],x['target_rva'],x['forwarder']) for x in exports}
        expected={(x.ordinal,x.name.decode() if x.name else None,x.address,x.forwarder.decode() if x.forwarder else None) for x in reference}
        self.assertEqual(actual,expected)

if __name__=='__main__': unittest.main()
