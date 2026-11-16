#!/usr/bin/env python3
import csv
import json
from pathlib import Path
import struct
import tempfile
import unittest

from inventory_cpp_classes import Demangler, Image, explicit_type_names, find_cols, find_names, find_vtables, member_owner, pointer_hits, validate_manifest


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.image = Image.__new__(Image)
        self.image.base = 0x400000
        data = bytearray(0x500)
        code = bytearray(0x100)
        def put(off, fmt, *values): struct.pack_into(fmt, data, off, *values)
        # Type descriptor, its type_info vtable, and one ASCII mangled name.
        put(0x20, '<II', 0x400100, 0)
        data[0x28:0x28+len(b'.?AVThing@NS@@\0')] = b'.?AVThing@NS@@\0'
        put(0x100, '<I', 0x401000)
        # Complete-object locator -> hierarchy -> base array -> self descriptor.
        put(0x200, '<IIIII', 0, 0, 0, 0x400020, 0x400240)
        put(0x240, '<IIII', 0, 0, 1, 0x400260)
        put(0x260, '<I', 0x400280)
        put(0x280, '<IIiiiI', 0x400020, 0, 0, -1, 0, 0x40)
        put(0x300, '<II', 0x400200, 0x401000)
        # Same pattern in executable bytes is an explicitly rejected false positive.
        struct.pack_into('<II', code, 1, 0x400200, 0x401000)
        data[0x400:0x400+len(b'.?AXNotAClass@@\0')] = b'.?AXNotAClass@@\0'
        self.image.sections = [dict(index=0, name='.data', raw=0, size=len(data), rva=0, virtual_size=len(data), flags=0x40000040, data=bytes(data)),
                               dict(index=1, name='.text', raw=len(data), size=len(code), rva=0x1000, virtual_size=len(code), flags=0x60000020, data=bytes(code))]
        self.image.raw = bytes(data + code)

    def test_fallback(self):
        d = Demangler()
        self.assertEqual(d.name('.?AVThing@NS@@'), ('NS::Thing', 'simple_fallback'))
        self.assertEqual(d.name('.?AV?$x@H@@'), ('', 'unresolved'))

    def test_type_references_and_member_owners(self):
        proto = 'public: void __thiscall NS::Container<class NS::Thing>::put(class NS::Outer<struct NS::Inner> const &)'
        self.assertEqual(member_owner(proto), 'NS::Container<class NS::Thing>')
        self.assertEqual(explicit_type_names(proto), [('class', 'NS::Thing'), ('class', 'NS::Outer<struct NS::Inner>'), ('struct', 'NS::Inner')])
        self.assertEqual(member_owner('void __cdecl NS::free_function(void)'), '')
        self.assertEqual(explicit_type_names('class Bad<struct Inner'), [('struct', 'Inner')])
        self.assertEqual(member_owner('public: void __thiscall C::operator()(int)'), 'C')

    def test_raw_hits_and_col_and_vtable(self):
        raw, types, counts = find_names(self.image, Demangler())
        self.assertEqual(len(raw), 2)
        self.assertEqual(raw[1]['status'], 'unsupported_kind_marker')
        self.assertEqual(counts[0], 2)
        self.assertEqual(set(types), {0x400020})
        cols = find_cols(self.image, types)
        self.assertEqual(set(cols), {0x400200})
        tables = find_vtables(self.image, cols)
        self.assertEqual([x['status'] for x in tables], ['candidate', 'rejected_unaligned_and_in_executable_section'])
        self.assertEqual(tables[0]['vtable_va'], '0x400304')
        self.assertEqual(cols[0x400200]['_bases'][0][1][3], -1)

    def test_invalid_hierarchy_rejected(self):
        s = self.image.sections[0]
        b = bytearray(s['data'])
        struct.pack_into('<I', b, 0x280, 0x400021)
        s['data'] = bytes(b)
        _, types, _ = find_names(self.image, Demangler())
        self.assertFalse(find_cols(self.image, types))

    def test_pointer_hits_unaligned_and_section_boundary(self):
        s = self.image.sections[0]
        b = bytearray(s['data'])
        struct.pack_into('<I', b, 0x351, 0x400020)
        s['data'] = bytes(b)
        hits = [(sec['index'], off) for sec, off, _ in pointer_hits(self.image, {0x400020})]
        self.assertIn((0, 0x351), hits)
        self.assertTrue(all(off >= 0 for _, off in hits))
        self.assertEqual(list(pointer_hits(self.image, set())), [])

    def test_manifest_checks_content_and_metadata(self):
        import hashlib
        s = self.image.sections[0]
        item = {'index': 0, 'name': s['name'], 'raw_offset': s['raw'], 'raw_size': s['size'],
                'virtual_address': s['rva'], 'virtual_size': s['virtual_size'], 'characteristics': s['flags'],
                'sha256': hashlib.sha256(s['data']).hexdigest()}
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'manifest.json'
            path.write_text(json.dumps({'source_size': len(self.image.raw), 'sections':[item]}))
            self.assertEqual(validate_manifest(self.image, path), 1)
            item['sha256'] = '0'*64
            path.write_text(json.dumps({'source_size': len(self.image.raw), 'sections':[item]}))
            with self.assertRaises(ValueError): validate_manifest(self.image, path)

if __name__ == '__main__': unittest.main()
