#!/usr/bin/env python3
"""Tests for the read-only forensic workbench; no game EXE or third-party modules required."""
import contextlib
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

import forensic_harvester as h


class SyntheticTests(unittest.TestCase):
    def setUp(self):
        self.inv = {'image_base': 0x400000, 'size': 0x40, 'sections': [
            {'index': 0, 'name': ' .one', 'raw_offset': 0x10, 'raw_size': 16, 'virtual_address': 0x1000, 'virtual_size': 12, 'characteristics': 0x60000020},
            {'index': 1, 'name': '.two', 'raw_offset': 0x30, 'raw_size': 8, 'virtual_address': 0x2000, 'virtual_size': 12, 'characteristics': 0x40000040},
        ]}
        self.raw = bytearray(0x40)
        self.raw[0x10:0x14] = b'AAAA'
        struct.pack_into('<I', self.raw, 0x14, 0x401234)
        self.raw[0x18] = 0xe8
        struct.pack_into('<i', self.raw, 0x19, 0x401234 - (0x401008 + 5))
        self.raw[0x1f] = 0xe9  # incomplete instruction at end of section
        self.raw[0x30:0x33] = b'ABA'
        self.inv['sha256'] = hashlib.sha256(self.raw).hexdigest()

    def test_map_raw_padding_virtual_tail_and_unmapped(self):
        m = h.map_address(self.inv, 'va', 0x401004)[0]
        self.assertEqual((m['file_offset'], m['rva'], m['region']), ('0x14', '0x1004', 'raw_backed'))
        self.assertEqual(h.map_address(self.inv, 'file', 0x1f)[0]['region'], 'raw_padding_beyond_virtual_size')
        tail = h.map_address(self.inv, 'rva', 0x200a)[0]
        self.assertEqual((tail['file_offset'], tail['region']), (None, 'virtual_tail_no_file_bytes'))
        self.assertEqual(h.map_address(self.inv, 'va', 0x400001), [])
        self.assertEqual(h.map_address(self.inv, 'file', 0x20), [])
        self.assertEqual(h.map_address(self.inv, 'rva', 0x200c), [])  # end exclusive

    def test_mapping_ambiguous_returns_all(self):
        duplicate = dict(self.inv['sections'][0], index=2)
        self.inv['sections'].append(duplicate)
        self.assertEqual(len(h.map_address(self.inv, 'va', 0x401000)), 2)
        with self.assertRaises(ValueError): h.read_bytes(self.raw, self.inv, 'va', 0x401000, 2)

    def test_dump_rejects_crossing_and_virtual(self):
        r = h.read_bytes(self.raw, self.inv, 'va', 0x401000, 4)
        self.assertEqual((r['hex'], r['ascii_preview']), ('41 41 41 41', 'AAAA'))
        with self.assertRaises(ValueError): h.read_bytes(self.raw, self.inv, 'file', 0x1f, 2)
        with self.assertRaises(ValueError): h.read_bytes(self.raw, self.inv, 'rva', 0x200a, 1)

    def test_overlapping_search_and_section_selection(self):
        hits = list(h.find_bytes(self.raw, self.inv, b'AA'))
        self.assertEqual([x['file_offset'] for x in hits], ['0x10', '0x11', '0x12'])
        self.assertEqual(len(list(h.find_bytes(self.raw, self.inv, b'AA', '.one'))), 3)
        self.assertEqual(len(list(h.find_bytes(self.raw, self.inv, b'AA', '1'))), 0)
        with self.assertRaises(ValueError): list(h.find_bytes(self.raw, self.inv, b'A', 'unknown'))
        with self.assertRaises(ValueError): list(h.find_bytes(self.raw, self.inv, b''))
        result = h.limited(iter(range(10)), 2)
        self.assertEqual((result['total'], result['returned'], result['truncated']), (10, 2, True))

    def test_refs_u32_rel32_and_limit_per_kind(self):
        hits = list(h.raw_refs(self.raw, self.inv, 0x401234))
        self.assertEqual([(x['kind'], x['file_offset']) for x in hits],
                         [('absolute_u32_le', '0x14'), ('raw_e8_rel32_candidate', '0x18')])
        grouped = h.group_refs(hits + hits, 1)
        for key in ('absolute_u32_le', 'raw_e8_rel32_candidate'):
            self.assertEqual((grouped[key]['total'], grouped[key]['returned'], grouped[key]['truncated']), (2, 1, True))
        self.assertEqual(grouped['raw_e9_rel32_candidate']['total'], 0)
        with self.assertRaises(ValueError): list(h.raw_refs(self.raw, self.inv, 0x100000000))

    def test_negative_rel32(self):
        target = 0x400ff0
        self.raw[0x31] = 0xe9
        struct.pack_into('<i', self.raw, 0x32, target - (0x402001 + 5))
        hits = list(h.raw_refs(self.raw, self.inv, target))
        self.assertEqual([(x['kind'], x['file_offset']) for x in hits], [('raw_e9_rel32_candidate', '0x31')])

    def test_verify_exe_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'sample.bin'
            path.write_bytes(self.raw)
            self.assertEqual(h.verify_exe(Path(d), self.inv, path), self.raw)
            tampered = bytearray(self.raw)
            tampered[-1] ^= 1
            path.write_bytes(tampered)
            with self.assertRaisesRegex(ValueError, 'mismatch'): h.verify_exe(Path(d), self.inv, path)
            path.write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError, 'mismatch'): h.verify_exe(Path(d), self.inv, path)
            path.unlink()
            with self.assertRaisesRegex(ValueError, 'not found'): h.verify_exe(Path(d), self.inv, path)

    def test_extracted_backing(self):
        extracted = {s['index']: bytes(self.raw[s['raw_offset']:s['raw_offset'] + s['raw_size']]) for s in self.inv['sections']}
        self.assertEqual(list(h.find_bytes(extracted, self.inv, b'AA')), list(h.find_bytes(self.raw, self.inv, b'AA')))
        self.assertEqual(list(h.raw_refs(extracted, self.inv, 0x401234)), list(h.raw_refs(self.raw, self.inv, 0x401234)))
        self.assertEqual(h.read_bytes(extracted, self.inv, 'file', 0x10, 4)['hex'], '41 41 41 41')

    def test_manifest_unsafe_and_tampered(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); folder = root/'evidence/fear3-engine-sections'; folder.mkdir(parents=True)
            sec = dict(self.inv['sections'][1], raw_name_hex='2e74776f00000000')
            sec['sha256'] = hashlib.sha256(self.raw[0x30:0x38]).hexdigest()
            inv = dict(self.inv, sections=[sec]); (folder/'part.bin').write_bytes(self.raw[0x30:0x38])
            item = dict(sec, file='part.bin')
            (folder/'manifest.json').write_text(json.dumps({'source_size':self.inv['size'],'sections':[item]}))
            for _, (path, cols) in (list(h.DATA.items()) + list(h.ADDRESS_TABLES.items()) +
                                     [(key, (path, (col,))) for key, (path, col) in h.REL.items()]):
                dest = root/path; dest.parent.mkdir(parents=True, exist_ok=True)
                if not dest.exists():
                    with dest.open('w', newline='') as f: csv.writer(f).writerow(cols)
                else:
                    # The same CSV can be required with two distinct columns.
                    with dest.open(newline='') as f: existing = next(csv.reader(f))
                    with dest.open('w', newline='') as f: csv.writer(f).writerow(list(dict.fromkeys(existing+list(cols))))
            self.assertTrue(h.status(root, inv)['ok'])
            (folder/'part.bin').write_bytes(b'bad')
            self.assertFalse(h.status(root, inv)['ok'])
            item['file'] = '../escape'
            (folder/'manifest.json').write_text(json.dumps({'source_size':self.inv['size'],'sections':[item]}))
            result = h.status(root, inv)
            self.assertFalse(result['ok'])
            self.assertIn('unsafe manifest filename', str(result['errors']))


class RepositoryIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = h.ROOT
        cls.inv = h.context(cls.root)

    def test_doctor_without_exe_does_not_need_it(self):
        # Force the missing-EXE case without changing the repository.
        with tempfile.TemporaryDirectory() as d:
            nonexistent = Path(d)/'missing.exe'
            result = h.status(self.root, self.inv, nonexistent, require_exe=True)
            self.assertFalse(result['ok'])
            self.assertIn('not found', str(result['errors']))
        result = h.status(self.root, self.inv)
        self.assertTrue(result['ok'])

    def test_class_profile(self):
        r = h.class_profile(self.root, 'Despair::GameScriptPlayer', 2)
        self.assertEqual(r['class']['type_descriptor_va'], '0x169B418')
        self.assertEqual((r['cols']['total'], r['vtables']['total'], r['bases']['total']), (2, 2, 5))
        self.assertTrue(r['bases']['truncated'])
        self.assertEqual(h.class_profile(self.root, '0x169b418', 1)['class']['display_name'], 'Despair::GameScriptPlayer')
        with self.assertRaises(ValueError): h.class_profile(self.root, 'GameScriptPlayer', 1)

    def test_api_and_search(self):
        r = h.api_profile(self.root, 'gamescript.game.showmovie', 5)
        self.assertEqual(r['api']['total'], 1)
        self.assertEqual(r['game_registration_candidates']['items'][0]['stub_parameter_count'], '3')
        self.assertEqual(r['game_registration_candidates']['items'][0]['proxy_arity_suffix'], '2')
        s = h.search(self.root, 'ShowMovie', ['api'], 1)['api']
        self.assertEqual(s['total'], 2)
        self.assertTrue(s['truncated'])
        with self.assertRaises(ValueError): h.api_profile(self.root, 'no.such.path', 1)

    def test_map_and_cli_json_no_exe_required(self):
        self.assertEqual(h.map_address(self.inv, 'va', 0x1870e7c)[0]['file_offset'], '0x13FB27C')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(h.main(['map', '--va', '0x1870E7C']), 0)
        self.assertEqual(json.loads(output.getvalue())['result']['matches'][0]['section'].strip(), 'Game_dat')

    def test_extracted_cli_scope_and_unavailable_section(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(h.main(['find', '--text', 'GameScriptPlayer', '--nul', '--extracted']), 0)
        r = json.loads(output.getvalue())['result']
        self.assertEqual(r['coverage']['section_count'], 31)
        self.assertFalse(r['coverage']['all_pe_sections'])
        self.assertEqual(r['hits']['total'], 1)
        self.assertEqual(r['hits']['items'][0]['preferred_va'], '0x187130C')
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(h.main(['find', '--text', 'abc', '--section', '.text', '--extracted']), 1)
        self.assertIn('Unknown section', err.getvalue())

    def test_triage_combines_indexes_and_explicit_raw_scope(self):
        r = h.triage(self.root, self.inv, 'Despair::GameScriptPlayer', 2, 'extracted', True, None)
        self.assertEqual(r['exact_class_profile']['class']['type_descriptor_va'], '0x169B418')
        self.assertEqual(r['byte_search']['coverage']['section_count'], 31)
        self.assertFalse(r['descriptor_references']['coverage']['all_pe_sections'])
        self.assertEqual(r['descriptor_references']['groups']['absolute_u32_le']['total'], 0)
        r = h.triage(self.root, self.inv, 'GameScript.Game.ShowMovie', 2, 'none', False, None)
        self.assertEqual(r['exact_api_profile']['game_registration_candidates']['total'], 1)
        with self.assertRaises(ValueError): h.triage(self.root, self.inv, 'GameScriptPlayer', 2, 'none', True, None)
        with self.assertRaises(ValueError): h.triage(self.root, self.inv, 'GameScriptPlayer', 2, 'extracted', True, None)

    def test_empty_search_error(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output): self.assertEqual(h.main(['search', '']), 1)
        self.assertIn('Empty search query', output.getvalue())


if __name__ == '__main__': unittest.main()
