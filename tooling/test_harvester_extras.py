#!/usr/bin/env python3
"""Additional byte-analysis tests using synthetic buffers and checked-in metadata."""
import contextlib
import io
import random
import struct
import unittest

import forensic_harvester as h
import harvester_extras as x


class ExtraByteTests(unittest.TestCase):
    def test_patterns_randomized_against_brute_force(self):
        rng = random.Random(6174)
        for _ in range(300):
            data = bytes(rng.randrange(4) for _ in range(rng.randrange(0, 50)))
            pattern = [None if rng.randrange(3) == 0 else rng.randrange(4) for _ in range(rng.randrange(1, 12))]
            expected = [i for i in range(max(0, len(data) - len(pattern) + 1))
                        if all(p is None or data[i+j] == p for j, p in enumerate(pattern))]
            self.assertEqual(list(x.pattern_offsets(data, pattern)), expected)
        self.assertEqual(list(x.pattern_offsets(b'AAAA', x.masked_pattern('41 ??'))), [0, 1, 2])
        for bad in ('', '123', 'GG', 'A?', '0x11'):
            with self.assertRaises(ValueError): x.masked_pattern(bad)

    def test_strings_terminators_odd_offsets_and_long_runs(self):
        data = b'\xff' + 'Hello'.encode('utf-16le') + b'\0\0\xff'
        hit = list(x.string_hits(data, 'utf-16le', 4, 'ELLO', True))
        self.assertEqual(len(hit), 1)
        self.assertEqual((hit[0]['offset'], hit[0]['text_preview'], hit[0]['nul_terminated']), (1, 'Hello', True))
        data = b'\xff' + 'Hello'.encode('utf-16be') + b'\0\0\xff'
        hit = list(x.string_hits(data, 'utf-16be', 4, None, True))
        self.assertEqual((hit[0]['offset'], hit[0]['text_preview']), (1, 'Hello'))
        hits = list(x.string_hits(b'\0ABC\0NoTerm!', 'ascii', 3))
        self.assertEqual([a['text_preview'] for a in hits], ['ABC', 'NoTerm!'])
        self.assertTrue(hits[0]['nul_terminated'])
        self.assertFalse(hits[1]['nul_terminated'])
        self.assertTrue(hits[1]['reaches_section_end'])
        long = list(x.string_hits(b'A'*600, 'ascii', 4))[0]
        self.assertEqual((long['characters'], len(long['text_preview']), long['preview_truncated']), (600, 512, True))

    def test_statistics(self):
        self.assertEqual(x.statistics(b'\0\0AA')['entropy_bits_per_byte'], 1.0)
        self.assertEqual(x.statistics(b'\0\0AA')['longest_zero_run'], 2)
        self.assertEqual(x.statistics(b'')['entropy_bits_per_byte'], 0.0)
        self.assertEqual(x.statistics(b'\0\0AA')['printable_ascii_bytes'], 2)

    def test_words_and_compare(self):
        inv = {'image_base': 0x400000, 'sections': [{'index':0, 'name':'.data', 'raw_offset':0,
            'raw_size':16, 'virtual_address':0x1000, 'virtual_size':16, 'characteristics':0x40000040}]}
        raw = struct.pack('<IIII', 0x401004, 0xffffffff, 0x401004, 42)
        out = h.words(raw, inv, 'va', 0x401000, 4, 2)
        self.assertEqual(out['values'][1]['signed'], -1)
        self.assertEqual(out['values'][0]['preferred_va_section_matches_if_pointer'][0]['section_offset'], '0x4')
        comp = h.compare_bytes(raw, inv, 0x401000, 0x401008, 8, 1)
        self.assertFalse(comp['identical'])
        self.assertTrue(comp['differences']['truncated'])
        self.assertEqual(comp['differences']['total'], 4)
        with self.assertRaises(ValueError): h.compare_bytes(raw, inv, 0x40100f, 0x401000, 4, 10)

    def test_ff_indirect_patterns_at_valid_and_incomplete_sites(self):
        target = 0x401234
        inv = {'image_base': 0x400000, 'sections': [{'index':0,'name':'.data','raw_offset':0,
            'raw_size':16,'virtual_address':0x1000,'virtual_size':16,'characteristics':0x40000040}]}
        raw = b'\xff\x15'+struct.pack('<I',target)+b'\xff\x25'+struct.pack('<I',target)+b'\xff\x15\x34\x12'
        grouped = h.group_refs(h.raw_refs(raw, inv, target), 10)
        self.assertEqual(grouped['absolute_u32_le']['total'], 2)
        self.assertEqual(grouped['raw_ff15_indirect_call_candidate']['total'], 1)
        self.assertEqual(grouped['raw_ff25_indirect_jump_candidate']['total'], 1)
        self.assertEqual(grouped['raw_ff15_indirect_call_candidate']['items'][0]['preferred_va'], '0x401000')

    def test_missing_capstone_is_actionable(self):
        import builtins
        from unittest.mock import patch
        original = builtins.__import__
        def no_capstone(name, *args, **kwargs):
            if name == 'capstone' or name.startswith('capstone.'):
                raise ImportError('simulated missing optional dependency')
            return original(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=no_capstone):
            with self.assertRaisesRegex(ValueError, 'Capstone unavailable'):
                h.disassemble(b'\x90', {'machine': 0x14c}, 'va', 0, 1, 1)

    def test_optional_capstone(self):
        try:
            import sys
            sys.path.insert(0, str(h.ROOT/'tooling/python'))
            import capstone  # noqa: F401
        except ImportError:
            self.skipTest('optional Capstone not installed')
        inv = {'machine': 0x14c, 'image_base': 0x400000, 'sections': [{'index':0,'name':'.text','raw_offset':0,
            'raw_size':2,'virtual_address':0x1000,'virtual_size':2,'characteristics':0x60000020}]}
        result = h.disassemble(b'\x90\xc3', inv, 'va', 0x401000, 2, 2)
        self.assertEqual([i['mnemonic'] for i in result['instructions']], ['nop', 'ret'])
        self.assertEqual(result['bytes_decoded'], 2)
        self.assertEqual(result['instructions'][1]['preferred_va'], '0x401001')


class ExtraIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = h.context(h.ROOT)
        cls.raw, cls.scoped, _ = h.byte_source(h.ROOT, cls.inv, None, True)

    def test_vtable_extracted_uses_full_inventory_for_pointer_mapping(self):
        v = h.vtable_view(h.ROOT, self.raw, self.scoped, self.inv, 0x1870E7C, 2, 10)
        self.assertEqual(v['known_vtable_candidates']['total'], 1)
        self.assertEqual(v['preceding_u32']['value'], '0x153B0D0')
        self.assertEqual(v['values'][0]['hex'], '0x6C2D50')
        self.assertEqual(v['values'][0]['preferred_va_section_matches_if_pointer'][0]['section'], '.text')

    def test_address_lookup_and_radius(self):
        out = h.address_evidence(h.ROOT, self.inv, 'va', 0x169B418, 2, 8)
        self.assertEqual(out['evidence']['classes']['total'], 1)
        fields = out['evidence']['classes']['items'][0]['matched_fields']
        self.assertEqual([(m['field'], m['delta_from_query']) for m in fields], [('type_descriptor_va', 0), ('name_va', 8)])
        self.assertEqual(out['evidence']['vtables']['total'], 2)
        iat = h.address_evidence(h.ROOT, self.inv, 'va', 0x13F0254, 2)
        self.assertEqual(iat['evidence']['imports_iat_slots']['items'][0]['name'], 'GetProcAddress')

    def test_stats_strings_and_imports(self):
        stat = h.section_statistics(self.raw, self.scoped, 'Game_dat')[0]
        self.assertTrue(stat['matches_inventory_sha256'])
        self.assertEqual(stat['raw_bytes'], 743936)
        st = h.scan_strings(self.raw, self.scoped, ('ascii',), 4, 'GameScriptPlayer', True, 'Game_dat', 10)
        self.assertEqual(st['ascii']['total'], 2)
        i = h.imports_view(self.inv, 'MSVCP90', 'locale', 5)
        self.assertEqual(len(i['modules']), 1)
        self.assertGreater(i['symbols']['total'], 0)
        self.assertTrue(all(s['dll'].upper() == 'MSVCP90.DLL' for s in i['symbols']['items']))

    def test_exports_and_trace_string(self):
        e = h.cpp_exports(h.ROOT, 'GThread', 2)
        self.assertEqual(e['symbols']['total'], 20)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = h.main(['trace-string', '--text', 'ShowMovie', '--nul', '--extracted',
                           '--string-section', 'Game_dat', '--limit', '2'])
        import json
        result = json.loads(out.getvalue())['result']
        self.assertEqual(code, 0)
        self.assertEqual(result['occurrences']['total'], 1)
        self.assertEqual(result['occurrences']['items'][0]['preferred_va'], '0x1878B4C')
        self.assertEqual(result['coverage']['string_section_indices'], [9])
        self.assertEqual(len(result['coverage']['reference_section_indices']), 31)
        self.assertEqual(result['traces'][0]['groups']['absolute_u32_le']['total'], 0)

    def test_cli_pattern_rejects_all_wildcard_and_coverage(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = h.main(['pattern', '?? ??', '--extracted'])
        self.assertEqual(code, 1)
        self.assertIn('At least one literal', err.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = h.main(['pattern', '50 2d 6c 00', '--section', 'Game_dat', '--extracted', '--limit', '1'])
        import json
        result = json.loads(out.getvalue())['result']
        self.assertEqual(code, 0)
        self.assertEqual(result['coverage']['section_indices'], [9])
        self.assertGreaterEqual(result['hits']['total'], 1)

if __name__ == '__main__': unittest.main()
