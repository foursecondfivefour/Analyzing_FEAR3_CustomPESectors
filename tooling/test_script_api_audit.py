#!/usr/bin/env python3
"""Regression and negative-evidence checks for the static API audit."""
from pathlib import Path
import contextlib
import csv
import io
import json
import tempfile
import unittest

import audit_script_api as audit
import compare_script_api as prior

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'analysis/script-api-audit'


def read(name):
    with (OUT/name).open(encoding='utf-8',newline='') as f:return list(csv.DictReader(f))


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with contextlib.redirect_stdout(io.StringIO()):audit.main()

    def test_all_sections_and_reference_headings(self):
        sections=read('all-section-coverage.csv'); docs=read('reference-index-check.csv')
        self.assertEqual(len(sections),35)
        self.assertEqual([int(x['pe_index']) for x in sections],list(range(35)))
        self.assertEqual(len(docs),330)
        self.assertTrue(all(x['multiset_equal']=='true' for x in docs))
        self.assertEqual(sum(int(x['reference_headings']) for x in docs),3879)

    def test_api_classifications_are_partition(self):
        rows=read('all-api-evidence.csv');self.assertEqual(len(rows),3879)
        self.assertEqual(len({x['api_path'] for x in rows}),3879)
        self.assertTrue(all(x['highest_observed_evidence_not_runtime_proof'] in {'proxy-cfg-candidate','game-cfg-registration','exact-leaf-string-only','no-exact-nul-leaf'} for x in rows))
        row=next(x for x in rows if x['api_path']=='GameScript.FEAR.GameDebugDump')
        self.assertEqual(row['highest_observed_evidence_not_runtime_proof'],'no-exact-nul-leaf')

    def test_cfg_and_game_coverage(self):
        groups=read('cfg-anchor-summary.csv');rows=read('proxy-cfg-candidates.csv');game=read('gamescript-game-all-methods.csv')
        self.assertEqual(len(groups),5)
        self.assertTrue(all(x['sites_reached']==x['matching_sites'] and x['decode_errors']=='0' for x in groups))
        self.assertEqual(len(rows),209);self.assertTrue(all(x['cfg_reachable_sequence']=='true' for x in rows))
        self.assertEqual(len(game),161);self.assertEqual(len(set(x['api_path_name_correspondence_not_runtime_proof'] for x in game)),161)
        self.assertEqual(sum(x['arity_numbers_equal_not_abi_proof']=='false' for x in game),6)
        show=next(x for x in game if x['api_path_name_correspondence_not_runtime_proof']=='GameScript.Game.ShowMovie')
        self.assertEqual((show['proxy_arity_suffix'],show['stub_parameter_count'],show['target_va_only_if_immediate_eax']),('2','3','0x43E8A0'))

    def test_bad_exe_and_zip_fail_closed(self):
        orig_exe,orig_zip=prior.EXE,prior.ZIP
        try:
            with tempfile.TemporaryDirectory() as d:
                bad=Path(d)/'bad.bin';bad.write_bytes(b'not evidence')
                prior.EXE=bad
                with self.assertRaisesRegex(SystemExit,'EXE SHA-256 mismatch'):prior.main()
                prior.EXE=orig_exe;prior.ZIP=bad
                with self.assertRaisesRegex(SystemExit,'ZIP SHA-256 mismatch'):prior.main()
        finally:
            prior.EXE,prior.ZIP=orig_exe,orig_zip

    def test_manual_showmovie_witness(self):
        import pefile
        import struct
        pe=pefile.PE(str(prior.EXE));base=pe.OPTIONAL_HEADER.ImageBase
        def data(va,n):return pe.get_data(va-base,n)
        self.assertEqual(pe.get_string_at_rva(0x1878b4c-base),b'ShowMovie')
        self.assertEqual(data(0x127f4d6,5),b'\xb8\xa0\xe8\x43\x00')
        self.assertEqual(data(0x127f4dc,5),b'\x68\x4c\x8b\x87\x01')
        self.assertEqual(data(0x43e8a8,2),b'\x6a\x00')
        self.assertEqual(data(0x43e8b1,3),b'\xc2\x08\x00')
        col,=struct.unpack('<I',data(0x146b488-4,4))
        td=struct.unpack('<IIIII',data(col,20))[3]
        name=pe.get_string_at_rva(td-base+8)
        self.assertIn(b'ClassMethodProxy_void_const2@XVGameScriptGame@Despair@@',name)

    def test_expected_statistics(self):
        s=json.loads((OUT/'stats.json').read_text(encoding='utf-8'))
        self.assertEqual((s['game_api_names'],s['game_registration_matches'],s['game_proxy_vs_stub_arity_equal'],s['game_proxy_vs_stub_arity_different']),(161,161,155,6))
        self.assertFalse(s['game_missing_api_names'])


if __name__=='__main__':unittest.main()
