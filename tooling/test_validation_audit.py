#!/usr/bin/env python3
"""Regression checks for the standalone PE candidate audit."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tooling/python'))
try:
    import capstone
    import pefile
    import validate_rtti_candidates as v
except ImportError:
    capstone=None
    v=None


@unittest.skipUnless(capstone is not None,'optional pefile and capstone dependencies missing')
class CandidateAuditTests(unittest.TestCase):
    def setUp(self):
        self.md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
        self.md.detail=True

    def test_cfg_branch_and_unreachable_and_missing_anchor(self):
        # entry after padding: jmp to nop, then ret; independent unreachable byte.
        d=b'\xcc'*4+b'\xeb\x01\x90\x90\xc3'+b'\xcc'*4
        self.assertEqual(v.cfg_check(d,0x1000,7,8,self.md)['status'],'reachable')
        self.assertEqual(v.cfg_check(d,0x1000,6,7,self.md)['status'],'not_reached')
        self.assertEqual(v.cfg_check(b'\x90'*32,0x1000,4,5,self.md)['status'],'no_anchor')

    def test_rejects_unverified_exe_before_writing(self):
        with tempfile.TemporaryDirectory() as d:
            fake=Path(d)/'fake.exe';fake.write_bytes(b'MZ but not the verified image')
            out=Path(d)/'out'
            r=subprocess.run([sys.executable,str(ROOT/'tooling/validate_rtti_candidates.py'),
                              '--exe',str(fake),'--out',str(out)],capture_output=True,text=True)
            self.assertNotEqual(r.returncode,0)
            self.assertIn('EXE SHA-256 mismatch',r.stderr)
            self.assertFalse(out.exists())

    @unittest.skipUnless(v is not None and v.EXE.is_file(),'local full EXE or dependencies absent')
    def test_regenerated_evidence_and_candidate_partition(self):
        with tempfile.TemporaryDirectory() as d:
            r=subprocess.run([sys.executable,str(ROOT/'tooling/validate_rtti_candidates.py'),
                              '--out',d],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            report=json.loads((Path(d)/'rtti-validation-summary.json').read_text())
            checked=json.loads((ROOT/'analysis/harvester-validation/rtti-validation-summary.json').read_text())
            self.assertEqual(report,checked)
            self.assertEqual((report['type_descriptors_checked'],report['col_records_checked'],
                              report['base_rows_checked'],report['vtable_candidates_checked'],
                              report['vtable_rejected_checked']),(11951,15473,38310,15473,1))
            self.assertEqual(report['no_col_types'],2295)
            self.assertEqual(sum(report['evidence_tiers'].values()),2295)
            self.assertEqual(report['bad_cast_witness']['cfg_status'],'reachable')
            self.assertEqual((Path(d)/'no-col-evidence.csv').read_bytes(),
                             (ROOT/'analysis/harvester-validation/no-col-evidence.csv').read_bytes())
            with (Path(d)/'no-col-evidence.csv').open(encoding='utf8',newline='') as f: rows=list(csv.DictReader(f))
            self.assertEqual(len({r['type_descriptor_va'] for r in rows}),2295)
            self.assertTrue(all(int(r['raw_u32_references_all_sections'])>0 for r in rows))
            bad=next(r for r in rows if r['type_descriptor_va']=='0x164167C')
            self.assertEqual(bad['static_evidence_tier'],'exception_metadata_and_throw_sequence')


if __name__=='__main__':unittest.main()
