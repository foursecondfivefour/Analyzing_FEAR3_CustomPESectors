#!/usr/bin/env python3
"""Tests for evidence-labeled C++ function-candidate catalog and query."""
import contextlib
import io
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
    import inventory_cpp_functions as inv
except ImportError:
    inv=None
import query_cpp_functions as query


@unittest.skipUnless(inv is not None,'optional pefile and capstone missing')
class ScannerTests(unittest.TestCase):
    def test_raw_e8_overlapping_and_target_bounds(self):
        class Fake:
            sections=[{'flags':0x20000000,'va':0x1000,'bytes':b'\xe8\x00\x00\x00\x00\xc3\xe8\x00\x00\x00\x7f'}]
            def executable(self,a):return 0x1000<=a<0x100b
        self.assertEqual(list(inv.raw_calls(Fake())),[(0x1000,0x1005)])

    def test_cfg_call_and_iat_jump(self):
        class Fake:
            # call 1006; ret; jmp [2000]
            sec={'index':0,'flags':0x20000000,'va':0x1000,'size':12,'bytes':b'\xe8\x01\x00\x00\x00\xc3\xff\x25\x00\x20\x00\x00'}
            sections=[sec]
            def locate(self,a,size=1):
                off=a-0x1000
                return (self.sec,off) if 0<=off and off+size<=12 else None
            def executable(self,a):return self.locate(a) is not None
        edges,stats=inv.walk_cfg(Fake(),[0x1000],{0x2000:'test.dll!fn'})
        self.assertEqual([(x['site_va'],x['kind'],x['target_va']) for x in edges],
                         [('0x1000','direct_call','0x1006'),('0x1006','indirect_jump_iat','0x2000')])
        self.assertEqual(stats['decoded_instructions'],3)
        self.assertEqual(stats['indirect_jumps_not_followed_including_iat'],1)

    def test_category_multilabel_and_unknown(self):
        self.assertIn('script_api',inv.categories('GameScriptPlayer'))
        self.assertIn('gameplay_ai',inv.categories('GameScriptPlayer'))
        self.assertEqual(inv.categories('xyz'),[])

    def test_sha_mismatch_before_output(self):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'fake.exe';exe.write_bytes(b'MZ invalid')
            out=Path(d)/'out'
            proc=subprocess.run([sys.executable,str(ROOT/'tooling/inventory_cpp_functions.py'),'--exe',str(exe),'--out',str(out)],capture_output=True,text=True)
            self.assertNotEqual(proc.returncode,0);self.assertIn('EXE SHA-256 mismatch',proc.stderr)
            self.assertFalse(out.exists())

    @unittest.skipUnless((ROOT/'evidence/source-exe/F.E.A.R. 3.exe').is_file(),'local EXE absent')
    def test_full_independent_verifier(self):
        proc=subprocess.run([sys.executable,str(ROOT/'tooling/verify_cpp_functions.py')],capture_output=True,text=True)
        self.assertEqual(proc.returncode,0,proc.stderr)
        result=json.loads(proc.stdout)
        self.assertEqual((result['sections_checked'],result['vtable_first_slots_checked'],result['import_slots_checked']),(35,15473,930))
        self.assertEqual(result['candidate_addresses_checked'],107875)


class QueryTests(unittest.TestCase):
    def test_query_and_owners(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out):query.main(['--va','0x6c2d50','--owners'])
        result=json.loads(out.getvalue());self.assertEqual(result['total'],1)
        self.assertEqual(result['items'][0]['vtable_associations'][0]['type_descriptor_va'],'0x169B418')
        out=io.StringIO()
        with contextlib.redirect_stdout(out):query.main(['--query','showmovie','--limit','1'])
        result=json.loads(out.getvalue());self.assertEqual(result['total'],2);self.assertTrue(result['has_more'])
        out=io.StringIO()
        with contextlib.redirect_stdout(out):query.main(['--owner','Despair::GameScriptPlayer','--va','0x6c2d50'])
        self.assertEqual(json.loads(out.getvalue())['total'],1)

    def test_invalid_limit(self):
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):query.main(['--limit','-1'])

if __name__=='__main__':unittest.main()
