"""Check x86 dump interpretation without treating stack words as call frames."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build'))
from read_browser_dump import Dump

class BrowserDumpTests(unittest.TestCase):
    def dump(self,thread_stack_size=64):
        data=bytearray(1024);data[:4]=b'MDMP'
        struct.pack_into('<II',data,8,1,32)
        struct.pack_into('<III',data,32,3,52,64)
        struct.pack_into('<I',data,64,1)
        struct.pack_into('<I',data,68,123)
        struct.pack_into('<QII',data,92,0x1000,thread_stack_size,512)
        struct.pack_into('<II',data,108,204,128)
        struct.pack_into('<I',data,128+180,0x1010)
        struct.pack_into('<I',data,128+184,0x2000)
        struct.pack_into('<I',data,128+196,0x1000)
        struct.pack_into('<II',data,528,0,0x2345)
        return data

    def read(self,data):
        with tempfile.TemporaryDirectory(dir=ROOT/'.work') as name:
            path=Path(name)/'test.dmp';path.write_bytes(data);dump=Dump(path)
            try:return dump.report()
            finally:dump.data.close();dump.file.close()

    def test_normal_snapshot_retains_thread_context_without_inventing_exception(self):
        report=self.read(self.dump())
        self.assertNotIn('exception',report)
        thread=report['threads'][0]
        self.assertEqual(thread['tid'],123)
        self.assertEqual(thread['registers']['eip'],0x2000)
        self.assertEqual(thread['frame_pointer_chain'][0]['return']['address'],'0x2345')
        self.assertIsNone(thread['frame_pointer_chain'][0]['return']['module'])
        self.assertEqual(thread['unverified_stack_candidates'],[])

    def test_out_of_file_stack_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'thread stack bounds'):
            self.read(self.dump(4096))

    def test_truncated_context_is_rejected(self):
        data=self.dump();struct.pack_into('<II',data,108,204,1000)
        with self.assertRaisesRegex(ValueError,'x86 context unavailable'):
            self.read(data)

if __name__=='__main__':unittest.main()
