#!/usr/bin/env python3
"""Build optional Wine-derived demangler locally; downloads only via Python."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / 'tooling/python/undname-0.2-local'
SHA = 'f0d6604203db796a6372fe58ea5988800c055e94484b9e409dd487f61209eb04'
URL = 'https://pypi.org/pypi/undname/0.2/json'
SHIM = r'''#include <stdlib.h>
void error_message(int severity, const char *message) {(void)severity;(void)message;}
char *__unDName(char *, const char *, int, void *(*)(size_t), void (*)(void *), unsigned short);
char *undname_compat(const char *name) { return __unDName(NULL,name,0,malloc,free,0); }
'''

def main():
    with urllib.request.urlopen(URL, timeout=30) as response:
        meta = json.load(response)
    entries = [x for x in meta['urls'] if x['filename'] == 'undname-0.2.tar.gz']
    if len(entries) != 1 or entries[0]['digests']['sha256'] != SHA:
        raise SystemExit('Unexpected PyPI release digest')
    with urllib.request.urlopen(entries[0]['url'], timeout=60) as response:
        archive = response.read()
    if hashlib.sha256(archive).hexdigest() != SHA:
        raise SystemExit('Archive digest mismatch')
    DEST.mkdir(parents=True, exist_ok=True)
    # Extract only fixed paths, never the archive's arbitrary paths or symlinks.
    wanted = ['LICENSE', 'undname/src/undname.c', 'undname/src/msvcrt.h', 'undname/src/wine/debug.h']
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        for name in wanted:
            member = tar.getmember('undname-0.2/' + name)
            if not member.isfile():
                raise ValueError('Not a regular file: ' + name)
            target = DEST / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tar.extractfile(member).read())
    (DEST / 'shim.c').write_text(SHIM, encoding='utf-8')
    subprocess.run(['gcc', '-shared', '-fPIC', '-O2', '-o', str(DEST / 'libundname.so'),
                    str(DEST / 'shim.c'), str(DEST / 'undname/src/undname.c')], check=True)
    print('Built', DEST / 'libundname.so', '(Wine-derived source: LGPL-2.1-or-later; LICENSE retained)')

if __name__ == '__main__':
    main()
