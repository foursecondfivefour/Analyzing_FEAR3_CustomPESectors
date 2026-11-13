#!/usr/bin/env python3
"""Fetch an exact, checksum-pinned source snapshot without executing it."""
import hashlib
import io
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
from urllib.request import Request, urlopen
import zipfile

ROOT=Path(__file__).resolve().parent.parent
REV='4a7a7cf3d48f09dca446441d8af427f30556280d'
EXPECTED='1f3aa0fb555a8e2bbb05b04b6464aa49951416baaed568e5963440b6ea2b80e6'
TARGET=ROOT/'external/lua-api'
PREFIX='FEAR3-DespairEngineLuaAPI-'+REV

def main():
    if TARGET.exists(): raise SystemExit(f'{TARGET} already exists; refusing to overwrite')
    url='https://codeload.github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/zip/'+REV
    with urlopen(Request(url,headers={'User-Agent':'Resource-forensics'}),timeout=60) as f:
        archive=f.read(30_000_001)
    if len(archive)>30_000_000 or hashlib.sha256(archive).hexdigest()!=EXPECTED:
        raise SystemExit('Archive size or SHA-256 mismatch')
    TARGET.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.lua-api-',dir=TARGET.parent) as temp:
        root=Path(temp); snapshot=root/'snapshot'; snapshot.mkdir(); seen=set()
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            infos=z.infolist()
            if len(infos)>1500 or sum(i.file_size for i in infos)>30_000_000: raise ValueError('archive limits')
            for i in infos:
                path=PurePosixPath(i.filename)
                if (not path.parts or path.parts[0]!=PREFIX or path.is_absolute() or
                    any(part in ('.','..') for part in path.parts) or '\\' in i.filename or
                    stat.S_ISLNK(i.external_attr>>16) or i.flag_bits & 1): raise ValueError(i.filename)
                parts=path.parts[1:]
                if not parts: continue
                dst=snapshot.joinpath(*parts)
                if dst in seen: raise ValueError('duplicate archive path')
                seen.add(dst)
                if i.is_dir(): dst.mkdir(parents=True,exist_ok=True);continue
                dst.parent.mkdir(parents=True,exist_ok=True)
                with z.open(i) as inp,dst.open('xb') as out: shutil.copyfileobj(inp,out)
        (root/'source.zip').write_bytes(archive)
        # Temporary directory is on the same filesystem. Never replace an existing destination.
        root.rename(TARGET)
    print('Downloaded pinned source snapshot:',TARGET)

if __name__=='__main__': main()
