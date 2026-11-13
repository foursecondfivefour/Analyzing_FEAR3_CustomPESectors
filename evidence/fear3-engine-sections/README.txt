F.E.A.R. 3 PE section extraction

Source: C:\Games\F.E.A.R. 3\F.E.A.R. 3.exe
Machine: x86 (PE machine 0x014C)

The numbered .bin files contain raw section bytes copied from each PE section's
PointerToRawData for SizeOfRawData bytes. They are not independent DLLs or
standalone motherboard-like components; they are data/code regions that the
Windows loader maps into the single executable's image.

manifest.json records the original 8-byte PE section name, RVA, virtual size,
raw file offset, raw size, characteristics, output filename, and SHA-256.
Names such as Game_dat and Animatio are truncated in the PE section table's
8-byte name field; raw_name_hex preserves the exact bytes.

The extractor excludes conventional .text/.rdata/.data/.rsrc sections. It does
include the small .version metadata section along with the engine-named sections.
Extraction is byte-for-byte and does not modify the executable.
