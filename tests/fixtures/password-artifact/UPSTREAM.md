# John extractor fixtures

The deterministic binary builders in `tests/password-artifact-extractors.test.ts` encode the same
fields used by these upstream extractors at Openwall John jumbo commit
`5184bc0b8c105f8c5978b112e723d65b2de3e63e`:

- `run/ssh2john.py`
- `run/truecrypt2john.py`
- `run/luks2john.py`
- `src/dmg2john.c` and `src/filevault.h`
- `run/bitlocker2john.py`
- `src/keepass2john.c`
- `src/zip2john.c`
- `run/office2john.py`
- `run/pdf2john.py`
- `src/rar2john.c` and `src/rar2john.h`
- `run/7z2john.pl`
- `src/gpg2john.c`

Expected strings retain upstream field order, decimal rendering, lowercase hex, Base64, trailing
newline, and source-name placement. The fixtures cover encrypted legacy/OpenSSH keys, TrueCrypt
primary/hidden/boot headers, LUKS1, DMG v1/v2, BitLocker password/recovery VMKs, and KDBX
3.0/3.1/4.0/4.1.

The additional deterministic fixtures cover traditional ZIP and WinZip AES in ZIP/ZIP64, legacy
Excel and agile Office 2013 CFB streams, PDF Standard handler revisions 2 and 6, RAR3 and RAR5
encrypted headers, 7z AES encrypted-header folders with Copy and LZMA1 coder metadata, and binary
plus armored OpenPGP encrypted secret keys. Their expected lines were transcribed from the format
statements and print paths in the files above at the pinned commit; malformed variants mutate the
same fields to exercise truncation, invalid versions, checksums, and offset overflow.
