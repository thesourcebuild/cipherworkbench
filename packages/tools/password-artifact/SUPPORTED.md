# Password artifact extractor support

All John descriptor layouts and fixture expectations are pinned to Openwall John jumbo commit
`5184bc0b8c105f8c5978b112e723d65b2de3e63e`. The extractors use `ToolFileSource` bounded reads,
do not execute external programs, and replace `:` in untrusted names while rejecting NUL and line
breaks.

## Registered extractors

- `ssh2john`: encrypted RSA, DSA, and EC legacy PEM using the upstream CBC cipher table, plus
  `openssh-key-v1` with bcrypt-PBKDF and AES-256-CBC/CTR. PKCS#8, unencrypted keys, other OpenSSH
  ciphers/KDFs, and multi-key OpenSSH blobs are rejected.
- `truecrypt2john`: password-only primary, hidden, and system-encryption boot headers. VeraCrypt
  formats and keyfiles are not accepted; keyfiles require additional file inputs that the tool
  contract does not expose.
- `luks2john`: LUKS1 with AES, `cbc-essiv:sha256`, SHA-1, and an active password keyslot. LUKS2 and
  other LUKS1 cipher/hash profiles are rejected because the pinned upstream descriptor does not
  support them.
- `dmg2john`: encrypted DMG v1 and v2 file images, including `.sparseimage` files. Sparsebundle and
  backupbundle directories are not accepted because a `ToolFileSource` represents one file and
  cannot safely resolve the bundle's token and band files.
- `bitlocker2john`: BitLocker and BitLocker To Go password or recovery-password VMKs at an explicit
  partition offset. TPM, startup-key, clear-key, and TPM+PIN protectors have no password descriptor
  for this extractor and are ignored.
- `kdbx2john`: KDBX 3.0/3.1 and 4.0/4.1 with AES, Twofish, or ChaCha20 and the AES, Argon2d, or
  Argon2id KDFs. KeePass 1 databases, pre-release signatures, plugins, and external keyfiles are
  rejected; keyfiles require a second independently selected file.
- `zip2john`: single-part ZIP and ZIP64 central directories; traditional ZipCrypto for extraction
  versions 1.0, 2.0, and 4.5 with Store or Deflate; WinZip AES AE-1/AE-2 strengths 1-3. SFX,
  split archives, legacy code-page names, and PKWARE strong encryption are rejected.
- `office2john`: OLE/CFB versions 3 and 4; Excel BIFF standard RC4 and RC4 CryptoAPI; Word
  standard RC4 and 40/56/128-bit RC4 CryptoAPI; OOXML standard AES (Office 2007) and agile AES
  with SHA-1/SHA-512 (Office 2010/2013). XOR obfuscation, external providers, legacy PowerPoint,
  ambiguous streams, and files whose canonical line would require summary-property extraction are
  rejected.
- `pdf2john`: PDF Standard security handler revisions 2-6 and algorithms `/V` 1-5, with direct or
  uncompressed indirect encryption dictionaries and classic trailer `/ID`. Public-key handlers,
  duplicate encryption keys, object-stream-only dictionaries, and xref-stream-only trailers are
  rejected.
- `rar2john`: RAR3 `-hp` encrypted headers and non-solid RAR3 `-p` file entries using encryption
  version 2.9 or newer; RAR5 encrypted-header and per-file password-check records. Pre-1.50,
  SFX, multipart, unsupported Unicode-name encoding, and password-check-free RAR5 records are
  rejected.
- `7z2john`: 7z major version 0, one folder and one packed stream, AES encrypted headers or data,
  with Copy or one John-supported LZMA1/LZMA2/BZip2/Deflate/BCJ-family coder. Split/SFX archives,
  external folder metadata, multiple packed streams, and unsupported coder chains are rejected.
- `gpg2john`: binary or ASCII-armored OpenPGP v2-v4 primary RSA, ElGamal, and DSA secret-key
  packets protected by simple, salted, or iterated-and-salted S2K, plus v4 SKESK material in tag 9
  or tag 18 packets. GNU extension S2K, unsupported public-key/cipher algorithms, compressed packet
  traversal, and encrypted subkey-only input are rejected.

Inline encrypted material is capped per extractor. Oversized records are rejected rather than
emitting host-file pointer descriptors that cannot be reopened by a browser.
