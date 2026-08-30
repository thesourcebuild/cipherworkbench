# Cipher Workbench

**Cipher Workbench** is a cross-platform cryptography suite designed to compute and verify hashes, CRCs, checksums, MACs, key derivations, ciphers, public key algorithms, and text encodings. Running entirely client-side in a web browser tab or as a native desktop app from a single monorepo codebase, it executes all cryptographic logic locally with zero network reliance or server dependencies. Built-in verification panels, diagnostic engine rules, and standard test vectors allow developers and security researchers to analyze and validate cryptographic operations with privacy and precision.

## What it does today

Cipher Workbench ships **400+ tools** organized across 11 families:

| Family | Tools | Algorithms & Capabilities |
|---|---|---|
| **Hashes** | 158 | MD2, MD4, MD5, SHA-1, SHA-2 (224/256/384/512, 512/224, 512/256), SHA-3 (224/256/384/512), Keccak, SHAKE128/256, cSHAKE, TupleHash, ParallelHash, TurboSHAKE, KangarooTwelve, RIPEMD (128/160/256/320), BLAKE, BLAKE2b/2s, BLAKE3, SM3, Streebog-256/512, Tiger/Tiger2, Skein (256/512/1024), Ascon-Hash/XOF, HAVAL (15 variants), Snefru-256, GOST R 34.11-94, Whirlpool, MD5-SHA1, FNV-1/1a (32/64/128/256/512-bit), Jenkins, MurmurHash3, XXH32/64/3/128, Groestl, JH, CubeHash, Luffa, Fugue, SHAvite-3, Shabal, BelT-Hash, Rapidhash, HighwayHash, SpookyHash, CityHash, FarmHash, t1ha, wyhash, Poseidon, Poseidon2, Rescue-Prime, Monolith, Neptune, Reinforced Concrete, Anemoi, Griffin, Haraka-256/512, MeowHash, KomiHash, N-Hash |
| **Ciphers** | 114 | AES (128/192/256) in GCM / GCM-SIV / CCM / OCB / XTS / CTR / CBC / OFB / CFB / SIV / Key Wrap (RFC 3394 & 5649) / ECB; ChaCha20-Poly1305, XChaCha20-Poly1305, raw ChaCha20/12/8; XSalsa20-Poly1305, Salsa20; Ascon-AEAD128, AEGIS-128L/256; Camellia, ARIA, SM4 (GCM/CCM/CBC/CFB/OFB/CTR/ECB); Magma and Kuznyechik (GOST R 34.12-2015); Twofish, Serpent, Blowfish, CAST5/6, SEED, IDEA, SAFER+, RC2/4/5/6, 3DES, DES; SHACAL-1/2, QARMA-64, MANTIS-7, CRAFT, Midori-64, Kalyna, KASUMI, Khazad, MISTY1, HIGHT, CLEFIA, RoadRunneR; LWC block & stream ciphers (PRESENT, LED, PRIDE, PRINCE, SKINNY, RECTANGLE, SPARX, SIMON, SPECK, Piccolo, CHAM, TEA/XTEA/XXTEA, LS-Design, GIFT-COFB, Romulus, ISAP, Photon-Beetle, Sparkle, Elephant, NORX, MORUS, ACORN, Ketje Jr, Deoxys-II, SNOW 3G, SNOW-V, Sosemanuk, Grain, ZUC, BelT, ISAAC, PCG64, Xoshiro256++, Spritz, Crypto1, DECT-DSC, GEA, Adiantum, HCTR2). All bidirectional |
| **CRC** | 22 | Every width defined by the RevEng catalogue (3 to 82 bits) — all 113 named variants, plus custom model parameterization |
| **Classical** | 19 | Caesar, ROT13, Vigenère, Beaufort, Autokey, Playfair, Hill, Polybius, Bifid, Trifid, Four-Square, Affine, Atbash, Rail Fence, Columnar Transposition, Enigma (I, M3, M4), Hagelin M-209, Lorenz SZ40/SZ42, Solitaire/Pontifex, ADFGX/ADFGVX, Nihilist, Straddling Checkerboard |
| **Key derivation** | 19 | PBKDF2, HKDF, scrypt, Argon2 (i/d/id with pepper & AAD), bcrypt / bcrypt-pbkdf — with Verify mode — EvpKDF (OpenSSL `EVP_BytesToKey`), Balloon Hashing, Catena, Lyra2, Yescrypt, Makwa |
| **Encodings** | 15 | Hex (Base16), Base32 (RFC 4648, base32hex, Crockford), Base58 (Bitcoin, Ripple, Flickr, Base58check), Base64 (standard and URL-safe), Base85 (Ascii85, Z85, RFC 1924), basE91, Base45, Proquints, Punycode, Bencode, CBOR (RFC 8949), Bubble Babble, Baudot ITA2, PGP Word List, Reflected Binary Gray Code — all bidirectional |
| **Public key & Post-quantum** | 14 | RSA (keygen, PSS & PKCS#1 v1.5 signatures across 15 hashes, OAEP encryption), ECDSA over P-256/384/521 and secp256k1, Ed25519, ECDH over X25519 & P-curves, Post-Quantum ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Falcon, Classic McEliece, HQC, Stateful Hash Signatures (LMS/HSS & XMSS), Shamir's Secret Sharing, SLIP-0039, Pedersen Commitments |
| **MACs** | 13 | HMAC over 55 hashes (PHP `hash_hmac_algos` set + SM3, BLAKE1/2, Skein, Streebog), KMAC128/256 with customization, Skein-MAC, Ascon-MAC, Ascon-PRF/PRFShort, Poly1305, AES-CMAC, SipHash-2-4, HighwayHash, BLAKE3-MAC, Chaskey, Chaskey-LTS |
| **Checksums** | 9 | Sum check (8/16/32-bit over bytes or words), one’s complement sum (Internet checksum RFC 1071), two’s complement checksum, XOR checksum, LRC, BCC, Fletcher-16, Fletcher-32, Adler-32 |
| **Parity** | 5 | UART/Serial character parity (Even, Odd, Mark, Space), Hamming code ECC (7,4 / 15,11 / 31,26 / 63,57), BCH codes, Reed-Solomon ECC, and longitudinal parity |
| **Formats & generators** | 10 | URL percent-encoding (component, URI, form), HTML entities (named, numeric, hex), JWT decode, JSON & XML (validate, format, minify), case conversion in 10 styles, UUID (v1-v7, nil, max), passwords, random numbers, random bytes (from `crypto.getRandomValues` via rejection sampling) |

Each tool offers text, hex, loose hex, Base64 and file input where it makes sense;
hex/Base64/Base64url/Base32 (and decimal, for checksums) output; a verify panel that
auto-detects the encoding of a value you paste; a Test input menu of known strings; and lint
rules that flag the things that actually go wrong.

Text input can be read in **40 character encodings** — UTF-8, UTF-16LE/BE, true ISO-8859-1, the
ISO 8859 set, the Windows and DOS code pages, KOI8, the Mac ones, and GBK, gb18030, Big5, EUC-JP,
Shift_JIS, ISO-2022-JP and EUC-KR. That matters because a digest is over bytes: the SHA-256 of
日本語 is one value as UTF-8 and a completely different one as Shift_JIS.

## Layout

```
apps/
  web/              Next.js static export — the only build of the UI
  desktop/          Electron shell: app:// protocol, CSP, IPC. No runtime dependencies.
packages/
  contracts/        zod schemas, Diagnostic levels, PlatformApi
  cipher-engine/    catalogue / codec / lint / streaming core   (@ocs/engine)
  cipher-registry/  TOOL_MANIFESTS + loadTool()                 (@ocs/registry)
  algos/            pure implementations @noble and @scure lack
  tools/
    hash/  crc/  mac/  kdf/  cipher/  asymmetric/
  encodings/        legacy character encodings, loaded on demand
  platform/         web | electron adapter, chosen at runtime
  ui/               Button, Panel, Dialog, MonoBlock, SecretField
  config/           shared tsconfigs
tests/              1312 tests, driven by published vectors and OpenSSL parity
```

One static bundle serves both targets: a browser loads it from a static host, and
Electron loads the same `out/` directory over its own `app://` origin.

## Requirements

- **Node.js**: `>=20.11` (developed and verified against Node 24.x)
- **pnpm**: `10.x` — pinned via `packageManager` (`pnpm@10.34.5`). Install `pnpm` if you have not done already:
  `npm install -g pnpm@10`

## Setup

```bat
:: install the workspace
pnpm install        

:: Next dev server on http://localhost:3000
pnpm web            

:: Electron against the dev server — start `pnpm web` first
:: or use scripts\launch\launch_desktop.bat which starts the web :: server and waits for it
pnpm desktop        
```

First-run sanity check:

- **Windows PowerShell 5.1:**
  ```powershell
  pnpm typecheck; pnpm lint; pnpm test
  ```
- **Command Prompt (`cmd.exe`) or Git Bash:**
  ```bash
  pnpm typecheck && pnpm lint && pnpm test
  ```

For the Windows `scripts\*\*.bat` launchers, Linux/macOS `scripts/*/*.sh` scripts, and the full command table, see
[docs/scripts.md](docs/scripts.md).

## Packaging

Use the packaging scripts when you want release artifacts instead of a dev run:

- `pnpm build` - build the web export and the desktop bundle
- `pnpm package` - create the Windows installer release flow
- `scripts\build-helpers\build_all.bat -Verify -Package` - full checked build plus installer
- `scripts\package\create-package.bat -Binary` - web zip + desktop installer
- `scripts\package\create-package.bat -Release -Zip` - full release folder plus archive

The package version comes from the root `version` file, and the release output is
written under `dist/<version>/`.

See [docs/scripts.md](docs/scripts.md) for the full build/package/launch matrix.

## Credits & Acknowledgements

Cipher Workbench relies on and builds upon several outstanding open-source cryptography and algorithm projects:

- **[@noble cryptographic suites](https://github.com/paulmillr)** by Paul Miller:
  - [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) — Audited, zero-dependency implementations of AES, ChaCha20, Salsa20, AEGIS, and LWC ciphers.
  - [`@noble/curves`](https://github.com/paulmillr/noble-curves) — Audited implementations of ECDSA, Ed25519, X25519, and NIST P-curves.
  - [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) — Standards-compliant FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) primitives.
- **[hash-wasm](https://github.com/Danipen/hash-wasm)** by Daniil Penkin — High-performance WebAssembly hash engine used for verification and oracles.
- **[xxhash-wasm](https://github.com/mwilliamson/xxhash-wasm)** by Michael Williamson — WebAssembly bindings for xxHash verification.
- **[Greg Cook's RevEng Catalogue](https://mcmilk.de/projects/user-defined-crc/)** — The definitive catalogue of named CRC algorithms powering the 113 CRC variant definitions.
- **[emn178 / WHATWG Text Encoding](https://github.com/emn178/js-sha256)** — Legacy single-byte and multi-byte character encoding tables for exact byte-level digest input support.
- **[OpenSSL Project](https://www.openssl.org)** — Reference cryptographic implementation used for host parity and differential test suites.

We extend our deep gratitude to all the authors, maintainers, and security researchers whose work makes open-source cryptography reliable and accessible.

> **Third-Party Licenses:** All referenced libraries, specifications, and test suites remain the intellectual property of their respective authors and maintainers, governed by their respective open-source licenses (MIT, Apache-2.0, BSD, etc.).

---

## Contributions

Contributions of all sizes are warmly welcome!. Please feel free to:

- Report issues using [the issue guide](docs/create_a_issue.md)
- Submit pull requests
- Improve documentation
- Suggest new features
- Start a discussion

Let's make the library better for everyone.

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE)
(`GPL-3.0-only`). See [LICENSE](LICENSE) for the full text.

---

## Author

Muhammad Hassaan Shah

- GitHub: [@thesourcebuild](https://github.com/thesourcebuild)
- Project: [github.com/thesourcebuild/cipherworkbench](https://github.com/thesourcebuild/cipherworkbench)
