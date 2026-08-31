import type { SecurityPosture } from "@ocs/engine";

/**
 * The five cipher tools, as eager metadata.
 *
 * This is the family where the app's `insecure` level does the most work. A hash can only
 * be weak; a cipher can be used in a way that leaks the plaintext outright while producing
 * output that looks perfectly random. ECB and nonce reuse are both in that category, and
 * both are one dropdown click away.
 */
/**
 * One block/key pairing of a parameterised cipher.
 *
 * Simon and Speck are each ten functions selected by a `(block, key)` pair, and the pair changes
 * the IV length as well as the key length -- which is why this carries `blockSize` rather than
 * letting the tool's own `block.size` speak for all ten.
 */
export interface CipherParamSet {
  /** Stable id, `<blockBits>-<keyBits>`. It travels in a share link, so do not renumber these. */
  id: string;
  label: string;
  blockSize: number;
  keyLength: number;
  summary: string;
}

/**
 * One named instance of a keyed construction that has no block: a Schwaemm size, an ISAP profile, a
 * Romulus mode, an Elephant animal.
 *
 * Separate from `CipherParamSet` rather than a widening of it, because the two carry different facts. A
 * parameter set says what the *block* is; an instance says what the key, nonce and tag are. Merging
 * them would put a meaningless `blockSize` on nine tools, and `cipherBlockSize` reads that field.
 */
export interface CipherInstance {
  /** Stable id. It travels in a share link, so do not rename these. */
  id: string;
  label: string;
  summary: string;
  keyLen: number;
  nonceLen: number;
  /** Bytes. Omitted where every instance of the tool agrees, in which case `shape.tagLen` applies. */
  tagLen?: number;
}

export const COBBLESTONE_INSTANCES: readonly CipherInstance[] = [
  {
    id: "cobblestone128",
    label: "Cobblestone-128",
    summary: "SHA-512 + AES-128-GCM, 16-byte key (recommended)",
    keyLen: 16,
    nonceLen: 0,
    tagLen: 16,
  },
  {
    id: "cobblestone256",
    label: "Cobblestone-256",
    summary: "SHA-512 + AES-256-GCM, 32-byte key (compliance-oriented)",
    keyLen: 32,
    nonceLen: 0,
    tagLen: 16,
  },
];

export interface CipherToolMeta {
  id: string;
  label: string;
  category: string;
  /** True when the cipher authenticates as well as encrypts. */
  aead: boolean;
  security: SecurityPosture;
  tags: readonly string[];
  summary: string;
  /** True when the cipher supports incremental streaming operations. */
  streaming?: boolean;
  /**
   * Set for a block cipher this repo implements itself, rather than one noble provides.
   *
   * DES, 3DES and SM4 all arrive from `@ocs/algos` as a key schedule plus a block permutation, and the
   * modes come from the shared layer in `blockmodes.ts`. Declaring the three facts that vary -- block
   * size, key sizes, which modes make sense -- is what lets one compute path serve all of them, in the
   * same way one `OptionsForm` serves every tool.
   */
  block?: {
    /**
     * Bytes. Four and six appear because Simon and Speck define 32- and 48-bit blocks -- which is a
     * real constraint on how much may be encrypted under one key, not a curiosity. `blockmodes.ts` is
     * generic over this; `C007` computes the per-block-size ceiling.
     *
     * 32, 64 and 128 are Threefish, whose block is the same size as its key. A union rather than
     * `number` on purpose: the values here decide IV lengths and padding, and every addition to the
     * list is a deliberate widening rather than something a typo can introduce.
     */
    size: 4 | 6 | 8 | 12 | 16 | 20 | 32 | 64 | 128;
    /**
     * Bytes. The sizes the cipher accepts, in ascending order.
     *
     * Empty means the cipher takes a *range* rather than a list -- Blowfish is 4 to 56 bytes, the
     * only one here that is not a fixed set. `keyRange` carries the bounds in that case, and the
     * catalogue reads whichever is present; an empty list with no range is a configuration error the
     * option builder throws on rather than silently accepting a one-byte key.
     */
    keyLengths: readonly number[];
    /** The inclusive byte bounds, for a cipher whose key is a range. Blowfish only. */
    keyRange?: { min: number; max: number };
    /** Ids from AES_MODES. The AEAD and key-wrap modes are AES-only and are not listed here. */
    modes: readonly string[];
  };
  /**
   * Set for a cipher whose entire form is a key, a nonce and -- for an AEAD -- associated data.
   *
   * The counterpart to `block`, and it earns its place the same way: `shapedCipherOptions` builds the
   * whole catalogue from it and `requiredNonceLength`/`acceptedNonceLengths` read it, so adding ZUC-256
   * after ZUC-128 was two numbers, and adding nine NIST lightweight AEADs needed no option code at all.
   *
   * It began as `stream` and covered the six eSTREAM ciphers. The rename came with the AEADs: `tagLen`
   * and `instances` are what an authenticated construction needs, and a field called `stream` carrying
   * a tag length would be a lie about a third of its users.
   *
   * Deliberately *not* retrofitted onto RC4, ChaCha or Salsa. Each of those has a control of its own --
   * RC4's drop count, ChaCha's initial counter -- and a range rather than a list for RC4's key, so a
   * derived catalogue would have to grow a parameter per exception until it was no simpler than the
   * hand-written ones. The line is the same one AES sits on: AES has modes and no `block`, because its
   * catalogue does more than a derived one could.
   */
  shape?: {
    /**
     * Bytes, ascending. The *union* across every instance, which is all a once-per-tool catalogue can
     * declare; `resolveCipher` narrows it to the selected instance, where the message can name one.
     */
    keyLengths: readonly number[];
    /** Bytes, ascending. Same union rule. The largest is what Generate produces when there is a choice. */
    nonceLengths: readonly number[];
    /**
     * Tag length in bytes. Present exactly when the tool is an AEAD, and absent for a raw stream cipher.
     *
     * This is what puts the "AAD (Additional Authenticated Data)" field on the form, so a tool that sets
     * `aead: true` and omits this would authenticate and offer nowhere to put the header.
     */
    tagLen?: number;
    /**
     * The named instances this tool covers, when it covers more than one.
     *
     * The same idea as `paramSets` and it reuses the same option id, so the control is labelled
     * "Parameter set" in both cases -- but it carries key, nonce and tag lengths rather than a block
     * size, because these tools have no block. Where an instance omits `tagLen` the tool's own is used.
     */
    instances?: readonly CipherInstance[];
    /** Which of `instances` the form opens on. Required whenever `instances` is present. */
    defaultInstance?: string;
  };
  /**
   * The parameter sets this tool covers, when it covers more than one.
   *
   * Present for Simon and Speck. When it is set, `block.size` and `block.keyLengths` describe the
   * *default* set only -- they exist so the eager sidebar and the manifest have a number -- and
   * every read on the compute path must go through the resolved set instead. `resolveParamSet` and
   * `ResolvedCipher.blockSize` are how that is done; reading `tool.block.size` in a code path that
   * has a spec is the bug this comment exists to prevent.
   */
  paramSets?: readonly CipherParamSet[];
  /** Which of `paramSets` the form opens on. Required whenever `paramSets` is present. */
  defaultParamSet?: string;
}

export const CIPHER_TOOLS: readonly CipherToolMeta[] = [
  {
    id: "aes",
    label: "AES",
    category: "AES",
    // Depends on the mode; GCM and GCM-SIV are, the rest are not. `M`odes carry their own
    // flag in MODES below, and the lint rules read that rather than this.
    aead: true,
    security: "modern",
    tags: [
      "aes",
      "rijndael",
      "gcm",
      "cbc",
      "cfb",
      "ofb",
      "ctr",
      "ccm",
      "ocb",
      "xts",
      "ecb",
      "siv",
      "key wrap",
      "kw",
      "kwp",
      "rfc3394",
      "rfc5649",
      "rfc5297",
      "fips197",
      "encrypt",
      "decrypt",
    ],
    summary:
      "The block cipher everything uses, in nine modes. The mode matters more than the key size.",
  },
  {
    id: "chacha20poly1305",
    label: "ChaCha20-Poly1305",
    category: "ChaCha",
    aead: true,
    security: "modern",
    tags: ["chacha20", "poly1305", "aead", "rfc8439", "tls", "wireguard", "encrypt", "decrypt"],
    summary:
      "The AEAD from RFC 8439. As strong as AES-GCM and faster without hardware AES support.",
  },
  {
    id: "xchacha20poly1305",
    label: "XChaCha20-Poly1305",
    category: "ChaCha",
    aead: true,
    security: "modern",
    tags: ["xchacha20", "poly1305", "aead", "libsodium", "24-byte nonce", "encrypt", "decrypt"],
    summary:
      "ChaCha20-Poly1305 with a 192-bit nonce, so random nonces stop being a counting problem.",
  },
  {
    id: "fernet",
    label: "Fernet",
    category: "Recipes",
    aead: true,
    security: "modern",
    tags: [
      "fernet",
      "symmetric",
      "aes-cbc",
      "hmac-sha256",
      "cryptography.io",
      "token",
      "authenticated",
      "timestamp",
      "python",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Python cryptography's symmetric authenticated encryption recipe. AES-128-CBC with PKCS7 padding and HMAC-SHA256.",
  },
  {
    id: "cobblestone",
    label: "Cobblestone",
    category: "Streaming AEAD",
    aead: true,
    security: "modern",
    streaming: true,
    tags: [
      "cobblestone",
      "c2sp",
      "chunked-encryption",
      "streaming",
      "aead",
      "aes-gcm",
      "sha512",
      "hkdf",
      "key commitment",
      "cryptography.io",
      "encrypt",
      "decrypt",
    ],
    summary:
      "C2SP chunked streaming symmetric encryption up to 4 PiB. SHA-512 key derivation with commitment and AES-GCM.",
  },
  {
    id: "chacha20",
    label: "ChaCha20 (raw)",
    category: "ChaCha",
    aead: false,
    security: "legacy",
    tags: ["chacha20", "stream", "rfc8439", "unauthenticated", "encrypt", "decrypt"],
    summary: "Raw ChaCha20 keystream, unauthenticated. For reproducing test vectors.",
  },
  {
    /**
     * The reduced-round ChaCha variants, and the original 64-bit-nonce layout.
     *
     * All three are in the Bernstein family and none of them is what a protocol will specify, which is
     * exactly why they are here: they exist for reproducing something. ChaCha8 and ChaCha12 are what
     * several RNGs use -- Rust's `rand` seeds from ChaCha12, and both appear in `arc4random`
     * implementations -- and ChaCha20-original is the layout of every ChaCha test vector predating
     * RFC 8439, including Bernstein's own.
     *
     * The published vectors are `draft-strombergson-chacha-test-vectors`, whose TC1 this repo asserts
     * for all three round counts. `@noble/ciphers` implements them, so nothing here is hand-written --
     * what needed checking was the nonce layout, and that is what the tests below cover.
     */
    id: "chacha12",
    label: "ChaCha12",
    category: "ChaCha",
    aead: false,
    security: "legacy",
    tags: [
      "chacha12",
      "stream",
      "reduced rounds",
      "rng",
      "unauthenticated",
      "encrypt",
      "decrypt",
    ],
    summary: "Twelve-round ChaCha. What several RNGs use, and unauthenticated.",
  },
  {
    id: "chacha8",
    label: "ChaCha8",
    category: "ChaCha",
    aead: false,
    security: "legacy",
    tags: [
      "chacha8",
      "stream",
      "reduced rounds",
      "rng",
      "unauthenticated",
      "encrypt",
      "decrypt",
    ],
    summary: "Eight-round ChaCha. One round of margin over the best known attack.",
  },
  {
    /**
     * ChaCha20 as Bernstein defined it: a 64-bit nonce and a 64-bit counter.
     *
     * RFC 8439 moved one word from the counter into the nonce, giving 96 bits of nonce and 32 of
     * counter, and every modern protocol uses that layout. The original is not compatible: the same
     * key and the same eight bytes give a different keystream unless the counter is zero. Anyone
     * reading pre-2015 ChaCha output, or a test vector from the original paper, needs this one.
     */
    id: "chacha20orig",
    label: "ChaCha20 (original nonce)",
    category: "ChaCha",
    aead: false,
    security: "legacy",
    tags: [
      "chacha20",
      "stream",
      "64-bit nonce",
      "original",
      "bernstein",
      "unauthenticated",
      "encrypt",
      "decrypt",
    ],
    summary: "ChaCha20 with the original 64-bit nonce. For pre-RFC 8439 output.",
  },
  {
    /**
     * XSalsa20-Poly1305: libsodium's `crypto_secretbox`, and the reason this is here.
     *
     * NaCl's original AEAD, still what `secretbox` means in every libsodium binding and therefore
     * what a great deal of stored data is encrypted with. Anyone opening such data needs this
     * specific construction -- ChaCha20-Poly1305 will not read it, despite being the same idea one
     * revision later.
     */
    id: "xsalsa20poly1305",
    label: "XSalsa20-Poly1305",
    category: "Salsa",
    aead: true,
    security: "modern",
    tags: [
      "xsalsa20",
      "poly1305",
      "aead",
      "secretbox",
      "nacl",
      "libsodium",
      "24-byte nonce",
      "encrypt",
      "decrypt",
    ],
    summary: "NaCl's secretbox — XSalsa20 with Poly1305 and a 192-bit nonce.",
  },
  {
    id: "xsalsa20",
    label: "XSalsa20 (raw)",
    category: "Salsa",
    aead: false,
    security: "legacy",
    tags: ["xsalsa20", "stream", "nacl", "libsodium", "unauthenticated", "encrypt", "decrypt"],
    summary: "Salsa20 with a 192-bit nonce, unauthenticated. Half of secretbox.",
  },
  {
    id: "salsa20",
    label: "Salsa20 (raw)",
    category: "Salsa",
    aead: false,
    security: "legacy",
    tags: ["salsa20", "stream", "estream", "djb", "unauthenticated", "encrypt", "decrypt"],
    summary: "The 2005 stream cipher ChaCha was derived from. 8-byte nonce, unauthenticated.",
  },
  {
    id: "ascon",
    label: "Ascon-AEAD128",
    category: "Ascon",
    aead: true,
    security: "modern",
    tags: [
      "ascon",
      "ascon-aead128",
      "aead",
      "nist",
      "sp 800-232",
      "lightweight",
      "iot",
      "sponge",
      "encrypt",
      "decrypt",
    ],
    summary: "NIST's lightweight AEAD, SP 800-232. One permutation for encryption and hashing.",
  },
  {
    id: "aegis128l",
    label: "AEGIS-128L",
    category: "AEGIS",
    aead: true,
    security: "modern",
    tags: [
      "aegis",
      "aegis-128l",
      "aead",
      "caesar",
      "libsodium",
      "aes-ni",
      "encrypt",
      "decrypt",
    ],
    summary: "AES-round-based AEAD from the CAESAR portfolio. 128-bit key, 1024-bit state.",
  },
  {
    id: "aegis256",
    label: "AEGIS-256",
    category: "AEGIS",
    aead: true,
    security: "modern",
    tags: ["aegis", "aegis-256", "aead", "caesar", "libsodium", "aes-ni", "encrypt", "decrypt"],
    summary: "The 256-bit-key AEGIS. Six state blocks, one message block per update.",
  },
  {
    id: "camellia",
    label: "Camellia",
    category: "Other block ciphers",
    aead: false,
    security: "modern",
    tags: [
      "camellia",
      "rfc 3713",
      "nessie",
      "cryptrec",
      "iso 18033",
      "ntt",
      "mitsubishi",
      "openssl",
      "encrypt",
      "decrypt",
    ],
    summary: "The Japanese 128-bit block cipher, RFC 3713. A NESSIE and CRYPTREC standard.",
    block: {
      size: 16,
      keyLengths: [16, 24, 32],
      modes: ["gcm", "ccm", "cbc", "cfb", "ofb", "ctr", "ecb"],
    },
  },
  {
    id: "aria",
    label: "ARIA",
    category: "Other block ciphers",
    aead: false,
    security: "modern",
    tags: [
      "aria",
      "rfc 5794",
      "korea",
      "national standard",
      "ks x 1213",
      "openssl",
      "encrypt",
      "decrypt",
    ],
    summary: "South Korea's national block cipher, RFC 5794. The counterpart to SM4.",
    block: {
      size: 16,
      keyLengths: [16, 24, 32],
      modes: ["gcm", "ccm", "cbc", "cfb", "ofb", "ctr", "ecb"],
    },
  },
  {
    id: "sm4",
    label: "SM4",
    category: "SM",
    aead: false,
    security: "modern",
    tags: [
      "sm4",
      "smx",
      "gb/t 32907",
      "rfc 8998",
      "china",
      "national standard",
      "encrypt",
      "decrypt",
    ],
    summary: "China's national block cipher, GB/T 32907. The companion to SM3.",
    block: {
      size: 16,
      // GCM and CCM first, because RFC 8998 specifies exactly those two for TLS 1.3 with SM3 -- and
      // this is the only cipher here where the AEAD modes are the *standardised* use.
      modes: ["gcm", "ccm", "cbc", "cfb", "ofb", "ctr", "ecb"],
      keyLengths: [16],
    },
  },
  {
    id: "belt",
    label: "BelT",
    category: "National",
    aead: false,
    security: "modern",
    tags: [
      "belt",
      "stb 34.101.31",
      "stb",
      "belarus",
      "national standard",
      "encrypt",
      "decrypt",
    ],
    summary: "Belarus's national block cipher, STB 34.101.31. The companion to belt-hash.",
    block: {
      size: 16,
      /**
       * No GCM and no CCM, and that is a choice rather than an omission.
       *
       * The mode layer is generic and the block is 128 bits, so `@ocs/algos` could hand BelT both --
       * exactly as it does Camellia, ARIA and SM4. Those three have them because *standards* specify
       * them (RFC 5528/5529, RFC 6209, RFC 8998). STB 34.101.31 specifies its own authenticated mode
       * instead, which is not implemented here, so pairing BelT with GCM would be inventing a
       * construction nothing else implements. Being able to offer a mode and choosing to are separate
       * judgements, and `tests/cipher.test.ts` asserts that policy rather than trusting it.
       */
      modes: ["cbc", "cfb", "ofb", "ctr", "ecb"],
      // STB defines all three widths, and the key *is* the eight subkeys -- there is no schedule.
      keyLengths: [16, 24, 32],
    },
  },
  {
    /**
     * Magma, the 64-bit half of GOST R 34.12-2015.
     *
     * The sixth cipher on the shared mode layer, and the one that shows what the layer is worth: a
     * `BlockCipher`, one `Record` entry and a published vector, with all five classical modes arriving
     * for free. It has no AEAD mode here and cannot -- GCM's field is GF(2^128) and CCM's counter
     * formatting assumes a 16-byte block, so both are undefined for a 64-bit cipher.
     *
     * `id-tc26-gost-28147-param-Z` is the fixed parameter set, which is what separates this from
     * `gost.ts`'s two interchangeable 28147-89 sets. RFC 8891 is the reachable English specification
     * and the source of the vector.
     */
    id: "magma",
    label: "Magma",
    category: "GOST",
    aead: false,
    security: "legacy",
    tags: [
      "magma",
      "gost",
      "gost r 34.12-2015",
      "gost 28147-89",
      "rfc 8891",
      "russia",
      "64-bit block",
      "encrypt",
      "decrypt",
    ],
    summary: "The 64-bit GOST cipher, RFC 8891. One fixed S-box set, five classical modes.",
    block: { size: 8, keyLengths: [32], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * Twofish and Serpent, the two AES finalists people still choose deliberately.
     *
     * Both are here for the same reason: they are what a disk-encryption tool offers when someone
     * wants a margin AES does not have. VeraCrypt, GnuPG and KeePass list them, usually as a cascade
     * with AES. Neither has an OpenSSL name, ever -- so both rest on Bouncy Castle's published
     * vectors, one per key size.
     */
    id: "twofish",
    label: "Twofish",
    category: "AES finalists",
    aead: false,
    security: "modern",
    tags: [
      "twofish",
      "schneier",
      "aes finalist",
      "veracrypt",
      "gnupg",
      "keepass",
      "encrypt",
      "decrypt",
    ],
    summary: "The AES finalist with key-dependent S-boxes. Unbroken, and Blowfish's successor.",
    block: { size: 16, keyLengths: [16, 24, 32], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    id: "serpent",
    label: "Serpent",
    category: "AES finalists",
    aead: false,
    security: "modern",
    tags: [
      "serpent",
      "anderson",
      "biham",
      "knudsen",
      "aes finalist",
      "veracrypt",
      "32 rounds",
      "encrypt",
      "decrypt",
    ],
    summary: "The AES finalist with the largest margin: 32 rounds, and second place on speed.",
    block: { size: 16, keyLengths: [16, 24, 32], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * Kuznyechik, the 128-bit half of GOST R 34.12-2015, beside Magma which is the 64-bit half.
     *
     * Two ciphers from one standard, and both here for the same reason: reproducing Russian
     * government-mandated output. This one is the SP-network, structurally closer to AES than to its
     * own Feistel-network sibling.
     */
    id: "kuznyechik",
    label: "Kuznyechik",
    category: "GOST",
    aead: false,
    security: "modern",
    tags: [
      "kuznyechik",
      "gost",
      "gost r 34.12-2015",
      "rfc 7801",
      "grasshopper",
      "russia",
      "encrypt",
      "decrypt",
    ],
    summary: "The 128-bit GOST cipher, RFC 7801. An SP-network, unlike its sibling Magma.",
    block: { size: 16, keyLengths: [32], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * SEED and CAST5: two national and protocol ciphers whose value is entirely interoperability.
     */
    id: "seed",
    label: "SEED",
    category: "National",
    aead: false,
    security: "legacy",
    tags: ["seed", "kisa", "ks x 1213", "rfc 4269", "korea", "banking", "encrypt", "decrypt"],
    summary: "South Korea's other national cipher, RFC 4269. What Korean banking ran on.",
    block: { size: 16, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    id: "cast5",
    label: "CAST5",
    category: "Legacy",
    aead: false,
    security: "legacy",
    tags: [
      "cast5",
      "cast-128",
      "rfc 2144",
      "openpgp",
      "gnupg",
      "64-bit block",
      "encrypt",
      "decrypt",
    ],
    summary: "OpenPGP's other required cipher, RFC 2144. Three different round functions.",
    block: {
      size: 8,
      // 40 to 128 bits in 8-bit steps, which RFC 2144 section 2.5 spells out as twelve sizes.
      keyLengths: [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
      modes: ["cbc", "cfb", "ofb", "ctr", "ecb"],
    },
  },
  {
    /**
     * IDEA and RC2, the two ciphers here whose only remaining job is opening old files.
     */
    id: "idea",
    label: "IDEA",
    category: "Legacy",
    aead: false,
    security: "legacy",
    tags: ["idea", "pgp", "lai", "massey", "64-bit block", "legacy", "encrypt", "decrypt"],
    summary: "PGP 2.x's cipher. Multiplication modulo 65537, and no tables at all.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    id: "rc2",
    label: "RC2",
    category: "Legacy",
    aead: false,
    security: "legacy",
    tags: [
      "rc2",
      "rivest",
      "rfc 2268",
      "s/mime",
      "pkcs#12",
      "export grade",
      "64-bit block",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Rivest's export-era cipher, RFC 2268. The effective key length is a separate control.",
    block: {
      size: 8,
      // 1 to 128 bytes, so a range rather than a list -- Blowfish is the only other one here.
      keyLengths: [],
      keyRange: { min: 1, max: 128 },
      modes: ["cbc", "cfb", "ofb", "ctr", "ecb"],
    },
  },
  {
    /**
     * Blowfish, and the reason it is still worth having: `bcrypt` is its key schedule.
     *
     * A 64-bit block dates it, and that is the whole of the problem -- there is no attack on the
     * cipher, only on the block size. `C002`'s note about a few gigabytes under one key applies here
     * as it does to DES and 3DES.
     */
    id: "blowfish",
    label: "Blowfish",
    category: "Legacy",
    aead: false,
    security: "legacy",
    tags: [
      "blowfish",
      "bf",
      "schneier",
      "bcrypt",
      "openpgp",
      "64-bit block",
      "legacy",
      "encrypt",
      "decrypt",
    ],
    summary: "Schneier's 1993 cipher. A 4-to-56-byte key, and the schedule bcrypt is built on.",
    block: {
      size: 8,
      // A range, not a list: 4 to 56 bytes, which is the only cipher here that works that way.
      keyLengths: [],
      keyRange: { min: 4, max: 56 },
      modes: ["cbc", "cfb", "ofb", "ctr", "ecb"],
    },
  },
  {
    /**
     * PRESENT, at both key sizes. The reference lightweight cipher, and here to read hardware output.
     *
     * ISO/IEC 29192-2, about 1570 gate equivalents, which is roughly a quarter of the smallest AES.
     * There is no software reason to choose it -- it is bit-sliced, so software is exactly where it is
     * slowest -- and that is the honest summary.
     *
     * **Only the 80-bit set has published vectors.** The paper standardises 80 and describes the
     * 128-bit key schedule in an appendix prefaced with "we do not expect it to be used", giving no
     * values; no library reachable from here implements it. The two share the S-box, the bit
     * permutation and all 31 rounds, so what is unchecked is the schedule alone -- see `present.ts` and
     * the note in `tests/algos-lightweight.test.ts`.
     */
    id: "present",
    label: "PRESENT",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "present",
      "present-80",
      "present-128",
      "lightweight",
      "iso 29192",
      "rfid",
      "64-bit block",
      "encrypt",
      "decrypt",
    ],
    summary: "The reference lightweight cipher, ISO/IEC 29192-2. 64-bit block, bit-sliced.",
    // Describes the *default* set. The block is 64 bits at both key sizes, as with RECTANGLE.
    block: { size: 8, keyLengths: [10], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
    defaultParamSet: "80",
    paramSets: [
      {
        id: "80",
        label: "PRESENT-80",
        blockSize: 8,
        keyLength: 10,
        summary: "80-bit key, the standardised size -- and the only one with published vectors",
      },
      {
        id: "128",
        label: "PRESENT-128",
        blockSize: 8,
        keyLength: 16,
        summary: "128-bit key: two S-box applications per round in the schedule instead of one",
      },
    ],
  },
  {
    /**
     * CHAM, the Korean lightweight ARX family (Koo, Roh, Kim, Jung, Lee and Kwon, ICISC 2017).
     *
     * `modern`: no attack on the full cipher. This is the **original** round count, which is what every
     * published vector uses; a revision at 88 and 112 rounds exists because a related-key differential
     * reached the original, and implementing that silently would reproduce nothing.
     *
     * The smallest block cipher in this repo by source size: **no S-box, no tables and no round-constant
     * table at all** -- the round *index* is the constant. One addition, two rotations and two XORs per
     * round, which is the point of a design targeting eight-bit microcontrollers.
     */
    id: "cham",
    label: "CHAM",
    category: "Lightweight",
    aead: false,
    security: "modern",
    tags: [
      "cham",
      "cham-64/128",
      "cham-128/128",
      "cham-128/256",
      "lightweight",
      "arx",
      "korea",
      "kisa",
      "icisc",
      "encrypt",
      "decrypt",
    ],
    summary:
      "A Korean lightweight ARX cipher with no tables at all -- the round index is the constant.",
    // Describes the *default* set, CHAM-128/128, as Simon's and Speck's do.
    block: { size: 16, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
    defaultParamSet: "128-128",
    paramSets: [
      {
        id: "64-128",
        label: "CHAM-64/128",
        blockSize: 8,
        keyLength: 16,
        summary:
          "64-bit block over 16-bit words, 80 rounds -- 32 GB under one key before blocks repeat",
      },
      {
        id: "128-128",
        label: "CHAM-128/128",
        blockSize: 16,
        keyLength: 16,
        summary: "128-bit block over 32-bit words, 80 rounds",
      },
      {
        id: "128-256",
        label: "CHAM-128/256",
        blockSize: 16,
        keyLength: 32,
        summary:
          "128-bit block with a 256-bit key -- the only set that changes the round count, to 96",
      },
    ],
  },
  {
    /**
     * Simeck, the Simon-Speck hybrid (Yang, Zhu, Suder, Aagaard and Gong, CHES 2015).
     *
     * `legacy`. No break of the full cipher, but the published cryptanalysis sits closer to the full
     * round count than Simon's or Speck's -- differential and linear attacks reach 20 of Simeck32/64's
     * 32 rounds -- so it does not get `modern` on the same terms they do.
     *
     * The design is one line: **Simon's Feistel with a cheaper round function.** Simon uses
     * `(x & rotl(x, 8)) ^ rotl(x, 2)`; Simeck uses `(x & rotl(x, 5)) ^ rotl(x, 1)`, one fewer distinct
     * rotation and therefore fewer wires. Its key schedule then runs that same function on itself, so
     * there is no separate schedule at all.
     *
     * All three sizes are offered. 48/96 was left out originally on the grounds that no vector was
     * reachable; the designers' own paper publishes one in its "Test Vectors" section, which was fetched
     * and parsed rather than transcribed -- and the same table's Simeck32/64 row matches Crypto++'s
     * independently, which is what makes the extraction trustworthy.
     */
    id: "simeck",
    label: "Simeck",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "simeck",
      "simeck32/64",
      "simeck48/96",
      "simeck64/128",
      "lightweight",
      "simon",
      "speck",
      "ches",
      "feistel",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Simon's Feistel with a cheaper round function, and a key schedule that reuses it.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
    defaultParamSet: "64-128",
    paramSets: [
      {
        id: "32-64",
        label: "Simeck32/64",
        blockSize: 4,
        keyLength: 8,
        summary:
          "32-bit block, 64-bit key, 32 rounds -- 256 KB under one key before blocks repeat",
      },
      {
        id: "48-96",
        label: "Simeck48/96",
        blockSize: 6,
        keyLength: 12,
        summary:
          "48-bit block, 96-bit key, 36 rounds -- 96 MB under one key before blocks repeat",
      },
      {
        id: "64-128",
        label: "Simeck64/128",
        blockSize: 8,
        keyLength: 16,
        summary:
          "64-bit block, 128-bit key, 44 rounds -- 32 GB under one key before blocks repeat",
      },
    ],
  },
  {
    /**
     * SKINNY, the tweakable block cipher family (Beierle et al., CRYPTO 2016), at all six sizes.
     *
     * `modern`: nothing breaks any full member after a decade of a public cryptanalysis competition
     * aimed at it. It is the most load-bearing cipher in this repo -- ISO/IEC 18033-7 standardises it and
     * three NIST lightweight submissions are built on it, one of which, Romulus, is a finalist and is
     * already here. So this tool and `romulus` share an implementation of the primitive.
     *
     * Note the whole tweakey is spent on key material here. SKINNY's third input is a *tweak*, and a
     * tool that exposed it separately would be a different, tweakable tool; what the standard defines as
     * a block cipher, and what its published vectors use, is this.
     */
    id: "skinny",
    label: "SKINNY",
    category: "Lightweight",
    aead: false,
    security: "modern",
    tags: [
      "skinny",
      "skinny-64-64",
      "skinny-64-128",
      "skinny-64-192",
      "skinny-128-128",
      "skinny-128-256",
      "skinny-128-384",
      "tweakable",
      "tweakey",
      "romulus",
      "forkae",
      "iso 18033-7",
      "lightweight",
      "crypto 2016",
      "encrypt",
      "decrypt",
    ],
    summary:
      "The tweakable family behind Romulus and ForkAE, at all six block and tweakey sizes.",
    block: { size: 16, keyLengths: [32], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
    defaultParamSet: "128-256",
    paramSets: [
      {
        id: "64-64",
        label: "SKINNY-64-64",
        blockSize: 8,
        keyLength: 8,
        summary:
          "64-bit block, 64-bit tweakey, 32 rounds -- one lane, so no LFSR in the schedule",
      },
      {
        id: "64-128",
        label: "SKINNY-64-128",
        blockSize: 8,
        keyLength: 16,
        summary:
          "64-bit block, two tweakey lanes, 36 rounds -- the set with a published vector",
      },
      {
        id: "64-192",
        label: "SKINNY-64-192",
        blockSize: 8,
        keyLength: 24,
        summary: "64-bit block, three tweakey lanes, 40 rounds",
      },
      {
        id: "128-128",
        label: "SKINNY-128-128",
        blockSize: 16,
        keyLength: 16,
        summary:
          "128-bit block, one tweakey lane, 40 rounds -- the other set with a published vector",
      },
      {
        id: "128-256",
        label: "SKINNY-128-256",
        blockSize: 16,
        keyLength: 32,
        summary: "128-bit block, two tweakey lanes, 48 rounds",
      },
      {
        id: "128-384",
        label: "SKINNY-128-384",
        blockSize: 16,
        keyLength: 48,
        summary: "128-bit block, three tweakey lanes, 56 rounds -- what Romulus reduces to 40",
      },
    ],
  },
  {
    /**
     * SPARX-64/128, the first ARX design with **provable** bounds against differential and linear
     * cryptanalysis (ASIACRYPT 2016).
     *
     * `modern`: no attack on the full cipher. Its interest is methodological, and it is why this belongs
     * beside Simon, Speck and CHAM rather than instead of them -- every other ARX cipher here rests on an
     * argument that its round function diffuses well, where SPARX was built by the "long trail strategy"
     * so that the bound can be *computed* the way an S-box-based SPN's can.
     *
     * The S-box is Speck's round function on 32 bits; the linear layer mixes the two branches. No tables,
     * and the only constants are the round numbers the key schedule adds.
     */
    id: "sparx",
    label: "SPARX-64/128",
    category: "Lightweight",
    aead: false,
    security: "modern",
    tags: [
      "sparx",
      "sparx-64/128",
      "arx",
      "long trail",
      "lightweight",
      "asiacrypt",
      "biryukov",
      "speck",
      "luxembourg",
      "encrypt",
      "decrypt",
    ],
    summary:
      "The first ARX cipher with provable differential bounds. Speck's round as its S-box.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * Chaskey-LTS, the block cipher underneath the ISO/IEC 29192-6 lightweight MAC.
     *
     * `modern`. Chaskey the MAC runs eight rounds; **LTS is "long term security", the same permutation at
     * sixteen** -- proposed by the designers after a differential-linear attack reached seven of the
     * eight. So this is the conservative member of the pair and the round count is the whole difference.
     *
     * It is the only **Even-Mansour** construction here: no key schedule at all, just the key XORed in
     * before the permutation and again after. The permutation itself is bare add-rotate-xor with no
     * constants of any kind, which makes it the smallest thing in this family after CHAM.
     */
    id: "chaskeylts",
    label: "Chaskey-LTS",
    category: "Lightweight",
    aead: false,
    security: "modern",
    tags: [
      "chaskey",
      "chaskey-lts",
      "chaskeylts",
      "lts",
      "even-mansour",
      "iso 29192-6",
      "arx",
      "mouha",
      "lightweight",
      "mac",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Even-Mansour over the Chaskey permutation at sixteen rounds. No key schedule at all.",
    block: { size: 16, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * TWINE-80, the generalised Feistel network (SAC 2012).
     *
     * `legacy`. No break of the full 36 rounds, but biclique and impossible-differential attacks reach
     * 23, and nothing has been built on it since. It is here because it showed a *type-2 generalised
     * Feistel* with a well-chosen nibble permutation can beat a plain SPN on hardware area -- a real
     * result, and the reason it is cited.
     *
     * Sixteen nibbles, one 4-bit S-box, one permutation of the sixteen positions. No matrix and no field
     * arithmetic anywhere.
     *
     * TWINE-128 is not offered: a different key schedule over 32 nibbles, and no reachable vector.
     */
    id: "twine",
    label: "TWINE-80",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "twine",
      "twine-80",
      "generalised feistel",
      "gfn",
      "nec",
      "suzaki",
      "minematsu",
      "lightweight",
      "sac 2012",
      "encrypt",
      "decrypt",
    ],
    summary:
      "A generalised Feistel over sixteen nibbles: one S-box, one permutation, no matrix.",
    block: { size: 8, keyLengths: [10], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * LED-64-80, the "Lightweight Encryption Device" (CHES 2011).
     *
     * `legacy`. No break of the full 48 rounds and unusually well analysed -- but nothing has been built
     * on it since, and what it is remembered for is the most extreme answer available to related-key
     * attacks: **there is no key schedule at all.** The key nibbles are XORed in cyclically, unchanged,
     * once every four rounds.
     *
     * Structurally AES over nibbles. Its S-box is PRESENT's and its round constants are the same six-bit
     * LFSR SKINNY uses -- both shared by their designers rather than by this repo, so neither is stored
     * twice.
     */
    id: "led",
    label: "LED-64-80",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "led",
      "led-64",
      "led-80",
      "lightweight",
      "ches 2011",
      "peyrin",
      "robshaw",
      "poschmann",
      "present",
      "no key schedule",
      "encrypt",
      "decrypt",
    ],
    summary:
      "AES over nibbles with no key schedule at all -- the key goes in unchanged, cyclically.",
    block: { size: 8, keyLengths: [10], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * PRINCE, the low-latency block cipher (ASIACRYPT 2012).
     *
     * `legacy`. No break of the full twelve rounds, but the design's own claim is 126 - n bits against an
     * attacker with 2^n plaintexts, and biclique and meet-in-the-middle results sit close to it. PRINCE-v2
     * changes the key schedule and is a different cipher; this is the original, which every published
     * vector uses.
     *
     * It is here for a property nothing else in this repo has: **alpha-reflection**. Decryption is
     * encryption with the two whitening words swapped and one 64-bit constant XORed into the round key, so
     * hardware gets the inverse for the price of an XOR. That is what PRINCE exists for -- unrolled
     * single-cycle decryption in the same circuit as encryption.
     */
    id: "prince",
    label: "PRINCE",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "prince",
      "low latency",
      "alpha reflection",
      "lightweight",
      "asiacrypt",
      "borghoff",
      "knudsen",
      "rechberger",
      "nxp",
      "encrypt",
      "decrypt",
    ],
    summary: "A low-latency cipher whose inverse is itself plus one XOR -- alpha-reflection.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * LBlock-80, the lightweight Feistel (ACNS 2011).
     *
     * `legacy`. No break of the full 32 rounds, but biclique attacks reach all of them just under
     * exhaustive search and impossible differentials reach 23.
     *
     * What sets it apart from TWINE and Piccolo, its neighbours here, is that it is the one with **eight
     * different S-boxes** in the round function plus two more in the key schedule. Ten tables of sixteen
     * nibbles is the largest count in this family and it is the whole of the cipher's non-linearity.
     */
    id: "lblock",
    label: "LBlock-80",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "lblock",
      "lblock-80",
      "feistel",
      "lightweight",
      "acns 2011",
      "wu",
      "zhang",
      "eight s-boxes",
      "encrypt",
      "decrypt",
    ],
    summary: "A lightweight Feistel with eight different S-boxes -- the most in this family.",
    block: { size: 8, keyLengths: [10], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * RECTANGLE, the bit-slice-oriented cipher (SCIENCE CHINA 2015), at both key sizes.
     *
     * `legacy`. No break of the full 25 rounds, but nothing is built on it and the 64-bit block carries the
     * usual birthday bound.
     *
     * It is the clearest example here of a cipher **designed to be bit-sliced**: the S-box is fourteen
     * logic gates applied to four rows at once, so there is no S-box table on the forward path at all, and
     * the permutation layer is three rotations. The two key sizes have genuinely different schedules, which
     * is why they are parameter sets rather than a key-length choice.
     */
    id: "rectangle",
    label: "RECTANGLE",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "rectangle",
      "rectangle-64-80",
      "rectangle-64-128",
      "bitslice",
      "lightweight",
      "rijmen",
      "zhang",
      "science china",
      "encrypt",
      "decrypt",
    ],
    summary:
      "A bit-sliced lightweight SPN: fourteen gates for an S-box and three rotations for diffusion.",
    // Describes the *default* set. The block is 64 bits at both key sizes here, unlike Simon or SKINNY.
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
    defaultParamSet: "64-128",
    paramSets: [
      {
        id: "64-80",
        label: "RECTANGLE-64-80",
        blockSize: 8,
        keyLength: 10,
        summary: "80-bit key: five 16-bit rows, and the schedule rotates a word by twelve",
      },
      {
        id: "64-128",
        label: "RECTANGLE-64-128",
        blockSize: 8,
        keyLength: 16,
        summary: "128-bit key: eight rows, and the schedule rotates bytes instead",
      },
    ],
  },
  {
    /**
     * PRIDE, the cipher built *for* a linear layer rather than around one (CRYPTO 2014).
     *
     * `legacy`. No break of the full 20 rounds, but differential attacks reach 19 and related-key work
     * reaches the full cipher.
     *
     * Its contribution is the design order: the authors searched for the best linear layer an eight-bit
     * microcontroller could afford and built the cipher round it, which is the opposite of every other
     * design in this family. The result is **four different linear maps** on four byte pairs where an SPN
     * would use one matrix -- and only two of the four are their own inverse.
     *
     * There is no key schedule: the first half of the key whitens at both ends and the second half is every
     * round key, distinguished only by a constant *added* to its odd bytes.
     */
    id: "pride",
    label: "PRIDE",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "pride",
      "lightweight",
      "crypto 2014",
      "leander",
      "paar",
      "albrecht",
      "bitslice",
      "linear layer",
      "no key schedule",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Built around the cheapest good linear layer: four different maps, and no key schedule.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * Piccolo-80, the generalised Feistel with a byte-permuting round shuffle (CHES 2011).
     *
     * `legacy`. No break of the full 25 rounds, but biclique attacks reach all of them just under
     * exhaustive search.
     *
     * What distinguishes it from TWINE and LBlock is the **round permutation**: rather than shuffling
     * nibbles it trades half-words between the four 16-bit state words, which is one byte-move per word on
     * an eight-bit machine and cheaper than any nibble shuffle. Its whitening keys are byte-interleaved
     * from the master key rather than sliced out of it.
     *
     * Piccolo-128 is not offered: a different schedule, and no reachable vector.
     */
    id: "piccolo",
    label: "Piccolo-80",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "piccolo",
      "piccolo-80",
      "generalised feistel",
      "lightweight",
      "ches 2011",
      "sony",
      "shibutani",
      "isobe",
      "encrypt",
      "decrypt",
    ],
    summary: "A generalised Feistel that trades half-words rather than shuffling nibbles.",
    block: { size: 8, keyLengths: [10], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * Robin, an LS-design (Grosso, Leurent, Standaert and Varici, FSE 2014).
     *
     * `broken`, and this is the one place in the family where that word is right. Leander, Minaud and
     * Ronjom's invariant-subspace attack applies to Robin's L-box and gives a distinguisher and weak-key
     * classes on the *full* cipher -- it is not a reduced-round result. Robin\* below is the authors' own
     * response to it, and is the member to use.
     *
     * The design is worth having anyway, because Robin is the cleanest demonstration of what an LS-design
     * is: a **L**inear box over a 16-bit word and an **S**ubstitution box across eight of them, both
     * involutions, so that decryption is encryption with the round constants reversed. There is no key
     * schedule.
     */
    id: "robin",
    label: "Robin",
    category: "Lightweight",
    aead: false,
    security: "broken",
    tags: [
      "robin",
      "ls-design",
      "lsdesign",
      "fse 2014",
      "grosso",
      "standaert",
      "bitslice",
      "involution",
      "invariant subspace",
      "lightweight",
      "encrypt",
      "decrypt",
    ],
    summary:
      "An LS-design with two involutions -- and a full-cipher invariant-subspace attack.",
    block: { size: 16, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * Robin*, the authors' response to the invariant-subspace attack on Robin.
     *
     * `legacy`. No attack on this one, and the change is remarkably small: **only the round constant**
     * differs, from a table lookup into the L-box's own first half to an incrementing counter rotated per
     * word. Every table is shared with Robin, which this repo's tests assert -- and the counter is what
     * breaks the invariant subspace.
     *
     * `legacy` rather than `modern` because it has had far less analysis than its own predecessor, and
     * because nothing has been built on it.
     */
    id: "robinstar",
    label: "Robin*",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "robin*",
      "robinstar",
      "robin star",
      "ls-design",
      "lsdesign",
      "fse 2014",
      "bitslice",
      "involution",
      "lightweight",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Robin with a counter for a round constant, which is what closes its invariant subspace.",
    block: { size: 16, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * Fantomas, the other LS-design from the same paper.
     *
     * `legacy`. No attack on the full twelve rounds. Where Robin picked involutions for both boxes and got
     * a free inverse, Fantomas gave that up for a better bound -- so it needs a separate inverse S-box and
     * a separate inverse L-box, and it runs twelve rounds where Robin runs sixteen.
     *
     * Its S-box is the more interesting of the two: a 5-bit box, a **3-bit Keccak S-box**, and two
     * cross-XOR layers between them -- which is how an 8-bit S-box gets built out of pieces small enough
     * to bitslice cheaply.
     */
    id: "fantomas",
    label: "Fantomas",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "fantomas",
      "ls-design",
      "lsdesign",
      "fse 2014",
      "grosso",
      "leurent",
      "standaert",
      "bitslice",
      "keccak s-box",
      "lightweight",
      "encrypt",
      "decrypt",
    ],
    summary: "An LS-design that trades Robin's free inverse for a better bound. Twelve rounds.",
    block: { size: 16, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * RoadRunneR at 80 bits, a Feistel whose round function is itself a small SPN (LightSec 2015).
     *
     * `legacy`. No attack on the full cipher; unstandardised and undeployed.
     *
     * The pair with `roadrunner128` is the interesting part: the two differ in more than key length,
     * because ten bytes is not a multiple of the four a round layer consumes -- so this variant walks the
     * key one byte at a time modulo ten and a layer's material straddles the wrap, where the 128-bit
     * variant reads four aligned words. Treating them as one cipher with a shorter key is right for the
     * first two layers of the first round and wrong from the third.
     */
    id: "roadrunner80",
    label: "RoadRunneR-80",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "roadrunner",
      "roadrunner80",
      "roadrunner-64/80",
      "lightsec 2015",
      "baysal",
      "sahin",
      "bitslice",
      "feistel",
      "spn round function",
      "lightweight",
      "encrypt",
      "decrypt",
    ],
    summary: "A Feistel whose round function is a three-layer SPN. Ten rounds at 80 bits.",
    block: { size: 8, keyLengths: [10], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * RoadRunneR at 128 bits: twelve rounds, and the key read as four aligned 32-bit words.
     *
     * Registered separately from `roadrunner80` rather than as a parameter set, because the two are
     * named separately in the paper and each has its own published vectors -- the same call the SPARX
     * and RECTANGLE pairs got. See `roadrunner80` for why the key handling is not simply "the same
     * thing, wider".
     */
    id: "roadrunner128",
    label: "RoadRunneR-128",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "roadrunner",
      "roadrunner128",
      "roadrunner-64/128",
      "lightsec 2015",
      "baysal",
      "sahin",
      "bitslice",
      "feistel",
      "spn round function",
      "lightweight",
      "encrypt",
      "decrypt",
    ],
    summary: "RoadRunneR at 128 bits: twelve rounds, and the key read as four aligned words.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * Lilliput-80, an extended generalised Feistel network (IEEE Trans. Computers 2016).
     *
     * `legacy`. Unstandardised and undeployed.
     *
     * Its Feistel is neither classical nor Type-2: sixteen nibble branches, and one round updates all
     * eight right-hand branches from all eight left-hand ones at once, with the last taking a running XOR
     * of seven of them. That is what buys full diffusion in a single round. The work is in the key
     * schedule rather than the round function -- two coupled linear feedback state machines over twenty
     * nibbles, with the round key bit-transposed through a multiply-by-four-modulo-31 pattern.
     */
    id: "lilliput",
    label: "Lilliput-80",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "lilliput",
      "lilliput-80",
      "egfn",
      "extended generalised feistel",
      "berger",
      "francq",
      "minier",
      "thomas",
      "nibble",
      "lightweight",
      "encrypt",
      "decrypt",
    ],
    summary:
      "An extended generalised Feistel over sixteen nibbles. Thirty rounds; the schedule is the work.",
    block: { size: 8, keyLengths: [10], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * Ten functions behind one control.
     *
     * Speck's word size sets the block, the key word count sets the key, and both together decide the
     * round count -- so every one of the ten is a different function rather than a truncation or a
     * mode of another. That is a fact about the implementation, not a reason for ten sidebar
     * entries: `SIMON_SPECK_VARIANTS` in `@ocs/algos` is one parameterised implementation, and this
     * is one tool over it.
     *
     * `block` carries the *default* set's numbers so the eager half has something honest to show.
     * Everything in the compute path reads the resolved set instead -- see `resolveParamSet` -- and
     * that distinction matters here more than anywhere else in this family, because the block size
     * is what decides the IV length.
     */
    id: "speck",
    label: "Speck",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "speck",
      "lightweight",
      "arx",
      "nsa",
      "iso 29167",
      "encrypt",
      "decrypt",
      "speck32/64",
      "speck48/72",
      "speck48/96",
      "speck64/96",
      "speck64/128",
      "speck96/96",
      "speck96/144",
      "speck128/128",
      "speck128/192",
      "speck128/256",
      "speck128",
    ],
    summary: "Speck at ten block/key sizes, from 32 to 128 bits. No tables at all.",
    block: { size: 16, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
    defaultParamSet: "128-128",
    paramSets: [
      {
        id: "32-64",
        label: "Speck32/64",
        blockSize: 4,
        keyLength: 8,
        summary:
          "32-bit block, 64-bit key -- 256 KB under one key before ciphertext blocks repeat",
      },
      {
        id: "48-72",
        label: "Speck48/72",
        blockSize: 6,
        keyLength: 9,
        summary:
          "48-bit block, 72-bit key -- 96 MB under one key before ciphertext blocks repeat",
      },
      {
        id: "48-96",
        label: "Speck48/96",
        blockSize: 6,
        keyLength: 12,
        summary:
          "48-bit block, 96-bit key -- 96 MB under one key before ciphertext blocks repeat",
      },
      {
        id: "64-96",
        label: "Speck64/96",
        blockSize: 8,
        keyLength: 12,
        summary:
          "64-bit block, 96-bit key -- 32 GB under one key before ciphertext blocks repeat",
      },
      {
        id: "64-128",
        label: "Speck64/128",
        blockSize: 8,
        keyLength: 16,
        summary:
          "64-bit block, 128-bit key -- 32 GB under one key before ciphertext blocks repeat",
      },
      {
        id: "96-96",
        label: "Speck96/96",
        blockSize: 12,
        keyLength: 12,
        summary: "96-bit block, 96-bit key -- no practical repeat limit",
      },
      {
        id: "96-144",
        label: "Speck96/144",
        blockSize: 12,
        keyLength: 18,
        summary: "96-bit block, 144-bit key -- no practical repeat limit",
      },
      {
        id: "128-128",
        label: "Speck128/128",
        blockSize: 16,
        keyLength: 16,
        summary: "128-bit block, 128-bit key -- no practical repeat limit",
      },
      {
        id: "128-192",
        label: "Speck128/192",
        blockSize: 16,
        keyLength: 24,
        summary: "128-bit block, 192-bit key -- no practical repeat limit",
      },
      {
        id: "128-256",
        label: "Speck128/256",
        blockSize: 16,
        keyLength: 32,
        summary: "128-bit block, 256-bit key -- no practical repeat limit",
      },
    ],
  },
  {
    /**
     * Ten functions behind one control.
     *
     * Simon's word size sets the block, the key word count sets the key, and both together decide the
     * round count -- so every one of the ten is a different function rather than a truncation or a
     * mode of another. That is a fact about the implementation, not a reason for ten sidebar
     * entries: `SIMON_SPECK_VARIANTS` in `@ocs/algos` is one parameterised implementation, and this
     * is one tool over it.
     *
     * `block` carries the *default* set's numbers so the eager half has something honest to show.
     * Everything in the compute path reads the resolved set instead -- see `resolveParamSet` -- and
     * that distinction matters here more than anywhere else in this family, because the block size
     * is what decides the IV length.
     */
    id: "simon",
    label: "Simon",
    category: "Lightweight",
    aead: false,
    security: "legacy",
    tags: [
      "simon",
      "lightweight",
      "and-rotate-xor",
      "nsa",
      "iso 29167",
      "encrypt",
      "decrypt",
      "simon32/64",
      "simon48/72",
      "simon48/96",
      "simon64/96",
      "simon64/128",
      "simon96/96",
      "simon96/144",
      "simon128/128",
      "simon128/192",
      "simon128/256",
      "simon128",
    ],
    summary:
      "Simon at ten block/key sizes. Speck's twin, built for gates rather than registers.",
    block: { size: 16, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
    defaultParamSet: "128-128",
    paramSets: [
      {
        id: "32-64",
        label: "Simon32/64",
        blockSize: 4,
        keyLength: 8,
        summary:
          "32-bit block, 64-bit key -- 256 KB under one key before ciphertext blocks repeat",
      },
      {
        id: "48-72",
        label: "Simon48/72",
        blockSize: 6,
        keyLength: 9,
        summary:
          "48-bit block, 72-bit key -- 96 MB under one key before ciphertext blocks repeat",
      },
      {
        id: "48-96",
        label: "Simon48/96",
        blockSize: 6,
        keyLength: 12,
        summary:
          "48-bit block, 96-bit key -- 96 MB under one key before ciphertext blocks repeat",
      },
      {
        id: "64-96",
        label: "Simon64/96",
        blockSize: 8,
        keyLength: 12,
        summary:
          "64-bit block, 96-bit key -- 32 GB under one key before ciphertext blocks repeat",
      },
      {
        id: "64-128",
        label: "Simon64/128",
        blockSize: 8,
        keyLength: 16,
        summary:
          "64-bit block, 128-bit key -- 32 GB under one key before ciphertext blocks repeat",
      },
      {
        id: "96-96",
        label: "Simon96/96",
        blockSize: 12,
        keyLength: 12,
        summary: "96-bit block, 96-bit key -- no practical repeat limit",
      },
      {
        id: "96-144",
        label: "Simon96/144",
        blockSize: 12,
        keyLength: 18,
        summary: "96-bit block, 144-bit key -- no practical repeat limit",
      },
      {
        id: "128-128",
        label: "Simon128/128",
        blockSize: 16,
        keyLength: 16,
        summary: "128-bit block, 128-bit key -- no practical repeat limit",
      },
      {
        id: "128-192",
        label: "Simon128/192",
        blockSize: 16,
        keyLength: 24,
        summary: "128-bit block, 192-bit key -- no practical repeat limit",
      },
      {
        id: "128-256",
        label: "Simon128/256",
        blockSize: 16,
        keyLength: 32,
        summary: "128-bit block, 256-bit key -- no practical repeat limit",
      },
    ],
  },
  {
    /**
     * Two key sizes, and the shorter one is a different construction rather than a shorter key.
     *
     * 24 bytes is three-key 3DES -- `des-ede3` -- and 16 bytes is the two-key variant, where the
     * third key repeats the first. `constructionLabel` reads the key length to tell them apart,
     * which is why the label it produces is `3DES-EDE3` or `3DES-EDE` rather than a size in bits
     * like every other multi-key cipher here.
     */
    id: "3des",
    label: "Triple DES",
    category: "Legacy",
    aead: false,
    security: "legacy",
    tags: [
      "3des",
      "triple des",
      "tdea",
      "des-ede3",
      "des3",
      "legacy",
      "pkcs12",
      "openssl",
      "encrypt",
      "decrypt",
    ],
    summary: "DES applied three times. What `openssl enc -des-ede3-cbc` wrote for two decades.",
    block: { size: 8, keyLengths: [16, 24], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    id: "des",
    label: "DES",
    category: "Legacy",
    aead: false,
    security: "broken",
    tags: ["des", "fips46", "legacy", "broken", "56-bit", "encrypt", "decrypt"],
    summary: "The 1977 standard, 56-bit key. Brute-forceable; kept for archaeology.",
    block: { size: 8, keyLengths: [8], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * An AES finalist, and the second cipher here whose S-boxes were already in the tree.
     *
     * CAST-256 is CAST5 widened: the same four S-boxes, the same three round functions, a 128-bit
     * block over four registers and 48 rounds as twelve quad-rounds. So `cast6.ts` stores no tables --
     * the reuse is the point, because those 1024 constants are already pinned by CAST5's own RFC 2144
     * vector, and a CAST-256 failure therefore points at its key schedule rather than at the tables.
     */
    id: "cast6",
    label: "CAST-256",
    category: "AES finalists",
    aead: false,
    security: "modern",
    tags: [
      "cast-256",
      "cast6",
      "cast256",
      "rfc 2612",
      "aes finalist",
      "entrust",
      "adams",
      "encrypt",
      "decrypt",
    ],
    summary: "RFC 2612's AES finalist. CAST5 widened to a 128-bit block over 48 rounds.",
    block: {
      size: 16,
      // Every 32-bit step the RFC defines. A shorter key is zero-padded to 256 bits by the schedule,
      // which is what makes 160, 192 and 224 legal sizes rather than special cases.
      keyLengths: [16, 20, 24, 28, 32],
      modes: ["cbc", "cfb", "ofb", "ctr", "ecb"],
    },
  },
  {
    /**
     * The other AES finalist here, and the one that introduced a quadratic round function.
     *
     * RC6's B * (2B + 1) exists to make the data-dependent rotation amount depend on every bit of B
     * rather than on its low five, which is the weakness RC5 had. Note the implementation constraint
     * that comes with it: that product overflows a double, so it needs `Math.imul`.
     */
    id: "rc6",
    label: "RC6",
    category: "AES finalists",
    aead: false,
    security: "modern",
    tags: [
      "rc6",
      "rivest",
      "aes finalist",
      "rsa security",
      "data-dependent rotation",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Rivest's AES finalist: RC5 widened to four registers, with a quadratic round function.",
    block: { size: 16, keyLengths: [16, 24, 32], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * RC5, where the round count is a real parameter rather than a naming convention.
     *
     * RC5-w/r/b is three numbers. Only the 32-bit word is offered -- the one every deployment used and
     * the one with reachable vectors -- but the rounds get their own control, because 12 and 16 are
     * both in the field and produce completely different ciphertext. This is the second option in this
     * family that belongs to a single tool, after RC2's effective key length.
     */
    id: "rc5",
    label: "RC5",
    category: "Legacy",
    aead: false,
    // Twelve rounds falls to differential cryptanalysis given about 2^44 chosen plaintexts, and 12 is
    // what the deployments used. Sixteen has no practical attack; the round-count control says so.
    security: "legacy",
    tags: [
      "rc5",
      "rc5-32",
      "rivest",
      "data-dependent rotation",
      "variable rounds",
      "encrypt",
      "decrypt",
    ],
    summary: "Rivest's 1994 cipher, RC5-32/r/b. The round count is a parameter, not a name.",
    block: {
      size: 8,
      // A range like Blowfish's: the specification allows up to 255 bytes, and the key is loaded into
      // little-endian words, so a 1-byte key is exactly its zero-padded 4-byte form.
      keyLengths: [],
      keyRange: { min: 1, max: 255 },
      modes: ["cbc", "cfb", "ofb", "ctr", "ecb"],
    },
  },
  {
    /**
     * Skein's block cipher, and the only tweakable one here.
     *
     * Three widths, and the key is always the same size as the block -- which is why this is one tool
     * with three parameter sets rather than three tools: nobody says "Threefish" meaning only the
     * 512-bit one, and the width is a knob in exactly the way Simon's and Speck's are.
     *
     * The tweak is its third input and gets its own control. It is neither secret nor required to be
     * unique; its job is to turn one key into a family of independent permutations, which is what disk
     * encryption wants and what Skein uses for domain separation.
     */
    id: "threefish",
    label: "Threefish",
    category: "Other block ciphers",
    aead: false,
    security: "modern",
    tags: [
      "threefish",
      "threefish-256",
      "threefish-512",
      "threefish-1024",
      "skein",
      "tweakable",
      "sha-3 finalist",
      "arx",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Skein's tweakable block cipher, at 256, 512 and 1024 bits. Add, rotate, XOR, no tables.",
    block: {
      size: 64,
      keyLengths: [32, 64, 128],
      modes: ["cbc", "cfb", "ofb", "ctr", "ecb"],
    },
    paramSets: [
      {
        id: "512-512",
        label: "Threefish-512",
        blockSize: 64,
        keyLength: 64,
        summary: "72 rounds, and the width Skein-512 uses",
      },
      {
        id: "256-256",
        label: "Threefish-256",
        blockSize: 32,
        keyLength: 32,
        summary: "72 rounds over four words",
      },
      {
        id: "1024-1024",
        label: "Threefish-1024",
        blockSize: 128,
        keyLength: 128,
        summary: "80 rounds over sixteen words -- the widest block in the app",
      },
    ],
    defaultParamSet: "512-512",
  },
  {
    /**
     * XTEA, and TEA below it: two ciphers that differ by one line of arithmetic.
     *
     * Both are 64-bit block, 128-bit key, 32 rounds, the same delta. XTEA is the authors' own repair --
     * TEA reuses its four key words in the same order every round, which is what its related-key
     * attack exploits, and XTEA selects a word by bits of the running sum instead.
     */
    id: "xtea",
    label: "XTEA",
    category: "Legacy",
    aead: false,
    // Not broken, but a 64-bit block collides after about 32 GB under one key, which `C007` computes.
    security: "legacy",
    tags: ["xtea", "tea", "wheeler", "needham", "tiny", "embedded", "encrypt", "decrypt"],
    summary: "The corrected Tiny Encryption Algorithm. 64-bit block, 128-bit key, no tables.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * XXTEA -- "Corrected Block TEA", the third and last of Needham and Wheeler's TEA papers (1998).
     *
     * `legacy`. No published break of the full cipher, and a 64-bit block collides after about 32 GB
     * under one key, which `C007` computes.
     *
     * Registered here at **two words**, which is the 64-bit-block instantiation: the same block, key
     * and 32 rounds as TEA and XTEA, so the three are directly comparable -- which is the only reason
     * to want this one. XXTEA is really variable-length (`6 + 52/n` rounds over `n` words, so a
     * different function per length); `xxteaWords` in `@ocs/algos` exposes that for anyone who needs it.
     *
     * **It has no published test vector anywhere.** The note prints reference C and no values;
     * Crypto++ has TEA and XTEA and not this; and the `xxtea.io` libraries are not a source, since
     * their own README says they implement something different. See `tea.ts`. It is offered on the
     * user's explicit instruction rather than because this repo's usual gate was met.
     */
    id: "xxtea",
    label: "XXTEA",
    category: "Legacy",
    aead: false,
    security: "legacy",
    tags: [
      "xxtea",
      "corrected block tea",
      "btea",
      "tea",
      "xtea",
      "wheeler",
      "needham",
      "tiny",
      "embedded",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Corrected Block TEA, at two words. Same shape as TEA and XTEA; no published vector.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    id: "tea",
    label: "TEA",
    category: "Legacy",
    aead: false,
    /**
     * `broken`, and specifically: a related-key attack recovers the key with about 2^23 chosen
     * plaintexts, and every key has three equivalents -- so the effective key size is 126 bits rather
     * than 128. It is here because the original Xbox's boot ROM and a great deal of embedded firmware
     * used it, which is a reason to be able to reproduce a value rather than to choose one.
     */
    security: "broken",
    tags: [
      "tea",
      "tiny encryption algorithm",
      "wheeler",
      "needham",
      "xbox",
      "embedded",
      "encrypt",
      "decrypt",
    ],
    summary: "Wheeler and Needham's 1994 cipher, in about ten lines. Related-key broken.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * SKIPJACK: the NSA's Clipper cipher, declassified in 1998, and here for the history as much as
     * the arithmetic.
     *
     * No key schedule at all -- the ten key bytes are used directly, cycled, so round k reads bytes 4k
     * through 4k+3 modulo 10. Two alternating round rules over four groups of eight.
     */
    id: "skipjack",
    label: "SKIPJACK",
    category: "Legacy",
    aead: false,
    // An 80-bit key is the problem rather than the design: 31 of its 32 rounds fall to impossible
    // differentials, the full cipher has no practical attack, and 80 bits is within reach.
    security: "broken",
    tags: [
      "skipjack",
      "clipper",
      "capstone",
      "nsa",
      "fortezza",
      "declassified",
      "80-bit",
      "encrypt",
      "decrypt",
    ],
    summary: "The declassified Clipper cipher. 64-bit block, 80-bit key, no key schedule.",
    block: { size: 8, keyLengths: [10], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * LEA, Korea's lightweight cipher and an ISO/IEC 29192-2 standard.
     *
     * Add-rotate-XOR throughout: no S-box, no table, and eight delta constants. Designed for speed in
     * *software* on a 32-bit machine, which is the opposite of PRESENT's gate-count goal -- both are in
     * ISO 29192 and they are lightweight in two different senses.
     */
    id: "lea",
    label: "LEA",
    category: "Lightweight",
    aead: false,
    security: "modern",
    tags: [
      "lea",
      "iso 29192",
      "ks x 3246",
      "korea",
      "kisa",
      "lightweight",
      "arx",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Korea's ISO 29192-2 lightweight cipher. 128-bit block, add-rotate-XOR, no tables.",
    block: {
      size: 16,
      // Three key sizes and, unusually, three genuinely different key schedules rather than one
      // parameterised by length. The round count follows: 24, 28, 32.
      keyLengths: [16, 24, 32],
      modes: ["cbc", "cfb", "ofb", "ctr", "ecb"],
    },
  },
  {
    /**
     * CLEFIA, RFC 6114 and ISO/IEC 29192-2. Sony's lightweight 128-bit block cipher.
     *
     * `modern`: no attack reaches the full round count at any key length, and it is a current ISO
     * lightweight standard. Its structure is a four-branch generalised Feistel network rather than an
     * SPN, which is what lets it use two different diffusion matrices and two different S-boxes -- one
     * built from four 4-bit boxes, the other from the inverse function over GF(2^8).
     *
     * Its 236 round constants are *derived* from a 16-bit seed rather than stored; RFC 6114 publishes
     * both the seed sequence and the constants, so the derivation is checked rather than trusted.
     */
    id: "clefia",
    label: "CLEFIA",
    category: "Other block ciphers",
    aead: false,
    security: "modern",
    tags: [
      "clefia",
      "sony",
      "rfc 6114",
      "iso 29192-2",
      "lightweight",
      "generalized feistel",
      "japan",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Sony's ISO lightweight standard. 128-bit block, a four-branch generalised Feistel.",
    block: { size: 16, keyLengths: [16, 24, 32], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * MARS, IBM's AES finalist.
     *
     * `legacy`, and the reason is the reason it lost: not an attack -- there is none on the full cipher
     * -- but complexity. MARS runs three structurally different phases (unkeyed forward mixing, sixteen
     * keyed rounds, unkeyed backward mixing) where Rijndael runs one, and the AES report singled that
     * out as making it the hardest of the five to analyse and to implement correctly. It is here
     * because reproducing an AES-finalist value is a real thing to need, not because anyone should
     * choose it over AES.
     *
     * Note that the round count does *not* change with the key size: 32 rounds always.
     */
    id: "mars",
    label: "MARS",
    category: "Other block ciphers",
    aead: false,
    security: "legacy",
    tags: ["mars", "ibm", "aes finalist", "aes candidate", "coppersmith", "encrypt", "decrypt"],
    summary:
      "IBM's AES finalist. Three phases, a 512-word S-box, and a data-dependent rotation.",
    block: { size: 16, keyLengths: [16, 24, 32], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * KASUMI, 3GPP TS 35.202 -- the cipher behind A5/3, GEA3, f8 and f9.
     *
     * `broken`, and not marginally: Biham, Dunkelman and Keller's 2010 related-key attack recovers the
     * full 128-bit key from four related keys with 2^26 data and 2^32 time, which is minutes of
     * computation. That is a related-key model rather than a single-key break, and the honest posture is
     * still `broken` -- 3G's key hierarchy makes related keys reachable, and the attack was published
     * with a working implementation.
     *
     * It is here to reproduce values: this is what GSM, GPRS and 3G confidentiality actually ran on for
     * two decades, so a captured frame is a real thing to want to check.
     *
     * A modification of MISTY1, and *not* a configuration of it: different S-boxes, a different FI, and
     * a round structure that takes two rounds at a time.
     */
    id: "kasumi",
    label: "KASUMI",
    category: "Other block ciphers",
    aead: false,
    security: "broken",
    tags: [
      "kasumi",
      "a5/3",
      "gea3",
      "f8",
      "f9",
      "3gpp",
      "ts 35.202",
      "gsm",
      "gprs",
      "3g",
      "umts",
      "misty1",
      "encrypt",
      "decrypt",
    ],
    summary:
      "3GPP's MISTY1 variant, behind A5/3 and 3G. Broken under related keys; here to reproduce.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * Anubis, Barreto and Rijmen's NESSIE submission -- Khazad's sibling at a 128-bit block.
     *
     * `legacy`. No attack on the full cipher; NESSIE declined to select it and nothing has been built on
     * it since. Involutional, like Khazad: the S-box and the diffusion matrix are each their own
     * inverse, so encryption and decryption are one circuit and only the key schedule runs backwards.
     *
     * It is the only cipher here with **seven** key lengths -- 128 to 320 bits in 32-bit steps -- and
     * the round count moves with them, 12 to 18. And **nothing is stored except one S-box**: the tweaked
     * variant's is Khazad's entry for entry, the round constants are that S-box read four bytes at a
     * time, and every table an implementation normally ships comes out of the involutory matrix.
     */
    id: "anubis",
    label: "Anubis",
    category: "Other block ciphers",
    aead: false,
    security: "legacy",
    tags: [
      "anubis",
      "nessie",
      "barreto",
      "rijmen",
      "involutional",
      "khazad",
      "whirlpool",
      "tweaked",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Khazad's 128-bit sibling: involutional, seven key lengths, almost nothing stored.",
    block: {
      size: 16,
      keyLengths: [16, 20, 24, 28, 32, 36, 40],
      modes: ["cbc", "cfb", "ofb", "ctr", "ecb"],
    },
  },
  {
    /**
     * SAFER+, Massey, Khachatrian and Kuregian's AES candidate -- and Bluetooth's legacy pairing cipher.
     *
     * `legacy`. No break of the full cipher, but it did not reach the AES final five and its key
     * schedule is the reason: related-key and collision attacks reach reduced-round variants, and
     * nothing has been built on it since. It is here to reproduce values -- SAFER+ is the E21/E22/E1
     * primitive in Bluetooth pairing before 4.2, so a captured link key is a real thing to check.
     *
     * The design is unlike anything else here. **No S-box table and no MDS matrix**: substitution is
     * `45^x mod 257` and its inverse, and diffusion is a Pseudo-Hadamard Transform -- addition mod 256
     * rather than XOR -- with a fixed byte shuffle between passes. All 512 bytes of key-schedule bias
     * come out of the same exponentiation, so this cipher stores nothing at all.
     */
    id: "saferp",
    label: "SAFER+",
    category: "Other block ciphers",
    aead: false,
    security: "legacy",
    tags: [
      "safer+",
      "saferp",
      "safer plus",
      "aes candidate",
      "massey",
      "bluetooth",
      "e21",
      "e22",
      "e1",
      "pairing",
      "link key",
      "cylink",
      "encrypt",
      "decrypt",
    ],
    summary:
      "An AES candidate behind Bluetooth pairing. Exponentiation for an S-box, nothing stored.",
    block: { size: 16, keyLengths: [16, 24, 32], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * Khazad, Barreto and Rijmen's NESSIE submission -- an involutional 64-bit-block SPN.
     *
     * `legacy`. There is no attack on the full eight rounds, but the 64-bit block carries a birthday
     * bound at about 32 GB under one key, which `C007` computes; and NESSIE declined to select it,
     * citing the security margin of the earlier seven-round version rather than a break of this one.
     *
     * The design is worth knowing for one property: it is *involutional*. Its S-box and its diffusion
     * matrix are each their own inverse, so encryption and decryption are the same circuit and only the
     * key schedule runs backwards -- which is what made it attractive for hardware where area matters.
     * And nothing is stored: the 8-bit S-box is derived from sixteen bytes.
     */
    id: "khazad",
    label: "Khazad",
    category: "Other block ciphers",
    aead: false,
    security: "legacy",
    tags: [
      "khazad",
      "nessie",
      "barreto",
      "rijmen",
      "involutional",
      "anubis",
      "whirlpool",
      "lightweight",
      "encrypt",
      "decrypt",
    ],
    summary: "A NESSIE involutional cipher: one circuit for both directions, 64-bit block.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * MISTY1, RFC 2994 -- and the design 3GPP's KASUMI is a modification of.
     *
     * `legacy`: the full 8-round cipher has an integral cryptanalysis (Todo, 2015) recovering the key
     * with about 2^64 chosen plaintexts and 2^70 time. That is far from a practical break of a single
     * message and far from a margin anyone should build on, which is what `legacy` means here.
     *
     * Historically important for a reason worth stating: it was the first widely published cipher whose
     * round function was *provably* bounded against differential and linear cryptanalysis, rather than
     * argued to be resistant.
     */
    id: "misty1",
    label: "MISTY1",
    category: "Other block ciphers",
    aead: false,
    security: "legacy",
    tags: [
      "misty1",
      "misty",
      "matsui",
      "rfc 2994",
      "nessie",
      "kasumi",
      "3gpp",
      "japan",
      "encrypt",
      "decrypt",
    ],
    summary: "Matsui's provably differential-resistant Feistel. 64-bit block, 128-bit key.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * HIGHT, ISO/IEC 18033-3 and a Korean national standard (KS X 1213).
     *
     * `legacy` for the same shape of reason as MISTY1: there is no practical break, but a 64-bit block
     * has a birthday bound at about 32 GB under one key -- which `C007` computes and states rather than
     * leaving in a prose note -- and the published attacks reach the full 32 rounds in the related-key
     * setting.
     *
     * Designed to be small in hardware, which is why its round function is add/XOR/rotate over byte
     * lanes with no S-box at all. Its two F functions and its 128 round constants are *derived* rather
     * than stored -- see the header of `phase6-ciphers.ts`.
     */
    id: "hight",
    label: "HIGHT",
    category: "Other block ciphers",
    aead: false,
    security: "legacy",
    tags: [
      "hight",
      "high security and light weight",
      "kisa",
      "korea",
      "iso 18033-3",
      "lightweight",
      "arx",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Korea's lightweight standard. 64-bit block, 128-bit key, add-rotate-XOR, no S-box.",
    block: { size: 8, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * Noekeon, by four of the Rijndael and Keccak authors, submitted to NESSIE.
     *
     * The design goal was the smallest possible description: the round is four operations over four
     * words and the only constants are seventeen bytes of an LFSR sequence. In direct-key mode there is
     * no key schedule at all -- the key is used as it arrives.
     */
    id: "noekeon",
    label: "Noekeon",
    category: "Other block ciphers",
    aead: false,
    /**
     * `legacy`, and the reason is specific rather than a shrug: this is **direct-key mode**, which has
     * a related-key attack, and NESSIE cited exactly that when declining to select it. Noekeon also
     * defines an *indirect* mode that runs the cipher over the key first specifically to prevent it --
     * but direct mode is what every implementation ships and what the published vectors are for, so it
     * is what this reproduces. Under a single unrelated key there is no practical attack.
     */
    security: "legacy",
    tags: [
      "noekeon",
      "nessie",
      "daemen",
      "rijmen",
      "keccak team",
      "direct key",
      "encrypt",
      "decrypt",
    ],
    summary:
      "A NESSIE submission from the Rijndael authors, in direct-key mode. No key schedule.",
    block: { size: 16, keyLengths: [16], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * SHACAL-2: SHA-256's compression function run as a block cipher, and a NESSIE selection.
     *
     * The block *is* the 256-bit chaining value and the key *is* the 512-bit message block, expanded
     * through SHA-256's own message schedule -- with the Davies-Meyer feedforward removed, since adding
     * the input back is what makes a compression function one-way and a cipher has to invert.
     *
     * Two consequences worth stating: the key is *larger than the block*, which nothing else here does,
     * and the round constants are SHA-256's, so they are derived from the cube roots of the first 64
     * primes rather than transcribed.
     */
    id: "shacal2",
    label: "SHACAL-2",
    category: "Other block ciphers",
    aead: false,
    /**
     * `legacy` on deployment rather than on strength: NESSIE selected it, and no practical attack on
     * the full 64 rounds is known -- but nothing uses it, so a value produced here is being compared
     * against a reference implementation rather than against a system.
     */
    security: "legacy",
    tags: [
      "shacal",
      "shacal-2",
      "shacal2",
      "nessie",
      "sha-256",
      "davies-meyer",
      "encrypt",
      "decrypt",
    ],
    summary:
      "SHA-256's compression function as a cipher. 256-bit block, 512-bit key, NESSIE selected.",
    block: {
      size: 32,
      // A range, like Blowfish's: 128 to 512 bits, zero-padded to the full message block.
      keyLengths: [],
      keyRange: { min: 16, max: 64 },
      modes: ["cbc", "cfb", "ofb", "ctr", "ecb"],
    },
  },
  {
    id: "shacal1",
    label: "SHACAL-1",
    category: "Other block ciphers",
    aead: false,
    security: "legacy",
    tags: ["shacal", "shacal-1", "shacal1", "nessie", "sha-1", "davies-meyer", "encrypt", "decrypt"],
    summary: "SHA-1's compression function as a 160-bit block cipher with keys up to 512 bits.",
    block: {
      size: 20,
      keyLengths: [],
      keyRange: { min: 16, max: 64 },
      modes: ["cbc", "cfb", "ofb", "ctr", "ecb"],
    },
  },
  {
    id: "qarma",
    label: "QARMA-64",
    category: "Lightweight",
    aead: false,
    security: "modern",
    tags: ["qarma", "qarma-64", "qarma64", "arm", "pac", "tweakable", "pointer-authentication", "encrypt", "decrypt"],
    summary: "Hardware tweakable block cipher with alpha-reflection chosen for ARMv8.3-A Pointer Authentication (PAC).",
    block: {
      size: 8,
      keyLengths: [16],
      modes: ["cbc", "ctr", "ecb"],
    },
  },
  {
    id: "mantis",
    label: "MANTIS-7",
    category: "Lightweight",
    aead: false,
    security: "modern",
    tags: ["mantis", "mantis-7", "tweakable", "memory-encryption", "low-latency", "crypto2016", "encrypt", "decrypt"],
    summary: "Low-latency tweakable block cipher designed for memory bus and cache line encryption.",
    block: {
      size: 8,
      keyLengths: [16],
      modes: ["cbc", "ctr", "ecb"],
    },
  },
  {
    id: "craft",
    label: "CRAFT",
    category: "Lightweight",
    aead: false,
    security: "modern",
    tags: ["craft", "tweakable", "fault-attack", "lightweight", "fse2019", "encrypt", "decrypt"],
    summary: "Lightweight tweakable block cipher optimized for fault-attack resistance and fast round execution.",
    block: {
      size: 8,
      keyLengths: [16],
      modes: ["cbc", "ctr", "ecb"],
    },
  },
  {
    id: "midori",
    label: "Midori-64",
    category: "Lightweight",
    aead: false,
    security: "modern",
    tags: ["midori", "midori-64", "ultra-low-energy", "iot", "asiacrypt2015", "encrypt", "decrypt"],
    summary: "Ultra-low energy 64-bit block cipher designed for battery-less IoT and RFID devices.",
    block: {
      size: 8,
      keyLengths: [16],
      modes: ["cbc", "ctr", "ecb"],
    },
  },
  {
    /**
     * GOST 28147-89, the Soviet standard, and the cipher Magma is a respelling of.
     *
     * 64-bit block, 256-bit key, 32 Feistel rounds, and a key schedule that is not one: the eight
     * subkeys are the key, used in order three times and then in reverse.
     *
     * **The S-boxes are a parameter, and that is the whole difficulty of interoperating with it.** The
     * 1989 standard leaves them to the deploying organisation, so two implementations of "GOST"
     * agreeing on nothing is normal and it is always the tables. Both published sets are offered.
     */
    id: "gost28147",
    label: "GOST 28147-89",
    category: "National",
    aead: false,
    /**
     * `legacy`. Isobe and Dinur published attacks on the full cipher requiring the whole 2^64 codebook,
     * which is not practical but is below the design claim -- and Russia superseded it with Magma and
     * Kuznyechik in 2015. It is here to read old data, which is what a 64-bit block is for now.
     */
    security: "legacy",
    tags: [
      "gost",
      "gost 28147-89",
      "gost28147",
      "magma",
      "russia",
      "soviet",
      "national standard",
      "d-test",
      "cryptopro",
      "encrypt",
      "decrypt",
    ],
    summary:
      "The 1989 Soviet standard. 64-bit block, 256-bit key, and the S-boxes are a parameter.",
    block: { size: 8, keyLengths: [32], modes: ["cbc", "cfb", "ofb", "ctr", "ecb"] },
  },
  {
    /**
     * SNOW 3G, the generator behind 3GPP's 128-EEA1 and 128-EIA1 -- LTE confidentiality and integrity,
     * and UMTS's UEA2/UIA2 before them.
     *
     * `modern`, and it is the third 3GPP primitive here with three different verdicts: KASUMI is
     * `broken` under related keys, ZUC is the newer design 3GPP added alongside this one, and SNOW 3G
     * has no attack on its full form after two decades in every LTE handset.
     *
     * A sixteen-stage LFSR over GF(2^32) driving a three-register state machine -- SNOW 2.0 with a
     * third register and a second 32-bit S-box, which is what closed the distinguisher on SNOW 2.0.
     * One of those S-boxes substitutes bytes through the **AES S-box**, which is why the implementation
     * stores one table rather than two.
     *
     * Note this is the raw generator, keyed directly. The 128-EEA1 wrapper that LTE actually uses
     * derives the IV from a counter, a bearer id and a direction bit; feeding a captured bearer's
     * traffic through this tool means building that IV yourself.
     */
    id: "snow3g",
    label: "SNOW 3G",
    category: "Stream",
    aead: false,
    security: "modern",
    tags: [
      "snow3g",
      "snow 3g",
      "snow",
      "uea2",
      "uia2",
      "128-eea1",
      "128-eia1",
      "3gpp",
      "ts 35.216",
      "lte",
      "umts",
      "4g",
      "etsi",
      "sage",
      "stream",
      "encrypt",
      "decrypt",
    ],
    summary:
      "LTE's stream cipher. A GF(2^32) LFSR and a three-register FSM, half of it AES's S-box.",
    shape: { keyLengths: [16], nonceLengths: [16] },
  },
  {
    id: "snow-v",
    label: "SNOW-V",
    category: "Stream",
    aead: false,
    security: "modern",
    tags: ["snow-v", "snowv", "snow", "5g", "3gpp", "nr", "stream", "256-bit", "encrypt", "decrypt"],
    summary: "3GPP 5G New Radio stream cipher combining two 16-bit LFSRs with an AES-round FSM with 256-bit security.",
    shape: { keyLengths: [32], nonceLengths: [16] },
  },
  {
    id: "isaac",
    label: "ISAAC",
    category: "Stream",
    aead: false,
    security: "modern",
    tags: ["isaac", "isaac64", "prng", "csprng", "keystream", "jenkins", "encrypt", "decrypt"],
    summary: "Bob Jenkins' fast cryptographic keystream PRNG with guaranteed cycle length.",
    shape: { keyLengths: [16, 32], nonceLengths: [] },
  },
  {
    id: "pcg64",
    label: "PCG64",
    category: "Stream",
    aead: false,
    security: "not-encryption",
    tags: ["pcg", "pcg64", "dxsm", "prng", "keystream", "oneill", "encrypt", "decrypt"],
    summary: "Melissa O'Neill's PCG64 / PCG-DXSM fast statistical PRNG keystream generator.",
    shape: { keyLengths: [8, 16], nonceLengths: [] },
  },
  {
    id: "xoshiro256",
    label: "Xoshiro256++",
    category: "Stream",
    aead: false,
    security: "not-encryption",
    tags: ["xoshiro", "xoshiro256", "xoshiro256++", "prng", "vigna", "blackman", "encrypt", "decrypt"],
    summary: "Blackman & Vigna's fast high-dimensional PRNG keystream generator (period 2^256-1).",
    shape: { keyLengths: [32], nonceLengths: [] },
  },
  {
    id: "a5-1",
    label: "A5/1 (GSM Stream Cipher)",
    category: "Stream",
    aead: false,
    security: "legacy",
    tags: ["a51", "a5-1", "a5", "gsm", "cellular", "2g", "stream", "lfsr", "majority", "encrypt", "decrypt"],
    summary: "GSM 2G mobile communications stream cipher based on 3 clock-controlled LFSRs with majority rule.",
    shape: { keyLengths: [8], nonceLengths: [3] },
  },
  {
    id: "rc4-drop",
    label: "RC4-drop[N]",
    category: "Stream",
    aead: false,
    security: "legacy",
    tags: ["rc4-drop", "rc4", "arcfour", "stream", "drop768", "drop1024", "drop3072", "fms", "encrypt", "decrypt"],
    summary: "RC4 stream cipher discarding initial keystream bytes to eliminate Fluhrer-Mantin-Shamir initial state bias.",
    shape: { keyLengths: [5, 16, 32], nonceLengths: [] },
  },
  {
    /**
     * SOSEMANUK, eSTREAM's fourth software-profile winner -- and, with HC-128, HC-256 and Rabbit
     * already here, the one that completed the set.
     *
     * `modern`: no attack on the full cipher in the twenty years since, and the closest published work
     * is a guess-and-determine at about 2^148, above the 128-bit claim the designers make. Note the
     * claim *is* 128 bits regardless of key length -- a 256-bit key does not buy 256 bits of security
     * here, which the key note says outright, because a form offering 32 bytes implies otherwise.
     *
     * Structurally it is three unrelated pieces: Serpent's key schedule, Serpent reduced to 24 rounds
     * as the IV injection, and a ten-stage LFSR over GF(2^32) driving a two-register state machine
     * whose output goes through Serpent's S2 before being XORed back with the LFSR. Its name is Cree
     * for "snake", which is the joke about how much Serpent is in it.
     */
    id: "sosemanuk",
    label: "SOSEMANUK",
    category: "Stream",
    aead: false,
    security: "modern",
    tags: [
      "sosemanuk",
      "estream",
      "software profile",
      "serpent",
      "serpent24",
      "snow",
      "berbain",
      "lfsr",
      "gf(2^32)",
      "stream",
      "encrypt",
      "decrypt",
    ],
    summary: "eSTREAM's software finalist: Serpent's key schedule over an LFSR in GF(2^32).",
    shape: { keyLengths: [16, 24, 32], nonceLengths: [16] },
  },
  {
    /**
     * Trivium, eSTREAM's hardware-profile winner and the smallest cipher in this repo.
     *
     * `modern`: no attack on the full 1,152-round initialisation, and the published cryptanalysis
     * reaches reduced-round variants only -- cube attacks get to about 799 of its rounds. It is also an
     * ISO/IEC 29192-3 lightweight standard.
     *
     * 288 bits of state in three coupled nonlinear feedback registers, and **no tables, no constants and
     * no key schedule at all**. Its entire definition is fifteen tap positions.
     *
     * The IV is 32, 64 or 80 bits and eSTREAM publishes verified vectors for all three, which is why
     * three widths are offered rather than only the specification's 80.
     */
    id: "trivium",
    label: "Trivium",
    category: "Stream",
    aead: false,
    security: "modern",
    tags: [
      "trivium",
      "estream",
      "iso 29192-3",
      "de canniere",
      "preneel",
      "lightweight",
      "hardware",
      "stream",
      "encrypt",
      "decrypt",
    ],
    summary:
      "eSTREAM's hardware winner. 288 bits of state, no tables and no key schedule at all.",
    shape: { keyLengths: [10], nonceLengths: [4, 8, 10] },
  },
  {
    /**
     * Rabbit, RFC 4503 and an eSTREAM software portfolio finalist.
     *
     * `modern`: no attack better than exhaustive search on the full cipher, and it was one of the four
     * ciphers eSTREAM selected for its software profile. Its nonlinearity is a single squaring -- g(u,v)
     * XORs the two halves of a 64-bit square -- which is unusually simple for a cipher with no break.
     *
     * The IV is **optional**, and that is faithful rather than lax: RFC 4503 publishes vectors both
     * with and without IV setup, and they are unrelated keystreams. An empty nonce here means "no IV
     * setup", not "an IV of eight zero bytes" -- which is the one thing about this cipher a user can
     * get wrong with no error, so `C005` says so.
     */
    id: "rabbit",
    label: "Rabbit",
    category: "Stream",
    aead: false,
    security: "modern",
    tags: [
      "rabbit",
      "estream",
      "rfc 4503",
      "cryptico",
      "boesgaard",
      "stream",
      "encrypt",
      "decrypt",
    ],
    summary:
      "An eSTREAM software finalist. 128-bit key, optional 64-bit IV, one squaring per word.",
    shape: { keyLengths: [16], nonceLengths: [0, 8] },
  },
  {
    /**
     * ZUC-128, the 3GPP stream cipher: 128-EEA3 confidentiality in LTE and 5G.
     *
     * Structurally unlike anything else in this family -- a sixteen-stage LFSR over **GF(2^31 - 1)**
     * rather than GF(2), so its state advances by modular arithmetic instead of by shifts and XORs. A
     * bit-reorganisation layer then carves four 32-bit words out of five LFSR cells and feeds a
     * two-register nonlinear function.
     */
    id: "zuc128",
    label: "ZUC-128",
    category: "National",
    aead: false,
    /**
     * `modern`. Standardised by 3GPP as 128-EEA3 and by China as GB/T 33133.1, and there is no attack
     * on the full cipher -- the published cryptanalysis reaches reduced-round variants only. It is what
     * the phone in your pocket may be using right now.
     */
    security: "modern",
    tags: [
      "zuc",
      "zuc-128",
      "zuc128",
      "128-eea3",
      "eea3",
      "3gpp",
      "lte",
      "5g",
      "gb/t 33133",
      "china",
      "stream",
      "encrypt",
      "decrypt",
    ],
    summary: "The 3GPP stream cipher behind 128-EEA3 in LTE and 5G. An LFSR over GF(2^31 - 1).",
    shape: { keyLengths: [16], nonceLengths: [16] },
  },
  {
    /**
     * ZUC-256, the same core with a bespoke loading of a 256-bit key.
     *
     * Only the LFSR initialisation differs from ZUC-128 -- which is why one implementation serves both.
     * The 25-byte IV is scattered across the sixteen 31-bit cells with six bits folded into each of nine
     * loading constants, and there is no way to check that arrangement but a published keystream.
     */
    id: "zuc256",
    label: "ZUC-256",
    category: "National",
    aead: false,
    security: "modern",
    tags: [
      "zuc",
      "zuc-256",
      "zuc256",
      "3gpp",
      "5g",
      "256-bit",
      "china",
      "stream",
      "encrypt",
      "decrypt",
    ],
    summary: "ZUC at a 256-bit key and a 200-bit IV. The same core, loaded differently.",
    shape: { keyLengths: [32], nonceLengths: [25] },
  },
  {
    /**
     * HC-128, an eSTREAM phase-3 software portfolio member by Hongjun Wu.
     *
     * Two 512-word tables that rewrite themselves: each step updates one entry of P from three others
     * and reads a word out of Q to produce output. There is no S-box and no constant table anywhere in
     * the design, which is unusual enough to be worth saying -- nothing here could be mistyped.
     */
    id: "hc128",
    label: "HC-128",
    category: "eSTREAM",
    aead: false,
    /**
     * `modern`. An eSTREAM final portfolio selection with no attack on the full cipher, and the
     * keystream generation is genuinely fast in software -- about three cycles a byte on the hardware it
     * was designed for. Its cost is a 1280-word key setup, so it is wrong for short messages.
     */
    security: "modern",
    tags: [
      "hc-128",
      "hc128",
      "estream",
      "hongjun wu",
      "software portfolio",
      "stream",
      "encrypt",
      "decrypt",
    ],
    summary: "An eSTREAM software-portfolio stream cipher. Two self-updating 512-word tables.",
    shape: { keyLengths: [16], nonceLengths: [16] },
  },
  {
    /**
     * HC-256, the 256-bit sibling -- and a different function, not a widening.
     *
     * Twice the table size, more taps, and an output function that sums *four* byte-indexed lookups
     * where HC-128 sums two. Initialisation runs 4096 discarded steps against HC-128's 1024.
     *
     * A 128-bit key or IV is accepted and **expanded** rather than refused: the key is duplicated and
     * the IV repeated, which is what the reference implementation does and what eSTREAM's own 128-bit
     * vector files require. Refusing them would mean a tool that cannot reproduce its own designers'
     * published values.
     */
    id: "hc256",
    label: "HC-256",
    category: "eSTREAM",
    aead: false,
    security: "modern",
    tags: [
      "hc-256",
      "hc256",
      "estream",
      "hongjun wu",
      "256-bit",
      "stream",
      "encrypt",
      "decrypt",
    ],
    summary: "HC-128's 256-bit sibling: bigger tables, more taps, a different output function.",
    shape: { keyLengths: [16, 32], nonceLengths: [16, 32] },
  },
  {
    /**
     * Grain v1, eSTREAM's hardware portfolio: an 80-bit design for a few hundred gates.
     *
     * An LFSR and an NFSR of 80 bits each with a nonlinear filter reading taps from both. It clocks one
     * bit at a time by definition -- but every tap sits at least sixteen positions from the bit being
     * written, so sixteen bits can be produced at once, which is the standard hardware speed-up and how
     * this implementation runs.
     */
    id: "grainv1",
    label: "Grain v1",
    category: "eSTREAM",
    aead: false,
    /**
     * `legacy`, on the key size rather than on a break. An 80-bit key is 80 bits of security and that is
     * below any current recommendation, which is precisely why Grain-128 exists. There is no attack on
     * the full cipher.
     */
    security: "legacy",
    tags: [
      "grain",
      "grain v1",
      "grainv1",
      "estream",
      "hardware portfolio",
      "lfsr",
      "nfsr",
      "80-bit",
      "stream",
      "encrypt",
      "decrypt",
    ],
    summary:
      "eSTREAM's 80-bit hardware-portfolio stream cipher. An LFSR, an NFSR and a filter.",
    shape: { keyLengths: [10], nonceLengths: [8] },
  },
  {
    /**
     * Grain-128: the same architecture at twice the width, with a *simpler* nonlinear function.
     *
     * The NFSR feedback is degree two here against Grain v1's degree six -- the extra width bought the
     * margin the algebraic complexity was providing. It is not a scaled-up Grain v1 and cannot be
     * derived from one, which is why both are implemented rather than parameterised.
     */
    id: "grain128",
    label: "Grain-128",
    category: "eSTREAM",
    aead: false,
    /**
     * `legacy`. Dinur and Shamir's dynamic cube attack breaks the full cipher for a class of weak keys,
     * and the designers' own answer was Grain-128a with authentication -- which is what the NIST
     * lightweight submission Grain-128AEAD descends from. Fine for reproducing a value, not for new use.
     */
    security: "legacy",
    tags: [
      "grain",
      "grain-128",
      "grain128",
      "estream",
      "lfsr",
      "nfsr",
      "128-bit",
      "stream",
      "encrypt",
      "decrypt",
    ],
    summary: "Grain at 128 bits. Wider registers, and a lower-degree feedback than Grain v1.",
    shape: { keyLengths: [16], nonceLengths: [12] },
  },
  {
    /**
     * Kalyna -- DSTU 7624:2014, Ukraine's national block cipher.
     *
     * An AES-shaped SPN with three departures that matter: the whitening layers *add* the round key
     * modulo 2^64 per column rather than XORing it, the state is columns of 64 bits held little-endian,
     * and the key schedule runs the cipher's own round function three times over to derive an
     * intermediate key before producing any round key at all.
     *
     * **This is the widest block in the repo.** Five pairings, and the key is either the block size or
     * twice it; the round count follows the key. `blockmodes.ts` needed no change for a 512-bit block,
     * which is the third time that generic layer has paid for itself.
     */
    id: "kalyna",
    label: "Kalyna",
    category: "National",
    aead: false,
    /**
     * `modern`. A 2014 national standard with no attack on any full variant, designed after AES with the
     * benefit of that cryptanalysis. It is here to interoperate rather than as a recommendation --
     * almost nothing outside Ukraine implements it, which is exactly why reproducing a value is hard
     * without a tool like this.
     */
    security: "modern",
    tags: [
      "kalyna",
      "dstu 7624",
      "dstu7624",
      "ukraine",
      "national standard",
      "kalyna-128",
      "kalyna-256",
      "kalyna-512",
      "512-bit block",
      "encrypt",
      "decrypt",
    ],
    summary: "Ukraine's DSTU 7624 block cipher, at 128-, 256- and 512-bit blocks.",
    block: {
      size: 16,
      // The default set's key sizes. The union across all five sets is what the catalogue declares --
      // see `keyLengthFor`, and the note on `paramSets` about never reading this from a path with a spec.
      keyLengths: [16, 32],
      /**
       * GCM and CCM are absent on purpose rather than by oversight.
       *
       * Both assume a 128-bit block -- GCM's field is GF(2^128) and CCM's counter formatting is built
       * round sixteen bytes -- so they would be legal for Kalyna-128 and impossible for Kalyna-512.
       * `block.modes` is a property of the tool, not of the selected set, so a mode list that was right
       * for one set and wrong for two others is not something this form can express. Same reasoning
       * that keeps them off Speck and Simon.
       */
      modes: ["cbc", "cfb", "ofb", "ctr", "ecb"],
    },
    paramSets: [
      {
        id: "128-128",
        label: "Kalyna-128/128",
        blockSize: 16,
        keyLength: 16,
        summary: "128-bit block, 128-bit key, 10 rounds. The smallest, and AES-128's shape.",
      },
      {
        id: "128-256",
        label: "Kalyna-128/256",
        blockSize: 16,
        keyLength: 32,
        summary: "128-bit block, 256-bit key, 14 rounds. A key twice the block width.",
      },
      {
        id: "256-256",
        label: "Kalyna-256/256",
        blockSize: 32,
        keyLength: 32,
        summary: "256-bit block, 256-bit key, 14 rounds.",
      },
      {
        id: "256-512",
        label: "Kalyna-256/512",
        blockSize: 32,
        keyLength: 64,
        summary: "256-bit block, 512-bit key, 18 rounds.",
      },
      {
        id: "512-512",
        label: "Kalyna-512/512",
        blockSize: 64,
        keyLength: 64,
        summary: "512-bit block, 512-bit key, 18 rounds. The widest block here.",
      },
    ],
    defaultParamSet: "128-128",
  },
  {
    /**
     * ACORN-128 v3, one of the seven ciphers in CAESAR's final portfolio.
     *
     * `modern`: no attack on the full construction. It is the smallest authenticated cipher here by a
     * wide margin -- 293 bits of state in six coupled LFSRs, with **no tables, no constants and no key
     * schedule at all**. Only Trivium in this repo is that austere, and ACORN does authenticated
     * encryption with the same budget, which is why CAESAR put it in the lightweight-hardware slot.
     *
     * It is bit-serial by design, so it is slow in software here -- a few megabytes a second. That is a
     * property of the cipher rather than of this implementation; the whole point of the design is that
     * one bit per clock costs almost no gates.
     */
    id: "acorn",
    label: "ACORN-128",
    category: "AEAD",
    aead: true,
    security: "modern",
    tags: [
      "acorn",
      "acorn-128",
      "acorn128",
      "caesar",
      "portfolio",
      "lightweight",
      "hongjun wu",
      "lfsr",
      "bit serial",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary:
      "A CAESAR portfolio cipher: 293 bits of LFSR, no tables and no key schedule at all.",
    shape: { keyLengths: [16], nonceLengths: [16], tagLen: 16 },
  },
  {
    /**
     * Deoxys-II-256-128, one of the two ciphers CAESAR selected for its defence-in-depth use case.
     *
     * `modern`: no attack on the full construction, and the design has a security proof in the
     * tweakable-block-cipher model rather than only an argument. It is also the only AEAD here built on
     * a **tweakable** block cipher -- Deoxys-BC-384, an AES-round cipher taking a 384-bit tweakey
     * through the TWEAKEY framework -- where everything else either keys a permutation or bolts a MAC
     * onto a counter mode.
     *
     * The property worth having it for is **nonce-misuse resistance**. Repeating a nonce here leaks
     * whether two messages were equal and nothing more; repeating one under GCM or ChaCha20-Poly1305
     * hands over the keystream and, with it, the authentication key. That is bought with a second pass:
     * the tag is computed over the whole input first and then used as the encryption tweak, so nothing
     * can be emitted until the last byte has been read.
     */
    id: "deoxysii",
    label: "Deoxys-II",
    category: "AEAD",
    aead: true,
    security: "modern",
    tags: [
      "deoxys",
      "deoxys-ii",
      "deoxysii",
      "deoxys-ii-256-128",
      "deoxys-bc",
      "tweakey",
      "caesar",
      "misuse resistant",
      "nonce misuse",
      "defence in depth",
      "jean",
      "nikolic",
      "peyrin",
      "oasis",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary: "A CAESAR winner over a tweakable block cipher. Nonce-misuse resistant, two-pass.",
    shape: { keyLengths: [32], nonceLengths: [15], tagLen: 16 },
  },
  {
    /**
     * NORX32-4-1 (NORX v3.0), a CAESAR third-round candidate.
     *
     * `modern`: no attack on the full construction. It did not reach the final portfolio -- Ascon and
     * ACORN took the lightweight slots, AEGIS and OCB the others -- but it has no break, and it is here
     * for the design rather than as a warning.
     *
     * A Keccak-style duplex over a **BLAKE2-shaped ARX permutation**, which makes it the only sponge
     * AEAD here whose round function is add-rotate-xor rather than bit-sliced. And it is not quite ARX:
     * the mixing function is `(a ^ b) ^ ((a & b) << 1)`, a carry-free stand-in for addition, so the
     * whole cipher is XOR, AND, shift and rotate and is constant-time by construction.
     *
     * Three versions of NORX exist and they are mutually incompatible. This is v3.0, the last.
     */
    id: "norx",
    label: "NORX32-4-1",
    category: "AEAD",
    aead: true,
    security: "modern",
    tags: [
      "norx",
      "norx32",
      "norx32-4-1",
      "norx3241",
      "norx v3.0",
      "caesar",
      "sponge",
      "duplex",
      "arx",
      "blake2",
      "aumasson",
      "jovanovic",
      "neves",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary:
      "A CAESAR candidate: a duplex sponge over a BLAKE2-shaped permutation with no addition.",
    shape: { keyLengths: [16], nonceLengths: [16], tagLen: 16 },
  },
  {
    /**
     * Xoodyak -- the Xoodoo permutation under the Cyclist mode, from the Keccak team.
     *
     * One object that is an AEAD, a hash, a MAC and a stream cipher depending on how it is driven; this
     * tool is the AEAD and `xoodyak` in the hash family is the hash. Keccak's design philosophy at 384
     * bits with three planes instead of five.
     */
    id: "xoodyak",
    label: "Xoodyak",
    category: "NIST lightweight",
    aead: true,
    /**
     * `modern` for all nine of these. NIST ran a five-year public competition, these were the ten
     * finalists (Ascon, already here, won), and none has an attack on its full construction. They are
     * here to interoperate with constrained hardware, not as a warning.
     */
    security: "modern",
    tags: [
      "xoodyak",
      "xoodoo",
      "cyclist",
      "nist lightweight",
      "lwc",
      "finalist",
      "keccak team",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary: "The Keccak team's lightweight duplex. 128-bit key, nonce and tag.",
    shape: { keyLengths: [16], nonceLengths: [16], tagLen: 16 },
  },
  {
    /**
     * Ketje Jr -- the Keccak team's CAESAR entry, and the smallest permutation-based AEAD here.
     *
     * `legacy`. Nothing breaks it, but CAESAR chose Ascon and NORX, and the same team's Xoodyak (above)
     * is the successor. Here to reproduce values.
     *
     * **Its lanes are eight bits.** Every other Keccak-derived thing in this repo -- SHA-3, SHAKE,
     * TurboSHAKE, Xoodyak -- uses 64- or 32-bit lanes; Ketje Jr uses Keccak-p[200], so the whole state
     * is 25 *bytes* and its rotations are `rol8`. Its round constants are Keccak's truncated to a byte,
     * which is why `0x8000000000008089` appears here as `0x89`.
     *
     * Three consequences worth knowing at this level. The **nonce is at most 6 bytes**, and that is not
     * a design choice but arithmetic: an 18-byte key pack plus a nonce plus two frame bits have to fit
     * in 25 bytes. The **block is two bytes**, the smallest here after Hamsi's four -- so throughput is
     * one 200-bit permutation per two bytes of message. And the round counts are 12 to start, **one**
     * per step and 6 for the stride, which is what a MonkeyDuplex is: a single round between blocks,
     * paid for by a longer separation between phases.
     */
    id: "ketjejr",
    label: "Ketje Jr",
    category: "NIST lightweight",
    aead: true,
    security: "legacy",
    tags: [
      "ketje",
      "ketje jr",
      "ketjejr",
      "keccak",
      "keccak-p",
      "keccak-p[200]",
      "monkeyduplex",
      "caesar",
      "keccak team",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Keccak-p[200] as a MonkeyDuplex. Eight-bit lanes, a 25-byte state, a two-byte block.",
    shape: { keyLengths: [16], nonceLengths: [6], tagLen: 16 },
  },
  {
    /**
     * MORUS, at all three CAESAR v2 parameter sets -- and the only `broken` AEAD in this repo.
     *
     * **The break is on the full cipher, not a reduced-round version.** Ashur, Eichlseder, Lauridsen,
     * Leurent, Minaud, Rotella, Sasaki and Viguier (2018) found a keystream correlation of about 2^-16
     * in MORUS-1280 that survives every round, so plaintext bits leak from ciphertext without any key
     * recovery. It was a CAESAR finalist and this is part of why it did not win. `C004` fires, and it
     * should: nothing here should be encrypted with it.
     *
     * Registered anyway on the user's explicit instruction, and worth having for the reason any broken
     * primitive is: reproducing a value somebody already has.
     *
     * **640-128 and 1280-128 take the same key, nonce and tag lengths and are different ciphers.** So
     * the binding must read the resolved instance id rather than infer from lengths -- the Kalyna hazard
     * this repo records, and the second tool to hit it.
     *
     * No published known-answer file exists. What covers it is a cross-check between a port of the
     * designers' reference C and an independently written Python implementation; see `morus.ts` and
     * `tests/morus-vectors.ts`, which are explicit that this is not a KAT.
     */
    id: "morus",
    label: "MORUS",
    category: "NIST lightweight",
    aead: true,
    security: "broken",
    tags: [
      "morus",
      "morus-640-128",
      "morus-1280-128",
      "morus-1280-256",
      "caesar",
      "finalist",
      "wu",
      "huang",
      "broken",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary:
      "A CAESAR finalist with a full-cipher keystream correlation. Here to reproduce values only.",
    shape: {
      keyLengths: [16, 32],
      nonceLengths: [16],
      tagLen: 16,
      // The submission's primary member, and the one the published attack is stated against.
      defaultInstance: "1280-256",
      instances: [
        {
          id: "640-128",
          label: "MORUS-640-128",
          keyLen: 16,
          nonceLen: 16,
          tagLen: 16,
          summary:
            "32-bit words, a 16-byte block, and the only set the 2018 attack does not directly cover",
        },
        {
          id: "1280-128",
          label: "MORUS-1280-128",
          keyLen: 16,
          nonceLen: 16,
          tagLen: 16,
          summary:
            "64-bit words and a 32-byte block; the 128-bit key is repeated to fill a 256-bit register",
        },
        {
          id: "1280-256",
          label: "MORUS-1280-256",
          keyLen: 32,
          nonceLen: 16,
          tagLen: 16,
          summary:
            "The submission's primary member, and the one the published correlation attacks",
        },
      ],
    },
  },
  {
    /**
     * Schwaemm -- the SPARKLE permutation's AEAD, at four sizes.
     *
     * ARX throughout: the permutation is Alzette boxes and a linear layer, with no table anywhere. The
     * four instances are named `<nonceBits>-<keyBits>`, and unusually the *tag* width tracks the key --
     * Schwaemm256-256 has a 256-bit tag, which is key-committing in a way a 128-bit tag is not.
     */
    id: "schwaemm",
    label: "Schwaemm",
    category: "NIST lightweight",
    aead: true,
    security: "modern",
    tags: [
      "schwaemm",
      "sparkle",
      "alzette",
      "esch",
      "nist lightweight",
      "lwc",
      "finalist",
      "arx",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary: "SPARKLE's AEAD at four sizes. Add-rotate-XOR, no tables at all.",
    shape: {
      keyLengths: [16, 24, 32],
      nonceLengths: [16, 24, 32],
      tagLen: 16,
      instances: [
        {
          id: "128-128",
          label: "Schwaemm128-128",
          keyLen: 16,
          nonceLen: 16,
          tagLen: 16,
          summary: "256-bit state. The smallest, and the fastest for short messages.",
        },
        {
          id: "256-128",
          label: "Schwaemm256-128",
          keyLen: 16,
          nonceLen: 32,
          tagLen: 16,
          summary: "384-bit state, 256-bit rate. The submission's primary recommendation.",
        },
        {
          id: "192-192",
          label: "Schwaemm192-192",
          keyLen: 24,
          nonceLen: 24,
          tagLen: 24,
          summary: "384-bit state at a 192-bit security level.",
        },
        {
          id: "256-256",
          label: "Schwaemm256-256",
          keyLen: 32,
          nonceLen: 32,
          tagLen: 32,
          summary: "512-bit state, and a 256-bit tag that commits to the key.",
        },
      ],
      defaultInstance: "256-128",
    },
  },
  {
    /**
     * GIFT-COFB -- the GIFT-128 block cipher under COFB.
     *
     * One cipher call per block and a *64-bit* mask rather than a 128-bit one, which is what makes it the
     * smallest block-cipher-based finalist in hardware. It never inverts the cipher, which is why GIFT
     * itself is not registered as a block cipher here.
     */
    id: "giftcofb",
    label: "GIFT-COFB",
    category: "NIST lightweight",
    aead: true,
    security: "modern",
    tags: [
      "gift-cofb",
      "giftcofb",
      "gift",
      "gift-128",
      "cofb",
      "nist lightweight",
      "lwc",
      "finalist",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary: "GIFT-128 in combined feedback mode. One cipher call per block, 64-bit state.",
    shape: { keyLengths: [16], nonceLengths: [16], tagLen: 16 },
  },
  {
    /**
     * PHOTON-Beetle -- the PHOTON256 permutation under the Beetle sponge, at two rates.
     *
     * PHOTON256 is AES's shape over nibbles: an 8x8 grid, a 4-bit S-box, MixColumns over GF(2^4). The
     * rate is the whole choice -- 32 bits for the smallest possible hardware, 128 for throughput.
     */
    id: "photonbeetle",
    label: "PHOTON-Beetle",
    category: "NIST lightweight",
    aead: true,
    security: "modern",
    tags: [
      "photon-beetle",
      "photonbeetle",
      "photon",
      "beetle",
      "nist lightweight",
      "lwc",
      "finalist",
      "sponge",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary: "A nibble-oriented AES-shaped permutation in a sponge. Two rates.",
    shape: {
      keyLengths: [16],
      nonceLengths: [16],
      tagLen: 16,
      instances: [
        {
          id: "128",
          label: "PHOTON-Beetle-AEAD[128]",
          keyLen: 16,
          nonceLen: 16,
          summary: "A 128-bit rate: one permutation per 16 bytes.",
        },
        {
          id: "32",
          label: "PHOTON-Beetle-AEAD[32]",
          keyLen: 16,
          nonceLen: 16,
          summary: "A 32-bit rate: four times the permutations, a quarter of the hardware.",
        },
      ],
      defaultInstance: "128",
    },
  },
  {
    /**
     * Romulus -- SKINNY-128-384+ as a tweakable block cipher, in three modes.
     *
     * The only finalist offering three different security *properties* from one primitive: N is
     * nonce-respecting and single-pass, M survives a repeated nonce, T is leakage-resilient. Romulus-H
     * in the hash family is the same cipher again.
     */
    id: "romulus",
    label: "Romulus",
    category: "NIST lightweight",
    aead: true,
    security: "modern",
    tags: [
      "romulus",
      "skinny",
      "skinny-128-384",
      "tweakable",
      "nist lightweight",
      "lwc",
      "finalist",
      "misuse resistant",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary:
      "A tweakable block cipher in three modes: fast, misuse-resistant, or leakage-resilient.",
    shape: {
      keyLengths: [16],
      nonceLengths: [16],
      tagLen: 16,
      instances: [
        {
          id: "n",
          label: "Romulus-N",
          keyLen: 16,
          nonceLen: 16,
          summary: "Nonce-respecting, one pass, one cipher call per block. The primary member.",
        },
        {
          id: "m",
          label: "Romulus-M",
          keyLen: 16,
          nonceLen: 16,
          summary:
            "Misuse-resistant: a repeated nonce leaks only whether two messages were equal. Two passes.",
        },
        {
          id: "t",
          label: "Romulus-T",
          keyLen: 16,
          nonceLen: 16,
          summary:
            "Leakage-resilient: the session key is rekeyed every block. The slowest of the three.",
        },
      ],
      defaultInstance: "n",
    },
  },
  {
    /**
     * Elephant -- counter-mode encryption plus a parallel MAC over a public permutation, in three sizes.
     *
     * Not a sponge and not a duplex: everything is parallelisable and nothing needs the permutation
     * inverted. The three instances have names rather than numbers, and Delirium's tag is twice the
     * other two's -- which is why `CipherInstance` carries `tagLen` at all.
     */
    id: "elephant",
    label: "Elephant",
    category: "NIST lightweight",
    aead: true,
    security: "modern",
    tags: [
      "elephant",
      "dumbo",
      "jumbo",
      "delirium",
      "spongent",
      "keccak-f200",
      "nist lightweight",
      "lwc",
      "finalist",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Counter mode plus a parallel MAC over a public permutation. Dumbo, Jumbo or Delirium.",
    shape: {
      keyLengths: [16],
      nonceLengths: [12],
      tagLen: 8,
      instances: [
        {
          id: "dumbo",
          label: "Dumbo",
          keyLen: 16,
          nonceLen: 12,
          tagLen: 8,
          summary:
            "Spongent-pi[160], 80 rounds. The smallest, and the submission's primary member.",
        },
        {
          id: "jumbo",
          label: "Jumbo",
          keyLen: 16,
          nonceLen: 12,
          tagLen: 8,
          summary: "Spongent-pi[176], 90 rounds. A wider permutation for more margin.",
        },
        {
          id: "delirium",
          label: "Delirium",
          keyLen: 16,
          nonceLen: 12,
          tagLen: 16,
          summary: "Keccak-f[200], 18 rounds, and a 128-bit tag rather than 64.",
        },
      ],
      defaultInstance: "dumbo",
    },
  },
  {
    /**
     * ISAP -- leakage-resilient AEAD over Ascon-p or Keccak-p[400].
     *
     * The long-term key is used *only* inside a rekeying function that absorbs one bit at a time, so no
     * key material is ever combined with more than a single bit of attacker-chosen data. That is the
     * whole design, and it is why the four variants differ mostly in round counts.
     */
    id: "isap",
    label: "ISAP",
    category: "NIST lightweight",
    aead: true,
    security: "modern",
    tags: [
      "isap",
      "isap-a",
      "isap-k",
      "ascon-p",
      "keccak-p400",
      "nist lightweight",
      "lwc",
      "finalist",
      "leakage resilient",
      "side channel",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Leakage-resilient AEAD: the key touches one bit of data at a time. Four variants.",
    shape: {
      keyLengths: [16],
      nonceLengths: [16],
      tagLen: 16,
      instances: [
        {
          id: "a-128a",
          label: "ISAP-A-128A",
          keyLen: 16,
          nonceLen: 16,
          summary: "Ascon-p, reduced rounds. The fastest of the four and the primary member.",
        },
        {
          id: "a-128",
          label: "ISAP-A-128",
          keyLen: 16,
          nonceLen: 16,
          summary:
            "Ascon-p at twelve rounds throughout. More margin, twelve times the rekeying cost.",
        },
        {
          id: "k-128a",
          label: "ISAP-K-128A",
          keyLen: 16,
          nonceLen: 16,
          summary: "Keccak-p[400], reduced rounds, for hardware that already has Keccak.",
        },
        {
          id: "k-128",
          label: "ISAP-K-128",
          keyLen: 16,
          nonceLen: 16,
          summary: "Keccak-p[400] at full rounds.",
        },
      ],
      defaultInstance: "a-128a",
    },
  },
  {
    /**
     * Grain-128AEAD -- Grain-128a's registers with a 64-bit Wegman-Carter authenticator.
     *
     * The only bit-serial finalist: one keystream bit per clock, and the plaintext authenticated bit by
     * bit. Tiny in hardware, and the slowest of the nine in software by a wide margin.
     *
     * Not the same function as the `grain128` in the eSTREAM category -- the feedback has four extra
     * terms and the registers run the other way. Both are here and neither derives from the other.
     */
    id: "grain128aead",
    label: "Grain-128AEAD",
    category: "NIST lightweight",
    aead: true,
    security: "modern",
    tags: [
      "grain-128aead",
      "grain128aead",
      "grain-128a",
      "grain",
      "nist lightweight",
      "lwc",
      "finalist",
      "bit serial",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary:
      "Grain-128a plus a Wegman-Carter tag. Bit-serial: tiny in hardware, slow in software.",
    shape: { keyLengths: [16], nonceLengths: [12], tagLen: 8 },
  },
  {
    /**
     * TinyJAMBU -- the smallest of the finalists, by some distance.
     *
     * The whole permutation is a 128-bit NLFSR: one AND, four shifted taps and a key word per 32 bits.
     * No S-box, no table, no round constant. The three key sizes differ only in how many key words the
     * feedback cycles through and how long the wide permutation runs.
     */
    id: "tinyjambu",
    label: "TinyJAMBU",
    category: "NIST lightweight",
    aead: true,
    security: "modern",
    tags: [
      "tinyjambu",
      "tiny jambu",
      "jambu",
      "nlfsr",
      "nist lightweight",
      "lwc",
      "finalist",
      "smallest",
      "aead",
      "encrypt",
      "decrypt",
    ],
    summary: "A 128-bit NLFSR and nothing else. The smallest AEAD in the competition.",
    shape: {
      keyLengths: [16, 24, 32],
      nonceLengths: [12],
      tagLen: 8,
      instances: [
        {
          id: "128",
          label: "TinyJAMBU-128",
          keyLen: 16,
          nonceLen: 12,
          summary: "1024 rounds of the wide permutation. The primary member.",
        },
        {
          id: "192",
          label: "TinyJAMBU-192",
          keyLen: 24,
          nonceLen: 12,
          summary: "A 192-bit key and 1152 rounds.",
        },
        {
          id: "256",
          label: "TinyJAMBU-256",
          keyLen: 32,
          nonceLen: 12,
          summary: "A 256-bit key and 1280 rounds.",
        },
      ],
      defaultInstance: "128",
    },
  },
  {
    id: "rc4",
    label: "RC4",
    category: "Legacy",
    aead: false,
    security: "broken",
    tags: ["rc4", "arcfour", "stream", "wep", "legacy", "broken", "encrypt", "decrypt"],
    summary: "The stream cipher from 1987. Comprehensively broken; kept for legacy analysis.",
  },
  {
    id: "adiantum",
    label: "Adiantum",
    category: "Disk & Storage",
    aead: false,
    security: "modern",
    tags: ["adiantum", "wide-block", "android", "disk", "storage", "chacha12", "poly1305", "aes256"],
    summary: "Wide-block length-preserving cipher designed by Google for Android device storage encryption.",
    shape: { keyLengths: [32], nonceLengths: [12] },
  },
  {
    id: "hctr2",
    label: "HCTR2",
    category: "Disk & Storage",
    aead: false,
    security: "modern",
    tags: ["hctr2", "wide-block", "linux", "fscrypt", "disk", "storage", "aes256", "polyval"],
    summary: "Length-preserving wide-block disk encryption mode introduced in Linux Kernel 6.0+.",
    shape: { keyLengths: [32], nonceLengths: [16] },
  },
  {
    id: "spritz",
    label: "Spritz",
    category: "Stream",
    aead: false,
    security: "modern",
    tags: ["spritz", "rc4", "sponge", "rivest", "schuldt", "stream"],
    summary: "Ronald Rivest and Jacob Schuldt's modern sponge-based redesign of RC4.",
    shape: { keyLengths: [16, 32], nonceLengths: [0, 8, 16] },
  },
  {
    id: "keeloq",
    label: "KeeLoq",
    category: "Hardware & RFID",
    aead: false,
    security: "legacy",
    tags: ["keeloq", "hopping", "automotive", "microchip", "remote", "keyless"],
    summary: "32-bit block, 64-bit key hopping cipher used in automotive remote keyless entry systems.",
    block: { size: 4, keyLengths: [8], modes: ["ecb", "cbc", "ctr"] },
  },
  {
    id: "crypto1",
    label: "Crypto-1",
    category: "Hardware & RFID",
    aead: false,
    security: "broken",
    tags: ["crypto1", "crypto-1", "mifare", "rfid", "nxp", "smartcard", "stream"],
    summary: "Proprietary 48-bit RFID stream cipher used in NXP MIFARE Classic smartcards.",
    shape: { keyLengths: [6], nonceLengths: [4] },
  },
  {
    id: "dect-dsc",
    label: "DECT DSC",
    category: "Telecom",
    aead: false,
    security: "legacy",
    tags: ["dect", "dsc", "cordless", "telephony", "etsi", "stream"],
    summary: "Standard cordless telephony stream cipher from ETSI EN 300 175-6.",
    shape: { keyLengths: [8], nonceLengths: [4, 5] },
  },
  {
    id: "gea",
    label: "GPRS GEA",
    category: "Telecom",
    aead: false,
    security: "broken",
    tags: ["gea", "gea1", "gea2", "gprs", "cellular", "3gpp", "stream"],
    summary: "GPRS Encryption Algorithms (GEA-1 / GEA-2) used in cellular packet data.",
    shape: { keyLengths: [8], nonceLengths: [4] },
  },
  {
    id: "saturnin",
    label: "Saturnin",
    category: "Post-Quantum",
    aead: false,
    security: "modern",
    tags: ["saturnin", "post-quantum", "256-bit", "nist-lwc", "canteaut", "block"],
    summary: "Post-quantum 256-bit block cipher with 256-bit key designed for 256-bit security.",
    block: { size: 32, keyLengths: [32], modes: ["ecb", "cbc", "ctr"] },
  },
];

const BY_ID = new Map(CIPHER_TOOLS.map((t) => [t.id, t]));

export function getCipherTool(id: string): CipherToolMeta | undefined {
  return BY_ID.get(id);
}

export function requireCipherTool(id: string): CipherToolMeta {
  const meta = BY_ID.get(id);
  if (!meta) throw new Error(`Unknown cipher tool: ${id}`);
  return meta;
}

/**
 * The parameter set a tool is using, or undefined for the tools that have only one shape.
 *
 * Falls back to the declared default rather than to the first entry, and to the first entry only if
 * a tool declares sets without a default -- which `tests/cipher.test.ts` forbids.
 */
/**
 * The instance a shaped tool is using, or undefined for the tools that have only one.
 *
 * Falls back to the declared default rather than to the first entry, for the same reason `getParamSet`
 * does: a stale id left in the spec after switching tools should land on something legal.
 */
export function getCipherInstance(
  tool: CipherToolMeta,
  id: string | undefined,
): CipherInstance | undefined {
  const instances = tool.shape?.instances;
  if (!instances) return undefined;
  return (
    instances.find((instance) => instance.id === id) ??
    instances.find((instance) => instance.id === tool.shape!.defaultInstance) ??
    instances[0]
  );
}

export function getParamSet(
  tool: CipherToolMeta,
  id: string | undefined,
): CipherParamSet | undefined {
  if (!tool.paramSets) return undefined;
  return (
    tool.paramSets.find((set) => set.id === id) ??
    tool.paramSets.find((set) => set.id === tool.defaultParamSet) ??
    tool.paramSets[0]
  );
}

/** Every key length a tool can accept, across all of its parameter sets. */
export function allKeyLengths(tool: CipherToolMeta): readonly number[] {
  if (tool.paramSets) {
    return [...new Set(tool.paramSets.map((set) => set.keyLength))].sort((a, b) => a - b);
  }
  return tool.block?.keyLengths ?? [];
}

export const CIPHER_TOOL_IDS: readonly string[] = CIPHER_TOOLS.map((t) => t.id);

/**
 * AES modes. `aead` decides whether a tag and AAD apply; `nonceLen` is what the mode
 * actually requires, and `blockAligned` marks the two that need padding.
 */
export interface AesModeMeta {
  id: string;
  label: string;
  aead: boolean;
  /** Bytes. Zero means the mode takes no IV or nonce at all. The default where a range is allowed. */
  nonceLen: number;
  /**
   * Every nonce length the mode accepts, where more than one is legal.
   *
   * CCM takes 7 to 13 bytes and OCB 1 to 15, and in CCM's case the choice is not cosmetic: the nonce
   * and the message-length field share the block, so a 13-byte nonce caps the message at 64 KiB. That
   * is why 802.15.4 and WPA2 use 13 and TLS uses 12. `nonceLen` stays the default the form starts on.
   */
  nonceLens?: readonly number[];
  /**
   * Tag lengths the mode accepts, for the AEADs where it is a choice rather than fixed at 16.
   *
   * CCM allows any even 4 to 16; OCB allows any 1 to 16, and the even subset is what is offered here
   * because a 5-byte tag is a footgun with no protocol behind it. Note OCB folds the tag length into
   * its nonce formatting, so a 12-byte tag changes the *ciphertext* too -- truncating a 16-byte-tag
   * output is not the same thing.
   */
  tagLens?: readonly number[];
  nonceLabel: string;
  /** True when the ciphertext must be a whole number of 16-byte blocks. */
  blockAligned: boolean;
  /**
   * Provides integrity without an AAD field or a separate tag.
   *
   * Only the key-wrap modes. `aead` is the UI gate -- it decides whether the AAD control and the tag
   * readout appear -- and for KW both would be wrong: RFC 3394 takes no associated data and folds its
   * integrity check into the wrapped output. But it *is* authenticated, so `C002`'s warning about
   * unauthenticated modes must not fire on it. One flag for the UI, one for the truth.
   */
  authenticatedWithoutAad?: boolean;
  /** Input must be at least this many bytes. Key wrap has a floor; the block modes do not. */
  minInputLen?: number;
  /** Input length must be a multiple of this. 8 for RFC 3394 key wrap. */
  inputMultiple?: number;
  /**
   * Key lengths this mode accepts, where they differ from AES's 16/24/32.
   *
   * Only SIV, and the reason is worth stating: RFC 5297 splits the key in half, one for the CMAC that
   * derives the synthetic IV and one for the CTR that encrypts -- so AES-SIV with AES-128 takes 32
   * bytes, not 16. A user handed the usual "AES-256 means 32 bytes" would otherwise be told their
   * correct key was the wrong length with no explanation of why.
   */
  keyLengths?: readonly number[];
  insecure?: boolean;
  summary: string;
}

export const AES_MODES: readonly AesModeMeta[] = [
  {
    id: "gcm",
    label: "GCM",
    aead: true,
    nonceLen: 12,
    nonceLabel: "Nonce",
    blockAligned: false,
    summary: "Authenticated. The default choice.",
  },
  {
    /**
     * RFC 8452 defines AES-GCM-SIV for **128- and 256-bit keys only**, which is why this carries its
     * own `keyLengths` instead of inheriting AES's three.
     *
     * There is no AES-192-GCM-SIV. Without this line the mode inherited 16/24/32 and a 24-byte key
     * computed -- because `@noble/ciphers` accepts one, and says in its own source why: "RFC 8452
     * only standardizes 16-byte and 32-byte key-generating keys. The accepted 24-byte path is a
     * local AES-192 extension outside the RFC-defined AEADs." So the tool produced a plausible tag
     * and ciphertext that no other implementation would reproduce, which is the failure this repo
     * cares most about and the reason a mode's own restriction has to be stated rather than assumed
     * to be the cipher's.
     *
     * Declaring it also removes the Key size control here, since that is offered only where the mode
     * does not override the key length. That costs a convenience under one mode and is the same
     * treatment XTS and SIV already get; the resolver's message names 16 or 32.
     */
    id: "gcm-siv",
    label: "GCM-SIV",
    aead: true,
    keyLengths: [16, 32],
    nonceLen: 12,
    nonceLabel: "Nonce",
    blockAligned: false,
    summary: "Authenticated, and survives nonce reuse",
  },
  {
    id: "ctr",
    label: "CTR",
    aead: false,
    nonceLen: 16,
    nonceLabel: "Counter block",
    blockAligned: false,
    summary: "Stream mode, unauthenticated",
  },
  {
    id: "cbc",
    label: "CBC",
    aead: false,
    nonceLen: 16,
    nonceLabel: "IV",
    blockAligned: true,
    summary: "Block mode with padding, unauthenticated",
  },
  {
    id: "ofb",
    label: "OFB",
    aead: false,
    nonceLen: 16,
    nonceLabel: "IV",
    blockAligned: false,
    summary: "Stream mode, keystream independent of the data",
  },
  {
    id: "cfb",
    label: "CFB",
    aead: false,
    nonceLen: 16,
    nonceLabel: "IV",
    blockAligned: false,
    summary: "Stream mode from a block cipher, unauthenticated",
  },
  {
    /**
     * CCM, SP 800-38C: counter mode with a CBC-MAC, and the AEAD that constrained devices actually use.
     *
     * WPA2's CCMP, Bluetooth LE, Zigbee/802.15.4 and LoRaWAN are all CCM, because it needs only a block
     * cipher -- no field multiplication, no second primitive. The cost is that it is not online: the
     * message length goes into the first MAC block, so nothing can be authenticated until the total is
     * known.
     */
    id: "ccm",
    label: "CCM",
    aead: true,
    nonceLen: 12,
    nonceLens: [7, 8, 9, 10, 11, 12, 13],
    tagLens: [4, 6, 8, 10, 12, 14, 16],
    nonceLabel: "Nonce",
    blockAligned: false,
    summary: "Authenticated, from a block cipher alone. WPA2, Bluetooth, LoRaWAN",
  },
  {
    /**
     * OCB3, RFC 7253. One cipher call per block and nothing else.
     *
     * Faster than GCM without AES-NI and free of patents since 2021, which is why it is worth offering
     * now. The tag length is bound into the nonce formatting, so it changes the ciphertext rather than
     * just truncating the tag.
     */
    id: "ocb",
    label: "OCB",
    aead: true,
    nonceLen: 12,
    nonceLens: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    tagLens: [4, 6, 8, 10, 12, 14, 16],
    nonceLabel: "Nonce",
    blockAligned: false,
    summary: "Authenticated, one cipher call per block. Patent-free since 2021",
  },
  {
    /**
     * XTS, SP 800-38E: the mode disk encryption uses, and the only one here that takes two keys.
     *
     * BitLocker, LUKS, VeraCrypt, FileVault. The key string is *twice* the cipher's key -- 32 bytes for
     * XTS-AES-128 and 64 for XTS-AES-256, with no 192-bit variant defined -- because one half encrypts
     * the data and the other encrypts the tweak. The "nonce" is the data unit number, usually a sector
     * index, and it must be 16 bytes.
     *
     * Unauthenticated by necessity: a sector must encrypt to exactly a sector, leaving no room for a
     * tag. `C002` says so wherever it is chosen.
     */
    id: "xts",
    label: "XTS",
    aead: false,
    keyLengths: [32, 64],
    nonceLen: 16,
    nonceLabel: "Data unit",
    blockAligned: false,
    minInputLen: 16,
    summary: "Disk encryption. Two keys, a sector tweak, no authentication",
  },
  {
    /**
     * RFC 5297 AES-SIV, which is a different thing from AES-GCM-SIV above.
     *
     * Both are "SIV" and both survive nonce reuse, but this one is built from CMAC and CTR and takes
     * *no nonce at all* -- the synthetic IV is derived from the plaintext and the associated data, so
     * encrypting the same plaintext twice gives the same ciphertext by design. That is deterministic
     * authenticated encryption: exactly what you want for wrapping a key or deduplicating, and
     * exactly what leaks equality of plaintexts if you use it for messages.
     */
    id: "aessiv",
    label: "SIV (RFC 5297)",
    aead: true,
    keyLengths: [32, 48, 64],
    nonceLen: 0,
    nonceLabel: "",
    blockAligned: false,
    summary: "Deterministic authenticated encryption, no nonce",
  },
  {
    /**
     * AES-KW, RFC 3394. Notable for what it does not need: no IV, no nonce, no randomness.
     *
     * The key it wraps is already unpredictable, so the mode can be deterministic without leaking
     * anything -- and it authenticates, so a wrapped key that has been altered fails to unwrap rather
     * than producing a wrong key. JOSE's `A256KW` and PKCS#11 both use it.
     */
    id: "kw",
    label: "Key wrap (RFC 3394)",
    aead: false,
    authenticatedWithoutAad: true,
    nonceLen: 0,
    nonceLabel: "",
    blockAligned: false,
    minInputLen: 16,
    inputMultiple: 8,
    summary: "Wraps a key. No IV, authenticated, 8-byte multiples",
  },
  {
    id: "kwp",
    label: "Key wrap with padding (RFC 5649)",
    aead: false,
    authenticatedWithoutAad: true,
    nonceLen: 0,
    nonceLabel: "",
    blockAligned: false,
    minInputLen: 1,
    summary: "Key wrap for any length, RFC 5649",
  },
  {
    id: "ecb",
    label: "ECB",
    aead: false,
    nonceLen: 0,
    nonceLabel: "",
    blockAligned: true,
    insecure: true,
    summary: "No IV, and identical blocks encrypt identically",
  },
];

const MODE_BY_ID = new Map(AES_MODES.map((m) => [m.id, m]));

export function requireAesMode(id: string): AesModeMeta {
  const mode = MODE_BY_ID.get(id);
  if (!mode) throw new Error(`Unknown AES mode: ${id}`);
  return mode;
}

export function getAesMode(id: string): AesModeMeta | undefined {
  return MODE_BY_ID.get(id);
}

export const DEFAULT_AES_MODE = "gcm";
