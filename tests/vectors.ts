/**
 * Official test vectors, quoted from the standard that defines each algorithm.
 *
 * The rule this repo holds itself to: a tool does not get registered in
 * `@ocs/registry` until it reproduces at least one published vector here. Not a
 * value this implementation produced and someone eyeballed — a value from the
 * document, with the document named. That is the only thing that makes a
 * cryptographic tool worth anything, and it is cheap to insist on.
 */

/** Every digest vector below is over the ASCII input named in `input`. */
export interface DigestVector {
  algorithm: string;
  /** ASCII source text. Empty, and `inputHex` set, when the input is not printable. */
  input: string;
  /**
   * The input as hex, for the standards that specify one in bytes rather than in text.
   *
   * STB 34.101.31's hash vectors are the first here to need it: their messages are prefixes of
   * BelT's own H-block, which is 256 bytes of table rather than a sentence. When this is set,
   * `input` is a human-readable description instead of the actual bytes.
   */
  inputHex?: string;
  /** Expected digest, lower-case hex. */
  hex: string;
  /** Where this value is published. */
  source: string;
  /**
   * Option values to compute under, for the tools that cover a grid of functions.
   *
   * HAVAL is one tool spanning fifteen functions and Tiger one spanning six, so a vector has to say
   * which. The values are deliberately **strings**: these are `enum` options, a select produces a
   * string, and a test that wrote numbers would be exercising a shape the form never sends. That is
   * precisely how AEGIS's 256-bit tag length stayed broken in the app with a green suite.
   */
  options?: Readonly<Record<string, string>>;
}

export const DIGEST_VECTORS: readonly DigestVector[] = [
  /**
   * BLAKE, from the round-3 submission paper's own worked examples (section 4.5).
   *
   * Both were checked against a value recalled independently of this implementation before being
   * written down, which is the only corroboration available offline: OpenSSL has no BLAKE1, and
   * neither `hash-wasm` nor `xxhash-wasm` implements it, so there is no oracle for this family the
   * way there is for the other 48 algorithms. That is stated rather than glossed over.
   */
  {
    algorithm: "blake256",
    input: "",
    hex: "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a",
    source: "BLAKE submission paper (round 3), worked example",
  },
  {
    algorithm: "blake512",
    input: "",
    hex: "a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8",
    source: "BLAKE submission paper (round 3), worked example",
  },
  // RFC 1321, section A.5 "Test suite".
  {
    algorithm: "md5",
    input: "",
    hex: "d41d8cd98f00b204e9800998ecf8427e",
    source: "RFC 1321 §A.5",
  },
  {
    algorithm: "md5",
    input: "abc",
    hex: "900150983cd24fb0d6963f7d28e17f72",
    source: "RFC 1321 §A.5",
  },
  {
    algorithm: "md5",
    input: "message digest",
    hex: "f96b697d7cb7938d525a2f31aaf161d0",
    source: "RFC 1321 §A.5",
  },

  // FIPS 180-4 / NIST CAVP known-answer values.
  {
    algorithm: "sha1",
    input: "",
    hex: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    source: "FIPS 180-4 / NIST CAVP",
  },
  {
    algorithm: "sha1",
    input: "abc",
    hex: "a9993e364706816aba3e25717850c26c9cd0d89d",
    source: "FIPS 180-4 §A.1",
  },
  {
    algorithm: "sha1",
    input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    hex: "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
    source: "FIPS 180-4 §A.2",
  },

  {
    algorithm: "sha256",
    input: "",
    hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    source: "FIPS 180-4 / NIST CAVP",
  },
  {
    algorithm: "sha256",
    input: "abc",
    hex: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    source: "FIPS 180-4 §B.1",
  },
  {
    algorithm: "sha256",
    input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    hex: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    source: "FIPS 180-4 §B.2",
  },

  {
    algorithm: "sha512",
    input: "",
    hex: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    source: "FIPS 180-4 / NIST CAVP",
  },
  {
    algorithm: "sha512",
    input: "abc",
    hex: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    source: "FIPS 180-4 §C.1",
  },
  {
    algorithm: "sha224",
    input: "abc",
    hex: "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    source: "FIPS 180-4 §A.1 (SHA-224)",
  },
  {
    algorithm: "sha384",
    input: "abc",
    hex: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    source: "FIPS 180-4 §D.1",
  },
  {
    algorithm: "sha512-224",
    input: "abc",
    hex: "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
    source: "FIPS 180-4 §E.1 (SHA-512/224)",
  },
  {
    algorithm: "sha512-256",
    input: "abc",
    hex: "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    source: "FIPS 180-4 §E.2 (SHA-512/256)",
  },

  // FIPS 202 known-answer values.
  {
    algorithm: "sha3-224",
    input: "",
    hex: "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
    source: "FIPS 202 / NIST CAVP",
  },
  {
    algorithm: "sha3-256",
    input: "",
    hex: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    source: "FIPS 202 / NIST CAVP",
  },
  {
    algorithm: "sha3-256",
    input: "abc",
    hex: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    source: "FIPS 202 / NIST CAVP",
  },
  {
    algorithm: "sha3-384",
    input: "",
    hex: "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
    source: "FIPS 202 / NIST CAVP",
  },
  {
    algorithm: "sha3-512",
    input: "",
    hex: "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
    source: "FIPS 202 / NIST CAVP",
  },

  // Original Keccak padding — deliberately different from SHA-3 above, which is
  // the whole reason both are offered. The empty-input Keccak-256 value is the
  // most widely quoted constant in the Ethereum ecosystem.
  {
    algorithm: "keccak-256",
    input: "",
    hex: "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    source: "Keccak reference / Ethereum's keccak256 of empty input",
  },
  {
    algorithm: "keccak-256",
    input: "abc",
    hex: "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    source: "Keccak reference implementation",
  },
  {
    algorithm: "keccak-512",
    input: "",
    hex: "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
    source: "Keccak reference implementation",
  },
  {
    algorithm: "keccak-224",
    input: "",
    hex: "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd",
    source: "Keccak reference implementation",
  },
  {
    algorithm: "keccak-384",
    input: "",
    hex: "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff",
    source: "Keccak reference implementation",
  },

  // RFC 1320 / ISO-IEC 10118-3.
  {
    algorithm: "ripemd160",
    input: "",
    hex: "9c1185a5c5e9fc54612808977ee8f548b2258d31",
    source: "RIPEMD-160 reference (Dobbertin, Bosselaers, Preneel)",
  },
  {
    algorithm: "ripemd160",
    input: "abc",
    hex: "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    source: "RIPEMD-160 reference (Dobbertin, Bosselaers, Preneel)",
  },

  // RFC 7693 §B/§C and the BLAKE3 reference test vectors.
  {
    algorithm: "blake2b",
    input: "abc",
    hex: "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    source: "RFC 7693 §B (BLAKE2b-512)",
  },
  {
    algorithm: "blake2s",
    input: "abc",
    hex: "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
    source: "RFC 7693 §C (BLAKE2s-256)",
  },
  {
    algorithm: "blake3",
    input: "",
    hex: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    source: "BLAKE3 reference test vectors",
  },
  {
    algorithm: "blake3",
    input: "abc",
    hex: "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
    source: "BLAKE3 reference test vectors",
  },

  // The algorithms implemented in `packages/algos` because no suitable library exists —
  // see packages/algos/WHY-NOT-A-LIBRARY.md. Their full published suites are exercised in
  // `algos-hash.test.ts`; these entries carry them through the tool layer as well.
  {
    algorithm: "md2",
    input: "abc",
    hex: "da853b0d3f88d99b30283a69e6ded6bb",
    source: "RFC 1319 §A.5",
  },
  {
    algorithm: "md4",
    input: "abc",
    hex: "a448017aaf21d8525fc10ae87aa6729d",
    source: "RFC 1320 §A.5",
  },
  {
    algorithm: "sm3",
    input: "abc",
    hex: "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    source: "GB/T 32905-2016 §5.1",
  },
  /**
   * The algorithms PHP's `hash_algos()` lists that no other document covers.
   *
   * Where php-src has a dedicated test for an algorithm, its message is used: `haval.phpt`'s empty
   * string, `snefru.phpt`, `gost.phpt`, `joaat.phpt` and `murmurhash3.phpt`. Where it does not -- the
   * Tiger truncations and the four-pass variants -- the value comes from `hash_copy_001.phpt`, which
   * hashes `I can't remember anything` with every registered algorithm. `tests/php-parity.test.ts`
   * checks all sixty of those, on two messages; these entries are what the family's own
   * every-algorithm-has-a-vector gate needs.
   *
   * FNV's four are the offset basis itself, which is the one value in that specification that needs no
   * computation and the one a wrong constant fails immediately.
   */
  {
    algorithm: "tiger",
    options: { outputLength: "24", passes: "3" },
    input: "abc",
    hex: "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93",
    source: "Anderson & Biham, Tiger paper; also a NESSIE test vector",
  },
  {
    /**
     * Tiger2's one reachable vector, and why it counts.
     *
     * GNU Crypto's Tiger2 carries this as its self-test value; the same implementation's Tiger
     * self-test is the paper's `3293ac63...`, so it is correct on everything the two share. The empty
     * message is also the case that isolates what Tiger2 changes: with no input the whole block is
     * padding and length, so the 0x80 byte has nowhere to hide.
     */
    algorithm: "tiger2",
    input: "",
    hex: "4441be75f6018773c206c22745374b924aa8313fef919f41",
    source: "GNU Crypto Tiger2 self-test value (as shipped in Jacksum)",
  },
  {
    /**
     * The empty-message digest, from the SHA-3 competition's own known-answer tests.
     *
     * One per output length here; `tests/algos-sha3-candidates.test.ts` carries all 72, at eighteen
     * message lengths, because that is where the padding and the two permutations are exercised. This
     * entry exists so the "every algorithm ships a published vector" gate is satisfied from the same
     * source the family's other hashes use.
     */
    algorithm: "groestl224",
    input: "",
    hex: "f2e180fb5947be964cd584e22e496242c6a329c577fc4ce8c36d34c3",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "groestl256",
    input: "",
    hex: "1a52d11d550039be16107f9c58db9ebcc417f16f736adb2502567119f0083467",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "groestl384",
    input: "",
    hex: "ac353c1095ace21439251007862d6c62f829ddbe6de4f78e68d310a9205a736d8b11d99bffe448f57a1cfa2934f044a5",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "groestl512",
    input: "",
    hex: "6d3ad29d279110eef3adbd66de2a0345a77baede1557f5d099fce0c03d6dc2ba8e6d4a6633dfbd66053c20faa87d1a11f39a7fbe4a6c2f009801370308fc4ad8",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    /**
     * JH's empty-message digest. The block-aligned case, which is the one JH pads differently from
     * every other length -- see the note in `packages/algos/src/jh.ts`.
     */
    algorithm: "jh224",
    input: "",
    hex: "2c99df889b019309051c60fecc2bd285a774940e43175b76b2626630",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "jh256",
    input: "",
    hex: "46e64619c18bb0a92a5e87185a47eef83ca747b8fcc8e1412921357e326df434",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "jh384",
    input: "",
    hex: "2fe5f71b1b3290d3c017fb3c1a4d02a5cbeb03a0476481e25082434a881994b0ff99e078d2c16b105ad069b569315328",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "jh512",
    input: "",
    hex: "90ecf2f76f9d2c8017d979ad5ab96b87d58fc8fc4b83060f3f900774faa2c8fabe69c5f4ff1ec2b61d6b316941cedee117fb04b1f4c5bc1b919ae841c50eec4f",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    /** CubeHash16/32's empty-message digest. */
    algorithm: "cubehash224",
    input: "",
    hex: "f9802aa6955f4b7cf3b0f5a378fa0c9f138e0809d250966879c873ab",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "cubehash256",
    input: "",
    hex: "44c6de3ac6c73c391bf0906cb7482600ec06b216c7c54a2a8688a6a42676577d",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "cubehash384",
    input: "",
    hex: "98ae93ebf4e58958497f610a22c8cf60f2292319283ca6459daed1707be06e7591c5f2d84bd3339e66c770e485bfa1fb",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "cubehash512",
    input: "",
    hex: "4a1d00bbcfcb5a9562fb981e7f7db3350fe2658639d948b9d57452c22328bb32f468b072208450bad5ee178271408be0b16e5633ac8a1e3cf9864cfbfc8e043a",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    /**
     * Luffa's empty-message digest, one per output length.
     *
     * `tests/algos-sha3-candidates.test.ts` carries all 72; these four exist so the "every algorithm
     * ships a published vector" gate reads from the same source the rest of the family uses.
     */
    algorithm: "luffa224",
    input: "",
    hex: "dbb8665871f4154d3e4396aefbba417cb7837dd683c332ba6be87e02",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "luffa256",
    input: "",
    hex: "dbb8665871f4154d3e4396aefbba417cb7837dd683c332ba6be87e02a2712d6f",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "luffa384",
    input: "",
    hex: "117d3ad49024dfe2994f4e335c9b330b48c537a13a9b7fa465938e1a02ff862bcdf33838bc0f371b045d26952d3ea0c5",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "luffa512",
    input: "",
    hex: "6e7de4501189b3ca58f3ac114916654bbcd4922024b4cc1cd764acfe8ab4b7805df133eab345ffdb1c414564c924f48e0a301824e2ac4c34bd4efde2e43da90e",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    /** Fugue's empty-message digest, one per output length. All 72 are in the candidates test. */
    algorithm: "fugue224",
    input: "",
    hex: "e2cd30d51a913c4ed2388a141f90caa4914de43010849e7b8a7a9ccd",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "fugue256",
    input: "",
    hex: "d6ec528980c130aad1d1acd28b9dd8dbdeae0d79eded1fca72c2af9f37c2246f",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "fugue384",
    input: "",
    hex: "466d05f6812b58b8628e53816b2a99d173b804a964de971829159c3791ac8b524eebbf5fc73ba40ea8eea446d5424a30",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "fugue512",
    input: "",
    hex: "3124f0cbb5a1c2fb3ce747ada63ed2ab3bcd74795cef2b0e805d5319fcc360b4617b6a7eb631d66f6d106ed0724b56fa8c1110f9b8df1c6898e7ca3c2dfccf79",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    /** SHAvite-3's empty-message digest. All 72 are in the candidates test. */
    algorithm: "shavite224",
    input: "",
    hex: "b33f761f0d3a86bb1051905aec7a691bd0b5a24c3721f67d8e48d839",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "shavite256",
    input: "",
    hex: "08c5825af2e9e5947286a8fe208bd5f8c6a7c8e4da598947d7ff8eda0fcd2bd7",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "shavite384",
    input: "",
    hex: "814b55553ce7c0841f8ff0321e6287f9f50a8e0cae811932385ecc1b7c386b4eb14edb79c8381babf09276b69d1bb3ee",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "shavite512",
    input: "",
    hex: "a485c1b2578459d1efc5dddd840bb0b4a650ac82fe68f58c4442ccda747da006b2d1dc6b4a4eb7d84ff91e1f466fef429d259acd995dddcad16fa545c7a6e5ba",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    /**
     * Shabal-192 has no KAT array in the competition data -- only this one value, which the
     * reference implementation checks itself against. It is the only published vector covering
     * that length's initial values, which is why the message is a sentence rather than empty.
     */
    algorithm: "shabal192",
    input: "abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789-abcdefghijklmnopqrstuvwxyz",
    hex: "690fae79226d95760ae8fdb4f58c0537111756557d307b15",
    source: "sphlib test_shabal.c self-test value",
  },
  {
    /** The other four lengths carry eighteen vectors each; see the candidates test. */
    algorithm: "shabal224",
    input: "",
    hex: "562b4fdbe1706247552927f814b66a3d74b465a090af23e277bf8029",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "shabal256",
    input: "",
    hex: "aec750d11feee9f16271922fbaf5a9be142f62019ef8d720f858940070889014",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "shabal384",
    input: "",
    hex: "ff093d67d22b06a674b5f384719150d617e0ff9c8923569a2ab60cda886df63c91a25f33cd71cc22c9eebc5cd6aee52a",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "shabal512",
    input: "",
    hex: "fc2d5dff5d70b7f6b1f8c2fcc8c1f9fe9934e54257eded0cf2b539a2ef0a19ccffa84f8d9fa135e4bd3c09f590f3a927ebd603ac29eb729e6f2a9af031ad8dc6",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    /**
     * The five non-cryptographic families, each with the one value that stands for it here.
     *
     * All five carry hundreds more in `tests/algos-nonchash.test.ts` -- 512 for SpookyHash, 2,400 for
     * CityHash, 243 for t1ha, 195 for HighwayHash -- and those are what actually establish
     * correctness, because every one of these dispatches on input length. These entries exist so the
     * "every algorithm ships a published vector" gate is satisfied against the same sources rather
     * than waived, and so a reader looking one up in this file finds it.
     *
     * MetroHash's is over the author's 63-byte key rather than the empty message, because 63 is the
     * length its own test suite chose: 32 + 16 + 8 + 4 + 2 + 1 walks every tail branch in one value.
     */
    algorithm: "cityhash",
    input: "",
    hex: "4f40902f3b6ae19a",
    source: "google/cityhash city-test.cc, case 0 column 0 (CityHash64)",
    options: { outputLength: "8" },
  },
  {
    algorithm: "spookyhash",
    input: "",
    hex: "1909f56b",
    source: "burtleburtle.net TestSpookyV2.cpp, expected[0] (Hash32)",
    options: { outputLength: "4" },
  },
  {
    algorithm: "metrohash",
    input: "012345678901234567890123456789012345678901234567890123456789012",
    hex: "658f044f5c730e40",
    source: "jandrewrogers/MetroHash testvector.h, metrohash64_1 at seed 0",
    options: { outputLength: "8", hashVariant: "1" },
  },
  {
    algorithm: "t1ha",
    input: "the 64-byte t1ha test pattern",
    inputHex: "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778",
    hex: "037e203fd2534744",
    source: "erthink/t1ha t1ha2_selfcheck.c, t1ha_refval_2atonce[2] (t1ha2 over the 64-byte pattern)",
    options: { outputLength: "8", hashVariant: "t1ha2" },
  },
  {
    /**
     * The three algorithms that closed the SHA-3 competition set. Each entry is the empty message,
     * which is the case that reaches every one of these three implementations' empty-final-block
     * branch -- ECHO zeroes the counter keying its AES rounds, SIMD skips the tail compression, and
     * Hamsi's small variant still runs three blocks because its length field spans two of them.
     *
     * `tests/algos-sha3-candidates.test.ts` carries all 72 vectors apiece; these are here to satisfy
     * the "every algorithm ships a published vector" gate against the same source.
     */
    algorithm: "echo224",
    input: "",
    hex: "17da087595166f733fff7cdb0bca6438f303d0e00c48b5e7a3075905",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "echo256",
    input: "",
    hex: "4496cd09d425999aefa75189ee7fd3c97362aa9e4ca898328002d20a4b519788",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "echo384",
    input: "",
    hex: "134040763f840559b84b7a1ae5d6d64fc3659821a789cc64a7f1444c09ee7f81a54d72beee8273bae5ef18ec43aa5f34",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "echo512",
    input: "",
    hex: "158f58cc79d300a9aa292515049275d051a28ab931726d0ec44bdd9faef4a702c36db9e7922fff077402236465833c5cc76af4efc352b4b44c7fa15aa0ef234e",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "hamsi224",
    input: "",
    hex: "b9f6eb1a9b990373f9d2cb125584333c69a3d41ae291845f05da221f",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "hamsi256",
    input: "",
    hex: "750e9ec469f4db626bee7e0c10ddaa1bd01fe194b94efbabebd24764dc2b13e9",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "hamsi384",
    input: "",
    hex: "3943cd34e3b96b197a8bf4bac7aa982d18530dd12f41136b26d7e88759255f21153f4a4bd02e523612b8427f9dd96c8d",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "hamsi512",
    input: "",
    hex: "5cd7436a91e27fc809d7015c3407540633dab391127113ce6ba360f0c1e35f404510834a551610d6e871e75651ea381a8ba628af1dcf2b2be13af2eb6247290f",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "simd224",
    input: "",
    hex: "43e1d53656d7b85d10d5499e28afdef90bb497730d2853c8609b534b",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "simd256",
    input: "",
    hex: "8029e81e7320e13ed9001dc3d8021fec695b7a25cd43ad805260181c35fcaea8",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "simd384",
    input: "",
    hex: "5fdd62778fc213221890ad3bac742a4af107ce2692d6112e795b54b25dcd5e0f4bf3ef1b770ab34b38f074a5e0ecfcb5",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    algorithm: "simd512",
    input: "",
    hex: "51a5af7e243cd9a5989f7792c880c4c3168c3d60c4518725fe5757d1f7a69c6366977eaba7905ce2da5d7cfd07773725f0935b55f3efb954996689a49b6d29e0",
    source: "NIST SHA-3 competition KAT, via sphlib test data",
  },
  {
    /**
     * STB 34.101.31 tests A.23-1/2/3, whose messages are the first 13, 32 and 48 bytes of
     * BelT's H-block. Between them they cover every branch of a padding rule that has no
     * padding byte -- a partial block, exactly one block, and a block and a partial one.
     */
    algorithm: "belt-hash",
    input: "the first 13 bytes of BelT's H-block",
    inputHex: "b194bac80a08f53b366d008e58",
    hex: "abef9725d4c5a83597a367d14494cc2542f20f659ddfecc961a3ec550cba8c75",
    source: "STB 34.101.31 test A.23-1",
  },
  {
    algorithm: "belt-hash",
    input: "the first 32 bytes of BelT's H-block",
    inputHex: "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d",
    hex: "749e4c3653aece5e48db4761227742eb6dbe13f4a80f7beff1a9cf8d10ee7786",
    source: "STB 34.101.31 test A.23-2",
  },
  {
    algorithm: "belt-hash",
    input: "the first 48 bytes of BelT's H-block",
    inputHex: "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b",
    hex: "9d02ee446fb6a29fe5c982d4b13af9d3e90861bc4cef27cf306bfb0b174a154a",
    source: "STB 34.101.31 test A.23-3",
  },
  /**
   * The five NIST-lightweight hashes, from their submissions' own known-answer files.
   *
   * Two anchors each: the empty message, where a wrong initial state or a missing domain constant has
   * nowhere to hide, and a 16-byte message, which is the block boundary for three of the five and the
   * exact width of PHOTON-Beetle's state -- the one length in this whole family that produced a
   * first-attempt failure.
   *
   * `tests/algos-lwc.test.ts` carries 54 lengths per algorithm; these two are here because
   * `tests/hash.test.ts` requires every registered algorithm to ship a published vector through the
   * *tool*, and that is a different path -- options, resolver, binding, streaming.
   */
  {
    algorithm: "xoodyak-hash",
    input: "the empty message",
    inputHex: "",
    hex: "ea152f2b47bce24efb66c479d4adf17bd324d806e85ff75ee369ee50dc8f8bd1",
    source: "the Xoodyak submission KAT, Count = 1",
  },
  {
    algorithm: "xoodyak-hash",
    input: "the 16 bytes 00..0f",
    inputHex: "000102030405060708090a0b0c0d0e0f",
    hex: "9ea695347cdddff9bc63ece30fe231441d581768fe223dd6bd7367094fd216b3",
    source: "the Xoodyak submission KAT, Count = 17",
  },
  {
    algorithm: "esch256",
    input: "the empty message",
    inputHex: "",
    hex: "c0e815d78b875dc768c6c8b3afa51987cd69e5c087d387368628a511cfad5730",
    source: "the SPARKLE submission KAT, Count = 1",
  },
  {
    algorithm: "esch256",
    input: "the 16 bytes 00..0f",
    inputHex: "000102030405060708090a0b0c0d0e0f",
    hex: "acff841e2a526d83d6e94ab5564d6d64c98f5e8016bb1c2950386ed156c6c174",
    source: "the SPARKLE submission KAT, Count = 17",
  },
  {
    algorithm: "esch384",
    input: "the empty message",
    inputHex: "",
    hex: "2981715e2263ebd0cb6e5c2c99d0776d5e691ee737fde05247895e75d02e7447fd6ab707e2ec8385a539777965e472ee",
    source: "the SPARKLE submission KAT, Count = 1",
  },
  {
    algorithm: "esch384",
    input: "the 16 bytes 00..0f",
    inputHex: "000102030405060708090a0b0c0d0e0f",
    hex: "0008f97d6bbb701d5e33fcc178efe3e3d5e77915d4a4daf6e1ae34cd28edb895a053e19d930b50f72837e1a8f5b1f450",
    source: "the SPARKLE submission KAT, Count = 17",
  },
  {
    algorithm: "photonbeetle-hash",
    input: "the empty message",
    inputHex: "",
    hex: "44a99882fea033566856a27e7f0c94dc84fac7e411b08b890a4a574e3db75d4a",
    source: "the PHOTON-Beetle submission KAT, Count = 1",
  },
  {
    algorithm: "photonbeetle-hash",
    input: "the 16 bytes 00..0f",
    inputHex: "000102030405060708090a0b0c0d0e0f",
    hex: "ab0d1eb0315df8af7f7ae0ac42eaf2f52fb0fdf0904e182dcc796b6cb8d7981a",
    source: "the PHOTON-Beetle submission KAT, Count = 17",
  },
  {
    algorithm: "romulus-h",
    input: "the empty message",
    inputHex: "",
    hex: "249b3f4370030b979f230ce05029361085766858879b31044742afc4cde6b5ab",
    source: "the Romulus submission KAT, Count = 1",
  },
  {
    algorithm: "romulus-h",
    input: "the 16 bytes 00..0f",
    inputHex: "000102030405060708090a0b0c0d0e0f",
    hex: "c1e45f5ab2852c334ce470203c912537226bb6910fa32b295cd95e7674f025a2",
    source: "the Romulus submission KAT, Count = 17",
  },
  /**
   * The three lightweight sponges that are not NIST finalists.
   *
   * The breadth is in `tests/algos-lightweight-hash.test.ts` -- 35 GIMLI known-answer records, all four
   * Quark instances and both PHOTON vectors, plus the derivation checks. These exist because every
   * registered algorithm must reproduce a published value through the *tool*, which is a different path:
   * options, variant resolution, binding and streaming.
   *
   * Quark gets two rows -- the default `u-quark` and `c-quark` -- because one would not be enough. The
   * variant option has to reach the binding *and* set the digest width, and the default alone would pass
   * even if it did neither: 17 bytes is what an ignored variant produces. c-Quark's 48 is not.
   */
  {
    algorithm: "gimli",
    input: "the empty message",
    inputHex: "",
    hex: "27ae20e95fbc2bf01e972b0015eea431c20fc8818f25bc6dbe66232230db352f",
    source: "the GIMLI submission KAT, Count = 1",
  },
  {
    algorithm: "gimli",
    input: "the 16 bytes 00..0f",
    inputHex: "000102030405060708090a0b0c0d0e0f",
    hex: "404c130af1b9023a7908200919f690ffbb756d5176e056ffde320016a37c7282",
    source: "the GIMLI submission KAT, Count = 17",
  },
  {
    algorithm: "quark",
    input: "the empty message",
    inputHex: "",
    hex: "126b75bcab23144750d08ba313bbd800a4",
    source: "the Quark reference implementation's own u-Quark self-test",
    options: { hashVariant: "u-quark" },
  },
  {
    algorithm: "quark",
    input: "the empty message",
    inputHex: "",
    hex: "1cb9770ee7c25fa9dce2c9464578337c69c7e26cb4f1bdf44869f1a93639f1f360b888975ff9ffee880d2c499108a27a",
    source: "the Quark reference implementation's own c-Quark self-test",
    options: { hashVariant: "c-quark" },
  },
  {
    algorithm: "photon",
    input: "the two bytes 11 22",
    inputHex: "1122",
    hex: "b2397568e1e3e1279a1bbe8fd75dac5a",
    source: "FELICS's PHOTON_16_144_128 test vectors",
  },
  /**
   * The two CRC-32C-mixed variants.
   *
   * CityHashCrc's row is the 256-bit form over the empty message, which is case 0 of its own
   * `city-test.cc` table -- the 128-bit form at that length *is* CityHash128 by definition, so it would
   * not distinguish the tool from the one beside it. The 256-bit form has no such delegation at any
   * length.
   *
   * MetroHash128CRC's two rows use the reference's own 63-byte key, whose length its comment says is
   * chosen to "properly exercise every internal branch" -- 32 + 16 + 8 + 4 + 2 + 1. Two rows because
   * the variants differ only in constants and rotations, so one would pass on a control wired to
   * nothing.
   */
  {
    algorithm: "cityhashcrc",
    input: "the empty message",
    inputHex: "",
    hex: "30f9a5e6242f1695e006ebf1f4bd0868824d627ba6f3b1b30bd84cbd122fa6c9",
    source: "city-test.cc's testdata columns 11 to 14, case 0",
    options: { outputLength: "32" },
  },
  {
    algorithm: "metrohash128crc",
    input: "012345678901234567890123456789012345678901234567890123456789012",
    hex: "b329ed67831604d3dfac4e4876d8262f",
    source: "MetroHash's own testvector.h, metrohash128crc_1 at seed 0",
    options: { hashVariant: "1" },
  },
  {
    algorithm: "metrohash128crc",
    input: "012345678901234567890123456789012345678901234567890123456789012",
    hex: "0502a67e257bbd77206bbca6bbef2653",
    source: "MetroHash's own testvector.h, metrohash128crc_2 at seed 0",
    options: { hashVariant: "2" },
  },
  /**
   * FarmHash's three namespaces, over 65 bytes of its own self-test buffer.
   *
   * The length is chosen because it is one of the few where all three namespaces disagree: `uo`
   * delegates to `na` at 64 bytes and below, and `xo` delegates to `na` up to 32 and again from 97 to
   * 256, so most lengths cannot tell them apart. The empty message gives k2 for all three and would
   * pass on a dropdown wired to nothing.
   *
   * The input is bytes 4225 to 4289 of CityHash's 1 MB self-test buffer, which is FarmHash's own case
   * 65 (offset i*i, length i), and the expected values are that case's `Hash64` entries from
   * `farmhash.cc`. Both halves come from the reference; neither was produced here. The breadth is in
   * `tests/algos-farmhash.test.ts`, which asserts all 5,792.
   */

  {
    algorithm: "farmhash",
    input: "65 bytes of FarmHash's own self-test buffer, at its case 65",
    inputHex:
      "5ad402a5a42187df5c0c6c4db1a8663cdc2c55b7dbf8c410c109bec2f0847b6495fc6a14cc9be158d204aeefc4cf97fb8b2d3b9e0f30319a9adba14575370065d0",
    hex: "3cceab392bc39b3f",
    source: "farmhash.cc's farmhashnaTest self-test, case 65" ,
    options: { hashVariant: "na" },
  },
  {
    algorithm: "farmhash",
    input: "65 bytes of FarmHash's own self-test buffer, at its case 65",
    inputHex:
      "5ad402a5a42187df5c0c6c4db1a8663cdc2c55b7dbf8c410c109bec2f0847b6495fc6a14cc9be158d204aeefc4cf97fb8b2d3b9e0f30319a9adba14575370065d0",
    hex: "9cf7784ff16c8087",
    source: "farmhash.cc's farmhashuoTest self-test, case 65" ,
    options: { hashVariant: "uo" },
  },
  {
    algorithm: "farmhash",
    input: "65 bytes of FarmHash's own self-test buffer, at its case 65",
    inputHex:
      "5ad402a5a42187df5c0c6c4db1a8663cdc2c55b7dbf8c410c109bec2f0847b6495fc6a14cc9be158d204aeefc4cf97fb8b2d3b9e0f30319a9adba14575370065d0",
    hex: "626b3525c640cc96",
    source: "farmhash.cc's farmhashxoTest self-test, case 65" ,
    options: { hashVariant: "xo" },
  },
  /**
   * rapidhash at all four versions, over the same three bytes and the same seed.
   *
   * Three bytes is chosen deliberately: it is one of only two length ranges where all four versions
   * disagree (the other is 49 to 64), so four distinct expected values here prove the version dropdown
   * reaches the binding. At 13 bytes v2.0 and v2.2 legitimately coincide and two of these rows would
   * pass on a control wired to nothing.
   *
   * The seed is written out as `00` rather than left empty, because an empty field means each version's
   * *own* default and v1.0's is not zero -- see `compute.ts`.
   *
   * Values from `komiya-atsushi/rapidhash-js`'s generated vectors; the breadth is in
   * `tests/algos-rapidhash.test.ts`, which asserts 300 of them.
   */

  {
    algorithm: "rapidhash",
    input: "123",
    hex: "f8098dcbc713bb50",
    source: "rapidhash-js generated vectors, v1.0 at seed 0",
    options: { hashVariant: "v1.0", seed64: "00", seed64Encoding: "hex" },
  },
  {
    algorithm: "rapidhash",
    input: "123",
    hex: "366cd8137a946e51",
    source: "rapidhash-js generated vectors, v2.0 at seed 0",
    options: { hashVariant: "v2.0", seed64: "00", seed64Encoding: "hex" },
  },
  {
    algorithm: "rapidhash",
    input: "123",
    hex: "4ff17d290a897c99",
    source: "rapidhash-js generated vectors, v2.2 at seed 0",
    options: { hashVariant: "v2.2", seed64: "00", seed64Encoding: "hex" },
  },
  {
    algorithm: "rapidhash",
    input: "123",
    hex: "bbb9e0e685c2bf69",
    source: "rapidhash-js generated vectors, v3.0 at seed 0",
    options: { hashVariant: "v3.0", seed64: "00", seed64Encoding: "hex" },
  },
  /**
   * wyhash final 3, all seven of the reference's own vectors.
   *
   * From Zig's standard library, which states that they run `test_vector.cpp` from the wyhash
   * repository at commit `77e50f2`. Their seeds are the row index, which is what that program does.
   *
   * The lengths are the point: 0, 1 and 14 cross wyhash's short paths (under 4, and 4 to 16), 26
   * exercises the 16-byte tail loop, and 62 and 80 reach the three-lane 48-byte body. Seven values
   * covering four branches is better coverage than seventy at one length.
   */

  {
    algorithm: "wyhash",
    input: "the empty message",
    inputHex: "",
    hex: "0409638ee2bde459",
    source: "wyhash test_vector.cpp via Zig's standard library, seed 0",
    options: { seed64: "00", seed64Encoding: "hex" },
  },
  {
    algorithm: "wyhash",
    input: "a",
    hex: "a8412d091b5fe0a9",
    source: "wyhash test_vector.cpp via Zig's standard library, seed 1",
    options: { seed64: "01", seed64Encoding: "hex" },
  },
  {
    algorithm: "wyhash",
    input: "abc",
    hex: "32dd92e4b2915153",
    source: "wyhash test_vector.cpp via Zig's standard library, seed 2",
    options: { seed64: "02", seed64Encoding: "hex" },
  },
  {
    algorithm: "wyhash",
    input: "message digest",
    hex: "8619124089a3a16b",
    source: "wyhash test_vector.cpp via Zig's standard library, seed 3",
    options: { seed64: "03", seed64Encoding: "hex" },
  },
  {
    algorithm: "wyhash",
    input: "abcdefghijklmnopqrstuvwxyz",
    hex: "7a43afb61d7f5f40",
    source: "wyhash test_vector.cpp via Zig's standard library, seed 4",
    options: { seed64: "04", seed64Encoding: "hex" },
  },
  {
    algorithm: "wyhash",
    input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    hex: "ff42329b90e50d58",
    source: "wyhash test_vector.cpp via Zig's standard library, seed 5",
    options: { seed64: "05", seed64Encoding: "hex" },
  },
  {
    algorithm: "wyhash",
    input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    hex: "c39cab13b115aad3",
    source: "wyhash test_vector.cpp via Zig's standard library, seed 6",
    options: { seed64: "06", seed64Encoding: "hex" },
  },
  /**
   * The belt-and-mill pair, the two Ukrainian sizes and the Korean standard.
   *
   * Chosen to be the shortest published input at each size, so the entry is readable -- the breadth is
   * in `tests/algos-beltmill.test.ts`, which runs 78 RadioGatun vectors, 17 Kupyna and 7 HAS-160. These
   * exist because `tests/hash.test.ts` requires every registered algorithm to ship a vector through the
   * *tool*, which is a different path: options, resolver, binding and streaming.
   */
  {
    algorithm: "radiogatun32",
    input: "the empty message",
    inputHex: "",
    hex: "f30028b54afab6b3e55355d277711109a19beda7091067e9a492fb5ed9f20117",
    source: "the RadioGatun designers' own test file, via sphlib",
  },
  {
    algorithm: "radiogatun64",
    input: "the empty message",
    inputHex: "",
    hex: "64a9a7fa139905b57bdab35d33aa216370d5eae13e77bfcdd85513408311a584",
    source: "the RadioGatun designers' own test file, via sphlib",
  },
  {
    algorithm: "panama",
    input: "the empty message",
    inputHex: "",
    hex: "aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b",
    source: "the Panama designers' own test file, via sphlib",
  },
  {
    algorithm: "kupyna256",
    input: "0 bytes, 0x00 upward",
    inputHex: "",
    hex: "cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6",
    source: "DSTU 7564 annex, via Bouncy Castle's DSTU7564Test",
  },
  {
    algorithm: "kupyna384",
    input: "95 bytes, 0x00 upward",
    inputHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e",
    hex: "d9021692d84e5175735654846ba751e6d0ed0fac36dfbc0841287dcb0b5584c75016c3decc2a6e47c50b2f3811e351b8",
    source: "DSTU 7564 annex, via Bouncy Castle's DSTU7564Test",
  },
  {
    algorithm: "kupyna512",
    input: "0 bytes, 0x00 upward",
    inputHex: "",
    hex: "656b2f4cd71462388b64a37043ea55dbe445d452aecd46c3298343314ef04019bcfa3f04265a9857f91be91fce197096187ceda78c9c1c021c294a0689198538",
    source: "DSTU 7564 annex, via Bouncy Castle's DSTU7564Test",
  },
  {
    algorithm: "has160",
    input: "abc",
    hex: "975e810488cf2a3d49838478124afce4b1c78804",
    source: "TTAS.KO-12.0011, via RHash's test suite",
  },
  /**
   * LSH at its four sizes, from Crypto++'s vectors -- the shortest non-empty message at each.
   *
   * The breadth is in `tests/algos-lsh.test.ts`, which runs every length from 1 to 128 plus twenty
   * all-zero lengths to 65536. These exist because `tests/hash.test.ts` requires each registered
   * algorithm to ship a vector through the *tool*: options, resolver, binding and streaming.
   */
  {
    algorithm: "lsh224",
    input: "one byte, 0xca",
    inputHex: "ca",
    hex: "4253e6e91b3c37f75c231d53ca6dc8464885250d2058c41d495bd08f",
    source: "KISA's reference, via Crypto++ TestVectors/lsh256.txt",
  },
  {
    algorithm: "lsh256",
    input: "one byte, 0xce",
    inputHex: "ce",
    hex: "862f86db654094840d86df7881732fd69b7227ee4f7943868162feb733a9ca5b",
    source: "KISA's reference, via Crypto++ TestVectors/lsh256.txt",
  },
  {
    algorithm: "lsh384",
    input: "one byte, 0x76",
    inputHex: "76",
    hex: "52ff6386afce2189733ab9f206dd87774c22c1475b22f4e72cb7f603c1ac54402c63cabe2cf10cf01697a0da717de9ec",
    source: "KISA's reference, via Crypto++ TestVectors/lsh512.txt",
  },
  {
    algorithm: "lsh512",
    input: "one byte, 0x41",
    inputHex: "41",
    hex: "32e896b21bec19c15254f7a1f089f748e05918a68e6d829fb1a62b7d5822ad98b7de274f7dc6c73e6f52c5f0b7633666dbe6048661351d811105ee015b9dcac9",
    source: "KISA's reference, via Crypto++ TestVectors/lsh512.txt",
  },
  {
    algorithm: "tiger",
    options: { outputLength: "16", passes: "3" },
    input: "I can't remember anything",
    hex: "8d68e78bc5e62ba925a67aa48595cfc6",
    source: "php-src ext/hash/tests/hash_copy_001.phpt",
  },
  {
    algorithm: "tiger",
    options: { outputLength: "20", passes: "3" },
    input: "I can't remember anything",
    hex: "8d68e78bc5e62ba925a67aa48595cfc62cd1e5e0",
    source: "php-src ext/hash/tests/hash_copy_001.phpt",
  },
  {
    algorithm: "tiger",
    options: { outputLength: "16", passes: "4" },
    input: "I can't remember anything",
    hex: "a26ca3f58e74fb32ee44b099cb1b5122",
    source: "php-src ext/hash/tests/hash_copy_001.phpt",
  },
  {
    algorithm: "tiger",
    options: { outputLength: "20", passes: "4" },
    input: "I can't remember anything",
    hex: "a26ca3f58e74fb32ee44b099cb1b512203375900",
    source: "php-src ext/hash/tests/hash_copy_001.phpt",
  },
  {
    algorithm: "tiger",
    options: { outputLength: "24", passes: "4" },
    input: "I can't remember anything",
    hex: "a26ca3f58e74fb32ee44b099cb1b512203375900f30b741d",
    source: "php-src ext/hash/tests/hash_copy_001.phpt",
  },
  /**
   * MD6 at all three registered sizes, from Rivest's reference implementation.
   *
   * The only entry here whose source is a reference *implementation* rather than a document, and the
   * reason is recorded rather than glossed: MD6 was withdrawn after SHA-3 round 1, so there is no
   * standard with a test annex, and NIST's KAT files for the round-1 submissions are not mirrored
   * anywhere reachable. Same shape as Tiger2's entry, and corroborated the same way -- see
   * `tests/algos-md6.test.ts`, which checks 26 values from that implementation plus one from a second,
   * unrelated port over an input the first does not use.
   *
   * All three sizes, because MD6-128 is *not* a truncation of MD6-512: the digest size goes into the
   * control word and sets the round count, so each is a different function. A single vector at 256
   * would leave two of the three dropdown choices unverified.
   */
  {
    algorithm: "md6",
    options: { outputLength: "16" },
    input: "abc",
    hex: "8db50d79cf42fe7d1807ebaa15329c61",
    source: "MD6 reference implementation (Rivest), d=128",
  },
  {
    algorithm: "md6",
    options: { outputLength: "32" },
    input: "abc",
    hex: "230637d4e6845cf0d092b558e87625f03881dd53a7439da34cf3b94ed0d8b2c5",
    source: "MD6 reference implementation (Rivest), d=256",
  },
  {
    algorithm: "md6",
    options: { outputLength: "64" },
    input: "abc",
    hex:
      "00918245271e377a7ffb202b90f3bda5477d8feab12d8a3a8994ebc55fe6e74c" +
      "a8341520032eeea3fdef892f2882378f636212af4b2683ccf80bf025b7d9b457",
    source: "MD6 reference implementation (Rivest), d=512",
  },
  /**
   * "Progressive" at all three sizes, from a third source independent of the other two.
   *
   * Supplied against a reference the user already had, which makes it the most valuable kind of vector
   * this file can carry: it was checked *after* the implementation was written and by somebody who had
   * not seen it, so it cannot have been fitted to. All three matched first time.
   *
   * Note the input has no trailing newline -- the digests for `"Progressive"` and `"Progressive\n"` are
   * of course unrelated, and a value transcribed out of a tool that appends one would look like a
   * failure here rather than like the transcription it was. Worth stating because it is the single most
   * common way a hash comparison goes wrong.
   */
  {
    algorithm: "md6",
    options: { outputLength: "16" },
    input: "Progressive",
    hex: "08d59da8b9afce97cd91876a06c74d1b",
    source: "third-party MD6 reference, d=128",
  },
  {
    algorithm: "md6",
    options: { outputLength: "32" },
    input: "Progressive",
    hex: "470c33fd30ceef8d331df45bed88f36bd1e5a0610d80da7280d860e82f4bcab2",
    source: "third-party MD6 reference, d=256",
  },
  {
    algorithm: "md6",
    options: { outputLength: "64" },
    input: "Progressive",
    hex:
      "8cf89011b1d71259f6e2be38eadc50c70a8b11728d58ed685c89ea39162ef196" +
      "19ea850ae7e8b91a342cfa987d29d89fd0e5560f78cd0864e2c72ff39128c23c",
    source: "third-party MD6 reference, d=512",
  },
  /**
   * And the empty message, which is the one input a tree hash gets wrong independently.
   *
   * Zero bytes still produces one leaf, and that leaf is also the root -- so it is the only case where
   * the `z` bit and the leaf compression coincide. Every other length in the suite has at least one
   * byte for the padding count to describe.
   */
  {
    algorithm: "md6",
    options: { outputLength: "32" },
    input: "",
    hex: "bca38b24a804aa37d821d31af00f5598230122c5bbfc4c4ad5ed40e4258f04ca",
    source: "MD6 reference implementation (Rivest), d=256, empty message",
  },
  {
    algorithm: "haval",
    options: { outputLength: "16", passes: "3" },
    input: "",
    hex: "c68f39913f901f3ddf44c707357a7d70",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "20", passes: "3" },
    input: "",
    hex: "d353c3ae22a25401d257643836d7231a9a95f953",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "24", passes: "3" },
    input: "",
    hex: "e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "28", passes: "3" },
    input: "",
    hex: "c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "32", passes: "3" },
    input: "",
    hex: "4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "16", passes: "4" },
    input: "",
    hex: "ee6bbf4d6a46a679b3a856c88538bb98",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "20", passes: "4" },
    input: "",
    hex: "1d33aae1be4146dbaaca0b6e70d7a11f10801525",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "24", passes: "4" },
    input: "",
    hex: "4a8372945afa55c7dead800311272523ca19d42ea47b72da",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "28", passes: "4" },
    input: "",
    hex: "3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "32", passes: "4" },
    input: "",
    hex: "c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "16", passes: "5" },
    input: "",
    hex: "184b8482a0c050dca54b59c7f05bf5dd",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "20", passes: "5" },
    input: "",
    hex: "255158cfc1eed1a7be7c55ddd64d9790415b933b",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "24", passes: "5" },
    input: "",
    hex: "4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "28", passes: "5" },
    input: "",
    hex: "4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "haval",
    options: { outputLength: "32", passes: "5" },
    input: "",
    hex: "be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330",
    source: "php-src ext/hash/tests/haval.phpt",
  },
  {
    algorithm: "snefru",
    input: "",
    hex: "8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881",
    source: "php-src ext/hash/tests/snefru.phpt",
  },
  {
    algorithm: "gost94",
    input: "",
    hex: "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d",
    source: "php-src ext/hash/tests/gost.phpt",
  },
  {
    algorithm: "gost94-crypto",
    input: "",
    hex: "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0",
    source: "php-src ext/hash/tests/gost.phpt",
  },
  {
    algorithm: "fnv132",
    input: "",
    hex: "811c9dc5",
    source: "FNV specification: the offset basis",
  },
  {
    algorithm: "fnv1a32",
    input: "",
    hex: "811c9dc5",
    source: "FNV specification: the offset basis",
  },
  {
    algorithm: "fnv164",
    input: "",
    hex: "cbf29ce484222325",
    source: "FNV specification: the offset basis",
  },
  {
    algorithm: "fnv1a64",
    input: "",
    hex: "cbf29ce484222325",
    source: "FNV specification: the offset basis",
  },
  {
    algorithm: "joaat",
    input: "hello world",
    hex: "3e4a5a57",
    source: "php-src ext/hash/tests/joaat.phpt",
  },
  {
    algorithm: "murmur3a",
    input: "foo",
    hex: "f6a5c420",
    source: "php-src ext/hash/tests/murmurhash3.phpt",
  },
  {
    algorithm: "murmur3c",
    input: "hash me!",
    hex: "c7009299985a5627a9280372a9280372",
    source: "php-src ext/hash/tests/murmurhash3.phpt",
  },
  {
    algorithm: "murmur3f",
    input: "hash me!",
    hex: "c43668294e89db0ba5772846e5804467",
    source: "php-src ext/hash/tests/murmurhash3.phpt",
  },
  /**
   * Skein, from the 1.3 golden KAT -- one per state size at its natural output length.
   *
   * `tests/algos-skein.test.ts` runs 29 of these across seven output lengths; these three are what the
   * family-level gate needs. The empty message is the first case in the reference file for each size.
   */
  {
    algorithm: "skein256",
    input: "",
    hex: "c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba",
    source: "Skein 1.3 skein_golden_kat.txt, Skein-256-256 of the empty message",
  },
  {
    algorithm: "skein512",
    input: "",
    hex: "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a",
    source: "Skein 1.3 skein_golden_kat.txt, Skein-512-512 of the empty message",
  },
  {
    algorithm: "skein1024",
    input: "",
    hex: "0fff9563bb3279289227ac77d319b6fff8d7e9f09da1247b72a0a265cd6d2a62645ad547ed8193db48cff847c06494a03f55666d3b47eb4c20456c9373c86297d630d5578ebd34cb40991578f9f52b18003efa35d3da6553ff35db91b81ab890bec1b189b7f52cb2a783ebb7d823d725b0b4a71f6824e88f68f982eefc6d19c6",
    source: "Skein 1.3 skein_golden_kat.txt, Skein-1024-1024 of the empty message",
  },
  /**
   * Ascon, from the reference KAT that accompanies NIST SP 800-232.
   *
   * The message here is the KAT's 8-byte vector -- the bytes 00 through 07 -- rather than an ASCII
   * string, because that is what the published file contains. `tests/algos-ascon.test.ts` runs 43
   * hash lengths and 144 AEAD combinations from the same source; these two entries are what the
   * family-level gate needs.
   */
  {
    algorithm: "asconhash256",
    input: "",
    hex: "0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2",
    source: "ascon-c LWC_HASH_KAT_128_256, count 1 (NIST SP 800-232)",
  },
  {
    algorithm: "asconxof128",
    input: "",
    hex: "473d5e6164f58b39dfd84aacdb8ae42ec2d91fed33388ee0d960d9b3993295c6",
    source: "ascon-c LWC_XOF_KAT_128_512, count 1, first 32 bytes (NIST SP 800-232)",
  },
  /**
   * Streebog, RFC 6986's two worked examples at both lengths.
   *
   * Every hex string in that RFC is printed most significant byte first, and byte i of a message is
   * the i-th *least* significant -- so each value below is the reverse of what section 10 prints, and
   * example 1's message reads "2109876543..." there. `tests/algos-streebog.test.ts` carries the RFC's
   * strings verbatim and does the reversal in the open; these are the reversed forms, because this
   * file is consumed by the family-level tests that hash ordinary byte strings.
   *
   * Both examples, not one: there is no second implementation to compare against anywhere in this
   * repo's dependency tree -- no pure-ESM library has Streebog and OpenSSL needs its GOST engine --
   * so the RFC is the only check there is.
   */
  {
    algorithm: "streebog512",
    input: "012345678901234567890123456789012345678901234567890123456789012",
    hex: "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48",
    source: "RFC 6986 §10.1.1 (byte order reversed)",
  },
  {
    algorithm: "streebog256",
    input: "012345678901234567890123456789012345678901234567890123456789012",
    hex: "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500",
    source: "RFC 6986 §10.1.2 (byte order reversed)",
  },
  {
    algorithm: "whirlpool",
    input: "abc",
    hex: "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
    source: "ISO/IEC 10118-3:2004 (final Whirlpool)",
  },
  {
    algorithm: "xxh32",
    input: "abc",
    hex: "32d153ff",
    source: "xxHash reference implementation (seed 0)",
  },
  {
    algorithm: "xxh64",
    input: "abc",
    hex: "44bc2cf5ad770999",
    source: "xxHash reference implementation (seed 0)",
  },

  /**
   * RIPEMD-128, RIPEMD-256 and RIPEMD-320, from Antoon Bosselaers' own page -- the canonical
   * source for all four RIPEMD widths, and the one every other implementation cites.
   *
   * Extracted from `homes.esat.kuleuven.be/~bosselae/ripemd160.html` rather than recalled.
   * `tests/algos-ripemd.test.ts` checks all nine of that page's inputs for each width, including
   * the million-byte case; these three are the registry gate's entry point.
   */
  {
    algorithm: "ripemd128",
    input: "abc",
    hex: "c14a12199c66e4ba84636b0f69144c77",
    source: "Bosselaers' RIPEMD page, test-vector table",
  },
  {
    algorithm: "ripemd256",
    input: "abc",
    hex: "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
    source: "Bosselaers' RIPEMD page, test-vector table",
  },
  {
    algorithm: "ripemd320",
    input: "abc",
    hex:
      "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82f" + "a942d64cdbc4682d",
    source: "Bosselaers' RIPEMD page, test-vector table",
  },

  /**
   * MD5-SHA1 is a construction, not an algorithm, so no document publishes a check value
   * for it directly. These are the two published halves concatenated — the MD5 value from
   * RFC 1321 §A.5 and the SHA-1 value from FIPS 180-4, both of which appear above in their
   * own right. The derivation is the definition, so this is still a published vector rather
   * than an implementation's own output; `tests/openssl-parity.test.ts` independently
   * checks it against OpenSSL over many inputs.
   */
  {
    algorithm: "md5-sha1",
    input: "",
    hex: "d41d8cd98f00b204e9800998ecf8427eda39a3ee5e6b4b0d3255bfef95601890afd80709",
    source: "RFC 1321 §A.5 ‖ FIPS 180-4 (empty input)",
  },
  {
    algorithm: "md5-sha1",
    input: "abc",
    hex: "900150983cd24fb0d6963f7d28e17f72a9993e364706816aba3e25717850c26c9cd0d89d",
    source: "RFC 1321 §A.5 ‖ FIPS 180-4 §A.1",
  },
];

/**
 * Extendable-output functions, with the length that produced each value. Separate
 * from `DIGEST_VECTORS` because the length is part of the request rather than a
 * property of the algorithm.
 */
export const XOF_VECTORS: readonly {
  algorithm: string;
  input: string;
  outputLen: number;
  hex: string;
  source: string;
}[] = [
  {
    algorithm: "shake128",
    input: "",
    outputLen: 32,
    hex: "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
    source: "FIPS 202 / NIST CAVP (SHAKE128, 256-bit output)",
  },
  {
    algorithm: "shake256",
    input: "",
    outputLen: 64,
    hex: "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
    source: "FIPS 202 / NIST CAVP (SHAKE256, 512-bit output)",
  },
  {
    // The prefix property, as a vector rather than an assertion about it: 16 bytes
    // of SHAKE128 must be the first 16 bytes of the 32-byte value above.
    algorithm: "shake128",
    input: "",
    outputLen: 16,
    hex: "7f9c2ba4e88f827d616045507605853e",
    source: "FIPS 202, truncated — an XOF's shorter output is a prefix",
  },
];

/**
 * Bitcoin's double-SHA256. Included because the `iterations` option exists
 * specifically to reproduce it, so "iterations = 2" needs a published value to
 * be checked against rather than just being consistent with itself.
 */
export const DOUBLE_SHA256_VECTORS: readonly { input: string; hex: string; source: string }[] =
  [
    {
      input: "",
      hex: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
      source: "SHA-256 of the SHA-256 of the empty string",
    },
    {
      input: "hello",
      hex: "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50",
      source: "Bitcoin's HASH256 construction, widely published",
    },
  ];

/** RFC 4648 §10 "Test Vectors" — the base-encoding conformance set. */
export const BASE_ENCODING_VECTORS: readonly {
  input: string;
  base64: string;
  base32: string;
}[] = [
  { input: "", base64: "", base32: "" },
  { input: "f", base64: "Zg==", base32: "MY======" },
  { input: "fo", base64: "Zm8=", base32: "MZXQ====" },
  { input: "foo", base64: "Zm9v", base32: "MZXW6===" },
  { input: "foob", base64: "Zm9vYg==", base32: "MZXW6YQ=" },
  { input: "fooba", base64: "Zm9vYmE=", base32: "MZXW6YTB" },
  { input: "foobar", base64: "Zm9vYmFy", base32: "MZXW6YTBOI======" },
];

/**
 * The SHA-3 derived functions, which need more than an input and an output.
 *
 * Every value here was extracted from the document that publishes it, not recalled: NIST's own
 * `cSHAKE_samples.pdf`, `TupleHash_samples.pdf` and `ParallelHash_samples.pdf` for the SP 800-185
 * trio, XKCP's `tests/TestVectors/KangarooTwelve.txt` for KT128, and
 * `draft-irtf-cfrg-kangarootwelve-17` §5 for TurboSHAKE and KT256. That matters because a
 * remembered vector is worth nothing: checking these turned up one value this author had wrong
 * from memory (ParallelHash256) while the implementation was right, which is the same failure the
 * xxHash suite had years of this repo ago.
 *
 * `params` is passed straight through as spec options, so these exercise the real option plumbing
 * -- the byte decoding of the customisation string included -- rather than calling `@noble` twice.
 */
export interface Sha3AddonVector {
  algorithm: string;
  /** Message bytes as hex. Absent for TupleHash, whose input is `tuple`. */
  inputHex?: string;
  /** TupleHash's elements, as hex. */
  tuple?: readonly string[];
  /** Customisation string S, as text. */
  customization?: string;
  /** ParallelHash's block size B. */
  blockSize?: number;
  outputLen: number;
  hex: string;
  source: string;
}

const CSHAKE_DATA_4 = "00010203";
/** 1600 bits, 0x00 through 0xC7 -- the longer input NIST's cSHAKE samples use. */
const CSHAKE_DATA_200 = Array.from({ length: 200 }, (_, i) =>
  i.toString(16).padStart(2, "0"),
).join("");
/** SP 800-185's ParallelHash input: three runs of eight bytes. */
const PARALLEL_DATA = "000102030405060710111213141516172021222324252627";

export const SHA3_ADDON_VECTORS: readonly Sha3AddonVector[] = [
  {
    algorithm: "cshake128",
    inputHex: CSHAKE_DATA_4,
    customization: "Email Signature",
    outputLen: 32,
    hex: "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5",
    source: "NIST cSHAKE_samples.pdf, Sample #1",
  },
  {
    algorithm: "cshake128",
    inputHex: CSHAKE_DATA_200,
    customization: "Email Signature",
    outputLen: 32,
    hex: "c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b",
    source: "NIST cSHAKE_samples.pdf, Sample #2",
  },
  {
    algorithm: "cshake256",
    inputHex: CSHAKE_DATA_4,
    customization: "Email Signature",
    outputLen: 64,
    hex:
      "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd1" +
      "64020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c",
    source: "NIST cSHAKE_samples.pdf, Sample #3",
  },
  {
    algorithm: "cshake256",
    inputHex: CSHAKE_DATA_200,
    customization: "Email Signature",
    outputLen: 64,
    hex:
      "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac8643027309172" +
      "7f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb",
    source: "NIST cSHAKE_samples.pdf, Sample #4",
  },
  // ── TupleHash (NIST TupleHash_samples.pdf) ────────────────────────────────
  {
    algorithm: "tuplehash128",
    tuple: ["000102", "101112131415"],
    outputLen: 32,
    hex: "c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1",
    source: "NIST TupleHash_samples.pdf, Sample #1",
  },
  {
    algorithm: "tuplehash128",
    tuple: ["000102", "101112131415"],
    customization: "My Tuple App",
    outputLen: 32,
    hex: "75cdb20ff4db1154e841d758e24160c54bae86eb8c13e7f5f40eb35588e96dfb",
    source: "NIST TupleHash_samples.pdf, Sample #2",
  },
  {
    algorithm: "tuplehash128",
    tuple: ["000102", "101112131415", "202122232425262728"],
    customization: "My Tuple App",
    outputLen: 32,
    hex: "e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84",
    source: "NIST TupleHash_samples.pdf, Sample #3",
  },
  {
    algorithm: "tuplehash256",
    tuple: ["000102", "101112131415"],
    outputLen: 64,
    hex:
      "cfb7058caca5e668f81a12a20a2195ce97a925f1dba3e7449a56f82201ec6073" +
      "11ac2696b1ab5ea2352df1423bde7bd4bb78c9aed1a853c78672f9eb23bbe194",
    source: "NIST TupleHash_samples.pdf, Sample #4",
  },
  {
    algorithm: "tuplehash256",
    tuple: ["000102", "101112131415"],
    customization: "My Tuple App",
    outputLen: 64,
    hex:
      "147c2191d5ed7efd98dbd96d7ab5a11692576f5fe2a5065f3e33de6bba9f3aa1" +
      "c4e9a068a289c61c95aab30aee1e410b0b607de3620e24a4e3bf9852a1d4367e",
    source: "NIST TupleHash_samples.pdf, Sample #5",
  },
  {
    algorithm: "tuplehash256",
    tuple: ["000102", "101112131415", "202122232425262728"],
    customization: "My Tuple App",
    outputLen: 64,
    hex:
      "45000be63f9b6bfd89f54717670f69a9bc763591a4f05c50d68891a744bcc6e7" +
      "d6d5b5e82c018da999ed35b0bb49c9678e526abd8e85c13ed254021db9e790ce",
    source: "NIST TupleHash_samples.pdf, Sample #6",
  },

  // ── ParallelHash (NIST ParallelHash_samples.pdf) ──────────────────────────
  {
    algorithm: "parallelhash128",
    inputHex: PARALLEL_DATA,
    blockSize: 8,
    outputLen: 32,
    hex: "ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5",
    source: "NIST ParallelHash_samples.pdf, Sample #1",
  },
  {
    algorithm: "parallelhash128",
    inputHex: PARALLEL_DATA,
    blockSize: 8,
    customization: "Parallel Data",
    outputLen: 32,
    hex: "fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e495795b7206",
    source: "NIST ParallelHash_samples.pdf, Sample #2",
  },
  {
    algorithm: "parallelhash256",
    inputHex: PARALLEL_DATA,
    blockSize: 8,
    outputLen: 64,
    hex:
      "bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c45110553" +
      "1b7f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429",
    source: "NIST ParallelHash_samples.pdf, Sample #1 (256-bit strength)",
  },
  {
    algorithm: "parallelhash256",
    inputHex: PARALLEL_DATA,
    blockSize: 8,
    customization: "Parallel Data",
    outputLen: 64,
    hex:
      "cdf15289b54f6212b4bc270528b49526006dd9b54e2b6add1ef6900dda3963bb" +
      "33a72491f236969ca8afaea29c682d47a393c065b38e29fae651a2091c833110",
    source: "NIST ParallelHash_samples.pdf, Sample #2 (256-bit strength)",
  },

  // ── TurboSHAKE and KangarooTwelve ─────────────────────────────────────────
  {
    algorithm: "turboshake128",
    inputHex: "",
    outputLen: 32,
    hex: "1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c",
    source: "draft-irtf-cfrg-kangarootwelve-17 §5, TurboSHAKE128(M=empty, D=0x1F, 32)",
  },
  {
    algorithm: "turboshake256",
    inputHex: "",
    outputLen: 64,
    hex:
      "367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db" +
      "11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0",
    source: "draft-irtf-cfrg-kangarootwelve-17 §5, TurboSHAKE256(M=empty, D=0x1F, 64)",
  },
  {
    algorithm: "kt128",
    inputHex: "",
    outputLen: 32,
    hex: "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5",
    source: "XKCP tests/TestVectors/KangarooTwelve.txt, empty message and customisation",
  },
  {
    algorithm: "kt128",
    inputHex: "",
    outputLen: 64,
    hex:
      "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5" +
      "4269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71",
    source: "XKCP tests/TestVectors/KangarooTwelve.txt, 64-byte output",
  },
  {
    algorithm: "kt256",
    inputHex: "",
    outputLen: 64,
    hex:
      "b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404" +
      "e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9",
    source: "draft-irtf-cfrg-kangarootwelve-17 §5, KT256(M=empty, C=empty, 64)",
  },
];

/**
 * The four algorithms with no published vector, and why.
 *
 * NIST's sample-value documents cover cSHAKE, KMAC, TupleHash and ParallelHash but publish nothing
 * for the *XOF* forms of the last two -- and those are genuinely different functions rather than
 * truncations, because SP 800-185 encodes a zero output length into the XOF variants where the
 * fixed forms encode the requested one. So there is nothing to quote.
 *
 * They are not left unchecked: `tests/hash.test.ts` asserts the defining XOF property for each
 * (a shorter output is a prefix of a longer one) and that each differs from its fixed-length
 * sibling at the same length -- which is exactly the distinction that encoding creates.
 *
 * This list exists so the "every algorithm ships a published vector" gate stays meaningful. An
 * algorithm added without a vector has to be justified here, in writing, rather than silently
 * skipped.
 */
/**
 * BLAKE-224 and BLAKE-384 have no vector here, and the reason is narrow.
 *
 * BLAKE's round-3 SHA-3 submission ships its known-answer tests as NIST KAT files -- a generated
 * archive of 1024 message/digest pairs per variant -- rather than as a table in the paper. The paper
 * itself quotes worked values for BLAKE-256 and BLAKE-512 only, and those two *are* checked above,
 * from the document.
 *
 * What that leaves unchecked is small: 224 and 384 are the same two cores with different initial
 * values and a shorter output, so the round function, the message schedule, the salt handling and the
 * counter are all covered by the 256 and 512 vectors. `tests/hash.test.ts` additionally asserts each
 * produces its declared length and that no two BLAKE variants agree on the same input, which is what
 * a wrong IV would break.
 */
export const NO_PUBLISHED_VECTOR: readonly string[] = [
  "blake224",
  "blake384",
  "tuplehash128xof",
  "tuplehash256xof",
  "parallelhash128xof",
  "parallelhash256xof",
  /**
   * XXH3 and XXH128, for a different reason from the four above.
   *
   * The xxHash project does publish expected values, but as a 4.5 MB *generated* C header keyed to
   * a PRNG-filled buffer rather than as a table with quotable lines — there is no document entry to
   * cite. What `tests/algos-xxh3.test.ts` provides instead is agreement with the reference C, via
   * `hash-wasm`, across every length from 0 to 600, inputs straddling the 1024-byte block boundary
   * up to 5000 bytes, four seeds, and 320 streaming length/chunk combinations. That is broader
   * coverage than a quoted vector, and it is stated here rather than hidden behind a passing test.
   */
  "xxh3",
  "xxh128",
  /**
   * FSB, and it is the only genuinely *unverifiable* entry on this list rather than an awkwardly-cited
   * one -- so it is worth being precise about how thoroughly that was established.
   *
   * INRIA's page is live and both `fsbdoc.pdf` and `fsb_reference_implementation.zip` download. The PDF
   * was fetched and text-extracted: it contains no "test vector", no "known answer", no "digest of", and
   * **not one hexadecimal run of forty characters or more anywhere in 80,000 characters of text**. The
   * zip contains `Reference_Implementation` only -- `fsb.c`, `pi.h`, `main.c` and Whirlpool -- with no
   * KAT directory; `nessie.h` is Whirlpool's header, not a fixture. No library in this tree or any of
   * its oracles has ever implemented FSB. SUPERCOP's checksums would need its `try-anything` harness
   * reproduced, at which point a mismatch cannot say which side is wrong.
   *
   * What covers it instead, in `tests/algos-fsb.test.ts`: two independent formulations of the
   * compression required to agree at all six parameter sets -- the `crcReference` arrangement, which
   * caught a real inversion of the column window on its first run -- plus verification of the matrix
   * table's provenance against 19,200 recomputed digits of pi, the derived parameters, the padding
   * boundary and streaming.
   *
   * Registered on the user's explicit instruction. One published FSB digest from any source deletes this
   * entry and turns all of that into a real check.
   */
  "fsb",
];
