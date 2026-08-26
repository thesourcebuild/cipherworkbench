/**
 * Vectors for CLEFIA, MARS and Rabbit, extracted by script.
 *
 * | Cipher | Source |
 * |---|---|
 * | CLEFIA | RFC 6114 Appendices A (vectors) and B (Tables 4-9, the constant derivation) |
 * | MARS | Crypto++'s `TestVectors/mars.txt`, `Test: Encrypt` cases only |
 * | Rabbit | RFC 4503 Appendix A, both with and without IV setup |
 *
 * The CLEFIA constant tables are here so `phase6-ciphers.ts` can *derive* its 236 round constants
 * from IV_k and still be checked entry by entry. That is not decoration: the `z^-1` fold in GF(2^16)
 * was wrong on the first attempt and produced the right first two constants before diverging, which
 * only a full table comparison catches.
 *
 * MARS's six `MCT` entries are deliberately absent. They are Monte Carlo tests -- a 10,000-iteration
 * chained protocol with key feedback -- and feeding them through as single blocks silently compares a
 * chained answer against one encryption.
 */

export interface Phase6bCipherVector {
  readonly key: string;
  readonly plaintext: string;
  readonly ciphertext: string;
}

/** RFC 6114 Appendix A. The plaintext is the same for all three; only the key length changes. */
export const CLEFIA_VECTORS: readonly Phase6bCipherVector[] = [
  {
    key: "ffeeddccbbaa99887766554433221100",
    plaintext: "000102030405060708090a0b0c0d0e0f",
    ciphertext: "de2bf2fd9b74aacdf1298555459494fd",
  },
  {
    key: "ffeeddccbbaa99887766554433221100f0e0d0c0b0a09080",
    plaintext: "000102030405060708090a0b0c0d0e0f",
    ciphertext: "e2482f649f028dc480dda184fde181ad",
  },
  {
    key: "ffeeddccbbaa99887766554433221100f0e0d0c0b0a090807060504030201000",
    plaintext: "000102030405060708090a0b0c0d0e0f",
    ciphertext: "a1397814289de80c10da46d1fa48b38a",
  },
];

/** Crypto++'s MARS known-answer vectors, across all three key lengths. */
export const MARS_VECTORS: readonly Phase6bCipherVector[] = [
  { key: "80000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "b3e2ad5608ac1b6733a7cb4fdf8f9952" },
  { key: "00000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "dcc07b8dfb0738d6e30a22dfcf27e886" },
  { key: "00000000000000000000000000000000", plaintext: "dcc07b8dfb0738d6e30a22dfcf27e886", ciphertext: "33caffbddc7f1dda0f9c15fa2f30e2ff" },
  { key: "cb14a1776abbc1cdafe7243def2cea02", plaintext: "f94512a9b42d034ec4792204d708a69b", ciphertext: "225da2cb64b73f79069f21a5e3cb8522" },
  { key: "86edf4da31824cabef6a4637c40b0bab", plaintext: "4df955ad5b398d66408d620a2b27e1a9", ciphertext: "a4b737340ae6d2cafd930ba97d86129f" },
  { key: "000000000000000000000000000000000000000000000000", plaintext: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ciphertext: "97778747d60e425c2b4202599db856fb" },
  { key: "d158860838874d9500000000000000000000000000000000", plaintext: "93a953a82c10411dd158860838874d95", ciphertext: "4fa0e5f64893131712f01408d233e9f7" },
  { key: "791739a58b04581a93a953a82c10411dd158860838874d95", plaintext: "6761c42d3e6142d2a84fbfadb383158f", ciphertext: "f706bc0fd97e28b6f1af4e17d8755fff" },
  { key: "0000000000000000000000000000000000000000000000000000000000000000", plaintext: "62e45b4cf3477f1dd65063729d9aba8f", ciphertext: "0f4b897ea014d21fbc20f1054a42f719" },
  { key: "fba167983e7aef22317ce28c02aae1a3e8e5cc3cedbea82a99dbc39ad65e7227", plaintext: "1344aba4d3c44708a8a72116d4f49384", ciphertext: "458335d95ea42a9f4dccd41aecc2390d" },
];

export interface RabbitVector {
  readonly key: string;
  readonly blocks: readonly [string, string, string];
}
export interface RabbitIvVector {
  readonly iv: string;
  readonly blocks: readonly [string, string, string];
}

/** RFC 4503 A.1 -- no IV setup at all, which is a different keystream from an all-zero IV. */
export const RABBIT_NO_IV: readonly RabbitVector[] = [
  {
    key: "00000000000000000000000000000000",
    blocks: [
      "b15754f036a5d6ecf56b45261c4af702",
      "88e8d815c59c0c397b696c4789c68aa7",
      "f416a1c3700cd451da68d1881673d696",
    ],
  },
  {
    key: "912813292e3d36fe3bfc62f1dc51c3ac",
    blocks: [
      "3d2df3c83ef627a1e97fc38487e2519c",
      "f576cd61f4405b8896bf53aa8554fc19",
      "e5547473fbdb43508ae53b20204d4c5e",
    ],
  },
  {
    key: "8395741587e0c733e9e9ab01c09b0043",
    blocks: [
      "0cb10dcda041cdac32eb5cfd02d0609b",
      "95fc9fca0f17015a7b7092114cff3ead",
      "9649e5de8bfc7f3f924147ad3a947428",
    ],
  },
];

/** RFC 4503 A.2 -- all three under the all-zero key, so only the IV differs. */
export const RABBIT_WITH_IV: readonly RabbitIvVector[] = [
  {
    iv: "0000000000000000",
    blocks: [
      "c6a7275ef85495d87ccd5d376705b7ed",
      "5f29a6ac04f5efd47b8f293270dc4a8d",
      "2ade822b29de6c1ee52bdb8a47bf8f66",
    ],
  },
  {
    iv: "c373f575c1267e59",
    blocks: [
      "1fcd4eb9580012e2e0dccc9222017d6d",
      "a75f4e10d12125017b2499ffed936f2e",
      "ebc112c393e738392356bdd012029ba7",
    ],
  },
  {
    iv: "a6eb561ad2f41727",
    blocks: [
      "445ad8c805858dbf70b6af23a151104d",
      "96c8f27947f42c5baeae67c6acc35b03",
      "9fcbfc895fa71c17313df034f01551cb",
    ],
  },
];

/** RFC 6114 Table 4: T_128[i], the generator's own intermediate values. */
export const RFC6114_T_128: readonly number[] = [
  0x428a, 0x2145, 0xc4ba, 0x625d, 0xe536, 0x729b, 0xed55, 0xa2b2,
  0x5159, 0xfcb4, 0x7e5a, 0x3f2d, 0xcb8e, 0x65c7, 0xe6fb, 0xa765,
  0x87aa, 0x43d5, 0xf5f2, 0x7af9, 0xe964, 0x74b2, 0x3a59, 0xc934,
  0x649a, 0x324d, 0xcd3e, 0x669f, 0xe757, 0xa7b3,
];

/** Table 5: T_192[i]. */
export const RFC6114_T_192: readonly number[] = [
  0x7137, 0xec83, 0xa259, 0x8534, 0x429a, 0x214d, 0xc4be, 0x625f,
  0xe537, 0xa683, 0x8759, 0x97b4, 0x4bda, 0x25ed, 0xc6ee, 0x6377,
  0xe5a3, 0xa6c9, 0x877c, 0x43be, 0x21df, 0xc4f7, 0xb663, 0x8f29,
  0x938c, 0x49c6, 0x24e3, 0xc669, 0xb72c, 0x5b96, 0x2dcb, 0xc2fd,
  0xb566, 0x5ab3, 0xf941, 0xa8b8, 0x545c, 0x2a2e, 0x1517, 0xde93,
  0xbb51, 0x89b0,
];

/** Table 6: T_256[i]. */
export const RFC6114_T_256: readonly number[] = [
  0xb5c0, 0x5ae0, 0x2d70, 0x16b8, 0x0b5c, 0x05ae, 0x02d7, 0xd573,
  0xbea1, 0x8b48, 0x45a4, 0x22d2, 0x1169, 0xdcac, 0x6e56, 0x372b,
  0xcf8d, 0xb3de, 0x59ef, 0xf8ef, 0xa86f, 0x802f, 0x940f, 0x9e1f,
  0x9b17, 0x9993, 0x98d1, 0x9870, 0x4c38, 0x261c, 0x130e, 0x0987,
  0xd0db, 0xbc75, 0x8a22, 0x4511, 0xf690, 0x7b48, 0x3da4, 0x1ed2,
  0x0f69, 0xd3ac, 0x69d6, 0x34eb, 0xce6d, 0xb32e,
];

/** Table 7: CON_128[i], all sixty. */
export const RFC6114_CON_128: readonly number[] = [
  0xf56b7aeb, 0x994a8a42, 0x96a4bd75, 0xfa854521,
  0x735b768a, 0x1f7abac4, 0xd5bc3b45, 0xb99d5d62,
  0x52d73592, 0x3ef636e5, 0xc57a1ac9, 0xa95b9b72,
  0x5ab42554, 0x369555ed, 0x1553ba9a, 0x7972b2a2,
  0xe6b85d4d, 0x8a995951, 0x4b550696, 0x2774b4fc,
  0xc9bb034b, 0xa59a5a7e, 0x88cc81a5, 0xe4ed2d3f,
  0x7c6f68e2, 0x104e8ecb, 0xd2263471, 0xbe07c765,
  0x511a3208, 0x3d3bfbe6, 0x1084b134, 0x7ca565a7,
  0x304bf0aa, 0x5c6aaa87, 0xf4347855, 0x9815d543,
  0x4213141a, 0x2e32f2f5, 0xcd180a0d, 0xa139f97a,
  0x5e852d36, 0x32a464e9, 0xc353169b, 0xaf72b274,
  0x8db88b4d, 0xe199593a, 0x7ed56d96, 0x12f434c9,
  0xd37b36cb, 0xbf5a9a64, 0x85ac9b65, 0xe98d4d32,
  0x7adf6582, 0x16fe3ecd, 0xd17e32c1, 0xbd5f9f66,
  0x50b63150, 0x3c9757e7, 0x1052b098, 0x7c73b3a7,
];

/** Table 8: CON_192[i], all eighty-four. */
export const RFC6114_CON_192: readonly number[] = [
  0xc6d61d91, 0xaaf73771, 0x5b6226f8, 0x374383ec,
  0x15b8bb4c, 0x799959a2, 0x32d5f596, 0x5ef43485,
  0xf57b7acb, 0x995a9a42, 0x96acbd65, 0xfa8d4d21,
  0x735f7682, 0x1f7ebec4, 0xd5be3b41, 0xb99f5f62,
  0x52d63590, 0x3ef737e5, 0x1162b2f8, 0x7d4383a6,
  0x30b8f14c, 0x5c995987, 0x2055d096, 0x4c74b497,
  0xfc3b684b, 0x901ada4b, 0x920cb425, 0xfe2ded25,
  0x710f7222, 0x1d2eeec6, 0xd4963911, 0xb8b77763,
  0x524234b8, 0x3e63a3e5, 0x1128b26c, 0x7d09c9a6,
  0x309df106, 0x5cbc7c87, 0xf45f7883, 0x987ebe43,
  0x963ebc41, 0xfa1fdf21, 0x73167610, 0x1f37f7c4,
  0x01829338, 0x6da363b6, 0x38c8e1ac, 0x54e9298f,
  0x246dd8e6, 0x484c8c93, 0xfe276c73, 0x9206c649,
  0x9302b639, 0xff23e324, 0x7188732c, 0x1da969c6,
  0x00cd91a6, 0x6cec2cb7, 0xec7748d3, 0x8056965b,
  0x9a2aa469, 0xf60bcb2d, 0x751c7a04, 0x193dfdc2,
  0x02879532, 0x6ea666b5, 0xed524a99, 0x8173b35a,
  0x4ea00d7c, 0x228141f9, 0x1f59ae8e, 0x7378b8a8,
  0xe3bd5747, 0x8f9c5c54, 0x9dcfaba3, 0xf1ee2e2a,
  0xa2f6d5d1, 0xced71715, 0x697242d8, 0x055393de,
  0x0cb0895c, 0x609151bb, 0x3e51ec9e, 0x5270b089,
];

/** Table 9: CON_256[i], all ninety-two. */
export const RFC6114_CON_256: readonly number[] = [
  0x0221947e, 0x6e00c0b5, 0xed014a3f, 0x8120e05a,
  0x9a91a51f, 0xf6b0702d, 0xa159d28f, 0xcd78b816,
  0xbcbde947, 0xd09c5c0b, 0xb24ff4a3, 0xde6eae05,
  0xb536fa51, 0xd917d702, 0x62925518, 0x0eb373d5,
  0x094082bc, 0x6561a1be, 0x3ca9e96e, 0x5088488b,
  0xf24574b7, 0x9e64a445, 0x9533ba5b, 0xf912d222,
  0xa688dd2d, 0xcaa96911, 0x6b4d46a6, 0x076cacdc,
  0xd9b72353, 0xb596566e, 0x80ca91a9, 0xeceb2b37,
  0x786c60e4, 0x144d8dcf, 0x043f9842, 0x681edeb3,
  0xee0e4c21, 0x822fef59, 0x4f0e0e20, 0x232feff8,
  0x1f8eaf20, 0x73af6fa8, 0x37ceffa0, 0x5bef2f80,
  0x23eed7e0, 0x4fcf0f94, 0x29fec3c0, 0x45df1f9e,
  0x2cf6c9d0, 0x40d7179b, 0x2e72ccd8, 0x42539399,
  0x2f30ce5c, 0x4311d198, 0x2f91cf1e, 0x43b07098,
  0xfbd9678f, 0x97f8384c, 0x91fdb3c7, 0xfddc1c26,
  0xa4efd9e3, 0xc8ce0e13, 0xbe66ecf1, 0xd2478709,
  0x673a5e48, 0x0b1bdbd0, 0x0b948714, 0x67b575bc,
  0x3dc3ebba, 0x51e2228a, 0xf2f075dd, 0x9ed11145,
  0x417112de, 0x2d5090f6, 0xcca9096f, 0xa088487b,
  0x8a4584b7, 0xe664a43d, 0xa933c25b, 0xc512d21e,
  0xb888e12d, 0xd4a9690f, 0x644d58a6, 0x086cacd3,
  0xde372c53, 0xb216d669, 0x830a9629, 0xef2beb34,
  0x798c6324, 0x15ad6dce, 0x04cf99a2, 0x68ee2eb3,
];
