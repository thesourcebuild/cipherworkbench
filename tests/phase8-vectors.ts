/**
 * Vectors for Trivium, KASUMI and Khazad, extracted by script.
 *
 * | Cipher | Source |
 * |---|---|
 * | Trivium | eSTREAM's own verified vector files, at all three IV widths -- mirrored in avr-crypto-lib |
 * | KASUMI | Botan 2.19.3's `src/tests/data/block/kasumi.vec` |
 * | Khazad | The NESSIE submission's verified vectors, also via avr-crypto-lib |
 *
 * **Why avr-crypto-lib.** `ecrypt.eu.org` returns 502 and the eSTREAM and NESSIE submission archives
 * are no longer served from anywhere official. That repository mirrors the vector files verbatim, and it
 * is the only route to them found from this environment -- so it is named here rather than buried, and
 * it is worth trying first for anything else from either competition.
 *
 * **What is kept and what is dropped.** Trivium keeps two vectors per IV width out of ~82; each carries
 * four windows of keystream, one as far out as offset 448, so a state that drifted after the first block
 * cannot pass. Khazad keeps every fifteenth of 450, which spans all four NESSIE sets. Dropping the rest
 * is a size decision and `tests/algos-phase8.test.ts` says which -- a fixture that silently sampled
 * would read as full coverage.
 */

export interface TriviumWindow {
  /** Byte offset into the keystream. */
  readonly from: number;
  readonly hex: string;
}

export interface TriviumVector {
  readonly key: string;
  readonly iv: string;
  readonly streams: readonly TriviumWindow[];
}

/** Keyed by IV width in bits, because Trivium's IV is 32, 64 or 80 and all three are published. */
export const TRIVIUM_VECTORS: Readonly<Record<string, readonly TriviumVector[]>> = {
  "32": [
    {
      key: "80000000000000000000",
      iv: "00000000",
      streams: [
        { from: 0, hex: "38eb86ff730d7a9caf8df13a4420540dbb7b651464c87501552041c249f29a64d2fbf515610921ebe06c8f92cecf7f8098ff20cccc6a62b97be8ef7454fc80f9" },
        { from: 192, hex: "eaf2625d411f61e41f6baeeddd5fe202600bd472f6c9cd1e9134a745d900ef6c023e4486538f09930cfd37157c0eb57c3ef6c954c42e707d52b743ad83cff297" },
        { from: 256, hex: "9a203cf7b2f3f09c43d188aa13a5a2021ee998c42f777e9b67c3fa221a0aa1b041aa9e86bc2f5c52aff11f7d9ee480cb1187b20eb46d582743a52d7cd080a24a" },
        { from: 448, hex: "ebf14772061c210843c18cea2d2a275ae02fcb18e5d7942455ff77524e8a4ca51e369a847d1aeefb9002fcd02342983ceafa9d487cc2032b10192cd416310fa4" },
      ],
    },
    {
      key: "0f62b5085bae0154a7fa",
      iv: "288ff65d",
      streams: [
        { from: 0, hex: "5c7cd7c1d4567f3a09d316d794fbd9bc1671f88d5149148fd2ff329bf981efe0d1ba3a893ba4600da7652722421d56bd9c1dee7c1379a0fdcf41de8e5a715097" },
        { from: 65472, hex: "4906ed622eeeb4ad9e45baebdd713f85d3d13a3c508cb45383c12b01c03aca23d35fae0fa38059de7f5e051efe922baef9900c7ec384c17872264d4c652da4f4" },
        { from: 65536, hex: "e4638bca4f14c573c2055ab3beb474be242ce0bdd8df96a3a8908a0f8328b3c3c683ce0f4cbe45eb2702d41b5b0ac8f3e875b2997bd700e5f5900864a4be3c20" },
        { from: 131008, hex: "9af2cd658dd8f5d9d69b2cec16180222ebb3260ba90465025ca022c468127bd3c236d2bd8b801008db2e16e5cf4cccf1d350dd569171bbbf937239b97c555020" },
      ],
    },
  ],
  "64": [
    {
      key: "80000000000000000000",
      iv: "0000000000000000",
      streams: [
        { from: 0, hex: "38eb86ff730d7a9caf8df13a4420540dbb7b651464c87501552041c249f29a64d2fbf515610921ebe06c8f92cecf7f8098ff20cccc6a62b97be8ef7454fc80f9" },
        { from: 192, hex: "eaf2625d411f61e41f6baeeddd5fe202600bd472f6c9cd1e9134a745d900ef6c023e4486538f09930cfd37157c0eb57c3ef6c954c42e707d52b743ad83cff297" },
        { from: 256, hex: "9a203cf7b2f3f09c43d188aa13a5a2021ee998c42f777e9b67c3fa221a0aa1b041aa9e86bc2f5c52aff11f7d9ee480cb1187b20eb46d582743a52d7cd080a24a" },
        { from: 448, hex: "ebf14772061c210843c18cea2d2a275ae02fcb18e5d7942455ff77524e8a4ca51e369a847d1aeefb9002fcd02342983ceafa9d487cc2032b10192cd416310fa4" },
      ],
    },
    {
      key: "0f62b5085bae0154a7fa",
      iv: "288ff65dc42b92f9",
      streams: [
        { from: 0, hex: "914d430673d2c07255a7c2adf9a2fd7ae88671b4e2cce9536317a951e114f001fe802478294094fbb64df49c0f3f9771fc691360efbe986168bf6b32cfbf0e51" },
        { from: 65472, hex: "974317b75864f6ef36c81e4271a1ba7ec1e93ebdb00c6fbdc1b620af2c96bfe24ac1c4722b212a6b102068794b1d863a78b2d9683da069ce52c01dd371e95ca4" },
        { from: 65536, hex: "7f584246bfc52ada1bc7a8574d81244129b30d65c9382a8364c12f1dbbf8f6e3756d3aedbb9a867edff62867194a347fff643b0fbe48bdc4968f1c82ca22c06e" },
        { from: 131008, hex: "458bd178bea7f62dea9ce811e5fb05ff4c9c10631af290f661d819647c8b838c4cf3536db8f1d26535f6b89efe77fbdf1ecfce322d09232bee4ad20c83821054" },
      ],
    },
  ],
  "80": [
    {
      key: "80000000000000000000",
      iv: "00000000000000000000",
      streams: [
        { from: 0, hex: "38eb86ff730d7a9caf8df13a4420540dbb7b651464c87501552041c249f29a64d2fbf515610921ebe06c8f92cecf7f8098ff20cccc6a62b97be8ef7454fc80f9" },
        { from: 192, hex: "eaf2625d411f61e41f6baeeddd5fe202600bd472f6c9cd1e9134a745d900ef6c023e4486538f09930cfd37157c0eb57c3ef6c954c42e707d52b743ad83cff297" },
        { from: 256, hex: "9a203cf7b2f3f09c43d188aa13a5a2021ee998c42f777e9b67c3fa221a0aa1b041aa9e86bc2f5c52aff11f7d9ee480cb1187b20eb46d582743a52d7cd080a24a" },
        { from: 448, hex: "ebf14772061c210843c18cea2d2a275ae02fcb18e5d7942455ff77524e8a4ca51e369a847d1aeefb9002fcd02342983ceafa9d487cc2032b10192cd416310fa4" },
      ],
    },
    {
      key: "0f62b5085bae0154a7fa",
      iv: "288ff65dc42b92f960c7",
      streams: [
        { from: 0, hex: "a4386c6d7624983fea8dbe7314e5fe1f9d102004c2cec99ac3bfbf003a66433f3089a98fad8512c49d7aabc0639f90c5ffed06f9d35aa8c86630e76a838e26d7" },
        { from: 65472, hex: "04bb52cdf852e04b178fe3b07af57ec106f3180b9b0d59b2192d42bcc35cef6896555d57316ff9153c359a8c43ef14cf7be1f94d57a52669181d183dd5a4137f" },
        { from: 65536, hex: "613009063d291c419d0194d59aded6249d9365dae8d6a62864cf649f5842a21457bfad03153db891e63ac9a859bb91511c475a8bd44756480ffbf14aa766b443" },
        { from: 131008, hex: "cb18518e27f7f95a5207ae008c760f33c26947e5231847ad32a5adc1ac74df459526b62a2cd6956d14d3f48677ac338b13cd7b7a1b3a0c834e64ac03307f8830" },
      ],
    },
  ],
};

export interface BlockVector {
  readonly key: string;
  readonly plaintext: string;
  readonly ciphertext: string;
}

/** Botan's KASUMI vectors. Three, which is thin -- and each is checked in both directions. */
export const KASUMI_VECTORS: readonly BlockVector[] = [
  { key: "2bd6459f82c5b300952c49104881ff48", plaintext: "ea024714ad5c4d84", ciphertext: "df1f9b251c0bf45f" },
  { key: "8ce33e2cc3c0b5fc1f3de8a6dc66b1f3", plaintext: "d3c5d592327fb11c", ciphertext: "de551988ceb2f9b7" },
  { key: "4035c6680af8c6d1a8ff8667b1714013", plaintext: "62a540981ba6f9b7", ciphertext: "4592b0e78690f71b" },
];

export interface KhazadVector extends BlockVector {
  /** The result of encrypting the plaintext 100 times over, chained. */
  readonly iterated100: string;
  /** And 1,000 times. These are what catch a fault that only shows after the state cycles. */
  readonly iterated1000: string;
}

export const KHAZAD_VECTORS: readonly KhazadVector[] = [
  {
    key: "80000000000000000000000000000000",
    plaintext: "0000000000000000",
    ciphertext: "49a4ce32ac190e3f",
    iterated100: "61fd7ef96cef52c3",
    iterated1000: "012072ff15ced085",
  },
  {
    key: "00010000000000000000000000000000",
    plaintext: "0000000000000000",
    ciphertext: "be0114504a5ab78c",
    iterated100: "a1c979acf3186d25",
    iterated1000: "9555857e4d39ca93",
  },
  {
    key: "00000002000000000000000000000000",
    plaintext: "0000000000000000",
    ciphertext: "5167b68060821923",
    iterated100: "e6e1b2addc52e7e3",
    iterated1000: "1104d6d6cc33ba94",
  },
  {
    key: "00000000000400000000000000000000",
    plaintext: "0000000000000000",
    ciphertext: "bc48e780ed48fc73",
    iterated100: "3ca5a1055275e91a",
    iterated1000: "6de74e0f860c8476",
  },
  {
    key: "00000000000000080000000000000000",
    plaintext: "0000000000000000",
    ciphertext: "98c7b2c0ee8a76b2",
    iterated100: "700c896a4e1eab6c",
    iterated1000: "6c66aae5b9fd8c9a",
  },
  {
    key: "00000000000000000010000000000000",
    plaintext: "0000000000000000",
    ciphertext: "90a0183746bc79ce",
    iterated100: "0e489d141a4188ef",
    iterated1000: "00656ec833db2ee2",
  },
  {
    key: "00000000000000000000002000000000",
    plaintext: "0000000000000000",
    ciphertext: "aa4de442fef6863d",
    iterated100: "affdc13394f229cb",
    iterated1000: "f5413b4a3f1ebea3",
  },
  {
    key: "00000000000000000000000000400000",
    plaintext: "0000000000000000",
    ciphertext: "9bde6b193f3840e5",
    iterated100: "9c1835028addbd1d",
    iterated1000: "3a00ab6d182c2a00",
  },
  {
    key: "00000000000000000000000000000080",
    plaintext: "0000000000000000",
    ciphertext: "581b95a37fc98ec4",
    iterated100: "48228c22d87e9e34",
    iterated1000: "33857d9644cb35f9",
  },
  {
    key: "00000000000000000000000000000000",
    plaintext: "0100000000000000",
    ciphertext: "335cc26627d36d77",
    iterated100: "09ed85d5a4f99dc1",
    iterated1000: "6e3f699a91c7898e",
  },
  {
    key: "00000000000000000000000000000000",
    plaintext: "0000020000000000",
    ciphertext: "5dd833ee8fbc0f71",
    iterated100: "efc1a7f9b7a1b3f8",
    iterated1000: "d51c19ba100003cd",
  },
  {
    key: "00000000000000000000000000000000",
    plaintext: "0000000004000000",
    ciphertext: "8df64358c50a48eb",
    iterated100: "b041cee2786bcb90",
    iterated1000: "b24d2c48134b35fa",
  },
  {
    key: "00000000000000000000000000000000",
    plaintext: "0000000000000800",
    ciphertext: "1f7fc735fa638c98",
    iterated100: "71c2e932d2be8003",
    iterated1000: "bfb92428037dc087",
  },
  {
    key: "03030303030303030303030303030303",
    plaintext: "0303030303030303",
    ciphertext: "9bc7395bf39227d9",
    iterated100: "748a5be3954a6847",
    iterated1000: "bf55bc1f9dab2bbb",
  },
  {
    key: "12121212121212121212121212121212",
    plaintext: "1212121212121212",
    ciphertext: "8766393fff3d2019",
    iterated100: "e7efae51efaf5e75",
    iterated1000: "94a410a937e4719e",
  },
  {
    key: "21212121212121212121212121212121",
    plaintext: "2121212121212121",
    ciphertext: "a5a398cc68cce705",
    iterated100: "213e1766df2530f9",
    iterated1000: "976965d13d679cc8",
  },
  {
    key: "30303030303030303030303030303030",
    plaintext: "3030303030303030",
    ciphertext: "17cdb4aba682218a",
    iterated100: "7f72b7036e6ad9d6",
    iterated1000: "389046b57d016fcb",
  },
  {
    key: "3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f",
    plaintext: "3f3f3f3f3f3f3f3f",
    ciphertext: "6ce2fbbd5af384e9",
    iterated100: "3fb8a0aff4538718",
    iterated1000: "420a839262def08e",
  },
  {
    key: "4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e",
    plaintext: "4e4e4e4e4e4e4e4e",
    ciphertext: "c1b0143a80af43ac",
    iterated100: "821964fc86bd729e",
    iterated1000: "d103d4aaacf78132",
  },
  {
    key: "5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d",
    plaintext: "5d5d5d5d5d5d5d5d",
    ciphertext: "9378ac4c9061ccad",
    iterated100: "3cbd6a7105ef3540",
    iterated1000: "bcd709fb125ec1ef",
  },
  {
    key: "6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c",
    plaintext: "6c6c6c6c6c6c6c6c",
    ciphertext: "2a3bac1e4ef7b4bc",
    iterated100: "a249d66ea90140de",
    iterated1000: "f35d0ebe712d7e27",
  },
  {
    key: "7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b",
    plaintext: "7b7b7b7b7b7b7b7b",
    ciphertext: "49633804fcb7c19d",
    iterated100: "afc4e4229e633eba",
    iterated1000: "803eedaa9129563d",
  },
  {
    key: "8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a",
    plaintext: "8a8a8a8a8a8a8a8a",
    ciphertext: "83c804e0c927eba3",
    iterated100: "60824c9be81eca3a",
    iterated1000: "7759686cddd3cb83",
  },
  {
    key: "99999999999999999999999999999999",
    plaintext: "9999999999999999",
    ciphertext: "13f2d2e41c9cad30",
    iterated100: "d44b32fc24a17736",
    iterated1000: "c5e3bccfbdfaa3b8",
  },
  {
    key: "a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8",
    plaintext: "a8a8a8a8a8a8a8a8",
    ciphertext: "70661d3c15b483da",
    iterated100: "a9b46db8aad9907d",
    iterated1000: "93f34eeb5d89ebd6",
  },
  {
    key: "b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7",
    plaintext: "b7b7b7b7b7b7b7b7",
    ciphertext: "d332d2a68ff5cab9",
    iterated100: "7a58b623e90d3da8",
    iterated1000: "3934b052b98bd1d5",
  },
  {
    key: "c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6",
    plaintext: "c6c6c6c6c6c6c6c6",
    ciphertext: "9e7ed68d1de5c268",
    iterated100: "23da72c7a6413b94",
    iterated1000: "84f2e117d0c26521",
  },
  {
    key: "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5",
    plaintext: "d5d5d5d5d5d5d5d5",
    ciphertext: "7b9bffeecc549acb",
    iterated100: "2f4473a6be77edbd",
    iterated1000: "b239aae61c7751b0",
  },
  {
    key: "e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4",
    plaintext: "e4e4e4e4e4e4e4e4",
    ciphertext: "9303d3780c8e3ec6",
    iterated100: "7fdaa1b0e43fbab2",
    iterated1000: "7227a0876f0b0613",
  },
  {
    key: "f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3",
    plaintext: "f3f3f3f3f3f3f3f3",
    ciphertext: "3f2d63bea388ba83",
    iterated100: "c5a70bf43df55b5e",
    iterated1000: "e1f6af1a2a3d6935",
  },
];
