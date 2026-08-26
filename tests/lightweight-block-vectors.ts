/**
 * CHAM, Simeck and SKINNY vectors, extracted by script.
 *
 * | Set | Source | Count |
 * |---|---|---|
 * | `CHAM_VECTORS` | Crypto++'s `TestVectors/cham.txt`, the ECB entries | 30 |
 * | `SIMECK_VECTORS` | Crypto++'s `TestVectors/simeck.txt` plus the Simeck paper's 48/96 row | 21 |
 * | `SKINNY_VECTORS` | the SKINNY paper's own, via FELICS | 2 |
 *
 * **`paper` marks the designers' own value.** Crypto++'s file labels each entry's provenance, and one
 * per parameter set comes from the specification while the rest come from the reference implementation.
 * Both are worth having and they are not the same kind of evidence -- so the flag is kept and
 * `tests/algos-lightweight-block.test.ts` asserts that at least one of each set is a paper vector,
 * which is what stops a future trim from leaving only reference-implementation values.
 *
 * SKINNY's two are the only published raw-block vectors reachable from here: `rweather/lightweight-crypto`
 * has SKINNY-AEAD and ForkSkinny KATs but nothing for the bare cipher, and Bouncy Castle and Botan have
 * neither. The four members those two do not cover are checked differently -- see the test file.
 */

export interface LightweightBlockVector {
  readonly variant: string;
  readonly key: string;
  readonly plaintext: string;
  readonly ciphertext: string;
  /** True when the source is the specification rather than a reference implementation. */
  readonly paper: boolean;
}

export const CHAM_VECTORS: readonly LightweightBlockVector[] = [
  { variant: "64-128", key: "010003020504070609080b0a0d0c0f0e", plaintext: "1100332255447766", ciphertext: "453c63bcdcfabf4e", paper: true },
  { variant: "64-128", key: "02770a9ea2701fed460cc2699163e519", plaintext: "704a4e91eb9b688d", ciphertext: "cedad4dc00e3800d", paper: false },
  { variant: "64-128", key: "24cda3e2c16792f340b60017cabc07c4", plaintext: "115a31e5ee6587f7", ciphertext: "e1afb96f30794233", paper: false },
  { variant: "64-128", key: "0914eef6827c21b9c69705ceb28b7dd5", plaintext: "e7222e2b0f2cee49", ciphertext: "280d763b931bda81", paper: false },
  { variant: "64-128", key: "2fa2fb021cd59124ee271ec973076a13", plaintext: "9fc08c64f9f98163", ciphertext: "027786041b158cb9", paper: false },
  { variant: "64-128", key: "6035af8d6d976a471bc9cb881a4af2aa", plaintext: "657b5980aad8468b", ciphertext: "56842bf7606d67f8", paper: false },
  { variant: "64-128", key: "be3acf23eda69014023e098b37c39b9e", plaintext: "ff83911e2f3584a5", ciphertext: "92632bf99819783a", paper: false },
  { variant: "64-128", key: "ffde8a1521c5fb5eb6b11ec905aac629", plaintext: "7802c7a5d52f1868", ciphertext: "f810fad080f019bd", paper: false },
  { variant: "64-128", key: "fc25b83f50589cb6fe7a5d6c16355cfd", plaintext: "1ab21791a5d305aa", ciphertext: "e733fd94c357d36c", paper: false },
  { variant: "64-128", key: "fae35e23e3573e334468c72580e54a6e", plaintext: "5dc5c55f6b8d31e2", ciphertext: "5bc22475f93f6cc8", paper: false },
  { variant: "128-128", key: "03020100070605040b0a09080f0e0d0c", plaintext: "3322110077665544bbaa9988ffeeddcc", ciphertext: "c3746034b55700c58d64ec32489332f7", paper: true },
  { variant: "128-128", key: "a37beb0115c49898906f6f1c73f68cf3", plaintext: "463e4b34efe3faa8d8b74450967f34d1", ciphertext: "30269e994d70c5de7b0bc631a96a1458", paper: false },
  { variant: "128-128", key: "ad97ae3449a6596146872c2308a85a00", plaintext: "7c241f668511124583d76a6f8498946b", ciphertext: "633b6cb900b390d8d1bb84cbd84b9ccf", paper: false },
  { variant: "128-128", key: "012ddb51d216a5503b1632f369930aac", plaintext: "440a7ce023b8499f991482fde6069cbe", ciphertext: "b2b2194481c5becf091d3c08ee6d1749", paper: false },
  { variant: "128-128", key: "dfd8192bcab7764c12632c2395c96b55", plaintext: "a72c20401e6522496ceb83bed90a2816", ciphertext: "0416aae7302a5219cd20a3b86d879c22", paper: false },
  { variant: "128-128", key: "c3fe465edff5a38c308bcf68a6d45ba7", plaintext: "91167a4bb9641eb215195841f3301521", ciphertext: "36d1dd06e42c583d9aea8e5808ee2f3b", paper: false },
  { variant: "128-128", key: "e7365921729a2e4b5e9e2d426b53c079", plaintext: "9fd5fb98d2de345942cf3edb2104e849", ciphertext: "60f3dd59406e579ee45a2191526c5693", paper: false },
  { variant: "128-128", key: "b880a315e410aa2d9d8686e4ac033a6e", plaintext: "05251c25354ded8367d50c4c4a73b66f", ciphertext: "e3f879f58b41baf88b458da704343a03", paper: false },
  { variant: "128-128", key: "f0cb7d2758d7ac44937b882d526fb9f8", plaintext: "088ede84315ef4152e2e22b18b45e765", ciphertext: "4ff2532c66a12b2e869f476eaab2d53f", paper: false },
  { variant: "128-128", key: "28b841b29a5e552ce02170c8fee72a87", plaintext: "0fc61c4cfa1db4139d00765939df2ba9", ciphertext: "6fd504e7091aca2e32c887183e40b4a4", paper: false },
  { variant: "128-256", key: "03020100070605040b0a09080f0e0d0cf3f2f1f0f7f6f5f4fbfaf9f8fffefdfc", plaintext: "3322110077665544bbaa9988ffeeddcc", ciphertext: "a899c8a0c929d55cab670d380c4f7ac8", paper: true },
  { variant: "128-256", key: "4031c29153a387998e0a6bad6098a6c4e4a852f87daf676e873c3524e1527db8", plaintext: "aac76bc0ec99e00e9648a9391a37c8db", ciphertext: "c993c6821545b60c456af36cb97628e7", paper: false },
  { variant: "128-256", key: "0c7be2710ee365ff061b8e435dbc63e352a08866634223c98f4bcc4fa1223aee", plaintext: "49eec4ddeb938769a359a6bff69353a9", ciphertext: "6252cf6f6524f0ed0b3a272a33827bb4", paper: false },
  { variant: "128-256", key: "90c69c188fcac90f7c061078036f32795676641c40358d9fd74867ca5debd8fa", plaintext: "c27e5d18985bd57e25b7164e5acb6ceb", ciphertext: "c7c15e122287fd3d45875c14629a042c", paper: false },
  { variant: "128-256", key: "f7bae93e170bbccd42a1d993a6247a9cae609194075045fc95b22ad959e16c9c", plaintext: "87cc88e79f159afeb2e8967bff1ddd8b", ciphertext: "0887e5414b68e67fa46d19ff948290b6", paper: false },
  { variant: "128-256", key: "15747f3e359c8462151d0e6df06abade06f246e1c817332b1fa9102a52263db4", plaintext: "5c11eab63fa257df7da90d0e1bf46991", ciphertext: "3cabb22e79c7ad8ed502abf874e7d3bf", paper: false },
  { variant: "128-256", key: "4c70d57834042fbd8f4b7c4089ac864e1dee8bac4093f375308aa073655098f1", plaintext: "68c7097eab6c604387d2bc6741dece87", ciphertext: "362a9742dd8238a8d916409a4a3c11a1", paper: false },
  { variant: "128-256", key: "073359a05e54c5f8882ef21f01be08d57d5c5b87533059a5204e2bcd5652dfc5", plaintext: "ef94e8fb7bf2aa7cac73ef0a294ad1f8", ciphertext: "5914594ddb44ba25ac0bfc051b92a9fe", paper: false },
  { variant: "128-256", key: "dc359e46f5516d8489885aee191494fe25350de0692754961531e56359f9e0ee", plaintext: "d1c5fbd07d1e85fc7922d7416a5a44dc", ciphertext: "bbe95a6706b38ff2898dfda841fe29c7", paper: false },
  { variant: "128-256", key: "faf3682dcf6e656c53bd8c06de0f7f71678c5a2d34624762d88daf3721d5ad6c", plaintext: "55b324417a787fbc41b91ab29a5bf734", ciphertext: "2a7dab0b6769e989615789987e4be9a7", paper: false },
];

export const SIMECK_VECTORS: readonly LightweightBlockVector[] = [
  { variant: "32-64", key: "1918111009080100", plaintext: "65656877", ciphertext: "770d2c76", paper: true },
  { variant: "32-64", key: "3d6c4ae1678418be", plaintext: "48230029", ciphertext: "65359de9", paper: false },
  { variant: "32-64", key: "6df116495f906952", plaintext: "72ae2cd6", ciphertext: "0ab073ca", paper: false },
  { variant: "32-64", key: "2ea60bb301eb26e9", plaintext: "41bb5af1", ciphertext: "6ed0bc2e", paper: false },
  { variant: "32-64", key: "00990f3e390c7e87", plaintext: "153c12db", ciphertext: "76374119", paper: false },
  { variant: "32-64", key: "4db74d06491c440d", plaintext: "305e0124", ciphertext: "8252aa91", paper: false },
  { variant: "32-64", key: "4dc8074d2d1239b3", plaintext: "54de1547", ciphertext: "e288e7ea", paper: false },
  { variant: "32-64", key: "5d03701f26a6428b", plaintext: "66bb6443", ciphertext: "b73099ae", paper: false },
  { variant: "32-64", key: "1e1f3b2512384509", plaintext: "767d7a5a", ciphertext: "058a62df", paper: false },
  { variant: "32-64", key: "7ff57f966bfc63cb", plaintext: "1ad46e5d", ciphertext: "60c443f2", paper: false },
  /**
   * Simeck48/96's only reachable vector, and the reason it is the *paper's* rather than Crypto++'s:
   * `TestVectors/simeck.txt` implements 32 and 64 only. This row was parsed out of the designers' own
   * paper, whose Simeck32/64 row above is byte-for-byte Crypto++'s -- so one of the three is
   * independently corroborated, which is what makes the extraction trustworthy.
   */
  { variant: "48-96", key: "1a19181211100a0908020100", plaintext: "72696320646e", ciphertext: "f3cf25e33b36", paper: true },
  { variant: "64-128", key: "1b1a1918131211100b0a090803020100", plaintext: "656b696c20646e75", ciphertext: "45ce69025f7ab7ed", paper: true },
  { variant: "64-128", key: "0938251f43bb8ba606b747de870c3e99", plaintext: "f1bbe9ebe16cd6ae", ciphertext: "4d11c6b9da2f7e28", paper: false },
  { variant: "64-128", key: "323ba122444066d09e7d49dc407836fd", plaintext: "1cdbae3296f5453b", ciphertext: "1e6a0792f5a717c5", paper: false },
  { variant: "64-128", key: "61ff698f2ddc8e6653bf67d699d5e980", plaintext: "b9729d49e18b1fda", ciphertext: "fca0fa8194bda9c7", paper: false },
  { variant: "64-128", key: "cfd3902d597e35cf9e0cf4d52c53cbc9", plaintext: "844f4a779d9c1672", ciphertext: "562b1caa75266241", paper: false },
  { variant: "64-128", key: "f8466a046454ceb13b33821fd4618dbe", plaintext: "78818744e6d91d2a", ciphertext: "d946fa4941516d8e", paper: false },
  { variant: "64-128", key: "97278a5928ce0bf52543e53cadae2488", plaintext: "d0576876162f6768", ciphertext: "ca3e5050126fa61b", paper: false },
  { variant: "64-128", key: "a786c2b5c19be1c0978c2ff11128c18c", plaintext: "08614014c9cd68d4", ciphertext: "a307ab5aa10f5c29", paper: false },
  { variant: "64-128", key: "63b126df89a982790c9bb4479cfed971", plaintext: "d96ca166d923d155", ciphertext: "5e47b40d9854418a", paper: false },
  { variant: "64-128", key: "463608dc1b2861c93f41078428a11e20", plaintext: "3f895ef162e09612", ciphertext: "c5fd5a6c32056800", paper: false },
];

/** From the SKINNY specification, as transcribed by FELICS's benchmarking suite. */
export const SKINNY_VECTORS: readonly LightweightBlockVector[] = [
  {
    variant: "64-128",
    key: "9eb93640d088da6376a39d1c8bea71e1",
    plaintext: "cf16cfe8fd0f98aa",
    ciphertext: "6ceda1f43de92b9e",
    paper: true,
  },
  {
    variant: "128-128",
    key: "4f55cfb0520cac52fd92c15f37073e93",
    plaintext: "f20adb0eb08b648a3b2eeed1f0adda14",
    ciphertext: "22ff30d498ea62d7e45b476e33675b74",
    paper: true,
  },
];
