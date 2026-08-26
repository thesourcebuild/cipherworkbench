/**
 * GIMLI-Hash known-answer vectors from `rweather/lightweight-crypto`'s `test/kat/GIMLI-24-HASH.txt`,
 * generated from the NIST lightweight submission's own reference code.
 *
 * Extracted by script from the 1,024-record file, at lengths chosen for where a sponge goes wrong:
 * either side of the 16-byte rate and of each of its first several multiples, then a spread out to
 * 1,023 bytes. `tests/algos-lightweight-hash.test.ts` additionally walks *every* length from 0 to 200
 * against the full file logic by re-deriving the messages, so the committed subset is a regression
 * fixture rather than the whole check.
 *
 * The message of length n is bytes 0x00, 0x01, ... 0x(n-1) mod 256, which is the convention every
 * NIST lightweight KAT file uses -- so the messages are derived here rather than stored.
 */
export interface GimliVector {
  readonly length: number;
  readonly digest: string;
}

export const GIMLI_VECTORS: readonly GimliVector[] = [
  { length: 0, digest: "27ae20e95fbc2bf01e972b0015eea431c20fc8818f25bc6dbe66232230db352f" },
  { length: 1, digest: "feae3b182d3bf6ff48f63865146abeae85d89c13e5aa688677d0354a9e893fc4" },
  { length: 2, digest: "5feafd3c603b3bd7b31ee0982c5330e8348cb5b4cc9a10edb860e1226063d047" },
  { length: 15, digest: "b1916717d1e33912f6dfa0b2a141c2106b6588fe3508c6b8512f096e556a6ec8" },
  { length: 16, digest: "404c130af1b9023a7908200919f690ffbb756d5176e056ffde320016a37c7282" },
  { length: 17, digest: "19b0ccfda71cb90d9c11c4957f37e4938567ed771f82d52f5de62243560ce00f" },
  { length: 31, digest: "f0ef08b414b9dac794c89bb8047ead23fa29bf12d60f1275403bddf2b4d2c3a0" },
  { length: 32, digest: "a8f4fa28708bda7efb4c1914ca4afa9e475b82d588d36504f87dbb0ed9ab3c4b" },
  { length: 33, digest: "f92f1995858641eac474e0b7d160e50ebd06084cd74d4315ff6da6e87b3583a7" },
  { length: 47, digest: "aea94eb950409adc15cd7c7ebe9952ef45ffeb5e013af4a3aebce6f96164e70e" },
  { length: 48, digest: "94e17f25734152876bbe624038874c855650df94b43bfff839f14bebb59a50cc" },
  { length: 49, digest: "8d988f8ce6dc46f5fce86d745aa6d1cef53f0d8f15e69fc010f692ab73beccca" },
  { length: 63, digest: "6c30ba180a59e915632f318571508422cfd306f24a173d936d87f4006f88f5ee" },
  { length: 64, digest: "ce312a3f4af086e26e1700981d377e3569bdc4a43d9750612e74d42030c1f8f6" },
  { length: 65, digest: "640f0a93549fd6dc3f1e2eab991838bbb65b66a97b939a32258e01552ede721d" },
  { length: 95, digest: "64e1f0e63a54bf6aec9ebac957c775cb200beccc6849b5352ad4ff74aee39a97" },
  { length: 96, digest: "deaf48a2dfdfcb7af815c0221e5961250df5308d4fc8ef14f383c495cda61486" },
  { length: 97, digest: "98e7477108930c2b7338fa7cedc6e0a488b804839c862165339e766cd3dde933" },
  { length: 127, digest: "09f9bcc0f217ef3813022064fd44d14cd99cfba20226f1e846f7274951cba769" },
  { length: 128, digest: "4983e675ae9fe5391d3e946b169683ba3e07ebbabd067dab3157ce04490e2072" },
  { length: 129, digest: "587558c8d3ac2a50355cdeec4065b6978d7e01eb08bce1406318afdaa84646d2" },
  { length: 159, digest: "f06a3c383f34d93b82eada51129993d239beb64089b33acfaaeff80cdec5c2e6" },
  { length: 160, digest: "eb26a61d4f66e17966a5727f31fcd30c0697fcfe9f4219540d63c9689556590e" },
  { length: 200, digest: "1561d14f7304afdcf14a245f22a0e9191f26b47c9698f49775c42ee0bd56e4ab" },
  { length: 255, digest: "055120be205c9f8801f796dc82f57dd07335806f44619eca25440f30ec48aba2" },
  { length: 256, digest: "45dc00f2ae6cdd4f00ac9c4bd8fcbf0da4a4333d8c3bdc64948b823e53eb80b3" },
  { length: 300, digest: "b0da748bc1e402d0f7c4e392ecb754e844da73156e62ae3512a41f86f438645d" },
  { length: 400, digest: "c87066cf288f1f1981e6523e7e7e78e4df33067623fa1f33b4a9d8b2fa0cbafb" },
  { length: 500, digest: "feb7bc4d5703466756441a3f1aac198dfd76ed12b4967d7bcba5afbc28ff3349" },
  { length: 600, digest: "c29b315175fde99353d36cad18181dd0926bd0b8dbca4e00bbd8ce4bbd9ae16d" },
  { length: 700, digest: "745e55d80bac37862b20d71401e50672f8354e86eff7e050f7f9dd459fb853d2" },
  { length: 800, digest: "79c2aed2d9dd7dceedf238a7b0ba5c552b83e8773fa4896ddd49a8b034c1e81c" },
  { length: 900, digest: "fbe0ad1e7d9b34f59e6168ae8b0e352a0a32b8ff940fe2235e79bae45c889e36" },
  { length: 1000, digest: "921ddf541386a288c35261e0b178e5f411be27da33408d60c7131d35abfa36fc" },
  { length: 1023, digest: "35143163947d1f26c2f020b81ffb1a7657f9de817fd20e034bb439656eb91caa" },
];

/** The KAT convention: message n is 0x00, 0x01, ... 0x(n-1) mod 256. */
export function katMessage(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = i & 0xff;
  return out;
}
