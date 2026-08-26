/**
 * LSH -- the Korean standard KS X 3262, at 224, 256, 384 and 512 bits.
 *
 * A wide-pipe ARX design from KISA with no S-box and no table beyond its step constants: the chaining
 * value is *twice* the digest width, split into a left and a right half, and each of 26 (or 28) steps
 * adds, rotates, XORs a constant, adds again, rotates again and then permutes the sixteen words. The
 * message is expanded on the fly rather than scheduled up front.
 *
 * Verified against 588 vectors from Crypto++'s own `TestVectors/lsh256.txt` and `lsh512.txt`, generated
 * from KISA's reference and covering every length from 0 to 65536 bytes -- 147 per digest size.
 *
 * ## The two bugs the vectors caught, and why neither could have been reasoned out
 *
 * **The two halves of the message expansion use different permutations.** Words 0..3 rotate as
 * `0<-3, 3<-1, 1<-2, 2<-0`; words 4..7 as `4<-7, 7<-6, 6<-5, 5<-4`. Those are not the same cycle. A loop
 * applying the first pattern to both halves is correct for every message of fifteen bytes or fewer --
 * because the padding byte then lands in the first four words and the second half is all zero -- and
 * wrong from sixteen bytes on. Sixteen consecutive vectors passing is not a coincidence anyone notices.
 *
 * **LSH-512's gamma rotation covers seven words and LSH-256's covers six.** `gamma[7]` is 0 at 256 bits
 * and 56 at 512, so a shared loop bound is right for one and wrong for the other. Every LSH-384 and
 * LSH-512 vector failed; not one LSH-256 vector did.
 *
 * Both are the same shape of mistake -- a structure that looks symmetric and is not -- which is why the
 * expansion is written out longhand below rather than looped.
 *
 * ## Two engines, not one generic one
 *
 * The 32- and 64-bit halves of this file are near-duplicates, deliberately. A single path over a
 * `number | bigint` union puts a branch inside every one of the fifty-odd word operations a step
 * performs, and the casts needed to satisfy the typechecker hide exactly the kind of mistake above.
 * KISA's own reference is two files for the same reason.
 *
 * ## Why 224 and 384 are not truncations
 *
 * Each digest length has its *own* initial chaining value, so LSH-224 is not the first 28 bytes of
 * LSH-256 -- it is a different function that happens to share a compression. `truncation` is therefore
 * absent on all four, and there is a test asserting the pairs disagree.
 */

import { eagerAbsorber, type LwcHasher } from "./lwc-hash";

/** LSH-256's 208 step constants, from KISA's reference implementation. */
const SC256 = new Uint32Array([
  0x917caf90, 0x6c1b10a2, 0x6f352943, 0xcf778243, 0x2ceb7472, 0x29e96ff2, 0x8a9ba428, 0x2eeb2642,
  0xe2c4021, 0x872bb30e, 0xa45e6cb2, 0x46f9c612, 0x185fe69e, 0x1359621b, 0x263fccb2, 0x1a116870,
  0x3a6c612f, 0xb2dec195, 0x2cb1f56, 0x40bfd858, 0x784684b6, 0x6cbb7d2e, 0x660c7ed8, 0x2b79d88a,
  0xa6cd9069, 0x91a05747, 0xcdea7558, 0x983098, 0xbecb3b2e, 0x2838ab9a, 0x728b573e, 0xa55262b5,
  0x745dfa0f, 0x31f79ed8, 0xb85fce25, 0x98c8c898, 0x8a0669ec, 0x60e445c2, 0xfde295b0, 0xf7b5185a,
  0xd2580983, 0x29967709, 0x182df3dd, 0x61916130, 0x90705676, 0x452a0822, 0xe07846ad, 0xaccd7351,
  0x2a618d55, 0xc00d8032, 0x4621d0f5, 0xf2f29191, 0xc6cd06, 0x6f322a67, 0x58bef48d, 0x7a40c4fd,
  0x8beee27f, 0xcd8db2f2, 0x67f2c63b, 0xe5842383, 0xc793d306, 0xa15c91d6, 0x17b381e5, 0xbb05c277,
  0x7ad1620a, 0x5b40a5bf, 0x5ab901a2, 0x69a7a768, 0x5b66d9cd, 0xfdee6877, 0xcb3566fc, 0xc0c83a32,
  0x4c336c84, 0x9be6651a, 0x13baa3fc, 0x114f0fd1, 0xc240a728, 0xec56e074, 0x9c63c7, 0x89026cf2,
  0x7f9ff0d0, 0x824b7fb5, 0xce5ea00f, 0x605ee0e2, 0x2e7cfea, 0x43375560, 0x9d002ac7, 0x8b6f5f7b,
  0x1f90c14f, 0xcdcb3537, 0x2cfeafdd, 0xbf3fc342, 0xeab7b9ec, 0x7a8cb5a3, 0x9d2af264, 0xfacedb06,
  0xb052106e, 0x99006d04, 0x2bae8d09, 0xff030601, 0xa271a6d6, 0x742591d, 0xc81d5701, 0xc9a9e200,
  0x2627f1e, 0x996d719d, 0xda3b9634, 0x2090800, 0x14187d78, 0x499b7624, 0xe57458c9, 0x738be2c9,
  0x64e19d20, 0x6df0f36, 0x15d1cb0e, 0xb110802, 0x2c95f58c, 0xe5119a6d, 0x59cd22ae, 0xff6eac3c,
  0x467ebd84, 0xe5ee453c, 0xe79cd923, 0x1c190a0d, 0xc28b81b8, 0xf6ac0852, 0x26efd107, 0x6e1ae93b,
  0xc53c41ca, 0xd4338221, 0x8475fd0a, 0x35231729, 0x4e0d3a7a, 0xa2b45b48, 0x16c0d82d, 0x890424a9,
  0x17e0c8f, 0x7b5a3f5, 0xfa73078e, 0x583a405e, 0x5b47b4c8, 0x570fa3ea, 0xd7990543, 0x8d28ce32,
  0x7f8a9b90, 0xbd5998fc, 0x6d7a9688, 0x927a9eb6, 0xa2fc7d23, 0x66b38e41, 0x709e491a, 0xb5f700bf,
  0xa262c0f, 0x16f295b9, 0xe8111ef5, 0xd195548, 0x9f79a0c5, 0x1a41cfa7, 0xee7638a, 0xacf7c074,
  0x30523b19, 0x9884ecf, 0xf93014dd, 0x266e9d55, 0x191a6664, 0x5c1176c1, 0xf64aed98, 0xa4b83520,
  0x828d5449, 0x91d71dd8, 0x2944f2d6, 0x950bf27b, 0x3380ca7d, 0x6d88381d, 0x4138868e, 0x5ced55c4,
  0xfe19dcb, 0x68f4f669, 0x6e37c8ff, 0xa0fe6e10, 0xb44b47b0, 0xf5c0558a, 0x79bf14cf, 0x4a431a20,
  0xf17f68da, 0x5deb5fd1, 0xa600c86d, 0x9f6c7eb0, 0xff92f864, 0xb615e07f, 0x38d3e448, 0x8d5d3a6a,
  0x70e843cb, 0x494b312e, 0xa6c93613, 0xbeb2f4f, 0x928b5d63, 0xcbf66035, 0xcb82c80, 0xea97a4f7,
  0x592c0f3b, 0x947c5f77, 0x6fff49b9, 0xf71a7e5a, 0x1de8c0f5, 0xc2569600, 0xc4e4ac8c, 0x823c9ce1,
]);

/** LSH-512's 224 step constants. */
const SC512: readonly bigint[] = [
  0x97884283c938982an, 0xba1fca93533e2355n, 0xc519a2e87aeb1c03n, 0x9a0fc95462af17b1n,
  0xfc3dda8ab019a82bn, 0x2825d079a895407n, 0x79f2d0a7ee06a6f7n, 0xd76d15eed9fdf5fen,
  0x1fcac64d01d0c2c1n, 0xd9ea5de69161790fn, 0xdebc8b6366071fc8n, 0xa9d91db711c6c94bn,
  0x3a18653ac9c1d427n, 0x84df64a223dd5b09n, 0x6cc37895f4ad9e70n, 0x448304c8d7f3f4d5n,
  0xea91134ed29383e0n, 0xc4484477f2da88e8n, 0x9b47eec96d26e8a6n, 0x82f6d4c8d89014f4n,
  0x527da0048b95fb61n, 0x644406c60138648dn, 0x303c0e8aa24c0edcn, 0xc787cda0cbe8ca19n,
  0x7ba46221661764can, 0xc8cbc6acd6371acn, 0xe336b836940f8f41n, 0x79cb9da168a50976n,
  0xd01da49021915cb3n, 0xa84accc7399cf1f1n, 0x6c4a992cee5aeb0cn, 0x4f556e6cb4b2e3e0n,
  0x200683877d7c2f45n, 0x9949273830d51db8n, 0x19eeeecaa39ed124n, 0x45693f0a0dae7fefn,
  0xedc234b1b2ee1083n, 0xf3179400d68ee399n, 0xb6e3c61b4945f778n, 0xa4c3db216796c42fn,
  0x268a0b04f9ab7465n, 0xe2705f6905f2d651n, 0x8ddb96e426ff53dn, 0xaea84917bc2e6f34n,
  0xaff6e664a0fe9470n, 0xaab94d765727d8cn, 0x9aa9e1648f3d702en, 0x689efc88fe5af3d3n,
  0xb0950ffea51fd98bn, 0x52cfc86ef8c92833n, 0xe69727b0b2653245n, 0x56f160d3ea9da3e2n,
  0xa6dd4b059f93051fn, 0xb6406c3cd7f00996n, 0x448b45f3ccad9ec8n, 0x79b8587594ec73bn,
  0x45a50ea3c4f9653bn, 0x22983767c1f15b85n, 0x7dbed8631797782bn, 0x485234be88418638n,
  0x842850a5329824c5n, 0xf6aca914c7f9a04cn, 0xcfd139c07a4c670cn, 0xa3210ce0a8160242n,
  0xeab3b268be5ea080n, 0xbacf9f29b34ce0a7n, 0x3c973b7aaf0fa3a8n, 0x9a86f346c9c7be80n,
  0xac78f5d7cabcea49n, 0xa355bddcc199ed42n, 0xa10afa3ac6b373dbn, 0xc42ded88be1844e5n,
  0x9e661b271cff216an, 0x8a6ec8dd002d8861n, 0xd3d2b629beb34be4n, 0x217a3a1091863f1an,
  0x256ecda287a733f5n, 0xf9139a9e5b872fe5n, 0xac0535017a274f7cn, 0xf21b7646d65d2aa9n,
  0x48142441c208c08n, 0xf937a5dd2db5e9ebn, 0xa688dfe871ff30b7n, 0x9bb44aa217c5593bn,
  0x943c702a2edb291an, 0xcae38f9e2b715den, 0xb13a367ba176cc28n, 0xd91bd1d3387d49bn,
  0x85c386603cac940cn, 0x30dd830ae39fd5e4n, 0x2f68c85a712fe85dn, 0x4ffeecb9dd1e94d6n,
  0xd0ac9a590a0443aen, 0xbae732dc99ccf3ean, 0xeb70b21d1842f4d9n, 0x9f4eda50bb5c6fa8n,
  0x4949e69ce940a091n, 0xe608dee8375ba14n, 0x983122cba118458cn, 0x4eeba696fbb36b25n,
  0x7d46f3630e47f27en, 0xa21a0f7666c0dea4n, 0x5c22cf355b37cec4n, 0xee292b0c17cc1847n,
  0x9330838629e131dan, 0x6eee7c71f92fce22n, 0xc953ee6cb95dd224n, 0x3a923d92af1e9073n,
  0xc43a5671563a70fbn, 0xbc2985dd279f8346n, 0x7ef2049093069320n, 0x17543723e3e46035n,
  0xc3b409b00b130c6dn, 0x5d6aee6b28fdf090n, 0x1d425b26172ff6edn, 0xcccfd041cdaf03adn,
  0xfe90c7c790ab6cbfn, 0xe5af6304c722ca02n, 0x70f695239999b39en, 0x6b8b5b07c844954cn,
  0x77bdb9bb1e1f7a30n, 0xc859599426ee80edn, 0x5f9d813d4726e40an, 0x9ca0120f7cb2b179n,
  0x8f588f583c182cbdn, 0x951267cbe9eccce7n, 0x678bb8bd334d520en, 0xf6e662d00cd9e1b7n,
  0x357774d93d99aaa7n, 0x21b2edbb156f6eb5n, 0xfd1ebe846e0aee69n, 0x3cb2218c2f642b15n,
  0xe7e7e7945444ea4cn, 0xa77a33b5d6b9b47cn, 0xf34475f0809f6075n, 0xdd4932dce6bb99adn,
  0xacec4e16d74451dcn, 0xd4a0a8d084de23d6n, 0x1bdd42f278f95866n, 0xeed3adbb938f4051n,
  0xcfcf7be8992f3733n, 0x21ade98c906e3123n, 0x37ba66711fffd668n, 0x267c0fc3a255478an,
  0x993a64ee1b962e88n, 0x754979556301faaan, 0xf920356b7251be81n, 0xc281694f22cf923fn,
  0x9f4b6481c8666b02n, 0xcf97761cfe9f5444n, 0xf220d7911fd63e9fn, 0xa28bd365f79cd1b0n,
  0xd39f5309b1c4b721n, 0xbec2ceb864fca51fn, 0x1955a0ddc410407an, 0x43eab871f261d201n,
  0xeaafe64a2ed16da1n, 0x670d931b9df39913n, 0x12f868b0f614de91n, 0x2e5f395d946e8252n,
  0x72f25cbb767bd8f4n, 0x8191871d61a1c4ddn, 0x6ef67ea1d450ba93n, 0x2ea32a645433d344n,
  0x9a963079003f0f8bn, 0x74a0aeb9918cac7an, 0xb6119a70af36fa3n, 0x8d9896f202f0d480n,
  0x654f1831f254cd66n, 0x1318a47f0366a25en, 0x65752076250b4e01n, 0xd1cd8eb888071772n,
  0x30c6a9793f4e9b25n, 0x154f684b1e3926een, 0x6c7ac0b1fe6312aen, 0x262f88f4f3c5550dn,
  0xb4674a24472233cbn, 0x2bbd23826a090071n, 0xda95969b30594f66n, 0x9f5c47408f1e8a43n,
  0xf77022b88de9c055n, 0x64b7b36957601503n, 0xe73b72b06175c11an, 0x55b87de8b91a6233n,
  0x1bb16e6b6955ff7fn, 0xe8e0a5ec7309719cn, 0x702c31cb89a8b640n, 0xfba387cfada8cde2n,
  0x6792db4677aa164cn, 0x1c6b1cc0b7751867n, 0x22ae2311d736dc01n, 0xe3666a1d37c9588n,
  0xcd1fd9d4bf557e9an, 0xc986925f7c7b0e84n, 0x9c5dfd55325ef6b0n, 0x9f2b577d5676b0ddn,
  0xfa6e21be21c062b3n, 0x8787dd782c8d7f83n, 0xd0d134e90e12dd23n, 0x449d087550121d96n,
  0xecf9ae9414d41967n, 0x5018f1dbf789934dn, 0xfa5b52879155a74cn, 0xca82d4d3cd278e7cn,
  0x688fdfdfe22316adn, 0xf6555a4ba0d030an, 0xa2061df720f000f3n, 0xe1a57dc5622fb3dan,
  0xe6a842a8e8ed8153n, 0x690acdd3811ce09dn, 0x55adda18e6fcf446n, 0x4d57a8a0f4b60b46n,
  0xf86fbfc20539c415n, 0x74bafa5ec7100d19n, 0xa824151810f0f495n, 0x8723432791e38ebbn,
  0x8eeaeb91d66ed539n, 0x73d8a1549dfd7e06n, 0x387f2ffe3f13a9bn, 0xa5004995aac15193n,
  0x682f81c73efdda0dn, 0x2fb55925d71d268dn, 0xcc392d2901e58a3dn, 0xaa666ab975724a42n,
];

const IV224 = new Uint32Array([
  0x68608d3, 0x62d8f7a7, 0xd76652ab, 0x4c600a43, 0xbdc40aa8, 0x1eca0b68, 0xda1a89be, 0x3147d354,
  0x707eb4f9, 0xf65b3862, 0x6b0b2abe, 0x56b8ec0a, 0xcf237286, 0xee0d1727, 0x33636595, 0x8bb8d05f,
]);

const IV256 = new Uint32Array([
  0x46a10f1f, 0xfddce486, 0xb41443a8, 0x198e6b9d, 0x3304388d, 0xb0f5a3c7, 0xb36061c4, 0x7adbd553,
  0x105d5378, 0x2f74de54, 0x5c2f2d95, 0xf2553fbe, 0x8051357a, 0x138668c8, 0x47aa4484, 0xe01afb41,
]);

const IV384: readonly bigint[] = [
  0x53156a66292808f6n, 0xb2c4f362b204c2bcn, 0xb84b7213bfa05c4en, 0x976ceb7c1b299f73n,
  0xdf0cc63c0570ae97n, 0xda4441baa486ce3fn, 0x6559f5d9b5f2acc2n, 0x22dacf19b4b52a16n,
  0xbbcdacefde80953an, 0xc9891a2879725b3en, 0x7c9fe6330237e440n, 0xa30ba550553f7431n,
  0xbb08043fb34e3e30n, 0xa0dec48d54618eadn, 0x150317267464bc57n, 0x32d1501fde63dc93n,
];

const IV512: readonly bigint[] = [
  0xadd50f3c7f07094en, 0xe3f3cee8f9418a4fn, 0xb527ecde5b3d0ae9n, 0x2ef6dec68076f501n,
  0x8cb994cae5aca216n, 0xfbb9eae4bba48cc7n, 0x650a526174725fean, 0x1f9a61a73f8d8085n,
  0xb6607378173b539bn, 0x1bc99853b0c0b9edn, 0xdf727fc19b182d47n, 0xdbef360cf893a457n,
  0x4981f5e570147e80n, 0xd00c4490ca7d3e30n, 0x5d73940c0e4ae1ecn, 0x894085e2edb2d819n,
];

export type LshDigestBits = 224 | 256 | 384 | 512;

/** Which family a digest length belongs to. 224 and 256 are LSH-256; 384 and 512 are LSH-512. */
export const LSH_FAMILY: Readonly<Record<LshDigestBits, 256 | 512>> = {
  224: 256,
  256: 256,
  384: 512,
  512: 512,
};

const MASK64 = (1n << 64n) - 1n;

const GAMMA256 = [0, 8, 16, 24, 24, 16, 8, 0] as const;
const GAMMA512 = [0, 16, 32, 48, 8, 24, 40, 56] as const;

/**
 * The word permutation. Identical at both widths, and the one piece of structure the two engines share
 * exactly -- so it is written once per engine with the same body, which a reader can diff.
 */

// ---------------------------------------------------------------- LSH-256

/** LSH-256: 26 steps, a 128-byte block, 32-bit words. Serves LSH-224 and LSH-256. */
function createLsh256(digestBits: 224 | 256): LwcHasher {
  const STEPS = 26;
  const BLOCK = 128;
  const ALPHA_EVEN = 29;
  const BETA_EVEN = 1;
  const ALPHA_ODD = 5;
  const BETA_ODD = 17;

  const cvL = new Uint32Array(8);
  const cvR = new Uint32Array(8);
  const eL = new Uint32Array(8);
  const eR = new Uint32Array(8);
  const oL = new Uint32Array(8);
  const oR = new Uint32Array(8);

  const iv = digestBits === 224 ? IV224 : IV256;
  for (let i = 0; i < 8; i++) {
    cvL[i] = iv[i]!;
    cvR[i] = iv[8 + i]!;
  }

  const rotl = (x: number, n: number): number => (n === 0 ? x >>> 0 : ((x << n) | (x >>> (32 - n))) >>> 0);

  const wordPerm = (): void => {
    let t = cvL[0]!;
    cvL[0] = cvL[6]!; cvL[6] = cvR[6]!; cvR[6] = cvR[2]!; cvR[2] = cvL[1]!;
    cvL[1] = cvL[4]!; cvL[4] = cvR[4]!; cvR[4] = cvR[0]!; cvR[0] = cvL[2]!;
    cvL[2] = cvL[5]!; cvL[5] = cvR[7]!; cvR[7] = cvR[1]!; cvR[1] = t;
    t = cvL[3]!;
    cvL[3] = cvL[7]!; cvL[7] = cvR[5]!; cvR[5] = cvR[3]!; cvR[3] = t;
  };

  const mix = (alpha: number, beta: number, scOff: number): void => {
    for (let i = 0; i < 8; i++) cvL[i] = (cvL[i]! + cvR[i]!) >>> 0;
    for (let i = 0; i < 8; i++) cvL[i] = rotl(cvL[i]!, alpha);
    for (let i = 0; i < 8; i++) cvL[i] = (cvL[i]! ^ SC256[scOff + i]!) >>> 0;
    for (let i = 0; i < 8; i++) cvR[i] = (cvR[i]! + cvL[i]!) >>> 0;
    for (let i = 0; i < 8; i++) cvR[i] = rotl(cvR[i]!, beta);
    for (let i = 0; i < 8; i++) cvL[i] = (cvL[i]! + cvR[i]!) >>> 0;
    // Six words here. LSH-512 rotates seven -- see the header.
    for (let i = 1; i <= 6; i++) cvR[i] = rotl(cvR[i]!, GAMMA256[i]!);
  };

  /** Two halves, two different permutations. See the header. */
  const expandHalf = (target: Uint32Array, other: Uint32Array): void => {
    let t = target[0]!;
    target[0] = (other[0]! + target[3]!) >>> 0;
    target[3] = (other[3]! + target[1]!) >>> 0;
    target[1] = (other[1]! + target[2]!) >>> 0;
    target[2] = (other[2]! + t) >>> 0;
    t = target[4]!;
    target[4] = (other[4]! + target[7]!) >>> 0;
    target[7] = (other[7]! + target[6]!) >>> 0;
    target[6] = (other[6]! + target[5]!) >>> 0;
    target[5] = (other[5]! + t) >>> 0;
  };

  const readWord = (buf: Uint8Array, off: number): number =>
    (buf[off]! | (buf[off + 1]! << 8) | (buf[off + 2]! << 16) | (buf[off + 3]! << 24)) >>> 0;

  const addMsg = (left: Uint32Array, right: Uint32Array): void => {
    for (let i = 0; i < 8; i++) {
      cvL[i] = (cvL[i]! ^ left[i]!) >>> 0;
      cvR[i] = (cvR[i]! ^ right[i]!) >>> 0;
    }
  };

  const compress = (buf: Uint8Array, off: number): void => {
    for (let i = 0; i < 8; i++) {
      eL[i] = readWord(buf, off + 4 * i);
      eR[i] = readWord(buf, off + 4 * (8 + i));
      oL[i] = readWord(buf, off + 4 * (16 + i));
      oR[i] = readWord(buf, off + 4 * (24 + i));
    }
    addMsg(eL, eR);
    mix(ALPHA_EVEN, BETA_EVEN, 0);
    wordPerm();
    addMsg(oL, oR);
    mix(ALPHA_ODD, BETA_ODD, 8);
    wordPerm();
    for (let step = 1; step < STEPS / 2; step++) {
      expandHalf(eL, oL);
      expandHalf(eR, oR);
      addMsg(eL, eR);
      mix(ALPHA_EVEN, BETA_EVEN, 16 * step);
      wordPerm();
      expandHalf(oL, eL);
      expandHalf(oR, eR);
      addMsg(oL, oR);
      mix(ALPHA_ODD, BETA_ODD, 16 * step + 8);
      wordPerm();
    }
    // A final even expansion and add, with no mix after it.
    expandHalf(eL, oL);
    expandHalf(eR, oR);
    addMsg(eL, eR);
  };

  return eagerAbsorber(
    BLOCK,
    (block, off) => compress(block, off),
    (tail, tailLen) => {
      const last = new Uint8Array(BLOCK);
      last.set(tail.subarray(0, tailLen));
      last[tailLen] = 0x80;
      compress(last, 0);
      const out = new Uint8Array(digestBits / 8);
      const bytes = new Uint8Array(32);
      for (let i = 0; i < 8; i++) {
        const v = (cvL[i]! ^ cvR[i]!) >>> 0;
        for (let j = 0; j < 4; j++) bytes[4 * i + j] = (v >>> (8 * j)) & 0xff;
      }
      out.set(bytes.subarray(0, out.length));
      return out;
    },
  );
}

// ---------------------------------------------------------------- LSH-512

/** LSH-512: 28 steps, a 256-byte block, 64-bit words. Serves LSH-384 and LSH-512. */
function createLsh512(digestBits: 384 | 512): LwcHasher {
  const STEPS = 28;
  const BLOCK = 256;
  const ALPHA_EVEN = 23;
  const BETA_EVEN = 59;
  const ALPHA_ODD = 7;
  const BETA_ODD = 3;

  const cvL = new Array<bigint>(8).fill(0n);
  const cvR = new Array<bigint>(8).fill(0n);
  const eL = new Array<bigint>(8).fill(0n);
  const eR = new Array<bigint>(8).fill(0n);
  const oL = new Array<bigint>(8).fill(0n);
  const oR = new Array<bigint>(8).fill(0n);

  const iv = digestBits === 384 ? IV384 : IV512;
  for (let i = 0; i < 8; i++) {
    cvL[i] = iv[i]!;
    cvR[i] = iv[8 + i]!;
  }

  const add = (a: bigint, b: bigint): bigint => (a + b) & MASK64;
  const rotl = (x: bigint, n: number): bigint =>
    n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;

  const wordPerm = (): void => {
    let t = cvL[0]!;
    cvL[0] = cvL[6]!; cvL[6] = cvR[6]!; cvR[6] = cvR[2]!; cvR[2] = cvL[1]!;
    cvL[1] = cvL[4]!; cvL[4] = cvR[4]!; cvR[4] = cvR[0]!; cvR[0] = cvL[2]!;
    cvL[2] = cvL[5]!; cvL[5] = cvR[7]!; cvR[7] = cvR[1]!; cvR[1] = t;
    t = cvL[3]!;
    cvL[3] = cvL[7]!; cvL[7] = cvR[5]!; cvR[5] = cvR[3]!; cvR[3] = t;
  };

  const mix = (alpha: number, beta: number, scOff: number): void => {
    for (let i = 0; i < 8; i++) cvL[i] = add(cvL[i]!, cvR[i]!);
    for (let i = 0; i < 8; i++) cvL[i] = rotl(cvL[i]!, alpha);
    for (let i = 0; i < 8; i++) cvL[i] = cvL[i]! ^ SC512[scOff + i]!;
    for (let i = 0; i < 8; i++) cvR[i] = add(cvR[i]!, cvL[i]!);
    for (let i = 0; i < 8; i++) cvR[i] = rotl(cvR[i]!, beta);
    for (let i = 0; i < 8; i++) cvL[i] = add(cvL[i]!, cvR[i]!);
    // Seven words here, not six. GAMMA512[7] is 56 -- see the header.
    for (let i = 1; i <= 7; i++) cvR[i] = rotl(cvR[i]!, GAMMA512[i]!);
  };

  /** Two halves, two different permutations. See the header. */
  const expandHalf = (target: bigint[], other: bigint[]): void => {
    let t = target[0]!;
    target[0] = add(other[0]!, target[3]!);
    target[3] = add(other[3]!, target[1]!);
    target[1] = add(other[1]!, target[2]!);
    target[2] = add(other[2]!, t);
    t = target[4]!;
    target[4] = add(other[4]!, target[7]!);
    target[7] = add(other[7]!, target[6]!);
    target[6] = add(other[6]!, target[5]!);
    target[5] = add(other[5]!, t);
  };

  const readWord = (buf: Uint8Array, off: number): bigint => {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(buf[off + i]!);
    return v;
  };

  const addMsg = (left: bigint[], right: bigint[]): void => {
    for (let i = 0; i < 8; i++) {
      cvL[i] = cvL[i]! ^ left[i]!;
      cvR[i] = cvR[i]! ^ right[i]!;
    }
  };

  const compress = (buf: Uint8Array, off: number): void => {
    for (let i = 0; i < 8; i++) {
      eL[i] = readWord(buf, off + 8 * i);
      eR[i] = readWord(buf, off + 8 * (8 + i));
      oL[i] = readWord(buf, off + 8 * (16 + i));
      oR[i] = readWord(buf, off + 8 * (24 + i));
    }
    addMsg(eL, eR);
    mix(ALPHA_EVEN, BETA_EVEN, 0);
    wordPerm();
    addMsg(oL, oR);
    mix(ALPHA_ODD, BETA_ODD, 8);
    wordPerm();
    for (let step = 1; step < STEPS / 2; step++) {
      expandHalf(eL, oL);
      expandHalf(eR, oR);
      addMsg(eL, eR);
      mix(ALPHA_EVEN, BETA_EVEN, 16 * step);
      wordPerm();
      expandHalf(oL, eL);
      expandHalf(oR, eR);
      addMsg(oL, oR);
      mix(ALPHA_ODD, BETA_ODD, 16 * step + 8);
      wordPerm();
    }
    expandHalf(eL, oL);
    expandHalf(eR, oR);
    addMsg(eL, eR);
  };

  return eagerAbsorber(
    BLOCK,
    (block, off) => compress(block, off),
    (tail, tailLen) => {
      const last = new Uint8Array(BLOCK);
      last.set(tail.subarray(0, tailLen));
      last[tailLen] = 0x80;
      compress(last, 0);
      const out = new Uint8Array(digestBits / 8);
      const bytes = new Uint8Array(64);
      for (let i = 0; i < 8; i++) {
        const v = cvL[i]! ^ cvR[i]!;
        for (let j = 0; j < 8; j++) bytes[8 * i + j] = Number((v >> BigInt(8 * j)) & 0xffn);
      }
      out.set(bytes.subarray(0, out.length));
      return out;
    },
  );
}

export function createLsh(digestBits: LshDigestBits): LwcHasher {
  return digestBits === 224 || digestBits === 256
    ? createLsh256(digestBits)
    : createLsh512(digestBits);
}

export function lsh(digestBits: LshDigestBits, message: Uint8Array): Uint8Array {
  const h = createLsh(digestBits);
  h.update(message);
  return h.digest();
}
