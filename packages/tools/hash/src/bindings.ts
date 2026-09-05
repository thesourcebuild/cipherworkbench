import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from "@noble/hashes/sha2.js";
import { md5, ripemd160, sha1 } from "@noble/hashes/legacy.js";
import type { FarmhashVariant, RapidhashVersion } from "@ocs/algos";
import {
  keccak_224,
  keccak_256,
  keccak_384,
  keccak_512,
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
  shake128,
  shake256,
} from "@noble/hashes/sha3.js";
import { blake224, blake256, blake384, blake512 } from "@noble/hashes/blake1.js";
import { blake2b, blake2s } from "@noble/hashes/blake2.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { concatBytes } from "@ocs/engine";
import {
  cshake128,
  cshake256,
  kt128,
  kt256,
  parallelhash128,
  parallelhash128xof,
  parallelhash256,
  parallelhash256xof,
  tuplehash128,
  tuplehash128xof,
  tuplehash256,
  tuplehash256xof,
  turboshake128,
  turboshake256,
} from "@noble/hashes/sha3-addons.js";
import { DEFAULT_PARALLEL_BLOCK_SIZE, DEFAULT_TURBOSHAKE_DOMAIN } from "./pure";
/**
 * Every algorithm this family implements itself arrives through a **dynamic import of its own
 * module**, so opening a hash tool downloads that algorithm's tables and nobody else's.
 *
 * The measurement that forced this. `bindings.ts` used to name all 58 of these symbols in one static
 * `import ... from "@ocs/algos"`, which makes every one of them genuinely reachable -- so
 * `sideEffects: false` and tree-shaking cannot help, and webpack put 629 KB of algorithm source into
 * the chunks the hash family's dynamic import requires. Opening SHA-256 fetched **441 KB across
 * twelve chunks**, including 102 KB of Snefru, Tiger, Skein and Streebog tables that SHA-256 has no
 * use for. FSB was fixed this way first, one table at a time; this is the same fix applied to the
 * rule rather than to the exception.
 *
 * Three things make it work, and each is load-bearing:
 *
 * - **The load is keyed by module, not by binding.** Streebog-256 and Streebog-512 share one
 *   `import()` specifier, so webpack gives them one chunk and `loadedModules` one entry -- so the
 *   second `prepare()` resolves without a second fetch. A per-binding cache would work and would
 *   re-await the same module once per algorithm, which for a category is once per row.
 * - **`prepare()` runs before the tool is handed over.** `loadTool()` awaits
 *   `prepareHashAlgorithm(id)`, because `Hasher` and `ToolStream.finish()` are synchronous and cannot
 *   await. The compute worker calls `loadTool` itself, so it prepares in its own context.
 * - **The sync accessor throws rather than loading.** A caller that skipped `prepare` gets a message
 *   naming what to await; returning a zeroed table would give a plausible wrong digest, which is the
 *   one failure a round-trip test cannot see.
 *
 * Adding an algorithm implemented here is therefore two lines rather than one: the `lazyModule` const
 * if its module is new, and the shim. `tests/hash.test.ts` asserts the map below covers every binding
 * that needs one, by parsing this file -- so a forgotten entry fails rather than throwing at runtime.
 */

interface LazyModule<M> {
  /** Load the module. Idempotent, and cheap after the first call. */
  prepare(): Promise<void>;
  /** The loaded module, or a throw naming what to await. */
  get(): M;
}

/**
 * Keyed by module name rather than held per `lazyModule`, so two bindings over one module share a
 * single load. See the note above.
 */
const loadedModules = new Map<string, unknown>();
const loadingModules = new Map<string, Promise<void>>();

function lazyModule<M>(name: string, load: () => Promise<M>): LazyModule<M> {
  return {
    prepare(): Promise<void> {
      if (loadedModules.has(name)) return Promise.resolve();
      let pending = loadingModules.get(name);
      if (!pending) {
        pending = load().then((module) => {
          loadedModules.set(name, module);
        });
        loadingModules.set(name, pending);
      }
      return pending;
    },
    get(): M {
      const module = loadedModules.get(name);
      if (module === undefined) {
        throw new Error(
          `The ${name} module has not been loaded yet. Await prepareHashAlgorithm() before ` +
            "hashing -- each algorithm's implementation is a dynamic import so that the other hash " +
            "tools do not download its tables.",
        );
      }
      return module as M;
    },
  };
}

/** A callable that behaves exactly like the module export it stands in for. */
type LazyCallable<T> = T extends (...args: infer A) => infer R ? (...args: A) => R : never;

/**
 * A stand-in for one module export, so the binding table below reads exactly as it did when these
 * were static imports. The indirection is what keeps 145 entries unchanged.
 */
function lazyFn<M, K extends keyof M>(module: LazyModule<M>, key: K): LazyCallable<M[K]> {
  return ((...args: unknown[]) =>
    (module.get()[key] as (...inner: unknown[]) => unknown)(...args)) as LazyCallable<M[K]>;
}

// ── one dynamic import per module ──────────────────────────────────────────

const M_ASCON = lazyModule("ascon", () => import("@ocs/algos/ascon"));
const M_BELT = lazyModule("belt", () => import("@ocs/algos/belt"));
const M_BELTMILL = lazyModule("beltmill", () => import("@ocs/algos/beltmill"));
const M_CITYCRC = lazyModule("citycrc", () => import("@ocs/algos/citycrc"));
const M_CITYHASH = lazyModule("cityhash", () => import("@ocs/algos/cityhash"));
const M_CUBEHASH = lazyModule("cubehash", () => import("@ocs/algos/cubehash"));
const M_ECHO = lazyModule("echo", () => import("@ocs/algos/echo"));
const M_FARMHASH = lazyModule("farmhash", () => import("@ocs/algos/farmhash"));
const M_FNV = lazyModule("fnv", () => import("@ocs/algos/fnv"));
const M_FSB = lazyModule("fsb", () => import("@ocs/algos/fsb"));
const M_FUGUE = lazyModule("fugue", () => import("@ocs/algos/fugue"));
const M_GIMLI = lazyModule("gimli", () => import("@ocs/algos/gimli"));
const M_GOST = lazyModule("gost", () => import("@ocs/algos/gost"));
const M_GROESTL = lazyModule("groestl", () => import("@ocs/algos/groestl"));
const M_HAMSI = lazyModule("hamsi", () => import("@ocs/algos/hamsi"));
const M_HAS160 = lazyModule("has160", () => import("@ocs/algos/has160"));
const M_HAVAL = lazyModule("haval", () => import("@ocs/algos/haval"));
const M_JH = lazyModule("jh", () => import("@ocs/algos/jh"));
const M_KUPYNA = lazyModule("kupyna", () => import("@ocs/algos/kupyna"));
const M_LSH = lazyModule("lsh", () => import("@ocs/algos/lsh"));
const M_LUFFA = lazyModule("luffa", () => import("@ocs/algos/luffa"));
const M_LWC_PHOTONBEETLE = lazyModule(
  "lwc-photonbeetle",
  () => import("@ocs/algos/lwc-photonbeetle"),
);
const M_LWC_ROMULUS = lazyModule("lwc-romulus", () => import("@ocs/algos/lwc-romulus"));
const M_LWC_SPARKLE = lazyModule("lwc-sparkle", () => import("@ocs/algos/lwc-sparkle"));
const M_LWC_XOODYAK = lazyModule("lwc-xoodyak", () => import("@ocs/algos/lwc-xoodyak"));
const M_MD2 = lazyModule("md2", () => import("@ocs/algos/md2"));
const M_MD4 = lazyModule("md4", () => import("@ocs/algos/md4"));
const M_MD6 = lazyModule("md6", () => import("@ocs/algos/md6"));
const M_METROHASH = lazyModule("metrohash", () => import("@ocs/algos/metrohash"));
const M_METROHASH_CRC = lazyModule("metrohash-crc", () => import("@ocs/algos/metrohash-crc"));
const M_MURMUR3 = lazyModule("murmur3", () => import("@ocs/algos/murmur3"));
const M_PHOTON = lazyModule("photon", () => import("@ocs/algos/photon"));
const M_QUARK = lazyModule("quark", () => import("@ocs/algos/quark"));
const M_RAPIDHASH = lazyModule("rapidhash", () => import("@ocs/algos/rapidhash"));
const M_RIPEMD = lazyModule("ripemd", () => import("@ocs/algos/ripemd"));
const M_SHABAL = lazyModule("shabal", () => import("@ocs/algos/shabal"));
const M_SHAVITE = lazyModule("shavite", () => import("@ocs/algos/shavite"));
const M_SIMD = lazyModule("simd", () => import("@ocs/algos/simd"));
const M_SKEIN = lazyModule("skein", () => import("@ocs/algos/skein"));
const M_SM3 = lazyModule("sm3", () => import("@ocs/algos/sm3"));
const M_SNEFRU = lazyModule("snefru", () => import("@ocs/algos/snefru"));
const M_SPOOKYHASH = lazyModule("spookyhash", () => import("@ocs/algos/spookyhash"));
const M_STREEBOG = lazyModule("streebog", () => import("@ocs/algos/streebog"));
const M_T1HA = lazyModule("t1ha", () => import("@ocs/algos/t1ha"));
const M_TIGER = lazyModule("tiger", () => import("@ocs/algos/tiger"));
const M_WHIRLPOOL = lazyModule("whirlpool", () => import("@ocs/algos/whirlpool"));
const M_WYHASH = lazyModule("wyhash", () => import("@ocs/algos/wyhash"));
const M_XXHASH3 = lazyModule("xxhash3", () => import("@ocs/algos/xxhash3"));
const M_XXHASH32 = lazyModule("xxhash32", () => import("@ocs/algos/xxhash32"));
const M_XXHASH64 = lazyModule("xxhash64", () => import("@ocs/algos/xxhash64"));
const M_POSEIDON = lazyModule("poseidon", () => import("@ocs/algos/poseidon"));
const M_RESCUEPRIME = lazyModule("rescue-prime", () => import("@ocs/algos/rescue-prime"));
const M_HARAKA = lazyModule("haraka", () => import("@ocs/algos/haraka"));
const M_MEOWHASH = lazyModule("meowhash", () => import("@ocs/algos/meowhash"));
const M_KOMIHASH = lazyModule("komihash", () => import("@ocs/algos/komihash"));
const M_NHASH = lazyModule("nhash", () => import("@ocs/algos/nhash"));
const M_MONOLITH = lazyModule("monolith", () => import("@ocs/algos/monolith"));
const M_NEPTUNE = lazyModule("neptune", () => import("@ocs/algos/neptune"));
const M_REINFORCEDCONCRETE = lazyModule("reinforced-concrete", () => import("@ocs/algos/reinforced-concrete"));
const M_ANEMOI = lazyModule("anemoi", () => import("@ocs/algos/anemoi"));
const M_GRIFFIN = lazyModule("griffin", () => import("@ocs/algos/griffin"));
const M_POSEIDON2 = lazyModule("poseidon2", () => import("@ocs/algos/poseidon2"));
const M_MIMC = lazyModule("mimc", () => import("@ocs/algos/mimc"));
const M_TIP5 = lazyModule("tip5", () => import("@ocs/algos/tip5"));
const M_PEARSON = lazyModule("pearson", () => import("@ocs/algos/pearson"));
const M_MURMUR1_2 = lazyModule("murmur1-2", () => import("@ocs/algos/murmur1-2"));
const M_LOOKUP3 = lazyModule("lookup3", () => import("@ocs/algos/lookup3"));

// ── the shims, which the binding table reads as though they were imports ───

const pearsonHash = lazyFn(M_PEARSON, "pearsonHash");
const murmurHash1 = lazyFn(M_MURMUR1_2, "murmurHash1");
const murmurHash2 = lazyFn(M_MURMUR1_2, "murmurHash2");
const jenkinsLookup3 = lazyFn(M_LOOKUP3, "jenkinsLookup3");

const cityhash = lazyFn(M_CITYHASH, "cityhash");
const cityhashCrc = lazyFn(M_CITYCRC, "cityhashCrc");
const createAsconHash256 = lazyFn(M_ASCON, "createAsconHash256");
const createAsconXof128 = lazyFn(M_ASCON, "createAsconXof128");
const createBeltHash = lazyFn(M_BELT, "createBeltHash");
const createCubehash = lazyFn(M_CUBEHASH, "createCubehash");
const createEcho = lazyFn(M_ECHO, "createEcho");
const createEsch = lazyFn(M_LWC_SPARKLE, "createEsch");
const createFnv = lazyFn(M_FNV, "createFnv");
const createFsb = lazyFn(M_FSB, "createFsb");
const createFugue = lazyFn(M_FUGUE, "createFugue");
const createGimliHash = lazyFn(M_GIMLI, "createGimliHash");
const createGost = lazyFn(M_GOST, "createGost");
const createGroestl = lazyFn(M_GROESTL, "createGroestl");
const createHamsi = lazyFn(M_HAMSI, "createHamsi");
const createHas160 = lazyFn(M_HAS160, "createHas160");
const createHaval = lazyFn(M_HAVAL, "createHaval");
const createJh = lazyFn(M_JH, "createJh");
const createJoaat = lazyFn(M_FNV, "createJoaat");
const createKupyna = lazyFn(M_KUPYNA, "createKupyna");
const createLsh = lazyFn(M_LSH, "createLsh");
const createLuffa = lazyFn(M_LUFFA, "createLuffa");
const createMd2 = lazyFn(M_MD2, "createMd2");
const createMd4 = lazyFn(M_MD4, "createMd4");
const createMd6 = lazyFn(M_MD6, "createMd6");
const createMurmur3 = lazyFn(M_MURMUR3, "createMurmur3");
const createPanama = lazyFn(M_BELTMILL, "createPanama");
const createPhotonBeetleHash = lazyFn(M_LWC_PHOTONBEETLE, "createPhotonBeetleHash");
const createPhotonHash = lazyFn(M_PHOTON, "createPhotonHash");
const createQuark = lazyFn(M_QUARK, "createQuark");
const createRadioGatun = lazyFn(M_BELTMILL, "createRadioGatun");
const createRipemd128 = lazyFn(M_RIPEMD, "createRipemd128");
const createRipemd256 = lazyFn(M_RIPEMD, "createRipemd256");
const createRipemd320 = lazyFn(M_RIPEMD, "createRipemd320");
const createRomulusH = lazyFn(M_LWC_ROMULUS, "createRomulusH");
const createShabal = lazyFn(M_SHABAL, "createShabal");
const createShavite = lazyFn(M_SHAVITE, "createShavite");
const createSimd = lazyFn(M_SIMD, "createSimd");
const createSkein = lazyFn(M_SKEIN, "createSkein");
const createSm3 = lazyFn(M_SM3, "createSm3");
const createSnefru = lazyFn(M_SNEFRU, "createSnefru");
const createStreebog = lazyFn(M_STREEBOG, "createStreebog");
const createTiger = lazyFn(M_TIGER, "createTiger");
const createTiger2 = lazyFn(M_TIGER, "createTiger2");
const createWhirlpool = lazyFn(M_WHIRLPOOL, "createWhirlpool");
const createXoodyakHash = lazyFn(M_LWC_XOODYAK, "createXoodyakHash");
const createXxHash32 = lazyFn(M_XXHASH32, "createXxHash32");
const createXxHash64 = lazyFn(M_XXHASH64, "createXxHash64");
const createXxh3_128 = lazyFn(M_XXHASH3, "createXxh3_128");
const createXxh3_64 = lazyFn(M_XXHASH3, "createXxh3_64");
const farmhashBytes = lazyFn(M_FARMHASH, "farmhashBytes");
const metrohash = lazyFn(M_METROHASH, "metrohash");
const metrohashCrc128Bytes = lazyFn(M_METROHASH_CRC, "metrohashCrc128Bytes");
const prepareFsb = lazyFn(M_FSB, "prepareFsb");
const rapidhashBytes = lazyFn(M_RAPIDHASH, "rapidhashBytes");
const spookyhash = lazyFn(M_SPOOKYHASH, "spookyhash");
const t1ha = lazyFn(M_T1HA, "t1ha");
const wyhashBytes = lazyFn(M_WYHASH, "wyhashBytes");
const poseidonHash = lazyFn(M_POSEIDON, "poseidonHash");
const rescuePrimeHash = lazyFn(M_RESCUEPRIME, "rescuePrimeHash");
const haraka256Hash = lazyFn(M_HARAKA, "haraka256Hash");
const haraka512Hash = lazyFn(M_HARAKA, "haraka512Hash");
const meowHash = lazyFn(M_MEOWHASH, "meowHash");
const komihash = lazyFn(M_KOMIHASH, "komihash");
const nhash = lazyFn(M_NHASH, "nhash");
const monolithHash = lazyFn(M_MONOLITH, "monolithHash");
const neptuneHash = lazyFn(M_NEPTUNE, "neptuneHash");
const reinforcedConcreteHash = lazyFn(M_REINFORCEDCONCRETE, "reinforcedConcreteHash");
const anemoiHash = lazyFn(M_ANEMOI, "anemoiHash");
const griffinHash = lazyFn(M_GRIFFIN, "griffinHash");
const poseidon2Hash = lazyFn(M_POSEIDON2, "poseidon2Hash");
const mimcHash = lazyFn(M_MIMC, "mimcHash");
const tip5Hash = lazyFn(M_TIP5, "tip5Hash");

/**
 * The one export here that is a value rather than a function, so it cannot be a `lazyFn` shim: read
 * through a getter at the point of use instead. Its only caller is rapidhash's binding.
 */
const rapidhashDefaultVersion = () => M_RAPIDHASH.get().RAPIDHASH_DEFAULT_VERSION;

/**
 * The only module in this package that imports an implementation.
 *
 * Reached exclusively through `./definition`, which the app loads on demand when a
 * tool is selected — so listing every algorithm in the sidebar costs nothing but
 * the strings in `catalogue/algorithm-meta.ts`.
 */

/** The minimum an incremental hasher has to offer. Satisfied by every `noble` hasher as-is. */
export interface Hasher {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

/**
 * A digest algorithm expressed as "make me a hasher of this length".
 *
 * Deliberately not just `CHash`. Stating the binding in terms of an *incremental*
 * hasher, parameterised by output length, means `compute` and `createStream` in
 * `./compute.ts` share one code path and neither branches per algorithm — and it
 * makes a variable-length algorithm a data entry rather than a special case, since
 * the only thing those need is for the length to reach `create`.
 *
 * Deciding *what* length to pass is not this module's job — see `resolveOutputLen`
 * in `./catalogue/algorithm-meta.ts`, which lives on the cheap side of the
 * manifest/definition split so `describeSpec` can use it too.
 */
/**
 * Everything an algorithm here might need in order to construct a hasher.
 *
 * A parameters object rather than positional arguments, and that is not cosmetic: the previous
 * signature was `create(outputLen, seed?)`, and `createHashStream` called it as
 * `create(outputLen)` -- silently dropping the seed, so a *streamed* xxHash with a non-zero seed
 * produced a different value from the one-shot path. Positional optionals invite exactly that.
 * With one object there is nothing to forget, and adding the SHA-3 addons' four parameters costs
 * no call-site changes.
 *
 * Every binding ignores the fields that do not apply to it. A stale `customization` left in the
 * spec after switching from cSHAKE to SHA-256 must not change SHA-256's answer.
 */
export interface HashParams {
  outputLen: number;
  /**
   * HAVAL's and Tiger's pass count -- an argument to one function, not a choice between six.
   *
   * Undefined for every algorithm that has no such axis, and the bindings that do take it read it
   * directly rather than through a default, so a missing value is a bug rather than a silent 3.
   */
  passes?: number;
  /** xxHash and MetroHash -- a 32-bit seed. */
  seed?: number;
  /** SpookyHash and t1ha -- a 64-bit seed, which does not fit a `number`. */
  seed64?: bigint;
  /** MetroHash and t1ha -- which named variant, by the reference's own name. */
  variant?: string;
  /** cSHAKE, TupleHash, ParallelHash, KangarooTwelve -- SP 800-185's customisation string S. */
  customization?: Uint8Array;
  /** cSHAKE only -- the function-name string N. */
  functionName?: Uint8Array;
  /** ParallelHash only -- block size B, in bytes. */
  blockLen?: number;
  /** TurboSHAKE only -- the domain-separation byte D. */
  domain?: number;
  /** BLAKE2 and BLAKE3 -- the MAC key, which goes into the initial state rather than around it. */
  key?: Uint8Array;
  /** BLAKE2 only -- RFC 7693's salt (16 bytes for 2b, 8 for 2s). */
  salt?: Uint8Array;
  /** BLAKE2 only -- RFC 7693's personalisation, same sizes as the salt. */
  personalization?: Uint8Array;
  /** BLAKE3 only -- `derive_key` context. Exclusive with `key`. */
  context?: Uint8Array;
}

export interface HashBinding {
  create(params: HashParams): Hasher;
  /**
   * Optional one-time async setup, awaited by `loadTool()` before the tool is handed over.
   *
   * Exists for FSB, whose 266 KB matrix table is a dynamic import so that the other 138 hash tools do
   * not download it. It has to happen *before* the definition is usable rather than inside a compute,
   * because `ToolStream.finish()` is synchronous and cannot await -- see the header of
   * `packages/algos/src/fsb.ts`.
   *
   * Must be idempotent and cheap to call again.
   */
  prepare?(): Promise<void>;
}

/** Minimal structural view of a noble fixed-output hash. */
interface FixedHash {
  create(): Hasher;
}

/**
 * Minimal structural view of a noble variable-output hash. SHAKE, BLAKE3, BLAKE2b
 * and BLAKE2s all expose exactly this — which is why the two very different
 * *semantics* (see `OutputMode`) share one binding shape here. The distinction
 * matters to the user, not to the plumbing.
 */
interface VariableHash {
  create(opts: { dkLen: number }): Hasher;
}

function fixed(hash: FixedHash): HashBinding {
  // The requested length is ignored, not clamped: `resolveOutputLen` has already
  // returned the algorithm's own size for a fixed-output entry.
  return { create: () => hash.create() };
}

function variable(hash: VariableHash): HashBinding {
  return { create: ({ outputLen }) => hash.create({ dkLen: outputLen }) };
}

/** Minimal structural view of BLAKE2, whose options are a superset of a variable hash's. */
interface Blake2Hash {
  create(opts: {
    dkLen: number;
    key?: Uint8Array;
    salt?: Uint8Array;
    personalization?: Uint8Array;
  }): Hasher;
}

/** Minimal structural view of BLAKE3, whose third parameter is a context rather than a salt. */
interface Blake3Hash {
  create(opts: { dkLen: number; key?: Uint8Array; context?: Uint8Array }): Hasher;
}

/**
 * BLAKE2, with its parameter block.
 *
 * Empty values are omitted rather than passed as zero-length arrays, and that is not tidiness: noble
 * distinguishes absent from empty, and a zero-length key is not the same function as no key at all --
 * RFC 7693 encodes the key length into the parameter block, so keying with nothing still changes the
 * initial state. Passing `undefined` is what produces a plain digest.
 */
function blake2Binding(hash: Blake2Hash): HashBinding {
  return {
    create: ({ outputLen, key, salt, personalization }) =>
      hash.create({
        dkLen: outputLen,
        ...(key && key.length > 0 ? { key } : {}),
        ...(salt && salt.length > 0 ? { salt } : {}),
        ...(personalization && personalization.length > 0 ? { personalization } : {}),
      }),
  };
}

/**
 * BLAKE3's three modes, picked by which parameter is present.
 *
 * `key` gives keyed_hash, `context` gives derive_key, neither gives the plain hash. Both at once is
 * not a mode BLAKE3 defines, and noble throws on it -- `resolveSpec` refuses it first, with a message
 * that says which one to clear.
 */
function blake3Binding(hash: Blake3Hash): HashBinding {
  return {
    create: ({ outputLen, key, context }) =>
      hash.create({
        dkLen: outputLen,
        ...(key && key.length > 0 ? { key } : {}),
        ...(context && context.length > 0 ? { context } : {}),
      }),
  };
}

/** A hash from `@ocs/algos` — same shape as noble's, so no adapter is needed. */
function local(create: () => Hasher): HashBinding {
  return { create: () => create() };
}

/** The same, for a hash whose shape depends on its parameters. */
function parameterised(create: (params: HashParams) => Hasher): HashBinding {
  return { create };
}

/**
 * Wraps a one-shot hash as the incremental interface, by accumulating.
 *
 * All five of the non-cryptographic families below read from the *end* of the message as well as the
 * start -- CityHash's long path takes words at `len - 16`, `len - 40` and `len - 56`, t1ha's tail reads
 * backwards, SpookyHash's padding depends on the remainder -- so none of them can stream, and saying so
 * here once beats five copies of the same buffer.
 */
function bufferedHasher(compute: (message: Uint8Array) => Uint8Array): Hasher {
  const chunks: Uint8Array[] = [];
  let length = 0;
  return {
    update: (chunk) => {
      chunks.push(chunk);
      length += chunk.length;
    },
    digest: () => {
      const all = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        all.set(chunk, offset);
        offset += chunk.length;
      }
      return compute(all);
    },
  };
}

/** The output-length select declares the union; this narrows it to what these families accept. */
const narrowLength = (bytes: number): 4 | 8 | 16 => (bytes === 4 ? 4 : bytes === 16 ? 16 : 8);

/**
 * t1ha's output length and variant are not independent: t1ha1 has no 128-bit form.
 *
 * The catalogue cannot say so -- `ToolDefinition.catalogue` is resolved once per tool and the two
 * controls are separate -- so the refusal lives here, where the message can name both. Same
 * arrangement as AES's per-mode nonce length and SLH-DSA's per-set key sizes.
 */
function t1haBytes(params: HashParams, message: Uint8Array): Uint8Array {
  const wide = params.outputLen === 16;
  const variant = params.variant === "t1ha1" ? "t1ha1" : "t1ha2";
  if (wide && variant === "t1ha1") {
    throw new Error(
      "t1ha1 has no 128-bit form; only t1ha2 does. Switch the variant or the length.",
    );
  }
  return t1ha(wide ? "t1ha2-128" : variant, message, params.seed64 ?? 0n);
}

/**
 * MD5 ‖ SHA-1, as OpenSSL's `md5-sha1`.
 *
 * The one entry here that composes two algorithms rather than binding one. Both hashers are
 * fed the same chunks, so the incremental contract holds and file streaming works exactly as
 * it does for every other entry — which is the reason this is expressed as a binding rather
 * than special-cased in `compute.ts`.
 */
function md5Sha1(): HashBinding {
  return {
    create: () => {
      const left = md5.create();
      const right = sha1.create();
      return {
        update(chunk) {
          left.update(chunk);
          right.update(chunk);
        },
        digest: () => concatBytes(left.digest(), right.digest()),
      };
    },
  };
}

/**
 * The xxHash pair. `digest()` there returns a number or a bigint rather than bytes, so
 * this is the one place a real adapter is needed — the big-endian byte form is what the
 * result panel and the verify field both work in.
 */
function seeded32(): HashBinding {
  return {
    create: ({ seed = 0 }) => {
      const engine = createXxHash32(seed >>> 0);
      return { update: (chunk) => engine.update(chunk), digest: () => engine.digestBytes() };
    },
  };
}

function seeded64(): HashBinding {
  return {
    create: ({ seed = 0 }) => {
      const engine = createXxHash64(seed >>> 0);
      return { update: (chunk) => engine.update(chunk), digest: () => engine.digestBytes() };
    },
  };
}

/** XXH3 and XXH128, whose engines already speak `update`/`digestBytes`. */
function seededXxh3(
  create: (seed?: bigint) => { update(chunk: Uint8Array): void; digestBytes(): Uint8Array },
): HashBinding {
  return {
    create: ({ seed = 0 }) => {
      const engine = create(BigInt(seed >>> 0));
      return { update: (chunk) => engine.update(chunk), digest: () => engine.digestBytes() };
    },
  };
}

export const HASH_BINDINGS: Readonly<Record<string, HashBinding>> = {
  md2: local(createMd2),
  md4: local(createMd4),
  /**
   * MD6 takes its digest size in *bits*, and it is not a truncation.
   *
   * `outputLen` arrives in bytes, as every other entry's does, so it is multiplied here -- and the
   * size then goes into the control word and sets the round count, which is why this is `create` on a
   * parameter rather than `variable()`. A hasher built for 256 bits cannot produce a 128-bit answer by
   * cutting its output in half.
   */
  md6: { create: ({ outputLen }) => createMd6(outputLen * 8) },
  md5: fixed(md5),
  sha1: fixed(sha1),
  ripemd160: fixed(ripemd160),
  // The other three widths come from @ocs/algos; noble carries only 160.
  ripemd128: local(createRipemd128),
  ripemd256: local(createRipemd256),
  ripemd320: local(createRipemd320),

  sha224: fixed(sha224),
  sha256: fixed(sha256),
  sha384: fixed(sha384),
  sha512: fixed(sha512),
  "sha512-224": fixed(sha512_224),
  "sha512-256": fixed(sha512_256),

  "sha3-224": fixed(sha3_224),
  "sha3-256": fixed(sha3_256),
  "sha3-384": fixed(sha3_384),
  "sha3-512": fixed(sha3_512),

  "keccak-224": fixed(keccak_224),
  "keccak-256": fixed(keccak_256),
  "keccak-384": fixed(keccak_384),
  "keccak-512": fixed(keccak_512),

  shake128: variable(shake128),
  shake256: variable(shake256),

  // The original BLAKE. Fixed output, unlike everything else in this category -- BLAKE1 has no
  // parameterised length, which is one of the things BLAKE2 added.
  blake224: fixed(blake224),
  blake256: fixed(blake256),
  blake384: fixed(blake384),
  blake512: fixed(blake512),
  blake2b: blake2Binding(blake2b),
  blake2s: blake2Binding(blake2s),
  blake3: blake3Binding(blake3),

  "md5-sha1": md5Sha1(),

  cshake128: cshake(cshake128),
  cshake256: cshake(cshake256),

  tuplehash128: customizable(tuplehash128),
  tuplehash256: customizable(tuplehash256),
  tuplehash128xof: customizable(tuplehash128xof),
  tuplehash256xof: customizable(tuplehash256xof),

  parallelhash128: blockSized(parallelhash128),
  parallelhash256: blockSized(parallelhash256),
  parallelhash128xof: blockSized(parallelhash128xof),
  parallelhash256xof: blockSized(parallelhash256xof),

  turboshake128: domainSeparated(turboshake128),
  turboshake256: domainSeparated(turboshake256),

  kt128: customizable(kt128),
  kt256: customizable(kt256),

  /**
   * Skein's three state sizes. The output length reaches `createSkein` because it is part of the
   * function -- see the note on the metadata -- which is exactly what `HashParams` exists to carry.
   */
  skein256: { create: ({ outputLen }) => createSkein(32, outputLen) },
  skein512: { create: ({ outputLen }) => createSkein(64, outputLen) },
  skein1024: { create: ({ outputLen }) => createSkein(128, outputLen) },

  asconhash256: local(createAsconHash256),
  // The one XOF here that is not a noble hash: `variable` expects noble's `create({ dkLen })`, and
  // Ascon's takes the length positionally.
  asconxof128: { create: ({ outputLen }) => createAsconXof128(outputLen) },

  sm3: local(createSm3),

  /**
   * The Tiger and HAVAL grids, and the other algorithms PHP's `hash_algos()` lists -- plus Tiger2,
   * which PHP does not have.
   *
   * Written as loops-worth of one-liners rather than generated, because `HASH_BINDINGS` is the one
   * place a reader can see which implementation every id reaches, and a generated map would hide
   * exactly that.
   */
  // One implementation, two arguments. `passes` is required here rather than
  // defaulted, so a spec that failed to resolve it fails loudly.
  tiger: { create: ({ passes, outputLen }) => createTiger(passes!, outputLen) },
  // Tiger2: three passes, 192 bits, 0x80 padding. See the note at the top of `tiger.ts` for the
  // provenance of the single vector it is checked against.
  tiger2: local(createTiger2),

  /**
   * The three SHA-3 competition designs, all from `@ocs/algos`.
   *
   * Each buffers its input rather than compressing per chunk -- Groestl's and JH's paddings carry a
   * total count, so neither can finalise before the whole message is seen -- which is why their
   * manifests report `streaming: false` rather than showing a progress bar they cannot honour.
   */
  groestl224: local(() => createGroestl(28)),
  groestl256: local(() => createGroestl(32)),
  groestl384: local(() => createGroestl(48)),
  groestl512: local(() => createGroestl(64)),
  jh224: local(() => createJh(28)),
  jh256: local(() => createJh(32)),
  jh384: local(() => createJh(48)),
  jh512: local(() => createJh(64)),
  cubehash224: local(() => createCubehash(28)),
  cubehash256: local(() => createCubehash(32)),
  cubehash384: local(() => createCubehash(48)),
  cubehash512: local(() => createCubehash(64)),
  luffa224: local(() => createLuffa(28)),
  luffa256: local(() => createLuffa(32)),
  luffa384: local(() => createLuffa(48)),
  luffa512: local(() => createLuffa(64)),
  fugue224: local(() => createFugue(28)),
  fugue256: local(() => createFugue(32)),
  fugue384: local(() => createFugue(48)),
  fugue512: local(() => createFugue(64)),
  shavite224: local(() => createShavite(28)),
  shavite256: local(() => createShavite(32)),
  shavite384: local(() => createShavite(48)),
  shavite512: local(() => createShavite(64)),
  shabal192: local(() => createShabal(24)),
  shabal224: local(() => createShabal(28)),
  shabal256: local(() => createShabal(32)),
  shabal384: local(() => createShabal(48)),
  shabal512: local(() => createShabal(64)),
  echo224: local(() => createEcho(28)),
  echo256: local(() => createEcho(32)),
  echo384: local(() => createEcho(48)),
  echo512: local(() => createEcho(64)),
  hamsi224: local(() => createHamsi(28)),
  hamsi256: local(() => createHamsi(32)),
  hamsi384: local(() => createHamsi(48)),
  hamsi512: local(() => createHamsi(64)),
  simd224: local(() => createSimd(28)),
  simd256: local(() => createSimd(32)),
  simd384: local(() => createSimd(48)),
  simd512: local(() => createSimd(64)),
  "belt-hash": local(() => createBeltHash()),

  // LSH, the second Korean standard here. Two engines, four digest sizes.
  lsh224: local(() => createLsh(224)),
  lsh256: local(() => createLsh(256)),
  lsh384: local(() => createLsh(384)),
  lsh512: local(() => createLsh(512)),

  // The belt-and-mill pair, the two Ukrainian standards and the Korean one.
  radiogatun32: local(() => createRadioGatun(32)),
  radiogatun64: local(() => createRadioGatun(64)),
  panama: local(createPanama),
  kupyna256: local(() => createKupyna(256)),
  kupyna384: local(() => createKupyna(384)),
  kupyna512: local(() => createKupyna(512)),
  has160: local(createHas160),

  // The four NIST lightweight hashes. All incremental -- see `lwc-hash.ts` for why that took work.
  "xoodyak-hash": { create: ({ outputLen }) => createXoodyakHash(outputLen) },
  esch256: local(() => createEsch(256)),
  esch384: local(() => createEsch(384)),
  "photonbeetle-hash": local(createPhotonBeetleHash),
  "romulus-h": local(createRomulusH),

  /**
   * The three lightweight sponges that are not finalists. All three stream.
   *
   * Quark's variant carries its own digest width, so its binding takes the variant and ignores
   * `outputLen`: `resolveOutputLen` has already read the width off the variant, and passing it here as
   * well would give the two a way to disagree.
   */
  gimli: { create: ({ outputLen }) => createGimliHash(outputLen) },
  quark: parameterised(({ variant }) => createQuark(variant ?? "u-quark")),
  photon: local(createPhotonHash),

  /**
   * FSB streams, and its output length picks the parameter set rather than truncating.
   *
   * The `outputLen` here is in bytes and `createFsb` wants bits. Building a set's matrix touches the
   * whole 266 KB pi table and is cached inside `@ocs/algos`, so switching lengths is cheap after the
   * first use of each.
   */
  fsb: {
    create: ({ outputLen }) => createFsb(outputLen * 8),
    prepare: prepareFsb,
  },

  /**
   * The wyhash lineage. Both read from the *end* of the message, so neither streams -- same
   * `bufferedHasher` arrangement as the five families above, and for the same reason.
   */
  wyhash: parameterised(({ seed64 }) => bufferedHasher((m) => wyhashBytes(m, seed64 ?? 0n))),
  /**
   * rapidhash's variant is a *version*, and the four are different functions rather than refinements.
   *
   * `seed64` is passed through as `undefined` when the field is empty so each version applies its own
   * default -- v1.0's is not zero. See `compute.ts` and `rapidhash.ts`.
   */
  /**
   * The two CRC-32C-mixed variants. Both read from the end of the message, so neither streams.
   *
   * `cityhashcrc` takes a length and no seed (its 128-bit seeded form needs a 128-bit seed, which the
   * one seed control cannot express); `metrohash128crc` takes the variant and a 32-bit seed.
   */
  cityhashcrc: parameterised(({ outputLen }) =>
    bufferedHasher((m) => cityhashCrc(outputLen === 32 ? 32 : 16, m)),
  ),
  metrohash128crc: parameterised(({ variant, seed }) =>
    bufferedHasher((m) => metrohashCrc128Bytes(m, variant === "2" ? "2" : "1", seed ?? 0)),
  ),

  /**
   * FarmHash names the *namespace*, never the public `Hash64` -- see the metadata for why. An absent
   * seed means the unseeded entry point, which is a different function from seeding with zero.
   */
  farmhash: parameterised(({ variant, seed64 }) =>
    bufferedHasher((m) => farmhashBytes(m, (variant ?? "na") as FarmhashVariant, seed64)),
  ),

  rapidhash: parameterised(({ variant, seed64 }) =>
    bufferedHasher((m) =>
      rapidhashBytes(m, (variant ?? rapidhashDefaultVersion()) as RapidhashVersion, seed64),
    ),
  ),

  haval: { create: ({ passes, outputLen }) => createHaval(passes!, outputLen) },

  snefru: local(createSnefru),
  gost94: { create: () => createGost("test") },
  "gost94-crypto": { create: () => createGost("crypto") },

  fnv132: { create: () => createFnv("fnv132") },
  fnv1a32: { create: () => createFnv("fnv1a32") },
  fnv164: { create: () => createFnv("fnv164") },
  fnv1a64: { create: () => createFnv("fnv1a64") },
  joaat: local(createJoaat),
  murmur3a: { create: () => createMurmur3("murmur3a") },
  murmur3c: { create: () => createMurmur3("murmur3c") },
  murmur3f: { create: () => createMurmur3("murmur3f") },
  // Two entries over one implementation, because the output length picks the initialising value
  // rather than truncating -- see the note on the 256-bit metadata entry.
  streebog512: local(() => createStreebog(64)),
  streebog256: local(() => createStreebog(32)),
  whirlpool: local(createWhirlpool),

  /**
   * The five non-cryptographic families. Each takes its parameters from `HashParams` rather than
   * having one entry per width or variant, which is what keeps them one tool each.
   */
  cityhash: parameterised((params) =>
    bufferedHasher((m) => cityhash(narrowLength(params.outputLen), m)),
  ),
  spookyhash: parameterised((params) =>
    bufferedHasher((m) => spookyhash(narrowLength(params.outputLen), m, params.seed64 ?? 0n)),
  ),
  metrohash: parameterised((params) =>
    bufferedHasher((m) =>
      metrohash(
        params.outputLen === 16 ? 16 : 8,
        params.variant === "2" ? 2 : 1,
        m,
        params.seed ?? 0,
      ),
    ),
  ),
  t1ha: parameterised((params) => bufferedHasher((m) => t1haBytes(params, m))),

  xxh32: seeded32(),
  xxh64: seeded64(),
  // XXH3 takes a 64-bit seed; the form's seed control is 32-bit, matching XXH32 and XXH64, so it
  // is widened here. A 64-bit seed field would be reachable only for these two of forty-eight
  // algorithms, which is not worth a second control kind.
  xxh3: seededXxh3(createXxh3_64),
  xxh128: seededXxh3(createXxh3_128),
  poseidon: { create: () => bufferedHasher(poseidonHash) },
  rescueprime: { create: () => bufferedHasher(rescuePrimeHash) },
  haraka256: { create: () => bufferedHasher(haraka256Hash) },
  haraka512: { create: () => bufferedHasher(haraka512Hash) },
  meowhash: { create: () => bufferedHasher(meowHash) },
  komihash: { create: () => bufferedHasher(komihash) },
  nhash: { create: () => bufferedHasher(nhash) },
  monolith: { create: () => bufferedHasher(monolithHash) },
  neptune: { create: () => bufferedHasher(neptuneHash) },
  "reinforced-concrete": { create: () => bufferedHasher(reinforcedConcreteHash) },
  anemoi: { create: () => bufferedHasher(anemoiHash) },
  griffin: { create: () => bufferedHasher(griffinHash) },
  poseidon2: { create: () => bufferedHasher(poseidon2Hash) },
  mimc: { create: () => bufferedHasher(mimcHash) },
  tip5: { create: () => bufferedHasher(tip5Hash) },
  pearson: { create: () => bufferedHasher((m) => pearsonHash(m)) },
  murmur1: parameterised(({ seed = 0 }) =>
    bufferedHasher((m) => {
      const h = murmurHash1(m, seed >>> 0);
      return Uint8Array.of((h >>> 24) & 0xff, (h >>> 16) & 0xff, (h >>> 8) & 0xff, h & 0xff);
    }),
  ),
  murmur2: parameterised(({ seed = 0 }) =>
    bufferedHasher((m) => {
      const h = murmurHash2(m, seed >>> 0);
      return Uint8Array.of((h >>> 24) & 0xff, (h >>> 16) & 0xff, (h >>> 8) & 0xff, h & 0xff);
    }),
  ),
  "jenkins-lookup3": parameterised(({ seed = 0 }) =>
    bufferedHasher((m) => {
      const h = jenkinsLookup3(m, seed >>> 0);
      return Uint8Array.of((h >>> 24) & 0xff, (h >>> 16) & 0xff, (h >>> 8) & 0xff, h & 0xff);
    }),
  ),
};

/**
 * Which module each algorithm's implementation lives in, and therefore what
 * `prepareHashAlgorithm()` has to load before that tool can compute.
 *
 * Absent means the algorithm comes from `@noble/hashes`, which is statically imported: it is shared
 * with the MAC family, it is what the default tools use, and it has no large tables. A test parses
 * the binding table and requires this map to agree with it, so an algorithm added here without an
 * entry fails the suite rather than throwing on its own page.
 */
const MODULE_FOR_ALGORITHM: Readonly<Record<string, LazyModule<unknown>>> = {
  asconhash256: M_ASCON,
  asconxof128: M_ASCON,
  "belt-hash": M_BELT,
  cityhash: M_CITYHASH,
  cityhashcrc: M_CITYCRC,
  cubehash224: M_CUBEHASH,
  cubehash256: M_CUBEHASH,
  cubehash384: M_CUBEHASH,
  cubehash512: M_CUBEHASH,
  echo224: M_ECHO,
  echo256: M_ECHO,
  echo384: M_ECHO,
  echo512: M_ECHO,
  esch256: M_LWC_SPARKLE,
  esch384: M_LWC_SPARKLE,
  farmhash: M_FARMHASH,
  fnv132: M_FNV,
  fnv164: M_FNV,
  fnv1a32: M_FNV,
  fnv1a64: M_FNV,
  fsb: M_FSB,
  fugue224: M_FUGUE,
  fugue256: M_FUGUE,
  fugue384: M_FUGUE,
  fugue512: M_FUGUE,
  gimli: M_GIMLI,
  gost94: M_GOST,
  "gost94-crypto": M_GOST,
  groestl224: M_GROESTL,
  groestl256: M_GROESTL,
  groestl384: M_GROESTL,
  groestl512: M_GROESTL,
  hamsi224: M_HAMSI,
  hamsi256: M_HAMSI,
  hamsi384: M_HAMSI,
  hamsi512: M_HAMSI,
  has160: M_HAS160,
  haval: M_HAVAL,
  jh224: M_JH,
  jh256: M_JH,
  jh384: M_JH,
  jh512: M_JH,
  joaat: M_FNV,
  kupyna256: M_KUPYNA,
  kupyna384: M_KUPYNA,
  kupyna512: M_KUPYNA,
  lsh224: M_LSH,
  lsh256: M_LSH,
  lsh384: M_LSH,
  lsh512: M_LSH,
  luffa224: M_LUFFA,
  luffa256: M_LUFFA,
  luffa384: M_LUFFA,
  luffa512: M_LUFFA,
  md2: M_MD2,
  md4: M_MD4,
  md6: M_MD6,
  metrohash: M_METROHASH,
  metrohash128crc: M_METROHASH_CRC,
  murmur3a: M_MURMUR3,
  murmur3c: M_MURMUR3,
  murmur3f: M_MURMUR3,
  panama: M_BELTMILL,
  photon: M_PHOTON,
  "photonbeetle-hash": M_LWC_PHOTONBEETLE,
  quark: M_QUARK,
  radiogatun32: M_BELTMILL,
  radiogatun64: M_BELTMILL,
  rapidhash: M_RAPIDHASH,
  ripemd128: M_RIPEMD,
  ripemd256: M_RIPEMD,
  ripemd320: M_RIPEMD,
  "romulus-h": M_LWC_ROMULUS,
  shabal192: M_SHABAL,
  shabal224: M_SHABAL,
  shabal256: M_SHABAL,
  shabal384: M_SHABAL,
  shabal512: M_SHABAL,
  shavite224: M_SHAVITE,
  shavite256: M_SHAVITE,
  shavite384: M_SHAVITE,
  shavite512: M_SHAVITE,
  simd224: M_SIMD,
  simd256: M_SIMD,
  simd384: M_SIMD,
  simd512: M_SIMD,
  skein1024: M_SKEIN,
  skein256: M_SKEIN,
  skein512: M_SKEIN,
  sm3: M_SM3,
  snefru: M_SNEFRU,
  spookyhash: M_SPOOKYHASH,
  streebog256: M_STREEBOG,
  streebog512: M_STREEBOG,
  t1ha: M_T1HA,
  tiger: M_TIGER,
  tiger2: M_TIGER,
  whirlpool: M_WHIRLPOOL,
  wyhash: M_WYHASH,
  "xoodyak-hash": M_LWC_XOODYAK,
  xxh128: M_XXHASH3,
  xxh3: M_XXHASH3,
  xxh32: M_XXHASH32,
  xxh64: M_XXHASH64,
  poseidon: M_POSEIDON,
  rescueprime: M_RESCUEPRIME,
  haraka256: M_HARAKA,
  haraka512: M_HARAKA,
  meowhash: M_MEOWHASH,
  komihash: M_KOMIHASH,
  nhash: M_NHASH,
  monolith: M_MONOLITH,
  neptune: M_NEPTUNE,
  "reinforced-concrete": M_REINFORCEDCONCRETE,
  anemoi: M_ANEMOI,
  griffin: M_GRIFFIN,
  poseidon2: M_POSEIDON2,
  mimc: M_MIMC,
  tip5: M_TIP5,
  pearson: M_PEARSON,
  murmur1: M_MURMUR1_2,
  murmur2: M_MURMUR1_2,
  "jenkins-lookup3": M_LOOKUP3,
};

/**
 * The binding, with its module's load folded into `prepare`.
 *
 * Composed here rather than written into all 145 entries: an entry says what the algorithm *is*, and
 * which chunk its implementation happens to arrive in is not something each one should restate.
 */
function withModule(id: string, binding: HashBinding): HashBinding {
  const module = MODULE_FOR_ALGORITHM[id];
  if (!module) return binding;
  return {
    create: binding.create,
    // Two stages for FSB, the one binding with a `prepare` of its own: loading `fsb.ts` does not
    // load `fsb-pi.ts`, whose 363 KB matrix is a dynamic import inside that module.
    prepare: async () => {
      await module.prepare();
      await binding.prepare?.();
    },
  };
}

export function getHashBinding(id: string): HashBinding | undefined {
  const binding = HASH_BINDINGS[id];
  return binding ? withModule(id, binding) : undefined;
}

export function requireHashBinding(id: string): HashBinding {
  const binding = HASH_BINDINGS[id];
  if (!binding) throw new Error(`No hash implementation bound for: ${id}`);
  return withModule(id, binding);
}

// ── SHA-3 derived functions ─────────────────────────────────────────────────

/**
 * The SP 800-185 family and its faster successors.
 *
 * Two things about noble's API matter here and are easy to get wrong. Its `personalization` and
 * `NISTfn` options want **`Uint8Array`**, not strings -- passing a string throws rather than being
 * coerced, which is why `resolve` decodes them through the byte-option path. And an *absent*
 * customisation is not the same as an empty one for every function in this family, so the options
 * are only set when non-empty rather than always being passed as a zero-length array.
 */
interface CustomizableHash {
  create(opts: {
    dkLen?: number;
    personalization?: Uint8Array;
    NISTfn?: Uint8Array;
    blockLen?: number;
    D?: number;
  }): Hasher;
}

/** cSHAKE: variable output, a customisation string, and a function name. */
function cshake(hash: CustomizableHash): HashBinding {
  return {
    create: ({ outputLen, customization, functionName }) =>
      hash.create({
        dkLen: outputLen,
        ...(customization && customization.length > 0
          ? { personalization: customization }
          : {}),
        ...(functionName && functionName.length > 0 ? { NISTfn: functionName } : {}),
      }),
  };
}

/**
 * TupleHash and KangarooTwelve: variable output plus a customisation string.
 *
 * For TupleHash the *tuple* is not a create-time parameter -- each `update()` call is one element,
 * which is why `compute.ts` drives it element by element and why the manifest marks it
 * non-streaming. See the note on `HashAlgorithmMeta.tupleInput`.
 */
function customizable(hash: CustomizableHash): HashBinding {
  return {
    create: ({ outputLen, customization }) =>
      hash.create({
        dkLen: outputLen,
        ...(customization && customization.length > 0
          ? { personalization: customization }
          : {}),
      }),
  };
}

/** ParallelHash: adds the block size B, which changes the digest and has no safe default. */
function blockSized(hash: CustomizableHash): HashBinding {
  return {
    create: ({ outputLen, customization, blockLen }) =>
      hash.create({
        dkLen: outputLen,
        blockLen: blockLen ?? DEFAULT_PARALLEL_BLOCK_SIZE,
        ...(customization && customization.length > 0
          ? { personalization: customization }
          : {}),
      }),
  };
}

/** TurboSHAKE: variable output plus the domain-separation byte D. */
function domainSeparated(hash: CustomizableHash): HashBinding {
  return {
    create: ({ outputLen, domain }) =>
      hash.create({ dkLen: outputLen, D: domain ?? DEFAULT_TURBOSHAKE_DOMAIN }),
  };
}
