import { decodeBytesOption } from "@ocs/engine";
import { cipherCatalogueFor } from "./catalogue/options";
import {
  AES_BLOCK_SIZE,
  DEFAULT_AES_MODE_FALLBACK,
  OPTION_AAD,
  OPTION_KEY,
  OPTION_NONCE,
  OPTION_TWEAK,
  readAesKeySizeBytes,
  readAnubisVariant,
  readCounter,
  readDirection,
  readDrop,
  readEffectiveKeyBits,
  readGostSbox,
  readMode,
  readPadding,
  readParamSet,
  readRc5Rounds,
  readTagLen,
  readTagLenFrom,
  type CipherDirection,
} from "./pure";
import {
  getAesMode,
  getCipherInstance,
  getCipherTool,
  getParamSet,
  requireAesMode,
  requireCipherTool,
  type CipherInstance,
  type CipherParamSet,
  type AesModeMeta,
} from "./catalogue/tool-meta";
import type { CipherSpec } from "./spec";
import type { PaddingScheme } from "@ocs/algos";
import {
  keySourceParams,
  keySourceProblem,
  readKeySource,
  type KeySource,
  type KeySourceParams,
} from "@ocs/kdf/key-source";

export interface ResolvedCipher {
  toolId: string;
  direction: CipherDirection;
  /**
   * The mode in force, for any cipher with a `block`. Undefined for a stream or shaped cipher.
   *
   * The comment here used to say "AES only; the other tools have a single fixed mode", which stopped
   * being true when the shared mode layer arrived -- `modeForSpec` resolves one for every tool that
   * declares `block.modes`, which is what makes `r.mode!.id` at the `blockCipherOperation` call site
   * safe. Corrected rather than left, because the Padding row keys off `mode.blockAligned` and would
   * have looked like it could never fire for Camellia or DES.
   */
  mode: AesModeMeta | undefined;
  /**
   * The parameter set in use, for the tools that have more than one. Simon and Speck only.
   *
   * Carried on the resolved spec so nothing downstream has to re-derive it -- and so `blockSize`
   * below has a single source. `undefined` for every other cipher.
   */
  paramSet: CipherParamSet | undefined;
  /**
   * The padding scheme, which only ECB and CBC read.
   *
   * Carried unconditionally rather than only for those two, so nothing downstream has to ask whether
   * the mode is block-aligned before it can pass a value along -- the mode layer already ignores it
   * everywhere else, which is the honest place for that knowledge to live.
   */
  padding: PaddingScheme;
  /**
   * Where the key comes from, and the parameters if it is derived.
   *
   * `key` below is **empty** whenever `keySource` is not `custom`: the derivation is deliberately not
   * done here. `resolveCipher` is synchronous with fourteen callers -- every lint rule, `describeSpec`,
   * both of the form's length helpers -- so deriving would run Argon2 at 64 MiB a dozen times per
   * keystroke on the main thread. `computeCipher` is already async and derives once.
   *
   * What is here instead is everything a *diagnostic* can say without the bytes: the parameters, and
   * the length the key will be. Anything that needs the bytes themselves has to stand down, which is
   * the same rule `C003` and the Padding row already follow -- a diagnostic may only draw conclusions
   * from values the selected configuration actually uses.
   */
  keySource: KeySource;
  keySourceParams: KeySourceParams;
  /** How many key bytes the KDF will be asked for. Equal to `key.length` under `custom`. */
  derivedKeyLength: number;
  /** How many IV bytes the KDF will be asked for on top of the key. Zero unless it derives the IV. */
  derivedIvLength: number;
  /**
   * The named instance in force, for a shaped tool that has more than one. Undefined otherwise.
   *
   * Carried here so nothing downstream re-derives it, and so the key, nonce and tag lengths have one
   * source -- the same arrangement `paramSet` has, and for the same reason.
   */
  instance: CipherInstance | undefined;
  /**
   * The block size actually in force, in bytes.
   *
   * Equal to `tool.block.size` for every cipher with one shape, and to the selected set's for Simon
   * and Speck. Padding, the IV length and the block-boundary checks all read this; reading the
   * tool's own number instead is how a 4-byte-block Speck would get padded to sixteen.
   */
  blockSize: number | undefined;
  key: Uint8Array;
  nonce: Uint8Array;
  aad: Uint8Array;
  counter: number;
  /** RC2 only: how many key bits the schedule is allowed to use. */
  effectiveKeyBits: number;
  /** RC5 only: the round count, which is part of the algorithm's name. */
  rc5Rounds: number;
  /** GOST 28147-89 only: which published S-box set. */
  gostSbox: string;
  anubisVariant: string;
  /**
   * Threefish only: its tweak, sixteen bytes, defaulting to zero.
   *
   * Not the nonce, and deliberately a separate field. A tweak is an input to the *permutation* -- one
   * key becomes a family of permutations indexed by it -- where an IV is an input to the mode. Reusing
   * `nonce` would have meant a control labelled "IV" that changes the cipher rather than the chaining,
   * and a CBC IV and a tweak are both in play at once.
   */
  tweak: Uint8Array;
  drop: number;
  /** True when the construction authenticates as well as encrypts. */
  aead: boolean;
  /**
   * Tag length in bytes for the AEADs, zero for everything else.
   *
   * On the resolved spec rather than read from the options at the point of use, because three places
   * need it -- the compute path's short-input check, the "Tag" field, and the binding -- and an
   * AEAD whose three disagreed would report a tag that was not the one it appended.
   */
  tagLen: number;
}

export type ResolveResult =
  { ok: true; resolved: ResolvedCipher } | { ok: false; problem: string; optionId: string };

/** Nonce length the construction actually requires, in bytes. Zero means it takes none. */
export function requiredNonceLength(
  toolId: string,
  mode: AesModeMeta | undefined,
  paramSetId?: string,
): number {
  /**
   * A block cipher this repo implements takes an IV of exactly one block, whatever that is.
   *
   * Read from the cipher rather than from the mode, because `AES_MODES` is shared and its `nonceLen`
   * is AES's 16 -- correct for SM4 and wrong for DES, whose block is 8. The mode decides *whether*
   * there is an IV; the cipher decides how long.
   *
   * And for Simon and Speck the *parameter set* decides, not the tool: one Speck tool spans 4-, 6-,
   * 8-, 12- and 16-byte blocks. `paramSetId` is optional so a caller asking about a tool in the
   * abstract still gets the default set's answer, but every path that has a spec passes it.
   */
  const tool = getCipherTool(toolId);
  const paramSet = tool ? getParamSet(tool, paramSetId) : undefined;
  if (tool?.block) {
    if (!mode || mode.nonceLen === 0) return 0;
    /**
     * An AEAD's nonce is the mode's, not the cipher's.
     *
     * CBC, CFB, OFB and CTR chain blocks, so their IV *is* one block and the cipher decides how long.
     * GCM and CCM do not: GCM's 96-bit nonce and CCM's 7-to-13-byte range are properties of the
     * construction and are the same on Camellia as on AES. Returning the block size here gave
     * Camellia-CCM a 16-byte nonce, which CCM refuses outright -- and Camellia-GCM a 16-byte one,
     * which is legal for GCM but not what any specification or oracle uses.
     */
    return mode.aead ? mode.nonceLen : (paramSet?.blockSize ?? tool.block.size);
  }

  /**
   * A shaped cipher declares its own nonce widths on the metadata.
   *
   * Read before the switch below rather than added to it, so the fifteen tools that carry `shape` need
   * no arm here at all -- which is the point of the field. An instance pins one width; without instances
   * the *first* declared width is returned, and where a cipher accepts more than one
   * `acceptedNonceLengths` is the authority -- this value is then only used to size a generated nonce,
   * for which any legal width is correct.
   */
  if (tool?.shape) {
    const instance = getCipherInstance(tool, paramSetId);
    return instance ? instance.nonceLen : (tool.shape.nonceLengths[0] ?? 0);
  }

  switch (toolId) {
    case "aes":
      return mode?.nonceLen ?? 0;
    case "chacha20poly1305":
    case "chacha20":
    // The reduced-round variants keep RFC 8439's layout -- only the round count changes.
    case "chacha12":
    case "chacha8":
      return 12;
    case "chacha20orig":
      // 64 bits, with the other 64 left to the counter. This is the whole difference.
      return 8;
    case "ascon":
    case "aegis128l":
      // 128 bits, per SP 800-232 and the AEGIS draft -- wider than GCM's 96, and the reason a random
      // nonce per message is a sound strategy for both.
      return 16;
    case "aegis256":
      // 256 bits, matching its key.
      return 32;
    case "xchacha20poly1305":
    // The eXtended-nonce constructions all take 24 bytes, which is the whole point of the X: large
    // enough to pick at random forever without tracking what has been used.
    case "xsalsa20poly1305":
    case "xsalsa20":
      return 24;
    case "salsa20":
      // Salsa20's original 8, which is small enough that random choice risks a repeat -- see C003.
      return 8;
    default:
      return 0;
  }
}

/**
 * Every nonce length the construction accepts, in ascending order.
 *
 * One entry for the modes with a fixed width, seven for CCM, fifteen for OCB. Empty when the mode takes
 * no nonce at all, which is how the caller distinguishes "ECB" from "any length would do".
 */
export function acceptedNonceLengths(
  toolId: string,
  mode: AesModeMeta | undefined,
  paramSetId?: string,
): readonly number[] {
  const tool = getCipherTool(toolId);
  const paramSet = tool ? getParamSet(tool, paramSetId) : undefined;
  if (tool?.block) {
    if (!mode || mode.nonceLen === 0) return [];
    // Same split as `requiredNonceLength`: an AEAD's nonce rules come from the mode -- CCM's range
    // included -- and a chaining mode's IV is one block of whatever cipher this is.
    if (mode.nonceLens) return [...mode.nonceLens];
    return [mode.aead ? mode.nonceLen : (paramSet?.blockSize ?? tool.block.size)];
  }
  if (tool?.shape) {
    const instance = getCipherInstance(tool, paramSetId);
    return instance ? [instance.nonceLen] : [...tool.shape.nonceLengths];
  }
  if (toolId === "aes") {
    if (!mode || mode.nonceLen === 0) return [];
    return mode.nonceLens ? [...mode.nonceLens] : [mode.nonceLen];
  }
  const fixed = requiredNonceLength(toolId, mode, paramSetId);
  return fixed > 0 ? [fixed] : [];
}

/**
 * The mode a spec selects. Every block cipher has one; the stream ciphers have none.
 *
 * A share link can name a mode the tool does not offer -- or one that does not exist -- so the
 * fallback is the tool's own first mode rather than AES's default. Pointing DES at GCM because a URL
 * said so would produce an error rather than a wrong answer, but the error would be about a mode the
 * menu never showed.
 *
 * Extracted from `resolveCipher` when `cipherGenerateLength` needed the same answer. It has to be the
 * *same* answer rather than a second reading of the option: the Generate button offers a length and
 * the resolver then judges it, so two different notions of "the selected mode" would put a value in
 * the field that the very next line refuses.
 */
export function modeForSpec(spec: CipherSpec): AesModeMeta | undefined {
  const tool = requireCipherTool(spec.variant);
  if (spec.variant === "aes") {
    return (
      getAesMode(readMode(spec.options, DEFAULT_AES_MODE_FALLBACK)) ??
      requireAesMode(DEFAULT_AES_MODE_FALLBACK)
    );
  }
  if (!tool.block) return undefined;
  const named = getAesMode(readMode(spec.options, tool.block.modes[0]!));
  return named && tool.block.modes.includes(named.id)
    ? named
    : requireAesMode(tool.block.modes[0]!);
}

/**
 * The key lengths this spec will actually accept, in bytes.
 *
 * One implementation, called by `resolveCipher` and by `cipherAcceptedByteLengths`. Extracted for the
 * same reason `modeForSpec` was: the form offers a length, the resolver then judges it, and two
 * derivations of "what is acceptable" is exactly how a field comes to refuse a key the algorithm
 * takes. Under AES-XTS the catalogue's union said 16/24/32 while the mode wanted 32 or 64.
 *
 * Returns `undefined` where there is no exact list -- Blowfish's 4-to-56 range and RC5's 1-to-255 --
 * in which case the option's own `min`/`max` are the answer and `decodeBytesOption` has already
 * enforced them.
 *
 * The precedence is the one `resolveCipher` documents: a mode's own list wins (AES-SIV's 32/48/64 are
 * not a subset of AES's three), then a parameter set's or instance's single length, then AES's
 * declared key size, then the catalogue's union.
 */
export function cipherKeyLengths(spec: CipherSpec): readonly number[] | undefined {
  const tool = requireCipherTool(spec.variant);
  const mode = modeForSpec(spec);
  const paramSetId = readParamSet(spec.options);
  const paramSet = getParamSet(tool, paramSetId);
  const instance = getCipherInstance(tool, paramSetId);
  const aesKeySize = spec.variant === "aes" ? readAesKeySizeBytes(spec.options) : undefined;
  /*
   * A mode with its own lengths is still narrowed by the declared key size, where the two agree.
   *
   * Without this the Key size control would render under XTS and reach nothing -- the mode's [32, 64]
   * would win outright, so choosing XTS-AES-256 would leave a field still accepting 32 and a Generate
   * still producing it. An inert control is this repo's most-repeated defect, and it would have been
   * introduced by the fix that added the dropdown.
   *
   * The guard is `includes` rather than a straight override: a stored size the mode does not offer --
   * AES-192 left behind by a switch from GCM to XTS -- falls back to the mode's full list rather than
   * to nothing, which is the same thing the form's disabled "(not set)" placeholder is showing.
   */
  /*
   * A mode with its own key lengths is the authority on what is *accepted*, and the Key size control
   * only decides what Generate produces.
   *
   * The first version narrowed acceptance to the selected size here too, and that was wrong in a way
   * the published vectors caught: `createSpec` seeds AES-256, XTS offers 32 and 64, and 32 is one of
   * them -- so a pasted 64-byte XTS-AES-256 key was refused by a *default* nobody had chosen, with a
   * message naming 32. The control is still live, because `cipherGenerateLength` reads the selection;
   * what it must not do is reject a key the mode defines.
   *
   * Ordinary AES modes are the other way round: they carry no `keyLengths`, so the declared size is
   * the only narrowing there is, and refusing a mismatch with the size named is the whole point of it.
   */
  if (mode?.keyLengths) return mode.keyLengths;
  return paramSet
    ? [paramSet.keyLength]
    : instance
      ? [instance.keyLen]
      : aesKeySize !== undefined
        ? [aesKeySize]
        : cipherCatalogueFor(spec.variant).require(OPTION_KEY).bytesLength?.exact;
}

/**
 * What the form should check a `bytes` field against, and describe it as.
 *
 * Key and nonce only: those are the two whose accepted set moves with the mode or the parameter set.
 * Everything else returns `undefined` and the catalogue's own `bytesLength` stands, which is correct
 * for a tweak, an AAD or anything else that depends on nothing.
 */
export function cipherAcceptedByteLengths(
  spec: CipherSpec,
  optionId: string,
): readonly number[] | undefined {
  if (optionId === OPTION_KEY) return cipherKeyLengths(spec);
  if (optionId !== OPTION_NONCE) return undefined;
  const accepted = acceptedNonceLengths(
    spec.variant,
    modeForSpec(spec),
    readParamSet(spec.options),
  );
  // Empty means the construction takes none -- ECB, key wrap, SIV -- and the field is not rendered.
  return accepted.length > 0 ? accepted : undefined;
}

/**
 * How many random bytes the Generate button beside a key or a nonce should produce, for this spec.
 *
 * `ToolDefinition.generateLength`'s implementation for this family, and it exists because the
 * catalogue's static number cannot know the mode. Measured before it was written: Generate produced a
 * length the resolver refused in **eleven** cipher/mode combinations -- AES in CTR, CBC, OFB, CFB and
 * XTS (12 bytes offered where 16 is required), and Camellia, ARIA and SM4 in GCM and CCM (16 offered
 * where 12 is). Nothing failed, because an IV of the wrong length looks exactly like an IV somebody
 * mistyped.
 *
 * The nonce answer is `requiredNonceLength`, unchanged and reused -- which is the point. It already
 * knows that a chaining mode's IV is one block of *this* cipher while an AEAD's nonce belongs to the
 * mode, and a second rule here would be a second thing to keep true. Where the mode accepts a range,
 * it returns the canonical width (12 for CCM and OCB), which is what somebody who has not chosen
 * wants.
 *
 * Returns `undefined` where the length does not depend on the spec, leaving the catalogue's static
 * number in charge -- ChaCha20's nonce is 12 whatever else is selected.
 */
export function cipherGenerateLength(spec: CipherSpec, optionId: string): number | undefined {
  /**
   * The key, where AES's declared size decides it.
   *
   * This is the half the Key size control was asked for: pressing Generate on a tool set to AES-128
   * should give sixteen bytes, not the thirty-two the catalogue's static number always produced. The
   * modes that carry their own key lengths are excluded, because the control is not offered there and
   * the mode's own length is the answer -- XTS wants 32 or 64 and SIV 32, 48 or 64.
   */
  if (optionId === OPTION_KEY) {
    if (spec.variant !== "aes") return undefined;
    /*
     * The last of whatever the field will accept, which is the same function the field's own check
     * uses. Reading the mode's list directly gave 64 under XTS however the Key size was set, so the
     * button and the control disagreed the moment the control gained choices.
     */
    const accepted = cipherKeyLengths(spec);
    if (!accepted || accepted.length === 0) return undefined;
    /*
     * The declared size where the mode offers it, so the dropdown drives the button even though it no
     * longer narrows what the field accepts. Under XTS, picking XTS-AES-256 generates 64 bytes while a
     * pasted 32-byte key is still legal -- which is the honest division between "what to make" and
     * "what is valid".
     */
    const declared = spec.variant === "aes" ? readAesKeySizeBytes(spec.options) : undefined;
    if (declared !== undefined && accepted.includes(declared)) return declared;
    return accepted[accepted.length - 1];
  }
  if (optionId !== OPTION_NONCE) return undefined;
  const paramSetId = readParamSet(spec.options);
  const length = requiredNonceLength(spec.variant, modeForSpec(spec), paramSetId);
  // Zero means the construction takes none -- ECB, key wrap -- and the field is not rendered anyway.
  return length > 0 ? length : undefined;
}

/**
 * Turns a spec into everything the compute path needs, or names what is wrong.
 *
 * The nonce length check lives here rather than in `bytesLength` because the AES tool has one
 * catalogue and five modes wanting two different lengths — see the note in
 * `catalogue/options.ts`. Doing it here means compute, lint and describe all agree, and the
 * message can name the mode.
 */
export function resolveCipher(spec: CipherSpec): ResolveResult {
  const tool = requireCipherTool(spec.variant);
  const direction = readDirection(spec.options);

  const mode = modeForSpec(spec);

  /**
   * The parameter set, resolved once and then carried.
   *
   * `getParamSet` falls back to the tool's declared default, so a stale `paramSet` left in the spec
   * after switching from Speck to Simon lands on something legal rather than on nothing.
   */
  const paramSetId = readParamSet(spec.options);
  const paramSet = getParamSet(tool, paramSetId);
  // Instances share `OPTION_PARAM_SET` with block ciphers' parameter sets -- see the note on
  // `shape.instances`. Exactly one of the two is ever defined, because a tool has `block` or `shape`.
  const instance = getCipherInstance(tool, paramSetId);
  const blockSize = paramSet?.blockSize ?? tool.block?.size;

  const catalogue = cipherCatalogueFor(spec.variant);

  /*
   * The key source decides whether there is a Key field to read at all.
   *
   * Under a KDF the field is not rendered, so demanding bytes from it would refuse every derived spec.
   * What is checked instead is the derivation's own parameters -- `keySourceProblem` does that without
   * deriving, which is the whole reason it is a separate function from `deriveKeySourceBytes`.
   */
  const keySource = readKeySource(spec.options);
  const derivedParams = keySourceParams(catalogue, spec.options);
  const derivedProblem = keySourceProblem(derivedParams, direction);
  if (derivedProblem) {
    return { ok: false, problem: derivedProblem.problem, optionId: derivedProblem.optionId };
  }

  const keyResult = decodeBytesOption(catalogue, spec.options, OPTION_KEY);
  if (!keyResult.ok) return { ok: false, problem: keyResult.error, optionId: OPTION_KEY };
  if (keySource === "custom" && keyResult.bytes.length === 0) {
    return { ok: false, problem: "Enter a key, or press Generate.", optionId: OPTION_KEY };
  }

  /**
   * Key length. AES accepts three sizes; ChaCha exactly one; RC4 a range.
   *
   * A mode's own list wins where it has one, rather than being checked on top of the catalogue's:
   * AES-SIV's 32/48/64 are not a subset of AES's 16/24/32, so applying both would refuse every legal
   * SIV key. The catalogue describes the control, the mode describes the algorithm.
   */
  const keyOption = catalogue.require(OPTION_KEY);
  /**
   * Blowfish takes a range, so there is no exact list to compare against.
   *
   * The option's own `bytesLength` carries `min`/`max` in that case and `decodeBytesOption` has
   * already enforced them, so this check has nothing left to do -- which is why it is skipped rather
   * than given a second set of bounds to keep in step.
   */
  /**
   * A parameter set's key length wins over the catalogue's list.
   *
   * The catalogue has to declare the *union* across all ten Simon or Speck sets -- 8, 9, 12, 16, 18,
   * 24 and 32 bytes -- because `ToolDefinition.catalogue` is resolved once per tool and cannot know
   * which set is selected. So the specific length is enforced here, where the message can name the
   * set: "Speck48/96 needs a key of 12 bytes" rather than "expected one of 8, 9, 12, 16, 18, 24, 32",
   * which would tell a user nothing. Fourth family to need this, after AES's modes, ECDSA's curves
   * and SLH-DSA's parameter sets.
   */
  /**
   * AES's declared key size narrows the catalogue's union, and sits *after* the mode's own list.
   *
   * The order matters. XTS and SIV carry their own `keyLengths` because an XTS key is two AES keys and
   * SIV's is split between a CMAC and a CTR -- so the mode still wins there, and the Key size control
   * is not offered for those two at all. For every other mode the union 16/24/32 is what the catalogue
   * can say and the selected size is what the user actually chose, which is the same
   * declare-the-union-narrow-in-the-resolver arrangement Simon's parameter sets use.
   */
  const aesKeySize = spec.variant === "aes" ? readAesKeySizeBytes(spec.options) : undefined;
  // Through the shared helper, so the form's hint and this check cannot disagree about what is
  // acceptable -- which is the whole defect `acceptedByteLengths` exists to close.
  const exact = cipherKeyLengths(spec);
  /*
   * Length checks are for a key the user typed. A derived one is asked for at exactly the length the
   * cipher wants, so there is nothing here that could disagree -- and `key` is empty under a KDF, which
   * every one of these checks would read as wrong.
   */
  if (keySource === "custom" && exact && !exact.includes(keyResult.bytes.length)) {
    return {
      ok: false,
      problem: mode?.keyLengths
        ? `AES-${mode.label} needs a key of ${exact.join(", ")} bytes — it splits the key in two, one half for the CMAC and one for the CTR — and this one is ${keyResult.bytes.length}.`
        : aesKeySize !== undefined
          ? // Names the size that was *chosen*, and the way out. "One of 16, 24, 32" told a reader
            // nothing about which of the two things they had got wrong.
            `Key size is set to AES-${aesKeySize * 8}, which needs a key of ${aesKeySize} bytes; this one is ${keyResult.bytes.length}. Change the key, or change the key size.`
          : `${paramSet?.label ?? instance?.label ?? tool.label} needs a key of ${exact.join(", ")} bytes; this one is ${keyResult.bytes.length}.`,
      optionId: OPTION_KEY,
    };
  }
  // Skipped where a set has pinned an exact length above: the union's bounds are wider by
  // construction and would only ever accept something the set has already refused.
  const min =
    keySource !== "custom" || paramSet || instance ? undefined : keyOption.bytesLength?.min;
  const max =
    keySource !== "custom" || paramSet || instance ? undefined : keyOption.bytesLength?.max;
  if (min !== undefined && keyResult.bytes.length < min) {
    return {
      ok: false,
      problem: `${tool.label} needs at least ${min} key bytes; this one is ${keyResult.bytes.length}.`,
      optionId: OPTION_KEY,
    };
  }
  if (max !== undefined && keyResult.bytes.length > max) {
    return {
      ok: false,
      problem: `${tool.label} accepts at most ${max} key bytes; this one is ${keyResult.bytes.length}.`,
      optionId: OPTION_KEY,
    };
  }

  const nonceResult = decodeBytesOption(catalogue, spec.options, OPTION_NONCE);
  if (!nonceResult.ok) return { ok: false, problem: nonceResult.error, optionId: OPTION_NONCE };

  /**
   * Nonce length: a set, not a number.
   *
   * CCM accepts 7 to 13 bytes and OCB 1 to 15, so the check cannot be an equality any more -- and the
   * message has to name what is acceptable rather than one value, or a user with a legal 13-byte CCM
   * nonce would be told it must be 12.
   */
  const accepted = acceptedNonceLengths(spec.variant, mode, paramSetId);
  const needed = requiredNonceLength(spec.variant, mode, paramSetId);
  /*
   * A derived IV is not the user's to get wrong.
   *
   * With Derives set to Key and IV the field is not rendered and holds nothing, so both checks below
   * would refuse every such spec -- and refusing what the app itself is about to supply is the shape
   * of bug that makes a feature unreachable. The KDF is asked for exactly `needed` extra bytes, so
   * there is nothing here that could disagree.
   */
  const ivIsDerived = keySource !== "custom" && derivedParams.derives === "key-iv";
  if (!ivIsDerived && accepted.length > 1 && !accepted.includes(nonceResult.bytes.length)) {
    const label =
      spec.variant === "aes"
        ? `AES-${mode!.label}`
        : `${paramSet?.label ?? instance?.label ?? tool.label}-${mode?.label ?? ""}`;
    const list =
      accepted.length > 3
        ? `${accepted[0]} to ${accepted[accepted.length - 1]}`
        : accepted.join(" or ");
    return {
      ok: false,
      problem:
        nonceResult.bytes.length === 0
          ? `${label} needs a ${label.includes("XTS") ? "data unit" : "nonce"} of ${list} bytes. Press Generate.`
          : `${label} accepts a nonce of ${list} bytes; this one is ${nonceResult.bytes.length}.`,
      optionId: OPTION_NONCE,
    };
  }
  if (
    !ivIsDerived &&
    accepted.length <= 1 &&
    needed > 0 &&
    nonceResult.bytes.length !== needed
  ) {
    /**
     * Name the cipher, not AES.
     *
     * This read `mode ? \`AES-${mode.label}\` : tool.label`, which was right while AES was the only
     * cipher with modes and became "AES-CBC needs exactly 16 bytes" under Camellia the moment the
     * shared mode layer arrived. The mode is still worth naming -- it is what decides the length.
     */
    const label =
      spec.variant === "aes"
        ? `AES-${mode!.label}`
        : mode
          ? `${tool.label}-${mode.label}`
          : (instance?.label ?? tool.label);
    return {
      ok: false,
      problem:
        nonceResult.bytes.length === 0
          ? `${label} needs a ${needed}-byte ${mode?.nonceLabel.toLowerCase() ?? "nonce"}. Press Generate.`
          : `${label} needs exactly ${needed} bytes here; this one is ${nonceResult.bytes.length}.`,
      optionId: OPTION_NONCE,
    };
  }

  const aadResult = decodeBytesOption(catalogue, spec.options, OPTION_AAD);
  if (!aadResult.ok) return { ok: false, problem: aadResult.error, optionId: OPTION_AAD };

  /**
   * Threefish's tweak, and empty is legal.
   *
   * The option declares no length, so an empty field decodes to zero bytes and the binding treats that
   * as the all-zero tweak -- which is what the published vectors use and what Skein's own zero-tweak
   * case is. A *partial* tweak is refused by `createThreefish` rather than zero-extended here: silently
   * padding twelve bytes to sixteen would encrypt under a tweak nobody asked for.
   */
  const tweakResult = decodeBytesOption(catalogue, spec.options, OPTION_TWEAK);
  if (!tweakResult.ok) return { ok: false, problem: tweakResult.error, optionId: OPTION_TWEAK };
  /**
   * Checked here rather than left to the catalogue, which declares `exact: [0, 16]` and does not
   * enforce it -- `decodeBytesOption` decodes, and every length rule in this family is the resolver's,
   * which is where a message can explain itself.
   *
   * Refused rather than zero-extended, and this is the "only refuse what cannot exist" line being
   * drawn on the other side for once: a twelve-byte tweak *could* be padded, and padding it would
   * encrypt under a tweak nobody asked for and say nothing. Empty is legal and means all zeroes, which
   * is what the published zero-tweak vectors use.
   */
  if (tweakResult.bytes.length !== 0 && tweakResult.bytes.length !== 16) {
    return {
      ok: false,
      problem: `Threefish's tweak is 0 or 16 bytes -- empty for the all-zero tweak, or all sixteen. This one is ${tweakResult.bytes.length}, and padding it would encrypt under a different tweak than the one entered.`,
      optionId: OPTION_TWEAK,
    };
  }

  const aead = spec.variant === "aes" ? (mode?.aead ?? false) : tool.aead;
  /**
   * Every AEAD here uses a 16-byte tag except AEGIS, which offers 16 or 32.
   *
   * Read from the options only where the tool actually has the control; otherwise a stale `tagLen`
   * left in a spec after switching tools would change AES-GCM's answer.
   */
  const tagLen = aead
    ? tool.shape
      ? // A shaped AEAD's tag length is fixed by the construction, not chosen: no control, and an
        // instance's own value wins where the instances disagree (Elephant's do -- 8 and 16).
        (instance?.tagLen ?? tool.shape.tagLen ?? 16)
      : spec.variant === "aegis128l" || spec.variant === "aegis256"
        ? readTagLen(spec.options)
        : mode?.tagLens
          ? // CCM and OCB, on AES and on the 128-bit block ciphers alike.
            readTagLenFrom(spec.options, mode.tagLens, 16)
          : 16
    : 0;

  return {
    ok: true,
    resolved: {
      toolId: spec.variant,
      direction,
      mode,
      paramSet,
      instance,
      blockSize,
      padding: readPadding(spec.options),
      keySource,
      keySourceParams: derivedParams,
      /*
       * The length the KDF will be asked for. `exact` is a set for a tool that accepts several -- AES
       * without a declared size, RC5's range -- so the last entry is taken, which is the same choice
       * `cipherGenerateLength` makes and keeps the two agreeing.
       */
      derivedKeyLength:
        keySource === "custom"
          ? keyResult.bytes.length
          : (exact?.[exact.length - 1] ?? keyResult.bytes.length),
      derivedIvLength:
        keySource !== "custom" && derivedParams.derives === "key-iv"
          ? requiredNonceLength(spec.variant, mode, paramSetId)
          : 0,
      key: keyResult.bytes,
      nonce: nonceResult.bytes,
      aad: aadResult.bytes,
      counter: readCounter(spec.options),
      effectiveKeyBits: readEffectiveKeyBits(spec.options, keyResult.bytes.length),
      rc5Rounds: readRc5Rounds(spec.options),
      gostSbox: readGostSbox(spec.options),
      anubisVariant: readAnubisVariant(spec.options),
      tweak: tweakResult.bytes,
      drop: readDrop(spec.options),
      aead,
      tagLen,
    },
  };
}

/** True when the ciphertext must be a whole number of the cipher's blocks. */
export function requiresBlockAlignment(resolved: ResolvedCipher): boolean {
  return resolved.mode?.blockAligned ?? false;
}

/**
 * The block size in bytes, for the message that reports a misaligned ciphertext.
 *
 * Not readable from the mode: `AES_MODES` is shared across every cipher that offers those five modes,
 * so its own numbers are AES's. DES's block is half that, and a message quoting 16 bytes for it would
 * send someone looking for a problem that is not there.
 */
export function cipherBlockSize(resolved: ResolvedCipher): number {
  // Off the resolved spec, not off the tool: a Speck tool's own `block.size` is only its default
  // set's, and padding a 4-byte-block cipher to 16 would produce something nothing can decrypt.
  return resolved.blockSize ?? getCipherTool(resolved.toolId)?.block?.size ?? AES_BLOCK_SIZE;
}

export { AES_BLOCK_SIZE };
