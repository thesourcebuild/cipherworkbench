import type { LintRule } from "@ocs/contracts/diagnostic";
import { isWeakDesKey } from "@ocs/algos";
import {
  OPTION_KDF_SALT,
  OPTION_KEY_SOURCE,
  OPTION_PBKDF2_ITERATIONS,
} from "@ocs/kdf/key-source";
import {
  bytesEncodingOf,
  decodeBytesOption,
  encodeBytesValue,
  randomBytes,
  randomBytesValue,
} from "@ocs/engine";
import { cipherCatalogueFor } from "../catalogue/options";
import { getAesMode, requireCipherTool } from "../catalogue/tool-meta";
import {
  OPTION_KEY,
  OPTION_MODE,
  OPTION_NONCE,
  OPTION_PARAM_SET,
  OPTION_PADDING,
  readMode,
  readParamSet,
  withMode,
} from "../pure";
import { acceptedNonceLengths, requiredNonceLength, resolveCipher } from "../resolve";
import type { CipherSpec } from "../spec";

/**
 * Sets the mode and brings the nonce with it.
 *
 * Every fix here must be a pure function of the spec it is *handed*, not of the spec that was
 * linted. `applyAllFixes` runs all fixes in one pass, so C002's switch to GCM can land before
 * C003's nonce generation — and a nonce sized from the mode captured at check time is then
 * wrong for the mode that is now set. That combination produced a spec neither rule would
 * have accepted on its own.
 *
 * So this reads the mode out of the argument and only replaces the nonce when its length no
 * longer fits, which leaves a spec that actually resolves whichever order the fixes ran in.
 */
function withModeAndValidNonce(spec: CipherSpec, modeId: string): CipherSpec {
  const next = { ...withMode(spec.options, modeId) };
  const mode = getAesMode(modeId);
  const needed = requiredNonceLength(spec.variant, mode, readParamSet(spec.options));

  if (needed === 0) {
    // ECB takes none; leaving a stale nonce would be harmless but confusing.
    delete next[OPTION_NONCE];
    delete next.nonceEncoding;
    return { ...spec, options: next };
  }

  const current = decodeBytesOption(cipherCatalogueFor(spec.variant), next, OPTION_NONCE);
  if (!current.ok || current.bytes.length !== needed) {
    Object.assign(next, generatedInto({ ...spec, options: next }, OPTION_NONCE, needed));
  }

  return { ...spec, options: next };
}

/**
 * A generated value written in the encoding the field is already showing.
 *
 * Every fix here that produces fresh bytes used to write hex and set the companion selector to `hex`,
 * which is the same surprise the Generate button was reported for: a user working in Base64 pressed a
 * fix and the selector moved. `randomBytesValue` honours the current encoding where it can and says
 * when it could not, and the selector is written only in that second case.
 */
function generatedInto(spec: CipherSpec, id: string, length: number): CipherSpec["options"] {
  const current = bytesEncodingOf(cipherCatalogueFor(spec.variant), spec.options, id);
  const produced = randomBytesValue(length, current);
  return {
    [id]: produced.value,
    // Written only when the request could not be honoured, so a field in Base64 stays in Base64.
    ...(produced.encoding === current ? {} : { [`${id}Encoding`]: produced.encoding }),
  };
}

/** Generates a fresh nonce of whatever length the spec's *current* mode requires. */
function withFreshNonce(spec: CipherSpec): CipherSpec {
  const mode = spec.variant === "aes" ? getAesMode(readMode(spec.options, "gcm")) : undefined;
  const needed = requiredNonceLength(spec.variant, mode, readParamSet(spec.options));
  if (needed === 0) return spec;
  return {
    ...spec,
    options: { ...spec.options, ...generatedInto(spec, OPTION_NONCE, needed) },
  };
}

export const RULE_CODES = [
  "C001",
  "C002",
  "C003",
  "C004",
  "C005",
  "C006",
  "C007",
  "C008",
  "C009",
  "C010",
  "C011",
  "C012",
  "C013",
] as const;

export const RULES: readonly LintRule<CipherSpec>[] = [
  {
    /**
     * ECB, which is the reason this family needs an `insecure` level at all.
     *
     * Level `error` would be defensible and is wrong: ECB is a real mode with real uses —
     * encrypting a single block, or implementing a construction that builds on it — and
     * blocking it would make this tool unable to do things people legitimately come here for.
     * `insecure` says do not use this for a message, which is the accurate claim.
     */
    code: "C001",
    check(spec) {
      if (spec.variant !== "aes") return [];
      const result = resolveCipher(spec);
      if (!result.ok || result.resolved.mode?.id !== "ecb") return [];

      return [
        {
          code: "C001",
          level: "insecure",
          message: "ECB encrypts identical plaintext blocks to identical ciphertext blocks.",
          detail:
            "Every 16-byte block is enciphered independently with no chaining, so the ciphertext preserves the structure of the plaintext — repeated blocks stay repeated, and an attacker can reorder or splice blocks freely. This is the mode behind the famous encrypted-penguin image. It is legitimate for a single block or as a building block inside another construction, and wrong for anything longer.",
          optionIds: [OPTION_MODE],
          fix: {
            label: "Switch to GCM",
            // Brings a nonce with it: GCM needs one and ECB has none, so setting only the
            // mode would leave a spec that cannot compute.
            apply: (s) => withModeAndValidNonce(s, "gcm"),
          },
        },
      ];
    },
  },
  {
    /**
     * Unauthenticated modes.
     *
     * A warning rather than `insecure`: CBC and CTR are correct primitives and appear in
     * plenty of sound protocols that add their own MAC. What is unsafe is using one bare and
     * assuming confidentiality implies integrity, which is what this says.
     */
    code: "C002",
    check(spec) {
      const result = resolveCipher(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (r.aead || r.mode?.id === "ecb" || r.toolId === "rc4") return [];

      /**
       * Name the mode wherever there is one. "DES encrypts but does not authenticate" would be true
       * of DES in every mode, and the reader is looking at one specific combination.
       */
      const tool = requireCipherTool(r.toolId);
      const name =
        r.toolId === "aes"
          ? `AES-${r.mode!.label}`
          : r.mode
            ? `${tool.label} in ${r.mode.label} mode`
            : tool.label;

      /**
       * XTS gets its own sentence, and the reason is the repo's rule against overclaiming.
       *
       * The generic text below says a flipped ciphertext bit flips the same plaintext bit -- true of
       * CBC's tail, CTR, OFB and CFB, and **false** of XTS, where a changed bit randomises its whole
       * 16-byte block. And the generic fix, "switch to GCM", is wrong advice rather than merely
       * incomplete: XTS is unauthenticated because a sector must encrypt to exactly a sector, leaving
       * nowhere to put a tag. Nobody can switch a disk format to GCM. What is worth saying is what XTS
       * does and does not promise, so there is no fix offered here at all.
       */
      if (r.mode?.id === "xts") {
        return [
          {
            code: "C002",
            level: "info",
            message: "XTS gives confidentiality with no integrity, by design.",
            detail:
              "An attacker who changes a byte of ciphertext cannot predict the plaintext that results, but nothing detects the change either — the 16-byte block simply decrypts to different random-looking data. That is not a flaw in the mode: a disk sector must encrypt to exactly one sector, so there is no room for an authentication tag anywhere in the format. It also means XTS leaks whether a sector's contents are unchanged, since the same plaintext at the same sector number always gives the same ciphertext. Full-disk encryption accepts both trade-offs; if you are encrypting a message rather than a sector, use AES-GCM instead.",
            optionIds: [OPTION_MODE],
          },
        ];
      }
      // A block cipher has no AEAD mode here, so the honest suggestion is a different cipher.
      const suggestion = r.toolId === "aes" || tool.block ? "AES-GCM" : "ChaCha20-Poly1305";

      return [
        {
          code: "C002",
          level: "warning",
          message: `${name} encrypts but does not authenticate.`,
          detail: `An attacker who cannot read the plaintext can still change it. Flipping a bit in ${name} ciphertext flips exactly the same bit in the decrypted plaintext, and nothing detects it — no error, no failure, just different data. Unless something else in your design supplies a MAC over this ciphertext, use ${suggestion}.`,
          optionIds: r.toolId === "aes" ? [OPTION_MODE] : [],
          ...(r.toolId === "aes"
            ? {
                fix: {
                  label: "Switch to GCM",
                  // CBC and CTR use a 16-byte nonce and GCM a 12-byte one, so the mode change
                  // has to resize it.
                  apply: (s) => withModeAndValidNonce(s, "gcm"),
                },
              }
            : {}),
        },
      ];
    },
  },
  {
    /**
     * Nonce reuse — the mistake this family cannot detect and must therefore always mention.
     *
     * The tool sees one computation at a time, so it has no way to know whether this nonce
     * has been used before. That is exactly why the note is unconditional for AEAD encryption
     * rather than conditional on something observable: the failure is invisible locally and
     * catastrophic globally.
     */
    code: "C003",
    check(spec) {
      const result = resolveCipher(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (r.direction !== "encrypt") return [];
      /*
       * A construction with no nonce cannot reuse one, and the check has to ask the *mode* rather than
       * look at the bytes.
       *
       * Reported: this fired on ECB and on the key-wrap modes, which have no IV field at all. The
       * cause is that switching mode leaves the previous mode's IV behind in the spec -- the field
       * stops rendering, so the value is invisible, but it is still stored and still decodes. So
       * `r.nonce.length` was 16 under ECB and the rule believed there was a nonce to reuse. The
       * resolver is right to ignore it (`acceptedNonceLengths` empty means both length checks skip),
       * which is exactly why nothing else caught this.
       *
       * `acceptedNonceLengths` is the same function the field, the Generate button and the resolver
       * use, so there is one answer to "does this take a nonce" rather than four.
       */
      if (acceptedNonceLengths(spec.variant, r.mode, readParamSet(spec.options)).length === 0) {
        return [];
      }
      if (r.nonce.length === 0) return [];
      // GCM-SIV was designed to survive this, so saying it would be wrong there.
      if (r.mode?.id === "gcm-siv") return [];
      /**
       * XTS's "nonce" is a sector number, and reusing it is not a mistake -- it is what the mode is
       * for. Rewriting sector 7 uses tweak 7 again every time. Telling someone never to reuse it
       * would be advice they cannot follow and that describes a different mode.
       */
      if (r.mode?.id === "xts") return [];

      const catastrophic = r.aead;
      return [
        {
          code: "C003",
          level: "info",
          message: `This nonce must never encrypt a second message under this key.`,
          detail: catastrophic
            ? "Two messages under one key and nonce reveal the XOR of their plaintexts and, for GCM and Poly1305, leak the authentication key — after which an attacker can forge arbitrary messages, not merely read these two. Generate a fresh nonce per message, or use AES-GCM-SIV, which is built to survive the mistake."
            : "Reusing a nonce means reusing the keystream, so the XOR of the two ciphertexts is the XOR of the two plaintexts. That is usually enough to recover both.",
          optionIds: [OPTION_NONCE],
          fix: {
            label: "Generate a fresh nonce",
            // Length from the spec passed in, not from `r.mode` captured above: another fix in
            // the same pass may already have changed the mode.
            apply: withFreshNonce,
          },
        },
      ];
    },
  },
  {
    code: "C004",
    check(spec) {
      const tool = requireCipherTool(spec.variant);
      if (tool.security !== "broken") return [];
      return [
        {
          code: "C004",
          level: "insecure",
          message: `${tool.label} is broken. Do not use it to protect anything.`,
          optionIds: [OPTION_KEY],
        },
      ];
    },
  },
  {
    /**
     * Everything `resolveCipher` refuses: a missing or wrong-length key, a nonce of the wrong
     * size for the chosen mode, an unparseable encoding.
     *
     * One rule rather than several, because the resolver already produces a message naming the
     * specific problem and the mode it applies to — a nonce-length rule of its own would have
     * to duplicate that logic to say the same thing. An earlier draft had exactly such a rule
     * and it could only return an empty array.
     */
    code: "C005",
    check(spec) {
      const result = resolveCipher(spec);
      if (result.ok) return [];
      return [
        {
          code: "C005",
          level: "error",
          message: result.problem,
          optionIds: [result.optionId],
        },
      ];
    },
  },
  {
    /**
     * A weak or semi-weak DES key.
     *
     * Reported, not refused, in keeping with the family's rule about preferring a warning: these are
     * legal keys, FIPS 46-3 does not forbid them, and OpenSSL encrypts with them happily, so a tool
     * that refused could not reproduce data that exists. What it costs the user is real though --
     * under one of the four weak keys the sixteen round keys are identical and DES becomes its own
     * inverse, so encrypting twice returns the plaintext.
     *
     * `isWeakDesKey` owns the list, on the same principle as C004 reading the posture: the knowledge
     * lives next to the algorithm, not in an id table here.
     */
    code: "C006",
    check(spec) {
      if (spec.variant !== "des" && spec.variant !== "3des") return [];
      const result = resolveCipher(spec);
      if (!result.ok) return [];
      /*
       * Nothing to say about a key that does not exist yet. Under a KDF the bytes appear inside
       * `computeCipher`, so this rule cannot see them -- and the chance a derivation lands on one of
       * DES's 64 weak keys is 2^-50. Staying quiet is the honest answer rather than a gap.
       */
      if (result.resolved.keySource !== "directinput") return [];

      const key = result.resolved.key;
      // 3DES is three 8-byte keys; any of them being weak weakens that stage of the EDE.
      const parts: Uint8Array[] = [];
      for (let i = 0; i + 8 <= key.length; i += 8) parts.push(key.subarray(i, i + 8));
      const weak = parts.filter((part) => isWeakDesKey(part));
      if (weak.length === 0) return [];

      const which =
        spec.variant === "des"
          ? "This key"
          : weak.length === parts.length
            ? "Every 8-byte key in this bundle"
            : `${weak.length} of the ${parts.length} 8-byte keys in this bundle`;

      return [
        {
          code: "C006",
          level: "warning",
          message: `${which} is one of DES's weak or semi-weak keys.`,
          detail:
            "The key schedule collapses: a weak key produces sixteen identical round keys, which makes DES its own inverse -- encrypt twice and you have the plaintext back. The twelve semi-weak pairs are similar, with each key of a pair decrypting the other's output. All 64 are legal keys and no standard forbids them, so this is a warning rather than a refusal; if you are choosing a key rather than reproducing existing data, choose another.",
          optionIds: [OPTION_KEY],
          fix: {
            label: "Generate a different key",
            // A fresh random key of the length the spec already uses. The weak keys number 64 out
            // of 2^56, so one draw is enough and a loop would only make the fix impure-looking.
            apply: (s) => {
              const resolved = resolveCipher(s);
              const bytes = resolved.ok ? resolved.resolved.key.length : 8;
              return {
                ...s,
                options: { ...s.options, ...generatedInto(s, OPTION_KEY, bytes) },
              };
            },
          },
        },
      ];
    },
  },
  {
    /**
     * How much may be encrypted under one key, for the parameter set actually selected.
     *
     * This exists because Simon and Speck became one tool each. Their ten sets span 32- to 128-bit
     * blocks, and the number that matters -- 256 kilobytes at one end, no practical limit at the
     * other -- differs by four orders of magnitude across a single dropdown. A fixed sentence on the
     * metadata cannot say it, and one that quoted the worst case would be wrong nine times out of
     * ten. That argument generalised: the per-tool `securityNote` this replaced for Simon and Speck
     * has since been removed everywhere, and rules like this one are what carry the caveats now.
     *
     * `info` rather than `warning`: at a 128-bit block there is nothing to act on, and where the
     * limit is low it is a property of the cipher the user chose deliberately, not a mistake. No
     * fix, for the same reason `C002` offers none for XTS -- the answer is a different cipher, and
     * moving the user to another tool would discard their input.
     */
    code: "C007",
    check(spec) {
      const result = resolveCipher(spec);
      if (!result.ok) return [];
      const set = result.resolved.paramSet;
      if (!set) return [];

      const blocks = 2 ** ((set.blockSize * 8) / 2);
      const bytes = blocks * set.blockSize;
      const readable =
        bytes >= 2 ** 30
          ? `${Math.round(bytes / 2 ** 30)} GB`
          : bytes >= 2 ** 20
            ? `${Math.round(bytes / 2 ** 20)} MB`
            : `${Math.round(bytes / 2 ** 10)} KB`;

      // Above a 64-bit block the figure is astronomical and saying it would be noise.
      if (set.blockSize > 8) return [];

      return [
        {
          code: "C007",
          level: "info",
          message: `${set.label} should not encrypt more than about ${readable} under one key.`,
          detail: `With a ${set.blockSize * 8}-bit block there are only ${set.blockSize * 8} bits of ciphertext-block space, so after roughly ${readable} two blocks are likely to come out identical -- and under CBC or CFB a repeat leaks the relationship between the two plaintext blocks behind it. Under CTR the keystream itself repeats, which is worse. Change the key before that point, or pick a parameter set with a wider block.`,
          optionIds: [OPTION_PARAM_SET],
        },
      ];
    },
  },
  {
    /**
     * An XTS key whose two halves are identical.
     *
     * XTS's key is two keys: the first enciphers the data, the second enciphers the tweak. Make them
     * equal and the two permutations become the same one, which is what the mode's security argument
     * rests on not being true -- the tweak stops being independent of the data. FIPS 140-3 forbids it
     * and OpenSSL refuses outright with `xts duplicated keys`, so this is also the case where someone
     * comparing our output against OpenSSL gets a value from us and an error from them, which is
     * worth saying in as many words.
     *
     * `insecure` rather than `error`, in keeping with the family's rule about preferring a warning:
     * the arithmetic is perfectly well defined and refusing would mean a tool that cannot reproduce
     * a value somebody is holding. That is the same call `C001` makes for ECB.
     *
     * The fix replaces the *second* half only. Regenerating both would discard a data key the user
     * may have arrived with, and the tweak key is the half that has to differ -- one draw is enough,
     * since two equal random halves is a 2^-128 event rather than something to loop over.
     */
    code: "C008",
    check(spec) {
      if (spec.variant !== "aes") return [];
      const result = resolveCipher(spec);
      if (!result.ok) return [];
      /*
       * The mode is read off the *resolved* spec rather than re-derived from the options. Two notions
       * of "the selected mode" is what put a 16-byte nonce under a 12-byte mode once already, and
       * here the resolver has to have succeeded anyway before there are key bytes to compare.
       */
      if (result.resolved.mode?.id !== "xts") return [];
      // Same reasoning as C006: a derived key has no bytes to compare until compute runs, and two
      // equal halves out of a KDF is a 2^-128 event rather than a mistake to warn about.
      if (result.resolved.keySource !== "directinput") return [];

      const key = result.resolved.key;
      const half = key.length / 2;
      // Guarded rather than assumed: the resolver has already enforced 32 or 64, and a rule that
      // divided an odd length would compare overlapping halves and report a phantom.
      if (!Number.isInteger(half) || half === 0) return [];
      const first = key.subarray(0, half);
      const second = key.subarray(half);
      if (first.some((byte, index) => byte !== second[index])) return [];

      return [
        {
          code: "C008",
          level: "insecure",
          message: `Both halves of this XTS key are the same ${half} bytes, so it is one key used twice.`,
          detail:
            'XTS needs two independent keys -- the first enciphers the data, the second enciphers the tweak. Identical halves make those two permutations the same, which removes the independence the mode\'s security argument depends on. FIPS 140-3 forbids the combination and OpenSSL refuses it outright with "xts duplicated keys", so this key will not round-trip against OpenSSL at all: you get a value here and an error there. It is reported rather than refused because the arithmetic is well defined, and a tool that blocked it could not reproduce output that already exists.',
          optionIds: [OPTION_KEY],
          fix: {
            label: "Randomise the tweak key",
            apply: (s) => {
              const resolved = resolveCipher(s);
              if (!resolved.ok) return s;
              /*
               * Rebuilt as *bytes* and re-spelled, rather than concatenated as hex.
               *
               * The string form pinned the field to hex, which is the bug this whole round is about:
               * a user working in Base64 pressed a fix and the selector moved. Splicing the second
               * half in place keeps the data key they arrived with.
               */
              const bytes = Uint8Array.from(resolved.resolved.key);
              const halfLen = Math.floor(bytes.length / 2);
              bytes.set(randomBytes(halfLen), halfLen);
              const current = bytesEncodingOf(
                cipherCatalogueFor(s.variant),
                s.options,
                OPTION_KEY,
              );
              const produced = encodeBytesValue(bytes, current);
              return {
                ...s,
                options: {
                  ...s.options,
                  [OPTION_KEY]: produced.value,
                  ...(produced.encoding === current ? {} : { keyEncoding: produced.encoding }),
                },
              };
            },
          },
        },
      ];
    },
  },
  {
    /**
     * Zero padding, whose removal cannot be trusted.
     *
     * Padding with zeros is unambiguous; *unpadding* is not. A plaintext genuinely ending in zero bytes
     * is indistinguishable from a padded one, so those bytes are stripped with the padding and nothing
     * in the ciphertext says it happened -- a short plaintext returned successfully, which is worse
     * than an error. Text is safe in practice and binary is not, which is exactly the distinction a
     * user cannot see from the output.
     *
     * Offered at all on the family's usual reasoning: refuse only what an algorithm genuinely cannot
     * do, and diagnose the rest. It is what CryptoJS's `ZeroPadding` does and what a good deal of
     * embedded protocol traffic uses, so a tool that omitted it could not reproduce those values.
     *
     * `warning` rather than `insecure`: nothing here is weaker cryptographically, and the risk is
     * losing data rather than losing confidentiality. The fix moves to PKCS#7, which is the same shape
     * of answer with none of the ambiguity -- and it is offered on *encrypt*, where switching is free,
     * rather than on decrypt, where the scheme has to match whatever produced the ciphertext.
     */
    code: "C009",
    check(spec) {
      const result = resolveCipher(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (!r.mode?.blockAligned || r.padding !== "zero") return [];
      return [
        {
          code: "C009",
          level: "warning",
          message: "Zero padding cannot be removed unambiguously.",
          detail:
            "The padding is zero bytes, so a plaintext that genuinely ends in zeros loses them on the way back -- they are stripped with the padding and nothing in the ciphertext distinguishes the two. Decryption reports success and returns a short plaintext, which is why this is worth saying before you rely on it. It is safe for text and unsafe for binary. Every other scheme here records its own length, so choose one of those unless you are reproducing something that already exists.",
          optionIds: [OPTION_PADDING],
          ...(r.direction === "encrypt"
            ? {
                fix: {
                  label: "Use PKCS#7",
                  apply: (s) => ({
                    ...s,
                    options: { ...s.options, [OPTION_PADDING]: "pkcs7" },
                  }),
                },
              }
            : {}),
        },
      ];
    },
  },
  {
    /**
     * ISO 10126, whose padding is random.
     *
     * `info` rather than a warning, because nothing is wrong: the scheme is well defined, decryption is
     * exact (the count is the last byte), and someone selecting it has chosen it. What is worth stating
     * is the one surprising consequence -- encrypting the same input twice gives different ciphertext,
     * so the Verify panel cannot confirm this tool's output against a second run of the same settings,
     * and a byte-for-byte comparison against another implementation will never match.
     *
     * No fix, for the reason `X003` and `P002` give: the setting is a deliberate choice and the useful
     * thing is to explain what it does, not to offer to undo it. Only reported when encrypting, since
     * decrypting an ISO 10126 ciphertext is entirely deterministic and the caveat does not apply.
     */
    code: "C010",
    check(spec) {
      const result = resolveCipher(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (!r.mode?.blockAligned || r.padding !== "iso10126") return [];
      if (r.direction !== "encrypt") return [];
      return [
        {
          code: "C010",
          level: "info",
          message: "ISO 10126 pads with random bytes, so this output is not reproducible.",
          detail:
            "The filler is random and only the final count byte is fixed, so encrypting the same input twice under the same key gives different ciphertext. That is the scheme working, not a fault -- and it means Verify cannot check this output against another run, and it will not match another implementation byte for byte even when both are correct. Decryption is unaffected. The scheme was withdrawn in 2007; PKCS#7 is what to use for anything new.",
          optionIds: [OPTION_PADDING],
        },
      ];
    },
  },
  {
    /**
     * EvpKDF, which is not a password KDF by any modern standard.
     *
     * One hash pass over an 8-byte salt is essentially free to brute-force, so a password behind it is
     * worth roughly what the password itself is worth and nothing more. `insecure` rather than a
     * warning, and deliberately not a refusal: it is the only way to read a file written by
     * `openssl enc -k` or by CryptoJS, and a tool that could not reproduce those would be useless for
     * the thing people actually arrive wanting. The KDF family's own `K009` says the same about the
     * standalone tool.
     *
     * The fix moves to PBKDF2 and is offered on **encrypt only**. On decrypt the KDF has to match
     * whatever produced the data, so "use something stronger" would be advice that breaks the task.
     */
    code: "C011",
    check(spec) {
      const result = resolveCipher(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (r.keySource !== "evpkdf") return [];
      return [
        {
          code: "C011",
          level: "insecure",
          message: "EvpKDF is not a password KDF.",
          detail:
            "EVP_BytesToKey applies its hash once per output block over an 8-byte salt, with no work factor worth the name -- so an attacker guessing passwords pays almost nothing per guess, and the key is only as strong as the password. It is here to read what already exists: openssl enc -k used it for about twenty years and CryptoJS still does. If you are choosing rather than reproducing, use PBKDF2 with a high iteration count, or scrypt or Argon2.",
          optionIds: [OPTION_KEY_SOURCE],
          ...(r.direction === "encrypt"
            ? {
                fix: {
                  label: "Use PBKDF2",
                  apply: (s) => ({
                    ...s,
                    options: { ...s.options, [OPTION_KEY_SOURCE]: "pbkdf2" },
                  }),
                },
              }
            : {}),
        },
      ];
    },
  },
  {
    /**
     * A PBKDF2 iteration count low enough to be worth saying so about.
     *
     * The threshold is OpenSSL's own default of 10,000 rather than OWASP's 600,000, and that is the
     * judgement here: 10,000 is what `openssl enc -pbkdf2` writes, so it is what reproducing a file
     * requires, and warning at the value the tool ships with would be warning about its own commonest
     * legitimate use -- which is how a checks panel stops being read. `F007` makes the same call about
     * 16 random bytes.
     *
     * So this fires *below* 10,000, where there is no interoperability argument left, and the detail
     * names the figure to aim for when nothing is being reproduced.
     */
    code: "C012",
    check(spec) {
      const result = resolveCipher(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (r.keySource !== "pbkdf2") return [];
      const { iterations } = r.keySourceParams;
      if (iterations >= 10_000) return [];
      return [
        {
          code: "C012",
          level: "warning",
          message: `${iterations.toLocaleString()} PBKDF2 iterations is below what any implementation defaults to.`,
          detail:
            "Iterations are the whole of PBKDF2's defence and the one cost an attacker also pays, so a low count makes the key worth about what the password is worth. openssl enc -pbkdf2 defaults to 10,000 and OWASP's figure for SHA-256 is 600,000 -- below the former there is not even an interoperability reason to stay. Both ends must use the same number, so raising it means re-encrypting rather than just changing this field.",
          optionIds: [OPTION_PBKDF2_ITERATIONS],
          fix: {
            label: "Use 600,000",
            apply: (s) => ({
              ...s,
              options: { ...s.options, [OPTION_PBKDF2_ITERATIONS]: 600_000 },
            }),
          },
        },
      ];
    },
  },
  {
    /**
     * The OpenSSL envelope with no salt entered, which is deliberately nondeterministic.
     *
     * `info` rather than a warning, because this is the correct and normal way to use it -- a fresh
     * random salt per message is what `openssl enc` does and what makes the envelope worth having. What
     * is worth stating is the one surprising consequence, which is the same one `C010` states for ISO
     * 10126: encrypting twice gives different output, so Verify cannot confirm this result against
     * another run and a byte comparison against another implementation will never match.
     *
     * No fix. Entering a salt to make it reproducible is a decision about what you are doing, not a
     * defect to repair, and the field's own detail explains it.
     */
    code: "C013",
    check(spec) {
      const result = resolveCipher(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (r.keySource === "directinput" || r.direction !== "encrypt") return [];
      if (r.keySourceParams.envelope !== "openssl") return [];
      if (r.keySourceParams.salt.length > 0) return [];
      return [
        {
          code: "C013",
          level: "info",
          message:
            "A fresh random salt is generated for each run, so this output is not reproducible.",
          detail:
            "That is what openssl enc does when you do not pass -S, and it is the right default: the salt travels in the Salted__ header, so a recipient needs only the password. It does mean encrypting the same input twice gives different ciphertext, that Verify cannot check this output against another run, and that comparing byte for byte against another tool will not match even when both are correct. Enter a salt if you need the same answer twice.",
          optionIds: [OPTION_KDF_SALT],
        },
      ];
    },
  },
];
