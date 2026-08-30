import { encodeHex, type ToolResult, type ToolResultField, type ToolStream } from "@ocs/engine";
import {
  aegisOperation,
  aesOperation,
  asconOperation,
  blockCipherOperation,
  chacha20Operation,
  chachaPolyOperation,
  cobblestoneOperation,
  createCobblestoneStream,
  fernetOperation,
  lwcOperation,
  rc4Operation,
  salsaOperation,
  streamCipherOperation,
  wideBlockCipherOperation,
  xchachaPolyOperation,
  xsalsaPolyOperation,
  type CipherOperation,
} from "./bindings";
import { requireCipherTool } from "./catalogue/tool-meta";
import {
  cipherBlockSize,
  requiresBlockAlignment,
  resolveCipher,
  type ResolvedCipher,
} from "./resolve";
import type { CipherSpec } from "./spec";
import { readBigUint64BE, type CobblestoneVariant, type PaddingScheme } from "@ocs/algos";
import { opensslHeader, type KeySource } from "@ocs/kdf/key-source";
import { concatBytes, randomBytes } from "@ocs/engine";

/**
 * The AEAD tag length, from the resolved spec.
 *
 * This was a `const TAG_LENGTH = 16` -- true of every AEAD here until AEGIS, which offers 128- and
 * 256-bit tags. Leaving the constant in place would have shown the wrong sixteen bytes in the "Tag"
 * field and rejected a legitimate 32-byte-tag ciphertext as too short.
 */
const tagLength = (r: ResolvedCipher): number => (r.tagLen > 0 ? r.tagLen : 16);

function operationFor(r: ResolvedCipher): CipherOperation {
  switch (r.toolId) {
    case "aes":
      return aesOperation(r.mode!.id, r.key, r.nonce, r.aad, tagLength(r), r.padding);
    case "ascon":
      return asconOperation(r.key, r.nonce, r.aad);
    case "aegis128l":
    case "aegis256":
      return aegisOperation(r.toolId, r.key, r.nonce, r.aad, r.tagLen);
    case "chacha20poly1305":
      return chachaPolyOperation(r.key, r.nonce, r.aad);
    case "xchacha20poly1305":
      return xchachaPolyOperation(r.key, r.nonce, r.aad);
    case "xsalsa20poly1305":
      return xsalsaPolyOperation(r.key, r.nonce, r.aad);
    case "xsalsa20":
      return salsaOperation(r.key, r.nonce, true);
    case "salsa20":
      return salsaOperation(r.key, r.nonce, false);
    case "fernet":
      return fernetOperation(r.key, {
        timestamp: r.timestamp,
        iv: r.nonce,
        ttl: r.ttl,
      });
    case "cobblestone":
      return cobblestoneOperation(r.key, {
        variant:
          (r.instance?.id as CobblestoneVariant) ??
          (r.key.length === 32 ? "cobblestone256" : "cobblestone128"),
        context: r.context,
        salt: r.salt,
      });
    case "des":
    case "3des":
    case "sm4":
    case "belt":
    case "camellia":
    case "aria":
    case "magma":
    case "blowfish":
    case "present":
    case "twofish":
    case "serpent":
    case "kuznyechik":
    case "seed":
    case "cast5":
    case "idea":
    case "rc2":
    // Simon and Speck were twenty ids matched by a regex above this switch. They are one tool each
    // now, so they sit with every other block cipher and the parameter set travels as an argument.
    case "speck":
    case "cham":
    case "simeck":
    case "skinny":
    case "simon":
    case "cast6":
    case "rc6":
    case "rc5":
    case "threefish":
    case "tea":
    case "xtea":
    case "xxtea":
    case "skipjack":
    case "lea":
    case "noekeon":
    case "shacal2":
    case "gost28147":
    case "misty1":
    case "hight":
    case "kasumi":
    case "khazad":
    case "anubis":
    case "saferp":
    case "sparx":
    case "chaskeylts":
    case "twine":
    case "led":
    case "prince":
    case "lblock":
    case "robin":
    case "robinstar":
    case "fantomas":
    case "roadrunner80":
    case "roadrunner128":
    case "lilliput":
    case "pride":
    case "piccolo":
    case "rectangle":
    case "clefia":
    case "mars":
    case "kalyna":
    case "keeloq":
    case "saturnin":
    case "shacal1":
    case "qarma":
    case "mantis":
    case "craft":
    case "midori":
      return blockCipherOperation(
        r.toolId,
        r.mode!.id,
        r.key,
        r.nonce,
        r.aad,
        tagLength(r),
        r.effectiveKeyBits,
        r.paramSet?.id,
        r.rc5Rounds,
        r.tweak,
        r.gostSbox,
        r.anubisVariant,
        r.padding,
      );
    case "chacha20":
    case "chacha12":
    case "chacha8":
    case "chacha20orig":
      return chacha20Operation(r.toolId, r.key, r.nonce, r.counter);
    /**
     * The stream ciphers that declare `stream` on their metadata.
     */
    case "zuc128":
    case "zuc256":
    case "hc128":
    case "hc256":
    case "grainv1":
    case "grain128":
    case "rabbit":
    case "trivium":
    case "sosemanuk":
    case "snow3g":
    case "snow-v":
    case "isaac":
    case "pcg64":
    case "xoshiro256":
    case "spritz":
    case "crypto1":
    case "dect-dsc":
    case "gea":
      return streamCipherOperation(r.toolId, r.key, r.nonce);
    case "adiantum":
    case "hctr2":
      return wideBlockCipherOperation(r.toolId, r.key, r.nonce);
    /**
     * The nine NIST lightweight finalists.
     *
     * Listed by id rather than dispatched on `tool.shape.tagLen` being set, for the same reason the
     * stream ciphers are: an exhaustive switch is what makes a tool added without a binding fail here
     * by name instead of falling through to `default` and reporting a tool id nobody recognises.
     */
    case "acorn":
    case "deoxysii":
    case "norx":
    case "xoodyak":
    case "ketjejr":
    case "morus":
    case "schwaemm":
    case "giftcofb":
    case "photonbeetle":
    case "romulus":
    case "elephant":
    case "isap":
    case "grain128aead":
    case "tinyjambu":
      return lwcOperation(r.toolId, r.key, r.nonce, r.aad, r.instance?.id);
    case "rc4":
      return rc4Operation(r.key, r.drop);
    default:
      throw new Error(`No operation for cipher tool: ${r.toolId}`);
  }
}

/** What to call each key source in a result field. */
const KEY_SOURCE_LABELS: Record<KeySource, string> = {
  directinput: "Direct Input",
  pbkdf2: "PBKDF2",
  evpkdf: "EvpKDF (EVP_BytesToKey)",
  hkdf: "HKDF",
  scrypt: "scrypt",
  argon2: "Argon2",
  bcryptpbkdf: "bcrypt-PBKDF",
};

/**
 * What to say beside the padding on the result, where the scheme has a consequence worth stating.
 *
 * PKCS#5's entry is the one that matters most and is the same device the checksum family's `sameAs`
 * uses: two schemes that produce one answer should say so, or somebody who tries both and gets
 * identical output is left suspecting the tool. The rest name a property of the output itself -- its
 * determinism, or what was stripped -- rather than advice, which is `C009` and `C010`'s job.
 */
const PADDING_HINTS: Partial<Record<PaddingScheme, string>> = {
  pkcs5:
    "Identical to PKCS#7 here, byte for byte. PKCS#5 is formally defined only for an 8-byte block and every library widens it by aliasing PKCS#7, so the two names are one scheme.",
  iso10126:
    "The filler is random, so encrypting the same input twice gives different ciphertext. Decryption is unaffected -- the count is the last byte.",
  zero: "Trailing zero bytes in the plaintext are indistinguishable from padding and are stripped.",
  none: "Nothing is added, so the input has to be a whole number of blocks.",
};

/**
 * What each scheme is called in a message, so a diagnostic can name the one actually selected.
 *
 * A `Record` whose miss is a compile error rather than a fall-through: this repo has shipped the other
 * arrangement six times, and the failure mode here would be a message confidently naming the wrong
 * scheme.
 */
const PADDING_LABELS: Record<PaddingScheme, string> = {
  pkcs7: "PKCS#7",
  pkcs5: "PKCS#5",
  iso7816: "ISO 9797-1 method 2",
  x923: "ANSI X9.23",
  iso10126: "ISO 10126",
  zero: "zero",
  none: "no",
};

/**
 * The key length to *name*, which is not always the key's own.
 *
 * `constructionLabel` is called by `describeSpec` and by half the lint rules, all of which run before
 * anything is derived -- and under a KDF `r.key` is empty until `computeCipher` fills it, so reading it
 * directly labelled every derived spec "AES-0-CBC". `derivedKeyLength` is the length the KDF will be
 * asked for and equals `key.length` under Custom, so one expression is right in both states.
 */
const keyBytesFor = (r: ResolvedCipher): number =>
  r.keySource === "directinput" ? r.key.length : r.derivedKeyLength;

/**
 * What to call the construction in the result panel.
 *
 * Derived from the tool's own metadata now, and it had to be: this began as a switch ending in
 * `default: return "ChaCha20-Poly1305"`, which was true of the five tools that existed then and
 * quietly became a lie the moment Salsa20 and DES were added -- a DES-CBC result labelled
 * "ChaCha20-Poly1305" with nothing failing. A label built from `requireCipherTool` cannot drift that
 * way, and the test asserting every tool produces its own name is what keeps it honest.
 */
export function constructionLabel(r: ResolvedCipher): string {
  const tool = requireCipherTool(r.toolId);

  /**
   * XTS is named for the cipher it uses, not for the key string it is handed.
   *
   * A 32-byte XTS key is XTS-AES-**128**: two 128-bit keys. `AES-256-XTS` would be the arithmetic
   * this function does everywhere else and a wrong answer here, since there is no 256-bit AES in a
   * 32-byte XTS key at all. The name is also written the way the standards write it -- SP 800-38E and
   * every disk-encryption tool say "XTS-AES-128", not "AES-128-XTS".
   */
  if (r.toolId === "aes" && r.mode!.id === "xts") return `XTS-AES-${(keyBytesFor(r) / 2) * 8}`;
  if (r.toolId === "aes") return `AES-${keyBytesFor(r) * 8}-${r.mode!.label}`;
  if (r.toolId === "rc4") return r.drop > 0 ? `RC4-drop${r.drop}` : "RC4";
  // OpenSSL's own names for the two 3DES key sizes, because that is what someone comparing output
  // will have typed: `des-ede3-cbc` for three keys, `des-ede-cbc` for two.
  if (r.toolId === "3des") {
    return `${keyBytesFor(r) === 24 ? "3DES-EDE3" : "3DES-EDE"}-${r.mode!.label}`;
  }

  if (tool.block) {
    /**
     * Name the key size wherever there is a choice of one -- a list of several, or a range.
     *
     * The range case is Blowfish, and it is the one where the size matters most: a 4-byte key and a
     * 56-byte key are both legal, and a result labelled plain "Blowfish" would leave someone
     * comparing output with no idea which they had used.
     */
    /**
     * A parameter set names itself, because its label already carries both numbers.
     *
     * "Speck48/96-CBC" is what the paper calls it; "Speck-96-CBC" would name the key and lose the
     * block, which is the half with a practical consequence. There is a test asserting every tool --
     * and now every parameter set -- produces a distinct construction name.
     */
    if (r.paramSet) return `${r.paramSet.label}-${r.mode!.label}`;
    const varies = tool.block.keyLengths.length > 1 || tool.block.keyRange !== undefined;
    return varies
      ? `${tool.label}-${keyBytesFor(r) * 8}-${r.mode!.label}`
      : `${tool.label}-${r.mode!.label}`;
  }

  /**
   * A shaped tool names its *instance*, because the instance is the construction.
   *
   * "Schwaemm" is a family; "Schwaemm256-128" is a function with a 256-bit nonce and a 128-bit key, and
   * a result panel that said only the former would leave someone comparing output unable to tell which
   * of four they had run. Same reasoning as `paramSet` above.
   */
  if (r.instance) return r.instance.label;

  // The stream ciphers. "(raw)" is a disambiguator for the sidebar, not part of the name.
  return tool.label.replace(" (raw)", "");
}

function fields(r: ResolvedCipher, output: Uint8Array): ToolResultField[] {
  const out: ToolResultField[] = [{ label: "Construction", value: constructionLabel(r) }];

  /*
   * The padding, on the two modes that have any.
   *
   * Worth a row rather than being left implicit: it is the one setting here that changes the *length*
   * of the output as well as its content, and someone comparing a ciphertext against another tool's
   * needs to know which scheme produced the difference. Omitted for every other mode, where the
   * control is not shown and the value would be a statement about nothing.
   */
  /*
   * What derived the key, and the key itself.
   *
   * Shown rather than hidden: the whole reason someone reaches for this is that another tool wants the
   * key bytes, and having derived them here they should not have to run the KDF tool separately to see
   * them. It is a secret, so it is in the result rather than in a field the share link would carry.
   *
   * Only when a KDF actually ran -- `key` is empty under Custom's own resolve and this is called from
   * `computeCipher`, after the derivation, so the bytes are real by the time it renders.
   */
  if (r.keySource !== "directinput" && r.key.length > 0) {
    out.push({
      label: "Derived key",
      value: encodeHex(r.key),
      hint: `${KEY_SOURCE_LABELS[r.keySource]}, ${r.key.length} bytes.${
        r.derivedIvLength > 0 ? " The IV below came from the same derivation." : ""
      }`,
    });
    if (r.derivedIvLength > 0 && r.nonce.length > 0) {
      out.push({
        label: "Derived IV",
        value: encodeHex(r.nonce),
        hint: "Taken from the bytes after the key, which is how openssl enc and CryptoJS split them.",
      });
    }
  }

  if (r.mode?.blockAligned) {
    out.push({
      label: "Padding",
      value: PADDING_LABELS[r.padding],
      ...(PADDING_HINTS[r.padding] ? { hint: PADDING_HINTS[r.padding]! } : {}),
    });
  }

  const tagLen = tagLength(r);
  if (r.aead && r.direction === "encrypt" && output.length >= tagLen) {
    /**
     * The tag is shown separately as well as being part of the output.
     *
     * noble appends it to the ciphertext, which is what every wire format does and what
     * decrypt expects back, so the primary output is the whole thing. But someone
     * implementing against a spec that carries the tag in its own field needs to see where
     * it starts, and counting sixteen bytes back from the end of a hex string by eye is
     * exactly the sort of thing to get wrong.
     */
    const split = output.length - tagLen;
    out.push({
      label: "Tag",
      value: encodeHex(output.subarray(split)),
      hint: `The last ${tagLen} bytes of the output above, already included. Shown separately only for protocols that transmit it in its own field.`,
    });
    out.push({ label: "Ciphertext without tag", value: encodeHex(output.subarray(0, split)) });
  }

  if (r.aead && r.direction === "decrypt") {
    out.push({
      label: "Authentication",
      value: "Tag verified",
      hint: "The ciphertext and any additional data are exactly what was encrypted. A single altered byte would have failed this.",
    });
  }

  if (r.aad.length > 0) {
    out.push({
      label: "Additional data",
      value: `${r.aad.length} bytes`,
      hint: "Authenticated, not encrypted. Decryption needs it supplied identically.",
    });
  }

  if (r.nonce.length > 0) {
    out.push({
      label: r.toolId === "aes" ? r.mode!.nonceLabel : "Nonce",
      value: encodeHex(r.nonce),
      /**
       * XTS gets its own sentence, because the general one is the opposite of the truth there.
       *
       * "Never reuse it under this key" is right for every nonce in this family and wrong for a data
       * unit number, where reuse is the design: rewriting sector 7 uses tweak 7 again every time.
       * Telling a user encrypting a disk never to reuse it would be advice they cannot follow.
       */
      hint:
        r.mode?.id === "xts"
          ? "The sector or block index, not a nonce. The same data unit number is used every time that sector is rewritten -- which is why XTS leaks whether a sector's contents changed, and why it is not secret."
          : "Not secret. Store or transmit it with the ciphertext, and never reuse it under this key.",
    });
  }

  if (r.toolId === "fernet") {
    if (r.direction === "encrypt" && output.length >= 57) {
      const ts = Number(readBigUint64BE(output, 1));
      const iv = output.slice(9, 25);
      const hmacVal = output.slice(output.length - 32);
      out.push({
        label: "Token timestamp",
        value: `${new Date(ts * 1000).toISOString().replace(".000Z", "Z")} (${ts})`,
        hint: "Recorded in the token header as a 64-bit big-endian integer.",
      });
      out.push({
        label: "Token IV",
        value: encodeHex(iv),
        hint: "16-byte initialization vector for AES-128-CBC.",
      });
      out.push({
        label: "HMAC",
        value: encodeHex(hmacVal),
        hint: "HMAC-SHA256 over Version (0x80) || Timestamp || IV || Ciphertext.",
      });
    }
  }

  if (r.toolId === "cobblestone") {
    if (r.direction === "encrypt" && output.length >= 56) {
      const salt = output.slice(0, 24);
      const commitment = output.slice(24, 56);
      const payloadLen = output.length - 56;
      const chunks = Math.floor(payloadLen / 16400) + 1;
      out.push({
        label: "Salt",
        value: encodeHex(salt),
        hint: "24-byte per-message salt in header.",
      });
      out.push({
        label: "Key commitment",
        value: encodeHex(commitment),
        hint: "32-byte HKDF commitment binding key, salt, and context.",
      });
      out.push({
        label: "Chunk count",
        value: `${chunks} chunks`,
        hint: "16 KiB chunks with short final chunk framing.",
      });
    }
  }

  return out;
}

export async function computeCipher(spec: CipherSpec, input: Uint8Array): Promise<ToolResult> {
  const result = resolveCipher(spec);
  // A half-filled key or nonce is the normal state of this form, so it comes back as a
  // rendered result rather than an exception.
  if (!result.ok) return { error: result.problem };

  let r = result.resolved;
  /**
   * The bytes the cipher actually sees.
   *
   * Equal to `input` except when decrypting out of an OpenSSL envelope, where the first sixteen bytes
   * are the header rather than ciphertext. Every length check below reads this rather than `input`, so
   * a message about block alignment counts the ciphertext and not the framing.
   */
  let payload = input;
  /** Set only for the OpenSSL envelope on encrypt, so the header can be prepended to the result. */
  let envelopeSalt: Uint8Array | undefined;

  /**
   * The key, and possibly the IV, from a password.
   *
   * Derived **here** rather than in the resolver, and that placement is the whole design: the resolver
   * is synchronous with fourteen callers, so Argon2 at 64 MiB would run a dozen times per keystroke
   * behind the form. This runs once, in an already-async function, inside the compute worker.
   *
   * The module is a dynamic import for the same reason FSB's table is: nobody opening AES should
   * download Argon2. `computeCipher` being async is what makes that free -- no `prepare` hook, no
   * synchronous accessor to guard.
   */
  if (r.keySource !== "directinput") {
    const kdf = await import("@ocs/kdf/key-source");
    const params = { ...r.keySourceParams };

    /*
     * OpenSSL's envelope decides where the salt comes from, and the two directions differ.
     *
     * Decrypting, the salt is in the input and the Salt field is ignored -- reading it from the field
     * instead would silently derive the wrong key from a correct file. Encrypting, an empty field
     * means a fresh random salt, which is what `openssl enc` does by default and is deliberately
     * nondeterministic; a filled one is honoured, which is `openssl enc -S` and is what makes a value
     * reproducible.
     */
    if (params.envelope === "openssl") {
      if (r.direction === "decrypt") {
        const read = kdf.readOpensslEnvelope(input);
        if (!read.ok) return { error: read.problem };
        params.salt = read.salt;
        payload = read.body;
      } else if (params.salt.length === 0) {
        envelopeSalt = randomBytes(kdf.OPENSSL_SALT_BYTES);
        params.salt = envelopeSalt;
      } else {
        envelopeSalt = params.salt.slice(0, kdf.OPENSSL_SALT_BYTES);
      }
    }

    let derived: Uint8Array;
    try {
      derived = kdf.deriveKeySourceBytes(params, r.derivedKeyLength + r.derivedIvLength);
    } catch (error) {
      // scrypt and Argon2 refuse parameter combinations the sync validator cannot fully check --
      // a memory figure the host cannot allocate, for one. Rendered rather than thrown.
      return { error: error instanceof Error ? error.message : String(error) };
    }

    /*
     * Key first, then the IV. Verified against the installed OpenSSL's own `enc -P` output for both
     * PBKDF2 and EvpKDF rather than against a round trip, which cannot see the two swapped.
     */
    r = {
      ...r,
      keySourceParams: params,
      key: derived.subarray(0, r.derivedKeyLength),
      ...(r.derivedIvLength > 0
        ? {
            nonce: derived.subarray(r.derivedKeyLength, r.derivedKeyLength + r.derivedIvLength),
          }
        : {}),
    };
  }

  /**
   * Length checks before calling the cipher, so the message names the actual problem.
   *
   * The two most common mistakes when decrypting are pasting hex into the Base64 box and
   * forgetting that the tag is part of the ciphertext. Both produce a library error about
   * padding or an invalid tag, which tells the user nothing about what to change.
   */
  if (r.direction === "decrypt" && requiresBlockAlignment(r)) {
    const blockSize = cipherBlockSize(r);
    if (payload.length === 0 || payload.length % blockSize !== 0) {
      return {
        error: `${constructionLabel(r)} ciphertext must be a whole number of ${blockSize}-byte blocks; this input is ${payload.length} bytes. Check the input encoding — hex pasted into the Base64 box is the usual cause.`,
      };
    }
  }

  /**
   * Key wrap's input rules, checked here rather than left to throw.
   *
   * RFC 3394 wraps whole 8-byte semiblocks and needs at least two of them; RFC 5649 pads, so it takes
   * any non-empty length. noble enforces both, but its message is about its own internals -- and the
   * situation is one a user reaches by pasting a key of the wrong length, which deserves a sentence
   * naming the rule.
   */
  if (r.mode?.minInputLen !== undefined && payload.length < r.mode.minInputLen) {
    return {
      error:
        r.mode.id === "xts"
          ? // XTS steals ciphertext instead of padding, so a sub-block input has nothing to steal
            // from. Saying only "needs 16 bytes" would read as an arbitrary limit.
            `${constructionLabel(r)} needs at least 16 bytes: a short final block borrows the tail of the preceding ciphertext block, and with fewer than 16 bytes there is no preceding block. This input is ${payload.length}.`
          : `${constructionLabel(r)} needs at least ${r.mode.minInputLen} bytes; this input is ${payload.length}.`,
    };
  }
  if (
    r.mode?.inputMultiple !== undefined &&
    r.direction === "encrypt" &&
    payload.length % r.mode.inputMultiple !== 0
  ) {
    return {
      error: `${constructionLabel(r)} wraps whole ${r.mode.inputMultiple}-byte units; this input is ${payload.length} bytes. Use the padded form (RFC 5649) for arbitrary lengths.`,
    };
  }

  if (r.direction === "decrypt" && r.aead && payload.length < tagLength(r)) {
    return {
      error: `Too short to contain a ${tagLength(r)}-byte authentication tag; this input is ${payload.length} bytes. The tag belongs appended to the ciphertext.`,
    };
  }

  try {
    const operation = operationFor(r);
    const output =
      r.direction === "encrypt" ? operation.encrypt(payload) : operation.decrypt(payload);
    /*
     * The envelope is prepended last, to the finished ciphertext, so nothing between here and the
     * cipher has to know about it. `fields` is handed the ciphertext without the header for the same
     * reason: the tag it splits off is at the end of the ciphertext, not of the framing.
     */
    const framed = envelopeSalt ? concatBytes(opensslHeader(envelopeSalt), output) : output;
    return { bytes: framed, fields: fields(r, r.direction === "encrypt" ? output : payload) };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    /**
     * A failed tag is the most important error this family reports, and the library's own
     * message for it is not something a user can act on. Rewriting it earns the special
     * case: it is not a malfunction but the cipher working, and which of three things went
     * wrong is what the user needs to know.
     */
    if (r.direction === "decrypt" && r.aead && /tag|authentic/i.test(message)) {
      return {
        error:
          "The authentication tag did not verify. Either the ciphertext or the additional data has been altered, or the key, nonce or AAD does not match what encrypted it. No plaintext is returned — that is the guarantee, not a limitation.",
      };
    }

    /**
     * Any failure decrypting a block-aligned mode.
     *
     * Matched on the *situation* rather than on the message text. noble's actual error here is
     * `aes: bad decrypt`, which contains neither "padding" nor anything else a user could act
     * on — an earlier version of this branch pattern-matched for "padding" and therefore never
     * fired, letting that string through verbatim. The situation is unambiguous: for CBC or ECB
     * on decrypt there is essentially one way to fail, and it is worth explaining properly.
     */
    if (r.direction === "decrypt" && requiresBlockAlignment(r) && r.padding !== "none") {
      /*
       * Named from the *selected* scheme rather than fixed at "PKCS#7", which it was until the Padding
       * control existed -- a sentence written once cannot follow a dropdown, which is the same defect
       * the removed `securityNote` field kept producing.
       *
       * And it stands aside for `none`: nothing is stripped there, so a failure is the alignment check
       * or the cipher itself, and this branch would otherwise replace a precise message with a lecture
       * about padding that does not apply.
       */
      return {
        error: `Could not decrypt: the ${PADDING_LABELS[r.padding]} padding is invalid. That almost always means the wrong key or IV rather than corrupt data — and CBC gives no way to tell those two apart, which is precisely what padding-oracle attacks exploit.`,
      };
    }

    return { error: message };
  }
}

/**
 * Creates an incremental streaming tool stream for ciphers that support streaming (e.g. Cobblestone).
 */
export function createCipherStream(spec: CipherSpec): ToolStream {
  const result = resolveCipher(spec);
  if (!result.ok) {
    return {
      update: () => {},
      finish: () => ({ error: result.problem }),
    };
  }
  const r = result.resolved;
  if (r.toolId === "cobblestone") {
    const stream = createCobblestoneStream(r.key, r.direction, {
      variant:
        (r.instance?.id as CobblestoneVariant) ??
        (r.key.length === 32 ? "cobblestone256" : "cobblestone128"),
      context: r.context,
      salt: r.salt,
    });
    const chunks: Uint8Array[] = [];
    return {
      update(chunk: Uint8Array) {
        const out = stream.update(chunk);
        if (out.length > 0) chunks.push(out);
      },
      finish(): ToolResult {
        try {
          const final = stream.finalize();
          if (final.length > 0) chunks.push(final);
          const totalLen = chunks.reduce((a, b) => a + b.length, 0);
          const combined = new Uint8Array(totalLen);
          let offset = 0;
          for (const c of chunks) {
            combined.set(c, offset);
            offset += c.length;
          }
          return {
            bytes: combined,
            fields: fields(r, combined),
          };
        } catch (err) {
          return { error: err instanceof Error ? err.message : String(err) };
        }
      },
    };
  }
  throw new Error(`Streaming is not supported for cipher tool "${r.toolId}".`);
}
