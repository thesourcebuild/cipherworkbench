import { describe, expect, it } from "vitest";
import {
  LOSSLESS_BYTES_ENCODINGS,
  randomValueEntropyBits,
  bytesEncodingOf,
  decodeBytesValue,
  encodeBytesValue,
  randomBytesValue,
} from "@ocs/engine";
import type { BytesEncoding } from "@ocs/contracts/encoding";
import { OPTION_KEY, OPTION_MODE, OPTION_NONCE } from "@ocs/cipher";
import { cipherCatalogueFor, createSpec, lint } from "@ocs/cipher/definition";

/**
 * Generate writes into the encoding the field is already set to.
 *
 * The reported bug: pressing Generate set the companion encoding selector to `hex` every time, so a
 * field being filled in Base64 had the selector moved out from under it. It was one call site shared by
 * every `bytes` option in the app -- key, IV, nonce, tweak, salt -- and by six lint fixes that generate
 * a value, which is why it was worth a helper rather than five edits.
 */
const ALL: BytesEncoding[] = ["hex", "base64", "base64url", "utf-8", "latin1"];

describe("generated values keep the field's encoding", () => {
  /**
   * Generate keeps **every** encoding, which is the second half of this fix.
   *
   * The first version kept the three that round-trip and moved `utf-8` and `latin1` to hex, on the
   * grounds that most byte strings are not valid UTF-8. True, and the wrong conclusion -- it was
   * reported as the same bug all over again: selecting Text (UTF-8) and pressing Generate moved the
   * selector. What a text encoding wants is a random *readable* key, and printable ASCII is one byte
   * per character, so N characters decode to exactly the N bytes the field asked for.
   */
  it("keeps every encoding, and always yields the requested number of bytes", () => {
    for (const encoding of ALL) {
      const produced = randomBytesValue(32, encoding);
      expect(produced.encoding, `${encoding} must be kept`).toBe(encoding);

      /*
       * And whatever it wrote decodes to 32 bytes *under the encoding it reported*. A value written as
       * hex while the selector still said base64 would decode to something else entirely -- silently a
       * different key, which is the failure being prevented.
       */
      const decoded = decodeBytesValue(produced.value, produced.encoding);
      expect(decoded.ok && decoded.bytes.length, encoding).toBe(32);
    }
  });

  /**
   * A text key is printable ASCII, drawn without bias, and the entropy is stated rather than implied.
   *
   * The bias check is the load-bearing one: `randomBelow` rejects instead of taking a modulo, and a
   * modulo over 94 would favour the first 68 characters by about 1.4% -- which would make the bit
   * figure the button quotes a claim it cannot support. Same reasoning `tests/random.test.ts` records
   * for the samplers.
   */
  it("generates printable ASCII for a text encoding, unbiased", () => {
    expect(randomValueEntropyBits(32, "hex")).toBe(256);
    expect(randomValueEntropyBits(32, "utf-8"), "log2(94) per byte, not 8").toBe(210);

    const counts = new Map<string, number>();
    for (let i = 0; i < 400; i++) {
      for (const character of randomBytesValue(32, "utf-8").value) {
        const code = character.charCodeAt(0);
        // Printable, and never a space: a leading or trailing one is invisible in a text field and
        // would silently change the key.
        expect(code).toBeGreaterThanOrEqual(0x21);
        expect(code).toBeLessThanOrEqual(0x7e);
        counts.set(character, (counts.get(character) ?? 0) + 1);
      }
    }
    const seen = [...counts.values()];
    expect(counts.size, "every printable character must be reachable").toBe(94);
    // 12,800 draws over 94 characters is ~136 each. The band is wide enough not to flake and narrow
    // enough that a modulo's skew would fail it.
    expect(Math.min(...seen)).toBeGreaterThan(80);
    expect(Math.max(...seen)).toBeLessThan(200);
  });

  /**
   * The exported list and the exhaustive `switch` inside `encodeBytesValue` must agree.
   *
   * The list exists so the button's tooltip can promise what pressing it will do; a tooltip that said
   * the encoding would be kept and then changed it would be worse than the original bug. Asserted
   * rather than kept in step by hand, and the list is exported from the engine rather than copied into
   * the form -- a mirror across packages is the shape this repo keeps finding.
   */
  /**
   * `LOSSLESS_BYTES_ENCODINGS` is about `encodeBytesValue`, not about Generate.
   *
   * The two questions are different and the lists are now different: this one asks whether *arbitrary*
   * bytes survive a round trip, which `utf-8` fails, and it is what `C008`'s fix needs -- that fix has
   * an XTS key in hand and cannot make it readable. Generate has no such constraint because it chooses
   * the bytes.
   */
  it("the lossless list matches what encodeBytesValue actually keeps", () => {
    const bytes = Uint8Array.from({ length: 16 }, (_, i) => i * 17);
    const kept = ALL.filter((e) => encodeBytesValue(bytes, e).encoding === e);
    expect(kept).toEqual([...LOSSLESS_BYTES_ENCODINGS]);
  });

  it("round-trips arbitrary bytes through every kept encoding", () => {
    // 0x00 and 0xff included deliberately: a codec that mishandled either would still pass over
    // mid-range bytes, and a key is exactly where that matters.
    const bytes = Uint8Array.from([
      0,
      255,
      1,
      254,
      ...Array.from({ length: 28 }, (_, i) => i * 9),
    ]);
    for (const encoding of LOSSLESS_BYTES_ENCODINGS) {
      const produced = encodeBytesValue(bytes, encoding);
      const back = decodeBytesValue(produced.value, encoding);
      expect(back.ok && Buffer.from(back.bytes).toString("hex"), encoding).toBe(
        Buffer.from(bytes).toString("hex"),
      );
    }
  });

  /**
   * And the lint fixes that generate a value do the same thing, which is the half a helper alone does
   * not guarantee: each fix has to *read* the current encoding rather than assume hex.
   */
  it("a fix that regenerates a nonce leaves a Base64 field in Base64", () => {
    const base = createSpec({ variant: "aes" });
    const spec = {
      ...base,
      options: {
        ...base.options,
        [OPTION_MODE]: "gcm",
        [OPTION_KEY]: "11".repeat(32),
        keyEncoding: "hex",
        /*
         * A *valid* 12-byte GCM nonce written in Base64, which is what C003 offers to regenerate.
         *
         * The first version of this used a wrong-length nonce, on the assumption that the length rule
         * would offer the fix. It does not: C005 fires only when `resolveCipher` fails and carries no
         * fix at all, and every rule that does carry one bails on an unresolvable spec. So the case to
         * test is the one that actually exists -- C003's "Generate a fresh nonce" on a spec that
         * resolves.
         */
        [OPTION_NONCE]: "AAAAAAAAAAAAAAAA",
        nonceEncoding: "base64",
      },
    };
    expect(bytesEncodingOf(cipherCatalogueFor("aes"), spec.options, OPTION_NONCE)).toBe(
      "base64",
    );

    const withFix = lint(spec).diagnostics.find(
      (d) => d.fix && d.optionIds?.includes(OPTION_NONCE),
    );
    expect(withFix, "some rule should offer to fix the nonce").toBeDefined();
    const fixed = withFix!.fix!.apply(spec);
    expect(fixed.options.nonceEncoding, "the fix must not move the selector back to hex").toBe(
      "base64",
    );
    const decoded = decodeBytesValue(String(fixed.options[OPTION_NONCE]), "base64");
    expect(decoded.ok && decoded.bytes.length, "and it must be a legal GCM nonce").toBe(12);
  });
});
