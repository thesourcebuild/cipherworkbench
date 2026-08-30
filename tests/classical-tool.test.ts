import { describe, expect, it } from "vitest";

import {
  CLASSICAL_MANIFESTS,
  CLASSICAL_TOOLS,
  OPTION_DIRECTION,
  OPTION_LETTER_CASE,
  OPTION_SHIFT,
  OPTION_SHOW_ALL,
  type ClassicalSpec,
} from "../packages/tools/classical/src/index";
import {
  ALL_CLASSICAL_OPTIONS,
  applyAllFixes,
  classicalToolDefinition,
  createSpec,
  describeSpec,
  lint,
  RULE_CODES,
  samplesFor,
  __testing,
} from "../packages/tools/classical/src/definition";
import { isAvailableOn, validateCatalogue } from "../packages/cipher-engine/src/index";

/**
 * The `classical` family, and the division of labour with `tests/algos-caesar.test.ts`.
 *
 * That file owns the cipher: the published examples, the negative modulus, which characters are in the
 * alphabet. None of it belongs here. What belongs here is everything between the option catalogue and
 * the rendered panel -- that the shift control reaches the cipher at all, that the brute-force table
 * is the table it claims to be, that each lint rule fires and its fix silences it, and that the family
 * carries the manifest flags its shape requires. That is the same split the cipher family uses, and it
 * is what stops a green suite over a control wired to nothing.
 */

const bytes = (text: string) => new TextEncoder().encode(text);

function specFor(options: ClassicalSpec["options"] = {}): ClassicalSpec {
  const base = createSpec({ variant: "caesar" });
  return { ...base, options: { ...base.options, ...options } };
}

async function run(options: ClassicalSpec["options"], input: string) {
  return classicalToolDefinition("caesar").compute(specFor(options), bytes(input));
}

async function textOf(options: ClassicalSpec["options"], input: string) {
  const result = await run(options, input);
  expect(result.error, `refused: ${result.error}`).toBeUndefined();
  return result.text!;
}

describe("the family's shape", () => {
  it("registers classical tools, text-output, both directions, not streaming", () => {
    expect(CLASSICAL_MANIFESTS.length).toBeGreaterThanOrEqual(1);
    const manifest = CLASSICAL_MANIFESTS.find((m) => m.id === "caesar")!;
    expect(manifest).toBeDefined();
    expect(manifest.id).toBe("caesar");
    expect(manifest.family).toBe("classical");
    /**
     * One encoding, which is what hides the Result panel's selector.
     *
     * The output is letters. Offering to spell it as Base64 would invite exactly the confusion this
     * cipher attracts -- that it could be applied to bytes or to hex -- and would be a control that
     * does nothing useful either way.
     */
    expect(manifest.outputEncodings).toEqual(["utf-8"]);
    expect(manifest.directions).toEqual(["forward", "inverse"]);
    expect(manifest.streaming).toBe(false);
    expect(manifest.readsInput).toBe(true);
    // A ciphertext is exactly the kind of value somebody already has, so Verify earns its place.
    expect(manifest.supportsVerify).toBe(true);
  });

  /**
   * `broken`, and the posture is a judgement worth pinning rather than leaving to drift.
   *
   * Not `not-encryption`, which the encoding and format families carry: Base64 makes no claim to hide
   * anything, whereas this is a cipher with a key that is meant to. It has 26 keys, so `broken` is the
   * strongest and most honest word the badge can carry -- and `X001` is what says it in a sentence.
   */
  it("declares itself broken", () => {
    expect(CLASSICAL_MANIFESTS[0]!.security).toBe("broken");
  });

  it("is findable under every name it is looked for", () => {
    const tags = CLASSICAL_TOOLS[0]!.tags;
    for (const term of ["caesar", "rot13", "shift cipher", "substitution", "cryptogram"]) {
      expect(tags, term).toContain(term);
    }
    /*
     * ROT47 is deliberately absent. It shifts 94 printable ASCII characters, which is a different
     * alphabet and therefore a different cipher -- listing it would make the search find this tool and
     * disappoint.
     */
    expect(tags).not.toContain("rot47");
  });

  it("has a clean catalogue and exposes only options that exist", () => {
    const definition = classicalToolDefinition("caesar");
    expect(validateCatalogue(definition.catalogue.options)).toEqual([]);
    const known = new Set(ALL_CLASSICAL_OPTIONS.map((option) => option.id));
    for (const id of CLASSICAL_TOOLS[0]!.exposes) expect(known, id).toContain(id);
    // Seeding a value for an option the tool does not render would be dead weight in every share link.
    for (const id of Object.keys(CLASSICAL_TOOLS[0]!.defaults)) {
      expect(CLASSICAL_TOOLS[0]!.exposes, id).toContain(id);
    }
  });

  /**
   * No option stranded, which is the gate the MAC family earned the hard way.
   *
   * `variantTag` here returns the direction and nothing is gated on it yet -- but an `availableOn`
   * added later would be silently unreachable if the tag stopped being produced, which is exactly how
   * four MAC controls came to render nowhere with a green suite.
   */
  it("leaves no option unreachable under its own default spec", () => {
    const definition = classicalToolDefinition("caesar");
    const tag = definition.variantTag?.(specFor());
    const unreachable = definition.catalogue.options
      .filter((option) => !isAvailableOn(option, tag))
      .map((option) => option.id);
    expect(unreachable).toEqual([]);
  });

  it("refuses an unknown tool id by name", () => {
    // `vigenere` rather than a number up from the newest thing: a fictional id that stays fictional.
    expect(() => classicalToolDefinition("vigenere")).toThrow(/Unknown classical tool: vigenere/);
  });
});

describe("the Caesar tool", () => {
  it("computes the examples the cipher is described by", async () => {
    expect(await textOf({ [OPTION_SHIFT]: 3 }, "HELLO")).toBe("KHOOR");
    expect(await textOf({ [OPTION_SHIFT]: 5 }, "HELLO")).toBe("MJQQT");
  });

  it("decrypts with the same shift in the other direction", async () => {
    expect(
      await textOf({ [OPTION_SHIFT]: 3, [OPTION_DIRECTION]: "decrypt" }, "KHOOR"),
    ).toBe("HELLO");
    expect(
      await textOf({ [OPTION_SHIFT]: 5, [OPTION_DIRECTION]: "decrypt" }, "MJQQT"),
    ).toBe("HELLO");
  });

  /**
   * The control reaches the cipher, asserted across the whole range.
   *
   * A shift that never arrived would leave every answer equal to the default's, which is the shape of
   * defect this repo records most often -- and over a single input it looks like a working tool.
   */
  it("gives a different answer for every shift", async () => {
    const seen = new Set<string>();
    for (let shift = 0; shift < 26; shift++) {
      seen.add(await textOf({ [OPTION_SHIFT]: shift }, "attack at dawn"));
    }
    expect(seen.size).toBe(26);
  });

  it("clamps a shift outside the control's range rather than refusing it", async () => {
    // Clamped, not reduced: the control offers 0..25, so 30 is a spinner mishap and lands on 25.
    expect(await textOf({ [OPTION_SHIFT]: 30 }, "A")).toBe(await textOf({ [OPTION_SHIFT]: 25 }, "A"));
    expect(await textOf({ [OPTION_SHIFT]: -4 }, "A")).toBe(await textOf({ [OPTION_SHIFT]: 0 }, "A"));
  });

  it("passes non-letters through and says how many", async () => {
    const result = await run({ [OPTION_SHIFT]: 1 }, "abc 12!");
    expect(result.text).toBe("bcd 12!");
    const field = (label: string) => result.fields!.find((f) => f.label === label)!.value;
    expect(field("Letters moved")).toBe("3 of 7");
  });

  it("reports the effective shift for a decryption", async () => {
    const result = await run({ [OPTION_SHIFT]: 3, [OPTION_DIRECTION]: "decrypt" }, "KHOOR");
    const shiftField = result.fields!.find((f) => f.label === "Shift applied")!.value;
    // Both spellings, because "back 3" and "forward 23" are the same operation and seeing the second
    // is what makes the modular arithmetic concrete.
    expect(shiftField).toContain("-3");
    expect(shiftField).toContain("+23");
  });

  it("notes that 13 is its own inverse, in the fields and in the checks", async () => {
    const result = await run({ [OPTION_SHIFT]: 13 }, "Spoiler");
    expect(result.fields!.some((f) => f.value.includes("ROT13"))).toBe(true);
    expect(lint(specFor({ [OPTION_SHIFT]: 13 })).diagnostics.some((d) => d.code === "X003")).toBe(
      true,
    );
    // And it really is: encrypt and decrypt agree at this shift.
    expect(await textOf({ [OPTION_SHIFT]: 13 }, "Spoiler")).toBe(
      await textOf({ [OPTION_SHIFT]: 13, [OPTION_DIRECTION]: "decrypt" }, "Spoiler"),
    );
  });

  it("flattens the case when asked", async () => {
    expect(await textOf({ [OPTION_SHIFT]: 3 }, "Hello, World!")).toBe("Khoor, Zruog!");
    expect(await textOf({ [OPTION_SHIFT]: 3, [OPTION_LETTER_CASE]: "upper" }, "Hello, World!")).toBe(
      "KHOOR, ZRUOG!",
    );
    expect(await textOf({ [OPTION_SHIFT]: 3, [OPTION_LETTER_CASE]: "lower" }, "Hello, World!")).toBe(
      "khoor, zruog!",
    );
  });
});

describe("the brute-force table", () => {
  it("has 26 rows and marks the shift in use", async () => {
    const result = await run({ [OPTION_SHIFT]: 3 }, "HELLO");
    const lines = result.working!.split("\n");
    // A heading plus 26 rows.
    expect(lines).toHaveLength(27);
    expect(lines[0]).toContain("Result");
    const marked = lines.filter((line) => line.startsWith(">"));
    expect(marked).toHaveLength(1);
    expect(marked[0]).toContain("3");
    expect(marked[0]).toContain("KHOOR");
    // And the marked row is the answer, which is what makes the table trustworthy.
    expect(marked[0]).toContain(result.text!);
  });

  /**
   * For a decryption the marked row is 26 - k, and that is the point of marking it at all.
   *
   * Decrypting at 3 applies a forward shift of 23, so the row that matches the result is 23 -- the same
   * statement as `-3 mod 26`, made visible next to it.
   */
  it("marks 26 - k when decrypting", async () => {
    const result = await run({ [OPTION_SHIFT]: 3, [OPTION_DIRECTION]: "decrypt" }, "KHOOR");
    const marked = result.working!.split("\n").find((line) => line.startsWith(">"))!;
    expect(marked).toMatch(/^>\s+23\s+HELLO$/);
  });

  it("contains the plaintext of the shipped cryptogram sample", async () => {
    const cryptogram = samplesFor("caesar")!.find((sample) => sample.id === "cryptogram")!.text;
    const result = await run({ [OPTION_DIRECTION]: "decrypt" }, cryptogram);
    // The whole attack: the answer is one of the 26 lines.
    expect(result.working).toContain("The quick brown fox jumps over 1 lazy dog!");
  });

  it("can be turned off", async () => {
    const off = await run({ [OPTION_SHOW_ALL]: false }, "HELLO");
    expect(off.working).toBeUndefined();
    const on = await run({ [OPTION_SHOW_ALL]: true }, "HELLO");
    expect(on.working).toBeDefined();
  });

  /**
   * A long input is truncated per row and the tool says so, rather than being wrapped or cut silently.
   *
   * Wrapping would destroy the one property that makes the table useful -- 26 scannable lines -- and a
   * silent cut would read as the whole answer.
   */
  it("truncates long rows and states that it did", async () => {
    const long = "a".repeat(__testing.PREVIEW_LIMIT + 40);
    const result = await run({ [OPTION_SHIFT]: 1 }, long);
    expect(result.working).toContain(`Showing the first ${__testing.PREVIEW_LIMIT} characters`);
    for (const line of result.working!.split("\n").slice(1, 27)) {
      expect(line.length).toBeLessThan(__testing.PREVIEW_LIMIT + 12);
    }
    // A short input is not truncated and says nothing about it.
    expect((await run({ [OPTION_SHIFT]: 1 }, "short")).working).not.toContain("Showing the first");
  });
});

describe("lint rules", () => {
  it("declares every code it can emit, and emits every code it declares", () => {
    const emitted = new Set<string>();
    /** One spec per rule, chosen to trip it. */
    const TRIPS: readonly ClassicalSpec[] = [
      specFor(),
      specFor({ [OPTION_SHIFT]: 0 }),
      specFor({ [OPTION_SHIFT]: 13 }),
    ];
    for (const spec of TRIPS) for (const d of lint(spec).diagnostics) emitted.add(d.code);
    expect([...emitted].sort()).toEqual([...RULE_CODES].sort());
  });

  /**
   * X001 fires always, because the cipher is always this weak.
   *
   * `insecure` rather than `error`: it computes exactly as specified and producing that output is the
   * whole point of the tool. And no fix, because there is nothing to fix -- a different shift is not
   * stronger and a different cipher is a different tool.
   */
  it("says what the cipher is worth, at every shift, without offering a fix", () => {
    for (const shift of [0, 1, 3, 13, 25]) {
      const found = lint(specFor({ [OPTION_SHIFT]: shift })).diagnostics.find(
        (d) => d.code === "X001",
      );
      expect(found, `shift ${shift}`).toBeDefined();
      expect(found!.level).toBe("insecure");
      expect(found!.fix).toBeUndefined();
      expect(found!.message).toMatch(/26 keys/);
    }
  });

  it("warns that a shift of 0 changes nothing, and the fix silences it", () => {
    const before = lint(specFor({ [OPTION_SHIFT]: 0 }));
    const identity = before.diagnostics.find((d) => d.code === "X002")!;
    expect(identity.level).toBe("warning");
    expect(identity.fix).toBeDefined();
    const fixed = applyAllFixes(specFor({ [OPTION_SHIFT]: 0 }));
    expect(lint(fixed).diagnostics.some((d) => d.code === "X002")).toBe(false);
  });

  it("stays quiet about 0 and 13 at an ordinary shift", () => {
    const codes = lint(specFor({ [OPTION_SHIFT]: 7 })).diagnostics.map((d) => d.code);
    expect(codes).toContain("X001");
    expect(codes).not.toContain("X002");
    expect(codes).not.toContain("X003");
  });

  it("blocks nothing: every diagnostic here still computes", async () => {
    for (const shift of [0, 13, 25]) {
      const spec = specFor({ [OPTION_SHIFT]: shift });
      expect(lint(spec).hasErrors, `shift ${shift}`).toBe(false);
      const result = await classicalToolDefinition("caesar").compute(spec, bytes("HELLO"));
      expect(result.error, `shift ${shift}`).toBeUndefined();
    }
  });

  it("leaves a computable spec after applying all fixes", async () => {
    const fixed = applyAllFixes(specFor({ [OPTION_SHIFT]: 0 }));
    const result = await classicalToolDefinition("caesar").compute(fixed, bytes("HELLO"));
    expect(result.error).toBeUndefined();
    expect(result.text).toBe("KHOOR");
  });
});

describe("samples and describe", () => {
  /**
   * The first sample is what a fresh box is seeded with, so it has to be the one that demonstrates the
   * tool at its defaults -- which for this cipher means HELLO, giving KHOOR at a shift of 3.
   */
  it("seeds HELLO, which the defaults turn into KHOOR", async () => {
    const samples = samplesFor("caesar")!;
    expect(samples[0]!.text).toBe("HELLO");
    expect(await textOf({}, samples[0]!.text)).toBe("KHOOR");
  });

  it("computes every sample under the default spec", async () => {
    for (const sample of samplesFor("caesar")!) {
      const result = await classicalToolDefinition("caesar").compute(specFor(), bytes(sample.text));
      expect(result.error, sample.id).toBeUndefined();
      expect(result.text, sample.id).toBeTruthy();
    }
  });

  it("gives every sample a unique id and a note", () => {
    const samples = samplesFor("caesar")!;
    expect(new Set(samples.map((s) => s.id)).size).toBe(samples.length);
    for (const sample of samples) expect(sample.note, sample.id).toBeTruthy();
  });

  it("has no samples for a tool that does not exist", () => {
    expect(samplesFor("vigenere")).toBeUndefined();
  });

  it("describes itself by the shift and the direction", () => {
    expect(describeSpec(specFor({ [OPTION_SHIFT]: 3 }))).toBe("Moves each letter forward 3 places.");
    // Singular at one, because "1 places" is the kind of thing a reader notices.
    expect(describeSpec(specFor({ [OPTION_SHIFT]: 1 }))).toContain("forward 1 place.");
    expect(
      describeSpec(specFor({ [OPTION_SHIFT]: 3, [OPTION_DIRECTION]: "decrypt" })),
    ).toBe("Moves each letter back 3 places -- forward 23 mod 26.");
    expect(describeSpec(specFor({ [OPTION_LETTER_CASE]: "upper" }))).toContain("upper case");
  });

  it("states the formula and the alphabet before anything is typed", () => {
    const info = classicalToolDefinition("caesar").info!(specFor());
    const field = (label: string) => info.find((f) => f.label === label)!;
    expect(field("Formula").value).toBe("E(x) = (x + k) mod 26");
    expect(field("Formula").hint).toContain("k = 3");
    // The question this cipher attracts most: bytes and hex are not in the alphabet.
    expect(field("Alphabet").hint).toMatch(/bytes or hex/);
    expect(field("Keyspace").value).toContain("26");
    expect(
      classicalToolDefinition("caesar").info!(specFor({ [OPTION_DIRECTION]: "decrypt" }))[0]!.value,
    ).toBe("D(x) = (x - k) mod 26");
  });
});
