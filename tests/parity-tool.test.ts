import { describe, expect, it } from "vitest";
import {
  OPTION_BAUD,
  OPTION_BIT_ORDER,
  OPTION_DATA_BITS,
  OPTION_DIRECTION,
  OPTION_HAMMING_CODE,
  OPTION_INVERTED,
  OPTION_PARITY,
  OPTION_PLACEMENT,
  OPTION_SCOPE,
  OPTION_SPACED,
  OPTION_STOP_BITS,
  PARITY_MANIFESTS,
  PARITY_TOOLS,
  type ParitySpec,
} from "@ocs/parity";
import {
  ALL_PARITY_OPTIONS,
  applyAllFixes,
  createSpec,
  describeSpec,
  lint,
  parityToolDefinition,
  RULE_CODES,
  samplesFor,
  UART_CAPTURE_SAMPLE,
  __testing,
} from "@ocs/parity/definition";
import { encodeHex, validateCatalogue, type ToolResultField } from "@ocs/engine";

/**
 * The parity family: the bit, the frame it travels in, and the codes that locate an error.
 *
 * `tests/algos-parity.test.ts` owns whether the arithmetic is right -- exhaustively, since the
 * domains are small enough to cover completely. What is left for this file is everything the *tools*
 * decide, which for a family whose difficulty is entirely convention is most of the value: which
 * option means what, what a refusal says, and whether the shorthand on screen (8N1, 7E2) describes
 * the settings actually chosen.
 */

const bytes = (text: string) => new TextEncoder().encode(text);
const CHECK_INPUT = bytes("123456789");

function specFor(variant: string, options: ParitySpec["options"] = {}): ParitySpec {
  const base = createSpec({ variant });
  return { ...base, options: { ...base.options, ...options } };
}

async function run(variant: string, options: ParitySpec["options"], input: Uint8Array = CHECK_INPUT) {
  // Copied rather than passed straight through: `ToolResult.bytes` is a `Uint8Array` over an
  // unspecified buffer flavour, and feeding one back in is a routine thing for a test in a
  // bidirectional family to want.
  return parityToolDefinition(variant).compute(
    specFor(variant, options),
    Uint8Array.from(input),
  );
}

async function hexOf(variant: string, options: ParitySpec["options"], input = CHECK_INPUT) {
  const result = await run(variant, options, input);
  expect(result.error, `${variant} refused: ${result.error}`).toBeUndefined();
  return encodeHex(result.bytes!);
}

async function textOf(variant: string, options: ParitySpec["options"], input = CHECK_INPUT) {
  const result = await run(variant, options, input);
  expect(result.error, `${variant} refused: ${result.error}`).toBeUndefined();
  return result.text!;
}

const field = (fields: readonly ToolResultField[] | undefined, label: string) =>
  fields?.find((f) => f.label === label)?.value ?? "";

/**
 * One row of the UART table, split into its cells.
 *
 * The columns are padded to their widest value, so they are separated by two spaces or more -- which
 * makes splitting on a run of two-or-more the reliable way to read a row, and is why the heading
 * "Data (8 bits, LSB first)" survives as one cell despite containing single spaces.
 */
const cells = (row: string): string[] => row.trim().split(/ {2,}/);

/** Hex to bytes, for the one tool whose check input cannot be typed as text. */
const fromHex = (text: string): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(text.match(/../g)!.map((pair) => parseInt(pair, 16)));

describe("the family's shape", () => {
  it("registers five tools, none streaming", () => {
    expect(PARITY_MANIFESTS).toHaveLength(5);
    for (const manifest of PARITY_MANIFESTS) {
      expect(manifest.family).toBe("parity");
      expect(manifest.security, manifest.id).toBe("not-a-mac");
      // Per-byte parity is incremental, but its result is one bit per input byte rather than a
      // fixed-width digest, which is not what a ToolStream is. See the note on the manifest.
      expect(manifest.streaming, manifest.id).toBe(false);
      expect(manifest.readsInput, manifest.id).toBe(true);
    }
  });

  /**
   * Binary first, which is this family's one departure from the rest of the app.
   *
   * `outputEncodings[0]` is what a tool opens on, and everywhere else that is hex. Here the result
   * *is* bits, and `01` says what `0x01` makes you decode.
   */
  it("opens on binary for the two tools that return bits, and offers no menu for the diagram", () => {
    for (const manifest of PARITY_MANIFESTS) {
      if (manifest.id === "uart") {
        expect(manifest.outputEncodings).toEqual(["utf-8"]);
      } else {
        expect(manifest.outputEncodings[0], manifest.id).toBe("binary");
      }
    }
  });

  it("has a clean catalogue per tool and no option rendered by a tool that does not expose it", () => {
    for (const meta of PARITY_TOOLS) {
      const tool = parityToolDefinition(meta.id);
      expect(validateCatalogue(tool.catalogue.options), meta.id).toEqual([]);
      // `exposes` documents the tool and the catalogue renders it. They have to agree, and neither is
      // derived from the other, so a disagreement is visible rather than impossible.
      expect(tool.catalogue.options.map((o) => o.id).sort(), meta.id).toEqual(
        [...meta.exposes].sort(),
      );
    }
    const ids = new Set(ALL_PARITY_OPTIONS.map((o) => o.id));
    expect(ids.size).toBeGreaterThan(0);
  });

  it("describes every tool in both directions without an empty sentence", () => {
    for (const meta of PARITY_TOOLS) {
      for (const direction of ["apply", "check"]) {
        const described = describeSpec(specFor(meta.id, { [OPTION_DIRECTION]: direction }));
        expect(described, `${meta.id}/${direction}`).not.toBe("");
        expect(described.endsWith("."), `${meta.id}/${direction}: ${described}`).toBe(true);
      }
    }
  });

  /**
   * The published check value, the convention the CRC and checksum families already use.
   *
   * These are conventions rather than algorithms, so one agreed value over one agreed input is how
   * two implementations confirm they mean the same thing -- and pinning it in the metadata means the
   * number cannot drift away from the code.
   */
  it("produces each tool's stated check value", async () => {
    /**
     * Over `123456789` for every tool but BCH, which names its own input.
     *
     * BCH's data unit is five bits, so every byte of the family's default is out of range and the tool
     * correctly refuses it. `checkInput` is the honest way out: masking those bytes down to five bits
     * would give a computable value for an input nobody supplied.
     */
    for (const meta of PARITY_TOOLS) {
      if (!meta.check) continue;
      const input = meta.checkInput === undefined ? CHECK_INPUT : fromHex(meta.checkInput);
      expect(await hexOf(meta.id, {}, input), meta.id).toBe(meta.check);
    }
    // Guards the guard: four of the five carry one, and a typo dropping them all would pass silently.
    expect(PARITY_TOOLS.filter((t) => t.check)).toHaveLength(4);
    expect(PARITY_TOOLS.filter((t) => t.checkInput).map((t) => t.id)).toEqual(["bch"]);
  });
});

describe("the parity bit", () => {
  /**
   * The three layouts over the same nine bytes, so the difference is on the page.
   *
   * `123456789` is 0x31 to 0x39. Even parity of each: 0x31 is 0011_0001 with three ones so the bit is
   * 1, 0x32 is 0011_0010 with three so 1, 0x33 is 0011_0011 with four so 0 -- giving 1,1,0,1,0,0,1,1,0,
   * worked out from the bytes rather than read off the implementation.
   */
  it("lays the same bits out three ways", async () => {
    // One byte per input byte: 1,1,0,1,0,0,1,1,0.
    expect(await hexOf("parity", { [OPTION_PLACEMENT]: "byte-each" })).toBe("010100010000010100");
    // The same nine bits, most significant first: 1101_0011 is 0xd3, then one bit padded to 0x00.
    expect(await hexOf("parity", { [OPTION_PLACEMENT]: "packed" })).toBe("d300");
    // And in the top bit, which needs seven data bits. 0x31 keeps its low seven and gains bit 7;
    // 0x33 has four ones already, so its parity bit is 0 and the byte is unchanged.
    expect(await hexOf("parity", { [OPTION_PLACEMENT]: "high-bit", [OPTION_DATA_BITS]: 7 })).toBe(
      "b1b233b43536b7b839",
    );
  });

  /**
   * The bits, stated once, whatever the layout and whatever the output encoding.
   *
   * This field exists because of a real report: the default layout is one byte per input byte and this
   * family's default output encoding is binary, so ten input bytes render as
   * `00000000 00000001 00000001 ...` -- eighty characters carrying ten bits, and nothing on screen
   * saying the answer is 0110100110. The primary value has to be *usable* (copied, saved, fed to
   * something expecting bytes) and cannot also be the legible form under every combination, so the
   * bits get their own row.
   *
   * Asserted across all three layouts with the same input, which is the property that matters: the
   * layout changes the bytes and must not change this.
   */
  it("spells the bits out in order, identically under every layout", async () => {
    const input = bytes("0123456789");
    for (const placement of ["byte-each", "packed", undefined]) {
      const result = await run(
        "parity",
        placement ? { [OPTION_PLACEMENT]: placement } : {},
        input,
      );
      expect(field(result.fields, "Parity bits"), placement ?? "default").toBe("01101001 10");
      expect(field(result.fields, "Bits set"), placement ?? "default").toBe("5 of 10");
    }
    // And in the top bit too, which needs seven data bits -- a different layout *and* a different
    // width, so the bits legitimately differ. Stated rather than skipped.
    const sevenBit = await run(
      "parity",
      { [OPTION_PLACEMENT]: "high-bit", [OPTION_DATA_BITS]: 7 },
      input,
    );
    expect(field(sevenBit.fields, "Parity bits")).toBe("01101001 10");
  });

  /** Grouped in eights, which is what makes a long run countable rather than a wall. */
  it("groups the bits in eights and says how many are set", async () => {
    const result = await run("parity", {}, bytes("A".repeat(20)));
    expect(field(result.fields, "Parity bits")).toBe("00000000 00000000 0000");
    expect(field(result.fields, "Bits set")).toBe("0 of 20");
  });

  /**
   * The working, which is the whole answer rather than a summary of it.
   *
   * Asked for directly after the eighty-characters-for-ten-bits report, and it is the right thing to
   * ask for: every step behind a parity bit is short, so all of them fit in a row. The columns are
   * asserted verbatim for the exact input that prompted it, because the point of a working is that
   * nothing in it has to be taken on trust -- including from this test.
   */
  it("shows its working, one row per byte", async () => {
    const result = await run("parity", {}, bytes("0123456789"));
    expect(result.working!.split("\n")).toEqual([
      "Char  Byte  Bits       Ones  Even parity bit",
      "0     0x30  0011 0000  2     0",
      "1     0x31  0011 0001  3     1",
      "2     0x32  0011 0010  3     1",
      "3     0x33  0011 0011  4     0",
      "4     0x34  0011 0100  3     1",
      "5     0x35  0011 0101  4     0",
      "6     0x36  0011 0110  4     0",
      "7     0x37  0011 0111  5     1",
      "8     0x38  0011 1000  3     1",
      "9     0x39  0011 1001  4     0",
    ]);
    // And the last column is the answer the Parity bits row states, read downwards.
    const column = result
      .working!.split("\n")
      .slice(1)
      .map((row) => cells(row).at(-1)!)
      .join("");
    expect(column).toBe("0110100110");
    expect(field(result.fields, "Parity bits")).toBe("01101001 10");
  });

  /**
   * The Bits column shows what was *counted*, and its heading says so.
   *
   * Seven data bits is the setting most likely to be misread -- a 7-bit ASCII byte with parity already
   * in bit 7 looks exactly like 8-bit data -- so showing eight bits of context beside a seven-bit count
   * would be the wrong kind of helpful.
   */
  it("narrows the working to the bits it counted", async () => {
    const result = await run(
      "parity",
      { [OPTION_DATA_BITS]: 7, [OPTION_PARITY]: "odd" },
      bytes("0"),
    );
    expect(result.working!.split("\n")).toEqual([
      "Char  Byte  Bits (low 7)  Ones  Odd parity bit",
      "0     0x30  011 0000      2     1",
    ]);
  });

  /**
   * Mark and space get "bit" rather than "parity bit" in the heading, which is not pedantry.
   *
   * Their column is a constant and does not depend on the count beside it, so calling it a parity bit
   * would be the overclaim `P002` exists to prevent -- and it would be an overclaim made in the one
   * place a reader goes to check the reasoning.
   */
  it("does not call a constant column a parity bit", async () => {
    const mark = await run("parity", { [OPTION_PARITY]: "mark" }, bytes("01"));
    expect(mark.working!.split("\n")[0]).toContain("Mark bit");
    expect(mark.working!.split("\n")[0]).not.toContain("parity bit");
    // And it really is constant, whatever the counts in the column beside it.
    expect(
      mark.working!.split("\n").slice(1).map((row) => cells(row).at(-1)!),
    ).toEqual(["1", "1"]);
  });

  /**
   * Checking answers "which bytes are wrong", and the working answers "why".
   *
   * Sent against Wanted side by side is also what makes a wrong *setting* obvious: every row failing
   * with the two differing the same way each time is odd parity read as even, not corrupt data.
   */
  it("shows what arrived against what was expected when checking", async () => {
    const framed = await run(
      "parity",
      { [OPTION_PLACEMENT]: "high-bit", [OPTION_DATA_BITS]: 7 },
      bytes("Hi"),
    );
    const corrupt = Uint8Array.from(framed.bytes!);
    corrupt[1] = corrupt[1]! ^ 0x80;

    const checked = await run(
      "parity",
      { [OPTION_DIRECTION]: "check", [OPTION_DATA_BITS]: 7 },
      corrupt,
    );
    const rows = checked.working!.split("\n");
    expect(cells(rows[0]!)).toEqual(["Char", "Byte", "Bits (low 7)", "Ones", "Sent", "Wanted"]);
    expect(cells(rows[1]!).at(-1)).toBe("ok");
    expect(cells(rows[2]!).at(-1)).toBe("FAIL");
    // The two columns that explain the verdict must actually disagree on the failing row.
    const failing = cells(rows[2]!);
    expect(failing.at(-3)).not.toBe(failing.at(-2));
  });

  /**
   * The row cap is stated rather than silently applied.
   *
   * "The first 256 of 4 million" is information; a table that just stops is a reader wondering whether
   * the tool gave up. The same rule the UART diagram follows.
   */
  it("caps the working and says how much it left out", async () => {
    const result = await run("parity", {}, new Uint8Array(300).fill(0x41));
    const rows = result.working!.split("\n");
    // 256 rows, one heading, a blank line and the note.
    expect(rows.filter((row) => row.startsWith("A  ")).length).toBe(256);
    expect(result.working!).toContain("and 44 more");
  });

  /** One bit over the whole message has no per-byte working to show, and does not invent one. */
  it("shows no working for whole-message parity", async () => {
    const result = await run("parity", { [OPTION_SCOPE]: "message" }, bytes("0123456789"));
    expect(result.working).toBeUndefined();
    expect(field(result.fields, "Parity bit")).toBe("1");
  });

  it("states the padding for the packed layout, because nothing else can", async () => {
    const nine = await run("parity", { [OPTION_PLACEMENT]: "packed" });
    expect(field(nine.fields, "Padding")).toMatch(/7 zero bits/);
    const eight = await run("parity", { [OPTION_PLACEMENT]: "packed" }, bytes("12345678"));
    expect(field(eight.fields, "Padding")).toMatch(/None/);
  });

  /**
   * Eight data bits with the parity in the top bit is nine bits, and there is no answer to give.
   *
   * Refused rather than clamped: this is the "only refuse what the thing genuinely cannot do" case,
   * alongside AES's key sizes, and the message names both ways out rather than only saying no.
   */
  it("refuses to put a parity bit into a byte that is already full", async () => {
    const result = await run("parity", {
      [OPTION_PLACEMENT]: "high-bit",
      [OPTION_DATA_BITS]: 8,
    });
    expect(result.error).toMatch(/nine bits on the wire/);
    expect(result.error).toMatch(/Drop to 7 data bits/);
  });

  it("inverts every bit for odd parity, and emits constants for mark and space", async () => {
    const even = await run("parity", { [OPTION_PARITY]: "even" });
    const odd = await run("parity", { [OPTION_PARITY]: "odd" });
    // Bit by bit, not character by character: the two differ in the *values*, and inverting the hex
    // spelling of "01" would give "10", which is a different byte rather than a flipped bit.
    expect([...odd.bytes!]).toEqual([...even.bytes!].map((bit) => bit ^ 1));
    expect(await hexOf("parity", { [OPTION_PARITY]: "mark" })).toBe("010101010101010101");
    expect(await hexOf("parity", { [OPTION_PARITY]: "space" })).toBe("000000000000000000");
  });

  it("takes one bit over the whole message, and says what it covers", async () => {
    const result = await run("parity", { [OPTION_SCOPE]: "message" });
    expect(encodeHex(result.bytes!)).toBe("01");
    expect(field(result.fields, "Covers")).toBe("9 bytes, 72 bits");
    // The property that makes it the weakest check there is, asserted through the tool.
    const twice = await run("parity", { [OPTION_SCOPE]: "message" }, bytes("AA"));
    expect(encodeHex(twice.bytes!)).toBe("00");
  });

  /**
   * Checking reports offsets, strips the parity bit, and notices when *everything* failed.
   *
   * The last part is the one worth having: a wrong parity setting makes every byte fail, and a reader
   * looking at nine failures out of nine needs to be told that is a configuration symptom rather than
   * nine corrupt bytes.
   */
  it("checks a 7E1 stream, names the bad offsets and strips the bit", async () => {
    const framed = await run("parity", {
      [OPTION_PLACEMENT]: "high-bit",
      [OPTION_DATA_BITS]: 7,
    });
    const corrupt = Uint8Array.from(framed.bytes!);
    corrupt[3] = corrupt[3]! ^ 0x80;

    const checked = await run(
      "parity",
      { [OPTION_DIRECTION]: "check", [OPTION_DATA_BITS]: 7 },
      corrupt,
    );
    expect(field(checked.fields, "Failed")).toBe("1");
    expect(field(checked.fields, "At offsets")).toBe("3");
    // The data comes back without the parity bit, which is what you wanted the bytes for.
    expect(encodeHex(checked.bytes!)).toBe(encodeHex(CHECK_INPUT));

    const wrongMode = await run(
      "parity",
      { [OPTION_DIRECTION]: "check", [OPTION_DATA_BITS]: 7, [OPTION_PARITY]: "odd" },
      framed.bytes!,
    );
    expect(field(wrongMode.fields, "Failed")).toBe("9");
    expect(field(wrongMode.fields, "Note")).toMatch(/setting is wrong rather than the data/);
  });

  it("refuses to check at 8 data bits, where the parity bit is not in the byte", async () => {
    const result = await run("parity", { [OPTION_DIRECTION]: "check", [OPTION_DATA_BITS]: 8 });
    expect(result.error).toMatch(/at most 7 bits wide/);
  });

  it("says the input is empty rather than returning nothing", async () => {
    // An empty Result panel with no explanation reads as the tool being broken, which is the one
    // thing worse than an error -- so every scope and direction has a sentence for it.
    expect((await run("parity", {}, new Uint8Array())).error).toMatch(/empty/);
    expect(
      (await run("parity", { [OPTION_DIRECTION]: "check" }, new Uint8Array())).error,
    ).toMatch(/empty/);
    expect((await run("parity", { [OPTION_SCOPE]: "message" }, new Uint8Array())).error).toMatch(
      /empty/,
    );
  });
});

describe("the UART frame", () => {
  /**
   * 'A' at 8N1, written out: start 0, then 0x41 least significant bit first, then stop 1.
   *
   * The one case that matters most, and asymmetric on purpose -- 0x55 reads the same in both
   * directions, so it cannot tell a correct frame from a reversed one.
   *
   * Asserted cell by cell rather than as one substring, because the table is padded to its column
   * widths: `0 10000010 1` was the whole row when the fields were separated by single spaces, and it
   * is now three columns under three headings. Reading the cells is also what checks the alignment,
   * which is the thing that was actually wrong -- the old header put five characters of "start" over a
   * one-bit field, so nothing lined up past the first column.
   */
  it("shows a byte as its frame, in labelled columns that line up", async () => {
    const rendered = await textOf("uart", {}, bytes("A"));
    const [heading, row] = rendered.split("\n") as [string, string];

    expect(cells(heading)).toEqual(["Byte", "Char", "Start", "Data (8 bits, LSB first)", "Stop"]);
    expect(cells(row)).toEqual(["0x41", "A", "0", "10000010", "1"]);

    // Every cell begins at its heading's column. This is the assertion the old format failed.
    for (const label of ["Start", "Data (8 bits, LSB first)", "Stop"]) {
      const at = heading.indexOf(label);
      expect(at, label).toBeGreaterThan(-1);
      expect(row.slice(at, at + 1), `${label} does not start under its heading`).not.toBe(" ");
    }
  });

  /**
   * The heading says which way round the data is, and that is not decoration.
   *
   * 0x30 is 0011_0000 and its frame shows 0000_1100. Without "LSB first" over the column that reads as
   * a bug -- which is exactly the report that prompted this table.
   */
  it("says the bit order in the data heading and in the fields", async () => {
    const lsb = await run("uart", {}, bytes("0"));
    expect(lsb.text!.split("\n")[0]).toContain("LSB first");
    expect(cells(lsb.text!.split("\n")[1]!)).toEqual(["0x30", "0", "0", "00001100", "1"]);
    expect(field(lsb.fields, "Bit order")).toMatch(/^Least significant first/);

    const msb = await run("uart", { [OPTION_BIT_ORDER]: "msb" }, bytes("0"));
    expect(msb.text!.split("\n")[0]).toContain("MSB first");
    expect(cells(msb.text!.split("\n")[1]!)).toEqual(["0x30", "0", "0", "00110000", "1"]);
    expect(field(msb.fields, "Bit order")).toMatch(/^Most significant first/);
  });

  /**
   * A space has to render as something, and rendering it as itself is an empty cell.
   *
   * Which is the same ambiguity the whole table exists to remove -- for the input "0" the digit
   * appeared three times with nothing to say which was the byte, which the character and which the
   * start bit. `SP` for a space, a dot for anything outside printable ASCII, because a control
   * character printed literally would move the cursor and wreck the alignment.
   */
  it("names a space rather than leaving its cell blank", async () => {
    const rendered = await textOf("uart", {}, bytes(" 0"));
    const rows = rendered.split("\n").slice(1);
    expect(cells(rows[0]!)[1]).toBe("SP");
    expect(cells(rows[1]!)[1]).toBe("0");
    // 0x07 is BEL, which is named rather than dotted -- see the character-column tests below, where
    // every byte to 0x7f is required to have a name.
    const control = await textOf("uart", {}, new Uint8Array([0x07]));
    expect(cells(control.split("\n")[1]!)[1]).toBe("BEL");
  });

  it("runs the bits together when the separators are turned off", async () => {
    const rendered = await textOf("uart", { [OPTION_SPACED]: false }, bytes("A"));
    expect(rendered).toContain("0100000101");
  });

  it("names the format the way a datasheet does", async () => {
    const plain = await run("uart", {}, bytes("A"));
    expect(field(plain.fields, "Format")).toBe("8N1");
    const seven = await run(
      "uart",
      { [OPTION_DATA_BITS]: 7, [OPTION_PARITY]: "even", [OPTION_STOP_BITS]: "2" },
      bytes("A"),
    );
    expect(field(seven.fields, "Format")).toBe("7E2");
    const mark = await run("uart", { [OPTION_PARITY]: "mark" }, bytes("A"));
    expect(field(mark.fields, "Format")).toBe("8M1");
  });

  /**
   * The timing figures, and the one people get wrong.
   *
   * Bytes per second is *not* the baud rate over eight: a byte at 8N1 costs ten bit times, so 9600
   * baud carries 960 bytes a second, and 8E2 drops that to 800. Both are asserted because the whole
   * reason the baud control exists is to answer this, and an off-by-the-overhead here would be a
   * plausible wrong number rather than an obvious one.
   */
  it("computes the frame time and the throughput from the whole frame, not the data", async () => {
    const plain = await run("uart", { [OPTION_BAUD]: 9600 }, bytes("A"));
    expect(field(plain.fields, "Bits per frame")).toBe("10 (8 of them data)");
    expect(field(plain.fields, "One frame takes")).toBe("1.042 ms");
    expect(field(plain.fields, "Throughput")).toBe("960.0 bytes/s at 9,600 baud");
    expect(field(plain.fields, "Efficiency")).toBe("80.0% — 2 bits of every 10 are overhead");

    const industrial = await run(
      "uart",
      { [OPTION_BAUD]: 9600, [OPTION_PARITY]: "even", [OPTION_STOP_BITS]: "2" },
      bytes("A"),
    );
    expect(field(industrial.fields, "Bits per frame")).toBe("12 (8 of them data)");
    expect(field(industrial.fields, "Throughput")).toBe("800.0 bytes/s at 9,600 baud");
  });

  /** A half stop bit is a duration: the frame time moves and the bit pattern does not. */
  it("counts 1.5 stop bits as a half without drawing half a bit", async () => {
    const half = await run("uart", { [OPTION_STOP_BITS]: "1.5", [OPTION_BAUD]: 9600 }, bytes("A"));
    expect(field(half.fields, "Bits per frame")).toBe("10.5 (8 of them data)");
    expect(field(half.fields, "One frame takes")).toBe("1.094 ms");
    // The pattern is unchanged: one stop bit drawn, and the half only in the timing above.
    const drawn = await textOf("uart", { [OPTION_STOP_BITS]: "1.5" }, bytes("A"));
    expect(cells(drawn.split("\n")[1]!)).toEqual(["0x41", "A", "0", "10000010", "1"]);
  });

  it("says which way up the line is", async () => {
    const ttl = await run("uart", {}, bytes("A"));
    expect(field(ttl.fields, "Idle level")).toMatch(/^High/);
    const rs232 = await run("uart", { [OPTION_INVERTED]: true }, bytes("A"));
    expect(field(rs232.fields, "Idle level")).toMatch(/^Low/);
    // Every level flipped, cell by cell: idle high becomes idle low, so the start bit is a 1.
    const upside = await textOf("uart", { [OPTION_INVERTED]: true }, bytes("A"));
    expect(cells(upside.split("\n")[1]!)).toEqual(["0x41", "A", "1", "01111101", "0"]);
  });

  /**
   * Nine data bits and a parity bit cannot coexist, and the message says why rather than only that.
   *
   * The ninth bit *is* the parity slot -- that is what makes it an address/data flag -- so this is a
   * refusal about the protocol rather than about this tool.
   */
  it("refuses nine data bits with a parity bit", async () => {
    const result = await run("uart", { [OPTION_DATA_BITS]: 9, [OPTION_PARITY]: "even" }, bytes("A"));
    expect(result.error).toMatch(/ninth bit occupies the parity slot/);
  });

  it("decodes its own frames back to the bytes", async () => {
    const diagram = await textOf("uart", {}, bytes("Hi!"));
    const decoded = await run("uart", { [OPTION_DIRECTION]: "check" }, bytes(diagram));
    // The diagram carries hex and ASCII columns too, and those are not bits -- so this also checks
    // that the decoder ignores everything that is not a 0 or a 1... which it cannot, since "41" is
    // digits. Feeding the bit string alone is the honest round trip.
    expect(decoded.error).toBeUndefined();

    const bitsOnly = await textOf("uart", { [OPTION_SPACED]: false }, bytes("Hi!"));
    const stripped = bitsOnly
      .split("\n")
      .slice(1)
      .map((row) => cells(row).at(-1)!)
      .join("");
    const clean = await run("uart", { [OPTION_DIRECTION]: "check" }, bytes(stripped));
    expect(new TextDecoder().decode(clean.bytes!)).toBe("Hi!");
    expect(field(clean.fields, "Errors")).toMatch(/None/);
  });

  /**
   * The sample capture is written out by hand rather than generated, so decoding it is a real check.
   *
   * A sample derived from the implementation it demonstrates would agree with a broken one.
   */
  it("decodes the hand-written sample capture", async () => {
    const result = await run("uart", { [OPTION_DIRECTION]: "check" }, bytes(UART_CAPTURE_SAMPLE));
    expect(result.error).toBeUndefined();
    expect(new TextDecoder().decode(result.bytes!)).toBe("Hi!");
    expect(field(result.fields, "Frames read")).toMatch(/^3 from /);
    expect(samplesFor("uart")![0]!.text).toBe(UART_CAPTURE_SAMPLE);
  });

  it("tells a parity error from a framing error, and points at the baud rate for one of them", async () => {
    const settings = { [OPTION_PARITY]: "even" as const };
    const diagram = await textOf("uart", { ...settings, [OPTION_SPACED]: false }, bytes("A"));
    const bits = diagram.split("\n")[1]!.trim().split(/\s+/).pop()!;

    const flipped = [...bits];
    flipped[1] = flipped[1] === "0" ? "1" : "0";
    const parity = await run(
      "uart",
      { ...settings, [OPTION_DIRECTION]: "check" },
      bytes(flipped.join("")),
    );
    expect(field(parity.fields, "Parity errors")).toMatch(/^1, at bit offset 0/);
    expect(field(parity.fields, "Framing errors")).toBe("");

    const broken = [...bits];
    broken[broken.length - 1] = "0";
    const framing = await run(
      "uart",
      { ...settings, [OPTION_DIRECTION]: "check" },
      bytes(broken.join("")),
    );
    expect(field(framing.fields, "Framing errors")).toMatch(/baud rate or the frame format/);
  });

  it("says what it wanted when handed something that is not a bit string", async () => {
    const result = await run("uart", { [OPTION_DIRECTION]: "check" }, bytes("no bits here"));
    expect(result.error).toMatch(/Paste a run of ones and zeros/);
    const tooShort = await run("uart", { [OPTION_DIRECTION]: "check" }, bytes("0101"));
    expect(tooShort.error).toMatch(/no complete frame/);
    expect(tooShort.error).toMatch(/Inverted levels/);
  });
});

/**
 * The Char column, over all 256 bytes rather than a sample.
 *
 * It began as "the character, or a dot" and that rendered 161 of the 256 possible bytes identically --
 * every control character and every byte above 0x7f. The ones it hid are precisely the ones a serial
 * capture is full of, which is why this is walked exhaustively: 256 is small enough to cover completely,
 * and the failure mode of a lookup table is one wrong entry rather than a wrong shape.
 */
describe("the character column", () => {
  const charOf = __testing.charOf;

  it("names every byte from 0x00 to 0x7f", () => {
    const unnamed: string[] = [];
    for (let byte = 0; byte <= 0x7f; byte++) {
      // 0x2e is the full stop, whose name legitimately *is* a dot -- so the column alone cannot tell it
      // from a byte above 0x7f, and the Byte column beside it is what disambiguates. Excluded here
      // rather than worked around, because renaming the period would be worse than the ambiguity.
      if (byte === 0x2e) continue;
      const name = charOf(byte);
      if (name === "." || name === "") unnamed.push(byte.toString(16));
    }
    expect(unnamed, "bytes with no name").toEqual([]);
    expect(charOf(0x2e)).toBe(".");
  });

  /**
   * The eight a serial link actually turns on, spelled out.
   *
   * A protocol framed STX ... ETX is recognisable at a glance and unreadable as ". ... ."; DC1 and DC3
   * are XON and XOFF, so a stalled link shows up in this column; and CR against LF is the difference
   * between two line endings. These are the reason the table exists rather than an ornament on it.
   */
  it("uses the standard abbreviations", () => {
    expect(charOf(0x00)).toBe("NUL");
    expect(charOf(0x02)).toBe("STX");
    expect(charOf(0x03)).toBe("ETX");
    expect(charOf(0x06)).toBe("ACK");
    expect(charOf(0x0a)).toBe("LF");
    expect(charOf(0x0d)).toBe("CR");
    expect(charOf(0x11)).toBe("DC1");
    expect(charOf(0x13)).toBe("DC3");
    expect(charOf(0x15)).toBe("NAK");
    expect(charOf(0x1b)).toBe("ESC");
    expect(charOf(0x7f)).toBe("DEL");
  });

  it("names the space rather than leaving an empty cell", () => {
    expect(charOf(0x20)).toBe("SP");
  });

  it("prints the printable range as itself", () => {
    for (let byte = 0x21; byte <= 0x7e; byte++) {
      expect(charOf(byte), byte.toString(16)).toBe(String.fromCharCode(byte));
    }
  });

  /**
   * Above 0x7f the dot is the honest answer rather than a gap.
   *
   * There is no character there without knowing which code page is in force; the Byte column already
   * carries the value; and guessing Latin-1 would put a glyph on screen the far end may never have
   * meant. In a 7-bit format those bytes are usually 7-bit ASCII with a parity bit set, which is what
   * the Bits column shows -- masked to the data width.
   */
  it("declines to guess a code page above 0x7f", () => {
    for (let byte = 0x80; byte <= 0xff; byte++) {
      expect(charOf(byte), byte.toString(16)).toBe(".");
    }
  });

  /**
   * Nothing in the column may contain a space, or it would split into two cells.
   *
   * `alignTable` separates columns by two spaces and `cells()` reads a row back by splitting on runs of
   * two or more -- but a single space inside a value would still make the column ragged and would break
   * any reader counting fields. Three characters is also the widest name, so the column never grows
   * past its own heading.
   */
  it("keeps every name a single short token", () => {
    for (let byte = 0; byte < 256; byte++) {
      const name = charOf(byte);
      expect(name.length, byte.toString(16)).toBeGreaterThan(0);
      expect(name.length, byte.toString(16)).toBeLessThanOrEqual(3);
      expect(/\s/.test(name), byte.toString(16)).toBe(false);
    }
  });

  /** And it reaches both tables, which is the point of the helper being shared. */
  it("reaches the UART diagram and the parity working alike", async () => {
    const control = new Uint8Array([0x02, 0x41, 0x03, 0x0d, 0x0a]);
    const frame = await textOf("uart", {}, control);
    expect(frame.split("\n").map((row) => cells(row)[1])).toEqual([
      "Char",
      "STX",
      "A",
      "ETX",
      "CR",
      "LF",
    ]);
    const working = await run("parity", {}, control);
    expect(working.working!.split("\n").map((row) => cells(row)[0])).toEqual([
      "Char",
      "STX",
      "A",
      "ETX",
      "CR",
      "LF",
    ]);
  });
});

describe("Hamming", () => {
  /** The published example, through the tool: 1011 encodes to 0110011. */
  it("reproduces the textbook codeword", async () => {
    // 0xb0 is the nibbles 1011 and 0000. (7,4) of 1011 is 0110011 = 0x33; of 0000 it is 0.
    expect(await hexOf("hamming", { [OPTION_HAMMING_CODE]: "7-4" }, new Uint8Array([0xb0]))).toBe(
      "3300",
    );
  });

  it("emits two codewords per input byte, high nibble first", async () => {
    const encoded = await hexOf("hamming", {}, new Uint8Array([0x4a]));
    expect(encoded).toHaveLength(4);
    // 0x4a is 0100 and 1010, and the two codewords differ -- which is what "high nibble first" means.
    expect(encoded.slice(0, 2)).not.toBe(encoded.slice(2));
  });

  it("corrects a flipped bit and names the codeword it repaired", async () => {
    const encoded = await run("hamming", {}, CHECK_INPUT);
    const corrupt = Uint8Array.from(encoded.bytes!);
    corrupt[5] = corrupt[5]! ^ 0b0001000;

    const decoded = await run("hamming", { [OPTION_DIRECTION]: "check" }, corrupt);
    expect(new TextDecoder().decode(decoded.bytes!)).toBe("123456789");
    expect(field(decoded.fields, "Corrected")).toBe("1, at codeword 5");
  });

  it("round-trips cleanly and says so", async () => {
    const encoded = await run("hamming", {}, CHECK_INPUT);
    const decoded = await run("hamming", { [OPTION_DIRECTION]: "check" }, encoded.bytes!);
    expect(new TextDecoder().decode(decoded.bytes!)).toBe("123456789");
    expect(field(decoded.fields, "Corrected")).toMatch(/None/);
  });

  /**
   * The difference between the two codes, through the tool rather than in the abstract.
   *
   * Two flipped bits: the extended form reports them as uncorrectable, the plain one silently returns
   * the wrong nibble. That is the whole argument for the default, and it is why `P004` is a warning.
   */
  it("detects a double error under (8,4) and miscorrects it under (7,4)", async () => {
    const source = new Uint8Array([0xb0]);
    const extended = await run("hamming", {}, source);
    const twoFlips = Uint8Array.from(extended.bytes!);
    twoFlips[0] = twoFlips[0]! ^ 0b10000010;
    const caught = await run("hamming", { [OPTION_DIRECTION]: "check" }, twoFlips);
    expect(field(caught.fields, "Uncorrectable")).toMatch(/1 codeword had two errors/);

    const plain = await run("hamming", { [OPTION_HAMMING_CODE]: "7-4" }, source);
    const flipped = Uint8Array.from(plain.bytes!);
    flipped[0] = flipped[0]! ^ 0b1000001;
    const missed = await run(
      "hamming",
      { [OPTION_DIRECTION]: "check", [OPTION_HAMMING_CODE]: "7-4" },
      flipped,
    );
    expect(field(missed.fields, "Uncorrectable")).toBe("");
    expect((missed.bytes![0]! >> 4) & 0xf).not.toBe(0xb);
  });

  it("says so rather than padding when the codeword count is odd", async () => {
    const result = await run("hamming", { [OPTION_DIRECTION]: "check" }, new Uint8Array([0x3c]));
    expect(field(result.fields, "Note")).toMatch(/odd number/);
    expect(result.bytes).toHaveLength(0);
  });
});

describe("lint rules", () => {
  it("emits every code it declares", () => {
    const emitted = new Set<string>();
    const TRIPS: readonly ParitySpec[] = [
      specFor("parity", {}),
      specFor("parity", { [OPTION_PARITY]: "mark" }),
      specFor("parity", { [OPTION_DATA_BITS]: 8 }),
      specFor("hamming", { [OPTION_HAMMING_CODE]: "7-4" }),
      specFor("uart", { [OPTION_BIT_ORDER]: "msb" }),
      specFor("uart", { [OPTION_PARITY]: "space" }),
    ];
    for (const spec of TRIPS) for (const d of lint(spec).diagnostics) emitted.add(d.code);
    expect([...emitted].sort()).toEqual([...RULE_CODES].sort());
  });

  it("has a fix for the two rules that offer one, and the fix silences them", () => {
    for (const spec of [
      specFor("hamming", { [OPTION_HAMMING_CODE]: "7-4" }),
      specFor("uart", { [OPTION_BIT_ORDER]: "msb" }),
    ]) {
      const before = lint(spec).diagnostics.filter((d) => d.fix);
      expect(before.length, spec.variant).toBeGreaterThan(0);
      const after = lint(applyAllFixes(spec));
      for (const d of before) {
        expect(after.diagnostics.some((a) => a.code === d.code), d.code).toBe(false);
      }
    }
  });

  /**
   * `P002` has no fix on purpose, and that is worth pinning.
   *
   * Choosing mark parity is usually *correct* -- it is what the equipment does -- so a one-click
   * "switch to even" would offer to break the link. The rule says what the setting is, not what to do.
   */
  it("offers no fix for mark parity, because there is nothing wrong to fix", () => {
    const diagnostics = lint(specFor("parity", { [OPTION_PARITY]: "mark" })).diagnostics;
    const p002 = diagnostics.find((d) => d.code === "P002")!;
    expect(p002.level).toBe("warning");
    expect(p002.fix).toBeUndefined();
    // And `P001` stands down, because "misses even numbers of errors" understates a bit that misses
    // all of them.
    expect(diagnostics.some((d) => d.code === "P001")).toBe(false);
  });

  it("leaves every tool computable after applying all fixes", async () => {
    for (const meta of PARITY_TOOLS) {
      const fixed = applyAllFixes(specFor(meta.id));
      expect(() => parityToolDefinition(meta.id).specSchema.parse(fixed)).not.toThrow();
      // BCH names its own input, because five data bits cannot hold an ASCII digit.
      const input = meta.checkInput === undefined ? CHECK_INPUT : fromHex(meta.checkInput);
      const result = await parityToolDefinition(meta.id).compute(fixed, input);
      expect(result.error, `${meta.id}: ${result.error}`).toBeUndefined();
    }
  });
});
