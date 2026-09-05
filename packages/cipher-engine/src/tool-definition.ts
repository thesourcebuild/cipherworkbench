import type { ZodType } from "zod";
import type { LintRule } from "@ocs/contracts/diagnostic";
import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { OptionValues } from "@ocs/contracts/options";
import type { OptionCatalogue } from "./catalogue/options";
import type { OptionGroupMeta } from "./catalogue/groups";

/**
 * The two fields every tool's spec must have, whatever else it adds.
 *
 * Stated as a constraint rather than left as a convention because two pieces of
 * generic UI depend on it and neither can know the concrete spec type: the
 * options form, which reads and writes `options` for any tool, and the share-link
 * builder, which has to strip every option the catalogue marks `secret` before
 * putting a spec in a URL. A tool that kept its key somewhere other than
 * `options` would silently defeat that stripping — so the shape is enforced here
 * instead.
 */
export interface ToolSpecBase {
  specVersion: number;
  options: OptionValues;
}

/**
 * `checksum` is a family of its own rather than a corner of `crc`, because the two are a different
 * idea rather than two strengths of the same one. A CRC is polynomial division and detects every
 * burst error shorter than its width; a sum, an XOR, an LRC or a Fletcher is addition, chosen
 * because it costs almost nothing on an eight-bit micro. Filing them together would imply a
 * spectrum where there is a category difference.
 */
export type ToolFamily =
  | "hash"
  | "crc"
  | "checksum"
  | "parity"
  | "mac"
  | "kdf"
  | "cipher"
  /**
   * Separate from `cipher`, on the same reasoning that keeps `crc` and `checksum` apart.
   *
   * A classical cipher has no key bytes, no block, no nonce and no mode; its alphabet is 26 letters
   * rather than 256 byte values, and its output is text. Filing Caesar under the heading that holds
   * AES-GCM would imply a spectrum -- the same cipher idea at different strengths -- where there is a
   * category difference: one is encryption you break with a pencil, the other is encryption nobody
   * breaks. It would also put "Caesar" and "AES-256-GCM" side by side in one sidebar group.
   */
  | "classical"
  | "asymmetric"
  | "encoding"
  | "format";

/**
 * How much this tool's output should be trusted, shown as a badge in the tool
 * header and used to sort search results so `sha256` outranks `md5`.
 *
 *  modern     — fit for new work today.
 *  legacy     — still correct, still needed for interop, no longer a first choice
 *               (SHA-1 for a git object id; RIPEMD-160 for a Bitcoin address).
 *  broken     — do not use for anything security-bearing. MD5, RC4, DES, ECB.
 *  not-a-mac  — works exactly as specified and provides no integrity guarantee
 *               whatsoever against a deliberate change. Every CRC, Adler-32,
 *               xxHash. The single most common misuse this app can head off.
 *  not-encryption — reversible by anyone, with no key involved. Every encoding.
 *               Its own value rather than reusing `not-a-mac`, because the badge is
 *               read as a sentence about the tool in front of you and "Not a MAC"
 *               on a Base64 tool answers a question nobody asked. What someone
 *               needs to be told about Base64 is that it hides nothing.
 */
export type SecurityPosture = "modern" | "legacy" | "broken" | "not-a-mac" | "not-encryption";

/** Which way the bytes flow. Hashes are forward-only; ciphers and encodings do both. */
export type ToolDirection = "forward" | "inverse";

/**
 * Cheap metadata for a tool, safe to bundle eagerly for every registered tool so
 * the sidebar can list them all without loading any tool's compute code.
 */
export interface ToolManifest {
  id: string;
  label: string;
  family: ToolFamily;
  /** Sidebar grouping within the family — "SHA-2", "Keccak", "CRC-32", "Symmetric". */
  category: string;
  tags: string[];
  summary: string;
  directions: readonly ToolDirection[];
  /**
   * What this tool is and is not, as one word, rendered as the header badge.
   *
   * There used to be a `securityNote` beside it: a sentence per tool explaining the posture, shown
   * in a banner under the header and as the badge's tooltip. It is gone on the user's instruction,
   * and the reason it is not missed is that the posture had grown into the *wrong* place for that
   * sentence. A note is written once and a merged tool covers a grid -- CRC-8 is thirteen models
   * from SMBus to Bluetooth LE to satellite broadcast, and its note claimed all of them were
   * designed for a two-wire bus. The Checks panel is where a caveat belongs, because a lint rule
   * reads the spec and can therefore be right about the configuration actually selected. `C007` is
   * the worked example: it replaced twenty static notes whose figures were wrong nine times in ten.
   */
  security: SecurityPosture;
  /** Output spellings this tool offers, narrowest-first. A digest omits `decimal`; a CRC includes it. */
  outputEncodings: readonly OutputEncoding[];
  /**
   * Whether the message comes from the Input panel at all.
   *
   * False for a *generator* -- `uuid` and `password`, whose whole input is their settings -- and for
   * TupleHash, whose input is a tuple supplied as an option rather than a byte string. A text box
   * that is read by nothing is worse than no text box: it invites someone to type into it and then
   * ignores what they typed, which is indistinguishable from the tool being broken.
   *
   * Read in four places and each is a real consequence, which is why this is a manifest field rather
   * than a family's private business: the Input panel drops its source, encoding, Clear and textarea
   * chrome; `useCompute` stops treating an empty box as "nothing to compute"; the Compute button
   * stays enabled; and the Test input menu -- which fills a box -- does not appear.
   *
   * Distinct from `supportsFile`, which is about *how* a message arrives rather than whether one
   * does. A tool reading no input cannot support a file either, and a test asserts that implication
   * rather than leaving the two to be set consistently by hand.
   */
  readsInput: boolean;
  /**
   * Whether "paste what you expected and see if it matches" means anything for this tool.
   *
   * False for the `format` family and for the UART frame diagram, and the test is not "could the panel
   * run" but "is there a value somebody could already have". Three reasons a tool fails it:
   *
   *  - **The output is a document.** A pretty-printed XML file or a decoded JWT is text to read, not a
   *    value to compare byte for byte -- and `VerifyPanel` compares `result.bytes`, which a text result
   *    does not have, so the panel rendered a box that could never say anything either way. A control
   *    that renders and does nothing is this repo's most-repeated defect.
   *  - **The output is a diagram.** The UART tool draws a labelled table of bits; there is no expected
   *    value for it. Its decode direction does return bytes, but those are recovered *data* rather than
   *    a published value anybody holds in advance.
   *  - **The output is freshly random.** A v4 UUID or a generated password cannot be checked against
   *    something you already have, because nothing you already have could be it.
   *
   * A manifest field rather than an inference from `outputEncodings` or from `result.bytes`: inferring
   * from the result would make the panel appear and disappear as the direction changes, and inferring
   * from the encodings would be right today and wrong for the first byte-output tool nobody verifies.
   * A test asserts the one implication that always holds -- a tool whose only output encoding is
   * `utf-8` has no bytes to compare and must not offer this.
   */
  supportsVerify: boolean;
  /** Whether file input is offered at all. */
  supportsFile: boolean;
  /**
   * Whether the tool can consume input incrementally — i.e. whether it
   * implements `createStream`. True for every digest and CRC; false for AEAD
   * ciphers, which cannot emit an authenticated result until they have seen
   * everything. A `supportsFile && !streaming` tool reads the file into memory
   * and says so, rather than pretending to stream.
   */
  streaming: boolean;
}

/**
 * A tool's output. Deliberately not just `Uint8Array`: a cipher needs to hand
 * back an IV and an auth tag alongside the ciphertext, a JWT decoder has no
 * bytes at all, and a failed decryption is a *result* the UI must render — not
 * an exception that unmounts the panel.
 */
export interface ToolResult {
  /** The primary output, spelled by the result panel using the chosen `OutputEncoding`. */
  bytes?: Uint8Array;
  /** For tools whose output is natively text (JSON formatting, decoded JWT, case conversion). */
  text?: string;
  /** Secondary labelled values: IV, auth tag, salt, derived key parameters, JWT claims. */
  fields?: readonly ToolResultField[];
  /**
   * The tool's working: a monospace block showing how the answer was arrived at, per unit.
   *
   * Distinct from all three of the members around it, and the divisions are worth stating because
   * this is the fourth place a family can put something.
   *
   *  - `fields` is label-and-value pairs. It renders in a table cell with `break-all`, so a
   *    multi-line block put there loses its alignment -- which is the whole content of a working.
   *  - `ToolDefinition.tables` is what the *algorithm* is made of and takes no input, so it cannot
   *    show a derivation over the bytes somebody typed.
   *  - `text` is the primary output and is spelled instead of the bytes, so a tool cannot use it for
   *    a working and still hand back bytes to copy.
   *
   * The immediate need is the parity tool: `0123456789` under the defaults gives ten parity bits, and
   * the useful thing to see is the byte, its bits, how many are set and what that makes the bit --
   * which is a table, per input byte. It is a general member rather than a parity one because most of
   * this repo's families have the same thing to show: a CRC's register after each byte, a checksum's
   * running sum, Hamming's syndrome per codeword.
   *
   * Rendered below the fields, in the same bounded `MonoBlock` the primary value uses -- so it scrolls
   * rather than growing the page, and its columns are not wrapped. A family producing one is expected
   * to cap the row count itself and say so, because "the first 256 of 4 million" is information and a
   * silent truncation is not.
   */
  working?: string;
  /**
   * Set when the tool ran and could not produce a result — a GCM tag that did
   * not verify, ciphertext too short to contain an IV, malformed JSON. This is
   * the normal failure channel; `compute` throws only on genuine programming
   * errors.
   */
  error?: string;
}

export interface ToolResultField {
  label: string;
  value: string;
  /** Rendered masked with a reveal toggle, and never copied by "Copy all". */
  secret?: boolean;
  /** One line explaining what this field is and whether it must be kept. */
  hint?: string;
}

/**
 * A reference table an algorithm is made of, for the Table panel.
 *
 * Not a result. A CRC's 256-entry lookup table is decided the moment you pick MODBUS from a
 * dropdown -- it does not depend on the input and does not change when it does, the same test
 * `info()` passes and `ToolResult.fields` fails. It is here rather than in `info()` because a
 * 256-cell grid is not a label and a value.
 *
 * Generic on purpose. The immediate need is CRC, but every table-driven algorithm in this repo has
 * one of these behind it -- AES's S-box, DES's eight, Blowfish's four from pi, BelT's H-block,
 * Camellia's rotations -- and a family that wants to show one now costs a `tables()` and nothing
 * else. A CRC-only panel would have been the mistake `CLAUDE.md` names: a component for one tool.
 */
/**
 * One sibling variant: what it is called, its parameters, and a way to compute it.
 *
 * See `ToolDefinition.variants`.
 */
export interface ToolVariant {
  /** Stable within the tool: a React key, and what a probe asks for. */
  id: string;
  /** What the variant calls itself -- the name a standard or a dropdown uses. */
  label: string;
  /**
   * Other names for the same thing, stacked under the label.
   *
   * Worth its own field rather than being folded into `label`, because it is what makes the table
   * usable: nobody is looking for "CRC-8/I-432-1", they are looking for "CRC-8/ITU", and a row that
   * shows only the canonical name is a row they scroll past.
   */
  aliases?: readonly string[];
  /**
   * A *fresh* stream for one run, created on demand.
   *
   * A factory rather than an instance, and that is what lets the panel exist before anything has been
   * computed: the names and the parameters are spec-derived and render immediately, while building
   * twenty CRC engines -- twenty 256-entry tables, in BigInt above width 32 -- is paid for only when
   * Run is pressed. Called once per run, never reused: a `ToolStream` is single-use by contract.
   */
  stream(): ToolStream;
  /**
   * One-time async setup this row needs before `stream()` can be called, awaited by the panel's Run.
   *
   * Exists because `stream()` is deliberately synchronous -- see above -- while an implementation may
   * arrive in a chunk of its own. The hash family loads every algorithm it implements itself through a
   * dynamic import, so opening SHA-256 does not download Tiger's S-boxes; a sibling row on another
   * page therefore has to be loaded before it can hash anything.
   *
   * The alternative was filtering unprepared rows out of the table, and it was measured before being
   * rejected: eight of the hash family's 51 categories span more than one module -- MD is md2, md4,
   * md5 and md6 in four -- so filtering would have emptied those tables rather than trimmed them, and
   * a category down to one member renders no panel at all. Preparing on Run keeps the rows visible
   * from the moment the tool loads, which is what makes the table spec-derived, and pays for the
   * loading exactly when the user asks for values.
   *
   * Must be idempotent. The panel awaits every row's before building any stream, so a family that
   * needs nothing simply omits it.
   */
  prepare?(): Promise<void>;
  /** True for the variant the tool is currently set to, which the panel marks. */
  selected?: boolean;
  /**
   * One string per entry in `ToolVariantTable.columns`, in that order.
   *
   * Pre-formatted, unlike `bytes`. These are parameters rather than output -- a polynomial is `0x07`
   * whatever encoding the Result panel is set to -- so the family that knows what they mean formats
   * them, and the panel does not try to.
   */
  cells: readonly string[];
}

/**
 * The variants table: what the columns are, and the rows under them.
 *
 * The columns come back *with* the rows rather than from a second member, because a header list and
 * a cell list that have to agree are exactly the mirror this repo keeps finding drifted -- the MAC
 * family's `EXACT_KEY_LENGTHS`, the hash family's duplicated `outputLen`. One return value, one
 * length to get right, and `cells.length !== columns.length` is a bug a test can state.
 */
export interface ToolVariantTable {
  /** Headings for the columns after Model and Result. Empty for a family with nothing to add. */
  columns: readonly string[];
  rows: readonly ToolVariant[];
  /**
   * What one row *is*, singular, for the count badge: "model", "checksum", "algorithm".
   *
   * Worth a field because the panel is shared and the word is not. "20 variants" under a heading
   * that already says "All variants" says the same thing twice, and the family is the only thing
   * that knows whether its rows are models of one algorithm or algorithms in their own right.
   * Defaults to "variant"; pluralised by the panel, which is safe for every noun any family has.
   */
  noun?: string;
}

/** The same input under every variant, once a run has produced them. Keyed by `ToolVariant.id`. */
export type ToolVariantValues = ReadonlyMap<string, Uint8Array>;

export interface ToolTable {
  /** Stable within a tool. Used as the selector's value when a tool offers several. */
  id: string;
  label: string;
  /** One line under the heading: what the table is and what it is for. */
  summary?: string;
  /** Cells per row. 16 for a byte-indexed table, which is what makes the index readable in hex. */
  columns: number;
  /**
   * Cell values in index order, already formatted and without a `0x` prefix.
   *
   * Strings rather than numbers because the panel does not know the width: a CRC-64 entry needs
   * sixteen hex digits zero-padded, and the tool is the only thing that knows that.
   */
  values: readonly string[];
  /**
   * Bits per entry, for the source-code export formats.
   *
   * A C array needs a type and a Rust one needs `[u32; 256]`, and neither can be guessed from a
   * string of hex digits -- a CRC-24 entry is six digits and belongs in a `uint32_t`. Rounded up to
   * 8, 16, 32 or 64 by the formatter. Omit it and the code formats fall back to the widest type,
   * which is safe and less informative.
   */
  bitWidth?: number;
  /**
   * Identifier for the exported array, in `snake_case`.
   *
   * One spelling in, four out: the formatter derives `crc_table` for C, `CRC_TABLE` for Rust and
   * Python and `crcTable` for Go, because emitting a C identifier into Go source is the sort of
   * detail that makes a paste look machine-generated. Defaults to `table`.
   */
  name?: string;
}

/** Incremental input, for file-sized data. Only tools with `streaming: true` provide one. */
export interface ToolStream {
  update(chunk: Uint8Array): void;
  finish(): ToolResult;
}

/**
 * The full contract a `packages/tools/<family>` package implements for one tool.
 * Loaded on demand (behind a dynamic `import()` keyed by `id`) once a tool is
 * actually selected — `ToolManifest` alone is what the sidebar costs.
 */
/**
 * A canned input this tool is worth trying on, offered in the Test input menu.
 *
 * The app has always had two of these -- the CRC check string and a wall of Lorem -- and they are
 * the right two for a digest, where the input is *bytes* and any bytes will do. They are the wrong
 * two for a tool whose input is a *document*: `123456789` is not JSON, not XML and not a JWT, so a
 * format tool opening on it shows a parse error where an answer should be, which reads as the tool
 * being broken rather than as the input being nonsense.
 *
 * So a family may declare its own, and the first one is also what a fresh box is seeded with. That
 * seeding is deliberately conservative -- it happens only while the input is still whatever the app
 * put there, never over something typed -- because an input box that rewrites itself when you change
 * tool is worse than one that holds the wrong thing.
 */
export interface ToolSample {
  id: string;
  /** Shown in the menu. Keep it short; the note carries the explanation. */
  label: string;
  /** Tooltip: what it is for, rather than what it says. */
  note: string;
  text: string;
}

export interface ToolDefinition<TSpec extends ToolSpecBase> extends ToolManifest {
  groups: Record<string, OptionGroupMeta>;
  catalogue: OptionCatalogue;
  lintRules: readonly LintRule<TSpec>[];
  createSpec(options?: unknown): TSpec;
  specSchema: ZodType<TSpec>;
  /** One human sentence describing what these settings will do. */
  describe(spec: TSpec): string;
  /**
   * What these settings *are*, as a table, for the Info section under the options.
   *
   * A pure function of the spec, exactly like `describe` — which is what makes it worth having as
   * its own member rather than as more fields on `ToolResult`. A CRC's seven parameters are decided
   * the moment you pick MODBUS from a dropdown; they do not depend on the input, they do not change
   * when it does, and they should not appear and disappear with a result. Putting them here means
   * they are on screen whenever the tool is, including before anything has been typed.
   *
   * `ToolResult.fields` keeps what genuinely comes *out* of a computation: an auth tag, a generated
   * keypair, the two halves of a Fletcher sum. The division is "would this still be true with an
   * empty input" — if yes it belongs here, and a family that answers no for everything simply omits
   * this.
   */
  info?(spec: TSpec): ToolResultField[];
  /**
   * How many random bytes the Generate button beside a `bytes` option should produce, for this spec.
   *
   * `OptionDef.bytesLength.generate` is a single number in the catalogue, and the catalogue is
   * resolved **once per tool** -- so it cannot know that AES-CBC wants a 16-byte IV while AES-GCM
   * wants 12. It was a static 12, which meant Generate filled the field with a value the tool then
   * refused: measured across every cipher and mode, eleven combinations were broken that way, and
   * five of them were AES's own (CTR, CBC, OFB, CFB and XTS). Nothing failed, because a rejected IV
   * looks exactly like an IV somebody typed wrongly.
   *
   * A function of the spec fixes it at the root rather than per tool. Return `undefined` to fall back
   * to the catalogue's static number, which is the right answer wherever the length does not depend
   * on anything -- ChaCha20's nonce is 12 whatever else is selected.
   *
   * Purely about *how many bytes to offer*; it decides nothing about what is accepted. The resolver
   * still owns that, and must, because a length arriving from a share link never went through this.
   */
  generateLength?(spec: TSpec, optionId: string): number | undefined;
  /**
   * The byte lengths this option will actually accept for *this* spec, narrowing what the catalogue
   * could declare.
   *
   * The other half of `generateLength`'s problem, and it was reported the same way: `Generate` under
   * AES-XTS correctly produced 64 bytes and the field then said "64 bytes -- needs 16, 24 or 32".
   * Both statements came from one catalogue, which is resolved once per tool and so has to declare
   * the union across every mode -- and 64 was not even in AES's union, so a valid XTS key had been
   * called invalid all along. The Generate fix only made it visible, because before that the button
   * produced 32, which the form happened to accept.
   *
   * Returning `undefined` falls back to the option's own `bytesLength`, which is right wherever the
   * accepted set depends on nothing. Where it is implemented the form uses it for both the validity
   * check and the hint, so the two cannot disagree.
   *
   * A *set* rather than a single number, because CCM accepts 7 to 13 and OCB 1 to 15 -- the same
   * reason `acceptedNonceLengths` exists in the cipher family and is what this reuses there.
   */
  acceptedByteLengths?(spec: TSpec, optionId: string): readonly number[] | undefined;
  /**
   * Reference tables these settings imply, for the Table panel. Omit for a tool with none.
   *
   * A pure function of the spec, like `describe` and `info`. Returning more than one is how a tool
   * offers orientations or variants -- CRC returns its lookup table msb-first and lsb-first -- and
   * the panel renders a selector when it gets more than one rather than the family inventing a
   * control for it.
   */
  tables?(spec: TSpec): readonly ToolTable[];
  /**
   * The same input under every sibling variant of this tool, for the Variants panel.
   *
   * The generic version of what crccalc.com and the sibling `web-cryptography` project do for CRC:
   * on CRC-8 they show all twenty CRC-8 models computed over what you typed, so you can identify an
   * unknown checksum by finding the row that matches it. That is a genuinely useful thing and it is
   * not CRC-specific -- any family whose tool covers a set of related functions can answer it, which
   * is why this is a member here rather than a component in the CRC family.
   *
   * A pure function of the spec, like `tables` and `info` -- it returns the *rows*, not the values,
   * so the names and parameters are on screen from the moment the tool loads. Each row carries a
   * `stream()` factory instead, and `runStreams` feeds one pass of the input to all of them.
   *
   * That split is what makes it viable on a large file. One read, N engines, one progress figure; the
   * marginal cost of a second variant is a table lookup per byte. It is also why the panel has its
   * own Run button rather than riding on `compute`: twenty engines over a hundred gigabytes is a
   * decision someone should make deliberately, not a thing that happens because they typed.
   *
   * Bytes come back from the streams, not from here, so the panel spells them in whichever output
   * encoding is selected -- the same reason `ToolResult.bytes` is bytes.
   */
  variants?(spec: TSpec): ToolVariantTable;
  /**
   * Inputs worth trying this tool on, offered in the Test input menu above the two generic ones.
   *
   * Not a function of the spec, unlike everything above: a sample is an *input*, and the whole point
   * is that it can be loaded before any setting has been touched. Omit for a tool whose input is
   * arbitrary bytes -- which is most of them -- and the generic two are then all that is offered.
   *
   * Whatever a family puts here has to compute cleanly under the tool's own default spec. A sample
   * that produces a parse error is worse than no sample, so there is a test over every one of them.
   */
  samples?: readonly ToolSample[];
  /**
   * The whole point of the tool. Async because some backends are (WebCrypto's
   * SubtleCrypto, Argon2's memory-hard loop yielding to the event loop) even
   * though most digests are synchronous.
   */
  compute(spec: TSpec, input: Uint8Array): Promise<ToolResult>;
  /**
   * Required when `streaming` is true, absent otherwise. The invariant every
   * streaming tool is tested for: feeding the same bytes through `createStream`
   * in arbitrary chunks must equal `compute` on the whole buffer.
   */
  createStream?(spec: TSpec): ToolStream;
  /**
   * Which `availableOn` tag(s) the current spec selects, so the options form knows which options
   * to show. Omit for a tool whose options never vary.
   *
   * Returning an array is for an algorithm that sits on more than one axis at once: cSHAKE is an
   * XOF *and* takes a customisation string *and* takes a function name, and ParallelHash adds a
   * block size. A single tag forced all of those onto one axis, which was fine until the SHA-3
   * addons arrived. Most families still return one string.
   */
  variantTag?(spec: TSpec): string | readonly string[] | undefined;
  /**
   * Whether this tool reads an input for *this* spec, overriding the static `ToolManifest.readsInput`.
   *
   * Most tools either always read input (like SHA-256 or AES) or never read input (like UUID).
   * Asymmetric tools offer multiple operations: `sign` and `encrypt` read input, while `generate`
   * reads no message input. When this returns false and the tool has no input material, the workbench
   * drops the input box and auto-update switch and renders the tool as a generator with a single
   * "Generate" action button.
   */
  readsInputForSpec?(spec: TSpec): boolean;
}

