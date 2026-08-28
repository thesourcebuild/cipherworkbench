import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { FORMAT_TOOLS, type FormatToolMeta } from "./catalogue/tool-meta";

/**
 * One entry, and the result panel's encoding selector therefore does not appear.
 *
 * Nine of the ten tools in this family return `ToolResult.text` -- a formatted document, a
 * percent-encoded string, a list of UUIDs -- which `ResultPanel` renders verbatim without consulting
 * this list. The encoding menu only means something where the output is *bytes* that could be spelled
 * several ways, and offering "Base64" over a pretty-printed XML document would be a control that
 * either does nothing or does something nobody asked for. `ResultPanel` hides the selector at a
 * single entry, which is exactly the intent.
 */
const TEXT_ONLY: readonly OutputEncoding[] = ["utf-8"];

/**
 * And the one tool whose result *is* bytes, which is exactly the case the note above describes.
 *
 * `hex` first, because that is how a key or an IV is read and pasted. `utf-8` is deliberately absent:
 * random bytes are not text, and decoding them as UTF-8 produces replacement characters and a
 * copy-paste that loses data. Every other entry is a spelling of the same bytes.
 */
const BYTE_ENCODINGS: readonly OutputEncoding[] = [
  "hex-upper",
  "hex",
  "base64",
  "base64url",
  "base32",
  "decimal",
  "binary",
];

function toManifest(meta: FormatToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "format",
    category: meta.category,
    tags: [...meta.tags],
    directions: meta.bidirectional ? ["forward", "inverse"] : ["forward"],
    summary: meta.summary,
    /**
     * `not-encryption`, the posture `@ocs/encoding` introduced, and it is the honest one for all
     * eight.
     *
     * Six of them are transformations that anyone can reverse -- which is the point of them -- and
     * `not-a-mac` would answer a question nobody asked of a URL encoder. The two generators are a
     * different case worth being careful about: a v4 UUID and a generated password *are* produced
     * from a CSPRNG, and calling them `modern` would read as a claim about the strength of whatever
     * you do with them. The badge says what the tool is, and the Checks panel is where the caveats
     * about entropy and about JWT verification live.
     */
    security: "not-encryption",
    outputEncodings: meta.emitsBytes ? BYTE_ENCODINGS : TEXT_ONLY,
    /**
     * File input, except for the generators.
     *
     * A 4 GB file is a reasonable thing to hand a JSON formatter and an unreasonable thing to hand a
     * UUID generator, which would read it and throw it away. `supportsFile: false` removes the File
     * entry from the source dropdown rather than leaving it there to be ignored.
     */
    readsInput: meta.usesInput,
    /**
     * None of the ten, and for two different reasons.
     *
     * Six produce a *document* -- a formatted JSON file, a decoded JWT, a converted identifier -- which
     * is text to read rather than a value to compare byte for byte. And the two generators produce
     * something freshly random, so nothing anybody already has could be it. `VerifyPanel` compares
     * `result.bytes` and nine of the ten return `text`, so it rendered a box that could never say
     * anything either way.
     *
     * `randombytes` is the interesting case and the answer is the same: it genuinely returns bytes, so
     * the panel *could* compare them -- and there is nothing to compare against, because the whole
     * point is that nobody has seen these bytes before. The registry test's implication runs one way
     * only (utf-8-only output means no Verify), which is what leaves room for this.
     */
    supportsVerify: false,
    supportsFile: meta.usesInput,
    /**
     * No streaming, and it is a property of the formats rather than a shortcut.
     *
     * Every one of these needs the whole document before it can emit anything: a JSON parser cannot
     * know the input is valid until the last brace, an XML formatter cannot indent a tree it has not
     * finished reading, and a percent-decoder handed a chunk boundary mid-escape would corrupt the
     * byte. Offering it for none is the honest answer; file input reads into memory and the Input
     * panel says so.
     */
    streaming: false,
  };
}

export const FORMAT_MANIFESTS: readonly ToolManifest[] = FORMAT_TOOLS.map(toManifest);
