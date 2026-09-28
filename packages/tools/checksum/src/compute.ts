import {
  createAdler32,
  createBcc,
  createFletcher16,
  createFletcher32,
  createLrc,
  createOnesComplementSum,
  createSumCheck,
  createTwosComplementChecksum,
  createXorChecksum,
  type ChecksumEngine,
} from "@ocs/algos";
import type { ToolResult, ToolResultField, ToolStream, ToolVariantTable } from "@ocs/engine";
import { CHECKSUM_TOOLS } from "./catalogue/tool-meta";
import { createSpec } from "./create-spec";
import {
  formatValue,
  readBccMode,
  declaredByteOrder,
  readByteOrder,
  readResult,
  readWidth,
  readWordSize,
} from "./pure";
import {
  getChecksumTool,
  requireChecksumTool,
  type ChecksumToolMeta,
} from "./catalogue/tool-meta";
import type { ChecksumSpec } from "./spec";

/** The output width in bits, which for two of the nine tools is an option. */
function widthOf(spec: ChecksumSpec, meta: ChecksumToolMeta): 8 | 16 | 32 {
  return meta.kind === "sum" || meta.kind === "twos"
    ? readWidth(spec.options, String(meta.width) as "8" | "16" | "32")
    : meta.width;
}

function engineFor(spec: ChecksumSpec, meta: ChecksumToolMeta): ChecksumEngine {
  const width = widthOf(spec, meta);
  const wordSize = readWordSize(spec.options);
  const bigEndian = readByteOrder(spec.options, declaredByteOrder(meta.defaults)) === "big";

  switch (meta.kind) {
    case "sum":
      return createSumCheck(width, wordSize, bigEndian);
    case "twos":
      return createTwosComplementChecksum(width, wordSize, bigEndian);
    case "ones":
      return createOnesComplementSum(readResult(spec.options) === "complement");
    case "xor":
      return createXorChecksum();
    case "lrc":
      return createLrc();
    case "bcc":
      return createBcc(readBccMode(spec.options));
    case "fletcher16":
      return createFletcher16();
    case "fletcher32":
      return createFletcher32(bigEndian);
    case "adler32":
      return createAdler32();
  }
}

const mask = (width: number): number => (width === 32 ? 0xffffffff : (1 << width) - 1);

/** True when nothing has been changed from the tool's defaults, so the check value still applies. */
function atDefaults(spec: ChecksumSpec, meta: ChecksumToolMeta): boolean {
  return meta.exposes.every(
    (id) => (spec.options[id] ?? meta.defaults[id]) === meta.defaults[id],
  );
}

/**
 * The values behind the value.
 *
 * Every field here is derived from the final result and the spec, never carried out of the engine.
 * That is deliberate: the streaming path and the one-shot path must report the same thing, and the
 * only state they share at the end is the digest. It happens to be enough — a two's complement is
 * invertible, and Fletcher's two sums are literally the two halves of its output — so nothing is
 * lost by insisting on it.
 */
function resultFields(
  spec: ChecksumSpec,
  meta: ChecksumToolMeta,
  value: number,
): ToolResultField[] {
  const width = widthOf(spec, meta);
  const fields: ToolResultField[] = [];

  switch (meta.kind) {
    case "sum":
    case "twos": {
      if (meta.kind === "twos") {
        fields.push({
          label: "Sum before negation",
          value: formatValue((-value & mask(width)) >>> 0, width),
          hint: "Add this to the checksum and the low bits come to zero — which is the whole reason a protocol picks a two's complement over a plain sum.",
        });
      }
      break;
    }
    case "lrc":
      fields.push({
        label: "Sum before negation",
        value: formatValue((-value & 0xff) >>> 0, 8),
        hint: "A Modbus ASCII receiver adds every byte of the frame including the LRC and expects zero in the low eight bits.",
      });
      break;
    case "ones": {
      const complemented = readResult(spec.options) === "complement";
      const folded = complemented ? (~value & 0xffff) >>> 0 : value;
      fields.push(
        {
          label: "Folded sum",
          value: formatValue(folded, 16),
          hint: "The one's-complement sum itself: 16-bit words added with every carry out of the top fed back in at the bottom. This is the value RFC 1071 section 3 prints for its worked example.",
        },
        {
          label: "Complement",
          value: formatValue((~folded & 0xffff) >>> 0, 16),
          hint: "What an IP, TCP, UDP or ICMP header carries. Summing the whole header including this field gives 0xFFFF.",
        },
      );
      break;
    }
    case "fletcher16":
    case "fletcher32": {
      const half = meta.kind === "fletcher16" ? 8 : 16;
      const low = value & mask(half);
      const high = (value / (mask(half) + 1)) >>> 0;
      fields.push(
        {
          label: "Simple sum",
          value: formatValue(low, half),
          hint: `The running sum of the input modulo ${mask(half)}. On its own this is an ordinary sum and cannot see a reordering.`,
        },
        {
          label: "Positional sum",
          value: formatValue(high, half),
          hint: "The running sum of the sum. This is the half that makes Fletcher position-sensitive, and it is the high half of the output.",
        },
      );
      break;
    }
    case "adler32": {
      fields.push(
        {
          label: "a",
          value: formatValue(value & 0xffff, 16),
          hint: "One plus the sum of the bytes, modulo 65521. Starting from one rather than zero is what lets Adler-32 distinguish an empty input from a run of zero bytes.",
        },
        {
          label: "b",
          value: formatValue((value >>> 16) & 0xffff, 16),
          hint: "The running sum of a, modulo 65521, and the high half of the output.",
        },
      );
      break;
    }
    case "bcc":
    case "xor":
      break;
  }

  return fields;
}

/**
 * What the settings are, as opposed to what came out of them: `ToolDefinition.info`.
 *
 * The split is "would this still be true with an empty input". How the bytes are grouped, which
 * convention a BCC means, which other tool computes the same value, and what this one produces for
 * "123456789" all follow from the spec alone, so they belong under the options and stay on screen
 * whether or not anything has been typed. Everything in `resultFields` above is the opposite: each
 * of those numbers is read back out of the digest.
 */
export function checksumInfo(spec: ChecksumSpec): ToolResultField[] {
  const meta = requireChecksumTool(spec.variant);
  const fields: ToolResultField[] = [];

  const grouped = meta.kind === "sum" || meta.kind === "twos" || meta.kind === "fletcher32";
  const wordSize = meta.kind === "fletcher32" ? 16 : readWordSize(spec.options);
  if (grouped) {
    fields.push({
      label: "Grouping",
      value:
        wordSize === 8
          ? "byte at a time"
          : `${wordSize}-bit words, ${readByteOrder(
              spec.options,
              declaredByteOrder(meta.defaults),
            )}-endian`,
      ...(wordSize > 8
        ? {
            hint:
              meta.kind === "fletcher32"
                ? "Fletcher-32 sums words, and its definition does not say which end of a word the first byte lands on. Little-endian is what the published vectors use, because the reference implementations walk a uint16_t pointer. Big-endian gives the same four bytes in a different order, so a value that looks byte-swapped is this setting rather than a fault."
                : "A trailing partial word is zero-padded, so an input whose length is not a multiple of the word size has the same checksum as the same input with zero bytes appended.",
          }
        : {}),
    });
  }

  if (meta.kind === "bcc") {
    fields.push({
      label: "Mode",
      value: readBccMode(spec.options) === "xor" ? "XOR (ISO 1155)" : "Additive sum",
    });
  }

  // The equivalences, stated rather than hidden. Someone who has tried both members of a pair and
  // got the same answer twice should be told that is expected, not left suspecting the tool.
  if (meta.sameAs) {
    const other = getChecksumTool(meta.sameAs);
    if (other) {
      fields.push({
        label: "Same as",
        value: other.label,
        hint: `${other.label} computes an identical value in its default configuration. Both are listed because the protocols name them separately, not because the arithmetic differs.`,
      });
    }
  }

  if (atDefaults(spec, meta)) {
    fields.push({
      label: "Check value",
      value: meta.check,
      hint: "This tool's published value for the ASCII input \"123456789\" — the RevEng CRC catalogue's convention, borrowed here because these algorithms have ambiguous names. Enter that as the input and the two should match.",
    });
  }

  return fields;
}

export async function computeChecksum(
  spec: ChecksumSpec,
  input: Uint8Array,
): Promise<ToolResult> {
  const meta = requireChecksumTool(spec.variant);
  const engine = engineFor(spec, meta);
  engine.update(input);
  return {
    bytes: engine.digestBytes(),
    fields: resultFields(spec, meta, engine.digest()),
  };
}

/**
 * All nine checksums over the same input.
 *
 * The whole family rather than one tool's parameter grid, because this family *is* nine tools -- one
 * per named algorithm, since the name is what people arrive searching for (see `CHECKSUM_TOOLS`).
 * The sibling set of "Fletcher-16" is therefore the other eight, not some inner axis it does not
 * have.
 *
 * It earns its place here more than anywhere else in the app, for a reason the family's own notes
 * already give: three of the nine compute the *same value* by construction. LRC is the two's
 * complement sum at eight bits, and a BCC in XOR mode is the XOR checksum. Someone with a mystery
 * byte off a serial link tries one, gets a match, and cannot tell whether they have identified the
 * algorithm or merely one of three names for it. The table shows all nine at once and the `Same as`
 * column says which coincidences are expected.
 *
 * Each row runs at *its own* defaults, not the current tool's -- the width and byte-order options
 * belong to individual tools and mean nothing to the rest.
 */
export function checksumVariants(spec: ChecksumSpec): ToolVariantTable {
  return {
    noun: "checksum",
    columns: ["Check", "Width", "Same as"],
    rows: CHECKSUM_TOOLS.map((tool) => ({
      id: tool.id,
      label: tool.label,
      stream: () => createChecksumStream(createSpec({ variant: tool.id })),
      selected: tool.id === spec.variant,
      cells: [
        tool.check,
        `${tool.width} bits`,
        tool.sameAs === undefined ? "—" : requireChecksumTool(tool.sameAs).label,
      ],
    })),
  };
}

export function createChecksumStream(spec: ChecksumSpec): ToolStream {
  const meta = requireChecksumTool(spec.variant);
  const engine = engineFor(spec, meta);
  let finished = false;

  return {
    update(chunk) {
      if (finished) throw new Error(`Cannot update a ${meta.label} stream after finish().`);
      engine.update(chunk);
    },
    finish() {
      if (finished) throw new Error(`finish() called twice on the same ${meta.label} stream.`);
      finished = true;
      // `digestBytes` before `digest`: both flush the word accumulator and both are idempotent, but
      // reading them in this order keeps the pair honest if that ever stops being true.
      const bytes = engine.digestBytes();
      return { bytes, fields: resultFields(spec, meta, engine.digest()) };
    },
  };
}
