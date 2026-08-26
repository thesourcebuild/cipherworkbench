import type { ByteSourceMode, TextEncoding } from "@ocs/contracts";
import { CHECK_STRING } from "./test-inputs";

/**
 * What the input panel is currently holding.
 *
 * `file` is kept out of everything that persists or travels — saved state, share
 * links — for the obvious reason that a `File` handle means nothing in another
 * session, and the less obvious one that the file's *name* is often the most
 * sensitive thing about a hashing session.
 */
export interface InputState {
  mode: ByteSourceMode;
  /** The raw text as typed, in whatever mode is active. Preserved across mode switches. */
  text: string;
  textEncoding: TextEncoding;
  file?: File;
}

export const EMPTY_INPUT: InputState = {
  mode: "text",
  text: "",
  textEncoding: "utf-8",
};

/**
 * What a fresh session opens on: the standard check string, already in the box.
 *
 * Every CRC model in the catalogue publishes its check value over exactly these nine bytes, and so
 * do most of the hash vectors this repo ships -- so the first thing anyone does here is type them.
 * It is the input, not a result: with `Auto update` off nothing is computed until Compute is
 * pressed, deliberately and without exception. What fills the page on a fresh load is the Variants
 * panel, whose rows come off the spec -- so you land on a named input and a table of the algorithms
 * it can be run through, with two buttons to press.
 *
 * Kept separate from `EMPTY_INPUT`, which stays genuinely empty: the share-link tests use it as
 * their "no input" base, and quietly giving it content would change what several of them assert.
 */
export const DEFAULT_INPUT: InputState = { ...EMPTY_INPUT, text: CHECK_STRING };

/** True when there is nothing to compute over — distinct from "the input is the empty string". */
export function isInputBlank(input: InputState): boolean {
  return input.mode === "file" ? input.file === undefined : input.text === "";
}

export function describeInputSize(input: InputState, byteLength: number | undefined): string {
  if (input.mode === "file") {
    if (!input.file) return "No file chosen";
    return `${input.file.name} — ${formatBytes(input.file.size)}`;
  }
  if (input.text === "") return "";
  /**
   * Characters, when the byte count is not available.
   *
   * Which is now only the two cases where it genuinely cannot be: text that does not decode in the
   * selected source mode, and a legacy encoding whose conversion tables are still loading. The count
   * of characters is the one measurement available without decoding, and it beats the alternative --
   * this returned `""` and the panel rendered its `|| "Nothing entered yet."` fallback over text the
   * user could see, which is what it did for every input while auto-update was off.
   */
  if (byteLength === undefined) {
    const count = input.text.length;
    return `${count} ${count === 1 ? "character" : "characters"}`;
  }
  return `${formatBytes(byteLength)}`;
}

/**
 * Rounded units and nothing else: `9 bytes`, `1.4 MiB`.
 *
 * Exists because `formatBytes` appends the exact count in brackets, which is right where the figure
 * appears once and repeats itself where two of them share a sentence -- "1.4 MiB (1,507,484 bytes)
 * of 1.4 MiB (1,507,484 bytes)" states one number four times. Pair this with `formatBytes` so the
 * exact count is printed once, on whichever side is the total.
 */
export function formatBytesShort(count: number): string {
  if (count < 1024) return `${count} ${count === 1 ? "byte" : "bytes"}`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = count / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  // One decimal below 10, none above — "1.4 MiB" and "347 MiB" both read cleanly.
  const rounded = value < 10 ? value.toFixed(1) : Math.round(value).toString();
  return `${rounded} ${units[unit]}`;
}

export function formatBytes(count: number): string {
  const short = formatBytesShort(count);
  // Below a kibibyte the short form already *is* the exact count; bracketing it would read
  // "512 bytes (512 bytes)".
  return count < 1024 ? short : `${short} (${count.toLocaleString()} bytes)`;
}
