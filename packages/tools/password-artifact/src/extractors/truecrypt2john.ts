import type { ToolFileSource } from "@ocs/engine";
import { basename, hex, johnName, readExact, sourceName } from "./binary";

const HEADER_SIZE = 512;
const HIDDEN_HEADER_OFFSET = 65_536;

export interface TrueCryptOptions {
  bootMode: boolean;
}

function descriptors(
  name: string,
  header: Uint8Array,
  location: "normal" | "hidden",
  bootMode: boolean,
): string[] {
  const tags = bootMode
    ? ["truecrypt_RIPEMD_160_BOOT"]
    : ["truecrypt_RIPEMD_160", "truecrypt_SHA_512", "truecrypt_WHIRLPOOL"];
  return tags.map((tag) => `${basename(name)}:${tag}$${hex(header)}:${location}::::${name}`);
}

/** Matches run/truecrypt2john.py for password-only volume headers. */
export async function extractTrueCrypt(
  source: ToolFileSource,
  { bootMode }: TrueCryptOptions,
): Promise<string> {
  const name = johnName(sourceName(source));
  if (source.metadata.size < HEADER_SIZE) {
    throw new Error(
      `TrueCrypt volume is truncated; at least ${HEADER_SIZE} bytes are required.`,
    );
  }

  const normal = await readExact(source, 0, HEADER_SIZE, "TrueCrypt primary header");
  const lines = descriptors(name, normal, "normal", bootMode);
  if (source.metadata.size >= HIDDEN_HEADER_OFFSET + HEADER_SIZE) {
    const hidden = await readExact(
      source,
      HIDDEN_HEADER_OFFSET,
      HEADER_SIZE,
      "TrueCrypt hidden-volume header",
    );
    lines.push(...descriptors(name, hidden, "hidden", false));
  }
  return `${lines.join("\n")}\n`;
}
