import { base64, hex } from "@scure/base";

export interface PemBlock {
  label: string;
  bytes: Uint8Array;
}

/**
 * Encodes binary DER bytes into a formatted PEM block.
 */
export function encodePem(label: string, der: Uint8Array): string {
  const b64 = base64.encode(der);
  const lines: string[] = [];
  const lineLength = 64;
  for (let i = 0; i < b64.length; i += lineLength) {
    lines.push(b64.slice(i, i + lineLength));
  }
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

/**
 * Parses all PEM blocks found in a text string.
 */
export function parseAllPem(text: string): PemBlock[] {
  const blocks: PemBlock[] = [];
  const beginMatches = [...text.matchAll(/-----BEGIN ([A-Z0-9 -]+)-----/g)];
  const endMatches = [...text.matchAll(/-----END ([A-Z0-9 -]+)-----/g)];

  if (beginMatches.length === 0 || endMatches.length === 0) {
    return [];
  }

  const count = Math.min(beginMatches.length, endMatches.length);
  for (let i = 0; i < count; i++) {
    const begin = beginMatches[i];
    const end = endMatches[i];
    if (!begin || !end || !begin[1] || begin.index === undefined || end.index === undefined) {
      continue;
    }
    const label = begin[1].trim();

    const startIndex = begin.index + begin[0].length;
    const endIndex = end.index;
    if (endIndex <= startIndex) continue;

    const body = text
      .slice(startIndex, endIndex)
      .replace(/\s+/g, "");

    try {
      const bytes = base64.decode(body);
      blocks.push({ label, bytes });
    } catch {
      // Ignore invalid blocks
    }
  }

  return blocks;
}

export type InputFormatKind = "pem" | "der" | "hex" | "unknown";

/**
 * Detects whether the input is PEM, hex-encoded DER, or raw DER bytes.
 */
export function detectInputBytes(input: Uint8Array | string): {
  kind: InputFormatKind;
  der: Uint8Array;
  label?: string;
  blocks?: PemBlock[];
} {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  if (bytes.length === 0) {
    throw new Error("Input is empty");
  }

  // Try decoding as UTF-8 string first to check for PEM or Hex
  let text = "";
  try {
    text = typeof input === "string" ? input.trim() : new TextDecoder("utf-8", { fatal: false }).decode(bytes).trim();
  } catch {
    // Binary
  }

  if (text.includes("-----BEGIN")) {
    const blocks = parseAllPem(text);
    const firstBlock = blocks[0];
    if (firstBlock) {
      return {
        kind: "pem",
        der: firstBlock.bytes,
        label: firstBlock.label,
        blocks,
      };
    }
  }

  // Check if it is a hex string (e.g. "3082...", "30:82:...", "0x30, 0x82...")
  const cleanHex = text
    .replace(/^0x/i, "")
    .replace(/0x/gi, "")
    .replace(/[\s:,\-_]+/g, "");
  if (/^[0-9a-fA-F]+$/.test(cleanHex) && cleanHex.length >= 8 && cleanHex.length % 2 === 0) {
    // If it starts with 30 (ASN.1 SEQUENCE), treat as hex DER
    if (cleanHex.startsWith("30")) {
      try {
        const der = hex.decode(cleanHex.toLowerCase());
        return { kind: "hex", der };
      } catch {
        // Fall through
      }
    }
  }

  // Check if it is a pure Base64 or Base64url string that decodes to ASN.1 DER (starts with 0x30)
  const cleanB64 = text
    .replace(/[\s\r\n]+/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  if (/^[0-9a-zA-Z+/=]+$/.test(cleanB64) && cleanB64.length >= 16) {
    try {
      const decoded = base64.decode(cleanB64);
      if (decoded.length > 0 && decoded[0] === 0x30) {
        return { kind: "der", der: decoded };
      }
    } catch {
      // Fall through
    }
  }

  // Check if raw bytes start with 0x30 (ASN.1 SEQUENCE)
  if (bytes.length > 0 && bytes[0] === 0x30) {
    return { kind: "der", der: bytes };
  }

  // Fallback: try raw bytes
  return { kind: "unknown", der: bytes };
}
