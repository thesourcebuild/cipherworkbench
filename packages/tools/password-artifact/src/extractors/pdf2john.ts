import type { ToolFileSource } from "@ocs/engine";
import { hex, readChunked } from "./binary";

const MAX_PDF_BYTES = 64 * 1024 * 1024;

function latin1(bytes: Uint8Array): string {
  let output = "";
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    output += String.fromCharCode(
      ...bytes.subarray(offset, Math.min(bytes.length, offset + chunk)),
    );
  }
  return output;
}

function isSpace(code: number): boolean {
  return code === 0 || code === 9 || code === 10 || code === 12 || code === 13 || code === 32;
}

function skipSpace(value: string, start: number): number {
  let offset = start;
  while (offset < value.length) {
    const code = value.charCodeAt(offset);
    if (isSpace(code)) {
      offset++;
      continue;
    }
    if (value[offset] === "%") {
      while (offset < value.length && value[offset] !== "\n" && value[offset] !== "\r")
        offset++;
      continue;
    }
    break;
  }
  return offset;
}

function dictionaryAt(value: string, start: number, label: string): string {
  if (value.slice(start, start + 2) !== "<<")
    throw new Error(`${label} dictionary is missing.`);
  let depth = 0;
  let offset = start;
  while (offset < value.length - 1) {
    if (value[offset] === "%") {
      while (offset < value.length && value[offset] !== "\n" && value[offset] !== "\r")
        offset++;
      continue;
    }
    if (value[offset] === "(") {
      offset++;
      let nested = 1;
      while (offset < value.length && nested > 0) {
        if (value[offset] === "\\") offset += 2;
        else {
          if (value[offset] === "(") nested++;
          if (value[offset] === ")") nested--;
          offset++;
        }
      }
      if (nested !== 0) throw new Error(`${label} contains a truncated literal string.`);
      continue;
    }
    if (value.slice(offset, offset + 2) === "<<") {
      depth++;
      offset += 2;
      continue;
    }
    if (value.slice(offset, offset + 2) === ">>") {
      depth--;
      offset += 2;
      if (depth === 0) return value.slice(start, offset);
      continue;
    }
    offset++;
  }
  throw new Error(`${label} dictionary is truncated.`);
}

function keyOffset(dictionary: string, key: string): number | undefined {
  const matches: number[] = [];
  let depth = 0;
  let offset = 0;
  while (offset < dictionary.length) {
    if (dictionary[offset] === "%") {
      while (
        offset < dictionary.length &&
        dictionary[offset] !== "\n" &&
        dictionary[offset] !== "\r"
      )
        offset++;
      continue;
    }
    if (dictionary[offset] === "(") {
      offset++;
      let nested = 1;
      while (offset < dictionary.length && nested > 0) {
        if (dictionary[offset] === "\\") offset += 2;
        else {
          if (dictionary[offset] === "(") nested++;
          if (dictionary[offset] === ")") nested--;
          offset++;
        }
      }
      if (nested !== 0) throw new Error("PDF dictionary contains a truncated literal string.");
      continue;
    }
    if (dictionary.slice(offset, offset + 2) === "<<") {
      depth++;
      offset += 2;
      continue;
    }
    if (dictionary.slice(offset, offset + 2) === ">>") {
      depth--;
      offset += 2;
      continue;
    }
    if (dictionary[offset] === "<") {
      const end = dictionary.indexOf(">", offset + 1);
      if (end < 0) throw new Error("PDF dictionary contains a truncated hex string.");
      offset = end + 1;
      continue;
    }
    if (depth === 1 && dictionary[offset] === "/") {
      const start = offset + 1;
      let end = start;
      while (end < dictionary.length && !/[\0\t\n\f\r ()<>\[\]{}/%]/.test(dictionary[end]!))
        end++;
      if (dictionary.slice(start, end) === key) matches.push(skipSpace(dictionary, end));
      offset = end;
      continue;
    }
    offset++;
  }
  if (matches.length > 1)
    throw new Error(`PDF encryption dictionary defines /${key} more than once.`);
  return matches[0];
}

function integerValue(dictionary: string, key: string, required = true): number | undefined {
  const offset = keyOffset(dictionary, key);
  if (offset === undefined) {
    if (required) throw new Error(`PDF encryption dictionary is missing /${key}.`);
    return undefined;
  }
  const match = /^[+-]?\d+/.exec(dictionary.slice(offset));
  if (!match) throw new Error(`PDF /${key} is not an integer.`);
  const value = Number(match[0]);
  if (!Number.isSafeInteger(value))
    throw new Error(`PDF /${key} exceeds the safe integer range.`);
  return value;
}

function nameValue(dictionary: string, key: string): string | undefined {
  const offset = keyOffset(dictionary, key);
  if (offset === undefined) return undefined;
  const match = /^\/([^\s<>\[\]()/%]+)/.exec(dictionary.slice(offset));
  if (!match) throw new Error(`PDF /${key} is not a name.`);
  return match[1];
}

function bytesValueAt(value: string, offset: number, label: string): Uint8Array {
  if (value[offset] === "<" && value[offset + 1] !== "<") {
    const end = value.indexOf(">", offset + 1);
    if (end < 0) throw new Error(`${label} hex string is truncated.`);
    let encoded = value.slice(offset + 1, end).replace(/[\0\t\n\f\r ]/g, "");
    if (!/^[0-9a-f]*$/i.test(encoded)) throw new Error(`${label} contains invalid hex data.`);
    if (encoded.length % 2) encoded += "0";
    return Uint8Array.from({ length: encoded.length / 2 }, (_, index) =>
      Number.parseInt(encoded.slice(index * 2, index * 2 + 2), 16),
    );
  }
  if (value[offset] !== "(") throw new Error(`${label} is not a PDF string.`);
  const output: number[] = [];
  let nested = 1;
  for (let index = offset + 1; index < value.length; index++) {
    const character = value[index]!;
    if (character === "\\") {
      index++;
      if (index >= value.length) throw new Error(`${label} escape is truncated.`);
      const escaped = value[index]!;
      const controls: Record<string, number> = { n: 10, r: 13, t: 9, b: 8, f: 12 };
      if (controls[escaped] !== undefined) output.push(controls[escaped]);
      else if (escaped === "\n") continue;
      else if (escaped === "\r") {
        if (value[index + 1] === "\n") index++;
      } else if (/[0-7]/.test(escaped)) {
        let octal = escaped;
        while (octal.length < 3 && /[0-7]/.test(value[index + 1] ?? ""))
          octal += value[++index];
        output.push(Number.parseInt(octal, 8) & 0xff);
      } else output.push(escaped.charCodeAt(0) & 0xff);
      continue;
    }
    if (character === "(") nested++;
    if (character === ")") {
      nested--;
      if (nested === 0) return Uint8Array.from(output);
    }
    if (nested > 0) output.push(character.charCodeAt(0) & 0xff);
  }
  throw new Error(`${label} literal string is truncated.`);
}

function bytesValue(dictionary: string, key: string, required = true): Uint8Array | undefined {
  const offset = keyOffset(dictionary, key);
  if (offset === undefined) {
    if (required) throw new Error(`PDF encryption dictionary is missing /${key}.`);
    return undefined;
  }
  return bytesValueAt(dictionary, offset, `PDF /${key}`);
}

function findTrailer(text: string): string {
  let search = text.length;
  while (search > 0) {
    const index = text.lastIndexOf("trailer", search);
    if (index < 0) break;
    const start = skipSpace(text, index + 7);
    if (text.slice(start, start + 2) === "<<") return dictionaryAt(text, start, "PDF trailer");
    search = index - 1;
  }
  throw new Error(
    "PDF trailer dictionary was not found; xref-stream-only PDFs are unsupported.",
  );
}

function encryptionDictionary(text: string, trailer: string): string {
  const offset = keyOffset(trailer, "Encrypt");
  if (offset === undefined)
    throw new Error("PDF is not encrypted: the trailer has no /Encrypt entry.");
  if (trailer.slice(offset, offset + 2) === "<<")
    return dictionaryAt(trailer, offset, "PDF encryption");
  const reference = /^(\d+)\s+(\d+)\s+R\b/.exec(trailer.slice(offset));
  if (!reference)
    throw new Error("PDF /Encrypt is not a supported dictionary or indirect reference.");
  const object = new RegExp(
    `(?:^|[\\r\\n])\\s*${reference[1]}\\s+${reference[2]}\\s+obj\\b`,
    "g",
  );
  const matches = [...text.matchAll(object)];
  if (matches.length !== 1) throw new Error("PDF encryption object is missing or ambiguous.");
  const match = matches[0]!;
  const start = skipSpace(text, match.index! + match[0].length);
  return dictionaryAt(text, start, "PDF encryption");
}

/** Canonical pdf2john.py descriptor for standard-handler revisions 2 through 6. */
export async function extractPdf(source: ToolFileSource): Promise<string> {
  const bytes = await readChunked(source, 0, source.metadata.size, MAX_PDF_BYTES, "PDF file");
  if (latin1(bytes.subarray(0, Math.min(8, bytes.length))).match(/^%PDF-\d\.\d/) === null) {
    throw new Error("PDF header magic or version is invalid.");
  }
  const text = latin1(bytes);
  const trailer = findTrailer(text);
  const dictionary = encryptionDictionary(text, trailer);
  if (nameValue(dictionary, "Filter") !== "Standard") {
    throw new Error("PDF uses an unsupported non-Standard security handler.");
  }
  const algorithm = integerValue(dictionary, "V")!;
  const revision = integerValue(dictionary, "R")!;
  if (![1, 2, 3, 4, 5].includes(algorithm) || ![2, 3, 4, 5, 6].includes(revision)) {
    throw new Error(
      `Unsupported PDF encryption algorithm V=${algorithm}, revision R=${revision}.`,
    );
  }
  const length = integerValue(dictionary, "Length", false) ?? 40;
  const permissions = integerValue(dictionary, "P")!;
  if (length <= 0 || length > 256 || length % 8 !== 0)
    throw new Error(`Unsupported PDF key length ${length}.`);
  const metadataOffset = keyOffset(dictionary, "EncryptMetadata");
  let encryptMetadata = 1;
  if (metadataOffset !== undefined) {
    const token = /^(true|false)\b/.exec(dictionary.slice(metadataOffset));
    if (!token) throw new Error("PDF /EncryptMetadata is not a boolean.");
    encryptMetadata = token[1] === "true" ? 1 : 0;
  }
  const idOffset = keyOffset(trailer, "ID");
  if (idOffset === undefined || trailer[idOffset] !== "[")
    throw new Error("PDF trailer has no valid /ID array.");
  const documentId = bytesValueAt(trailer, skipSpace(trailer, idOffset + 1), "PDF document ID");
  const max = revision >= 5 ? 48 : 32;
  const fields = ["U", "O", "UE", "OE"].flatMap((key) => {
    const value = bytesValue(dictionary, key, key === "U" || key === "O");
    if (!value) return [];
    const normalized = value.subarray(0, max);
    return [String(normalized.length), hex(normalized)];
  });
  if (revision >= 5 && fields.length !== 8)
    throw new Error(`PDF revision ${revision} requires /U, /O, /UE, and /OE.`);
  return `$pdf$${algorithm}*${revision}*${length}*${permissions}*${encryptMetadata}*${documentId.length}*${hex(documentId)}*${fields.join("*")}\n`;
}
