import type { OutputEncoding } from "@ocs/contracts";
import {
  encodeOutput,
  type ToolResult,
  type ToolResultField,
  type ToolSpecBase,
} from "@ocs/engine";
import type { InputState } from "./input-state";

export const RESULT_PREVIEW_BYTES = 8 * 1024;
export const RESULT_PREVIEW_TEXT_CHARS = 16 * 1024;
export const JSON_EXPORT_MAX_RESULT_BYTES = 1024 * 1024;

export interface ResultPresentation {
  value: string;
  truncated: boolean;
  totalBytes?: number;
  omittedBytes?: number;
  totalCharacters?: number;
  omittedCharacters?: number;
}

function splitLimit(limit: number): [number, number] {
  const head = Math.ceil(limit / 2);
  return [head, limit - head];
}

export function presentResult(
  result: ToolResult | undefined,
  encoding: OutputEncoding,
  hexPrefix = "",
): ResultPresentation {
  if (!result) return { value: "", truncated: false };

  if (result.text !== undefined) {
    if (result.text.length <= RESULT_PREVIEW_TEXT_CHARS) {
      return {
        value: result.text,
        truncated: false,
        totalCharacters: result.text.length,
        omittedCharacters: 0,
      };
    }
    const [headLength, tailLength] = splitLimit(RESULT_PREVIEW_TEXT_CHARS);
    const omittedCharacters = result.text.length - headLength - tailLength;
    return {
      value: `${result.text.slice(0, headLength)}\n... ${omittedCharacters} characters omitted ...\n${result.text.slice(-tailLength)}`,
      truncated: true,
      totalCharacters: result.text.length,
      omittedCharacters,
    };
  }

  const bytes = result.bytes;
  if (!bytes || bytes.length === 0) return { value: "", truncated: false };

  const prefix = (value: string) => (value === "" ? value : `${hexPrefix}${value}`);
  if (bytes.length <= RESULT_PREVIEW_BYTES) {
    return {
      value: prefix(encodeOutput(bytes, encoding)),
      truncated: false,
      totalBytes: bytes.length,
      omittedBytes: 0,
    };
  }

  const [headLength, tailLength] = splitLimit(RESULT_PREVIEW_BYTES);
  const omittedBytes = bytes.length - headLength - tailLength;
  const head = prefix(encodeOutput(bytes.subarray(0, headLength), encoding));
  const tail = prefix(encodeOutput(bytes.subarray(bytes.length - tailLength), encoding));
  const independentlyEncoded = ["base32", "base64", "base64url", "decimal", "utf-8"].includes(
    encoding,
  );
  return {
    value: independentlyEncoded
      ? `First ${headLength} bytes encoded as ${encoding}:\n${head}\n... ${omittedBytes} bytes omitted ...\nLast ${tailLength} bytes encoded as ${encoding}:\n${tail}`
      : `${head}\n... ${omittedBytes} bytes omitted ...\n${tail}`,
    truncated: true,
    totalBytes: bytes.length,
    omittedBytes,
  };
}

export interface JsonExportAvailability {
  allowed: boolean;
  reason?: string;
}

export function jsonExportAvailability(
  result: ToolResult | undefined,
  input?: InputState,
  spec?: ToolSpecBase,
  infoFields?: readonly ToolResultField[],
  outputEncoding: OutputEncoding = "hex",
): JsonExportAvailability {
  if (!result) return { allowed: false, reason: "No result available to save" };

  const outputFactor: Record<OutputEncoding, number> = {
    binary: 9,
    octal: 4,
    decimal: 3,
    hex: 2,
    "hex-upper": 2,
    base32: 1.7,
    base64: 1.4,
    base64url: 1.4,
    latin1: 6,
    "utf-8": 6,
  };
  const byteLength = (result.bytes?.length ?? 0) * outputFactor[outputEncoding];
  let characterCount = 4096 + (result.text?.length ?? 0) * 6;
  for (const field of result.fields ?? []) characterCount += field.value.length * 6;
  for (const field of infoFields ?? []) characterCount += field.value.length * 6;
  if (input?.mode !== "file") characterCount += (input?.text.length ?? 0) * 6;
  if (spec) characterCount += JSON.stringify(spec.options ?? {}).length;

  if (byteLength + characterCount > JSON_EXPORT_MAX_RESULT_BYTES) {
    return {
      allowed: false,
      reason:
        "JSON is disabled for results over 1 MiB; use Export to save the exact output bytes",
    };
  }
  return { allowed: true };
}
