import type { OutputEncoding } from "@ocs/contracts";
import { encodeOutput } from "@ocs/engine";
import type { ToolManifest, ToolResult, ToolResultField, ToolSpecBase } from "@ocs/engine";
import type { InputState } from "./input-state";
import { SITE_URL } from "./site";

/** Convert a human label like "Initial vector" or "Auth Tag" to a standardized camelCase property */
function normalizeResultKey(label: string): string {
  const clean = label.trim().toLowerCase();
  if (
    clean === "initial vector" ||
    clean === "initialization vector" ||
    clean === "token iv" ||
    clean === "iv"
  ) {
    return "initialVector";
  }
  if (clean === "timestamp" || clean === "time stamp" || clean === "token timestamp") {
    return "timeStamp";
  }
  if (clean === "version" || clean === "token version") {
    return "version";
  }
  if (clean === "authentication tag" || clean === "auth tag" || clean === "tag") {
    return "tag";
  }
  if (clean === "ciphertext without tag") {
    return "ciphertextWithoutTag";
  }
  if (clean === "hmac") {
    return "hmac";
  }
  if (clean === "derived key" || clean === "key") {
    return "key";
  }
  if (clean === "nonce") {
    return "nonce";
  }
  if (clean === "construction") {
    return "construction";
  }
  if (
    clean.startsWith("alias") ||
    clean.startsWith("aliases") ||
    clean.includes("also known as")
  ) {
    return "alias";
  }
  if (clean === "model") {
    return "model";
  }
  if (clean === "width") {
    return "width";
  }
  if (clean === "polynomial") {
    return "polynomial";
  }
  if (clean === "init") {
    return "init";
  }
  if (clean === "reflect in / out" || clean === "reflect in/out" || clean === "reflectinout") {
    return "reflectInOut";
  }
  if (clean === "final xor" || clean === "finalxor") {
    return "finalXor";
  }
  if (clean === "check value" || clean === "check" || clean === "checkvalue") {
    return "checkValue";
  }
  if (clean === "residue") {
    return "residue";
  }
  if (clean === "matches") {
    return "matches";
  }

  const words = label.trim().split(/[\s/_\n-]+/).filter(Boolean);
  if (words.length === 0) return "";
  const first = words[0]!.toLowerCase();
  const rest = words
    .slice(1)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join("");
  return first + rest;
}

const EXCLUDED_OPTION_KEYS = new Set([
  "key",
  "secret",
  "password",
  "direction",
  "mode",
  "action",
]);

export interface ExportPayload {
  tool: string;
  mode?: string;
  algorithm: string;
  result: Record<string, unknown>;
  info?: Record<string, unknown>;
  serverTimestamp: string;
  inputMessage?: string;
  fileName?: string;
  fileSize?: number;
  inputKey?: string;
  options?: Record<string, unknown>;
}

export function buildExportPayload(
  manifest: ToolManifest,
  spec: ToolSpecBase,
  input: InputState,
  result: ToolResult | undefined,
  outputEncoding: OutputEncoding = "hex",
  infoFields?: readonly ToolResultField[],
): ExportPayload {
  const options = spec.options ?? {};

  // 1. Determine active mode / direction
  let mode: string | undefined;
  if (typeof options["direction"] === "string") {
    mode = options["direction"];
  } else if (typeof options["mode"] === "string") {
    mode = options["mode"];
  } else if (typeof options["action"] === "string") {
    mode = options["action"];
  } else {
    switch (manifest.family) {
      case "cipher":
      case "classical":
        mode = "encrypt";
        break;
      case "asymmetric":
        mode = "compute";
        break;
      case "hash":
      case "checksum":
      case "crc":
      case "parity":
        mode = "hash";
        break;
      case "mac":
        mode = "authenticate";
        break;
      case "kdf":
        mode = "derive";
        break;
      case "encoding":
        mode = "encode";
        break;
      case "format":
        mode = "format";
        break;
    }
  }

  // 2. Algorithm naming
  const algorithm = manifest.label;

  // 3. Extract inputs
  let inputKey: string | undefined;
  if (typeof options["key"] === "string" && options["key"].length > 0) {
    inputKey = options["key"];
  } else if (typeof options["secret"] === "string" && options["secret"].length > 0) {
    inputKey = options["secret"];
  } else if (typeof options["password"] === "string" && options["password"].length > 0) {
    inputKey = options["password"];
  }

  // 4. Format primary output
  let primaryOutput = "";
  if (result) {
    if (result.text !== undefined) {
      primaryOutput = result.text;
    } else if (result.bytes) {
      primaryOutput = encodeOutput(result.bytes, outputEncoding);
    }
  }

  // 5. Build structured result object
  const resultObj: Record<string, unknown> = {};
  if (primaryOutput !== "") {
    resultObj["output"] = primaryOutput;
  }

  // Map result fields (e.g. Construction, Tag, Ciphertext without tag, Nonce, Timestamp, Initial vector, HMAC, Key)
  if (result?.fields) {
    for (const field of result.fields) {
      const key = normalizeResultKey(field.label);
      if (key) {
        resultObj[key] = field.value;
      }
    }
  }

  if (result?.error) {
    resultObj["error"] = result.error;
  }

  // 6. Build info object if infoFields provided
  let infoObj: Record<string, unknown> | undefined;
  if (infoFields && infoFields.length > 0) {
    const fieldsObj: Record<string, unknown> = {};
    for (const field of infoFields) {
      const key = normalizeResultKey(field.label);
      if (key) {
        fieldsObj[key] = field.value;
      }
    }
    if (Object.keys(fieldsObj).length > 0) {
      infoObj = fieldsObj;
    }
  }

  // 7. Collect other parameters into options object if present
  const extraOptions: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(options)) {
    if (EXCLUDED_OPTION_KEYS.has(k)) continue;
    if (v !== undefined && v !== "" && v !== null) {
      extraOptions[k] = v;
    }
  }

  // 8. Build ordered export payload
  const now = new Date().toISOString();
  const payload: ExportPayload = {
    tool: `${SITE_URL}/tools/${manifest.id}/`,
    mode,
    algorithm,
    result: resultObj,
    ...(infoObj ? { info: infoObj } : {}),
    serverTimestamp: now,
    ...(input.mode === "file" && input.file
      ? { fileName: input.file.name, fileSize: input.file.size }
      : { inputMessage: input.text }),
    ...(inputKey ? { inputKey } : {}),
    ...(Object.keys(extraOptions).length > 0 ? { options: extraOptions } : {}),
  };

  return payload;
}

export function downloadJsonFile(filename: string, data: object): void {
  const jsonStr = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename.endsWith(".json") ? filename : `${filename}.json`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export function downloadTextFile(filename: string, content: string, mimeType = "text/plain"): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

