import type { OptionValues, OutputEncoding } from "@ocs/contracts";
import type { OptionCatalogue, ToolSpecBase } from "@ocs/engine";
import { encodingOptionId } from "@ocs/engine";
import type { InputState } from "./input-state";

/**
 * A shareable link carries the tool, its settings and (optionally) the input — but
 * never a secret.
 *
 * The reference site this tool is modelled on puts everything in the link,
 * including the HMAC key. That is a genuine footgun: a URL ends up in browser
 * history, in a chat log, in a bug report, in a proxy's access log, and in the
 * Referer header of the next site visited. Every option the catalogue marks
 * `secret` is dropped here, and `omittedSecrets` reports which — so the UI can
 * say what was left out instead of silently producing a link that does not
 * reproduce the result.
 */

const VERSION = 1;
/**
 * Input above this is dropped from the link rather than truncated. Truncating
 * would produce a link that computes a *different, valid-looking* digest, which
 * is worse than one that computes nothing.
 */
const MAX_SHARED_INPUT_CHARS = 4096;

interface SharePayload {
  v: number;
  /** Tool id. */
  t: string;
  /** Everything in the spec except `options`, so a tool that adds fields keeps them. */
  s: Record<string, unknown>;
  /** Options, secrets already removed. */
  o: OptionValues;
  /** Output encoding, so a link reproduces the spelling the sender was looking at. */
  e?: OutputEncoding;
  /** Input: mode, text, text encoding. Absent for file input or oversized text. */
  i?: { m: string; t: string; x: string };
}

export interface ShareLinkResult {
  url: string;
  /** Labels of the secret options that were left out. */
  omittedSecrets: string[];
  /** True when the input was left out — file input, or text over the size cap. */
  omittedInput: boolean;
}

/**
 * Strips every option the catalogue marks `secret`, plus the companion encoding
 * selector that goes with it — a stray `keyEncoding: "hex"` in a link is
 * harmless but confusing, since the key it describes is gone.
 */
export function stripSecrets(
  catalogue: OptionCatalogue,
  options: OptionValues,
): { options: OptionValues; omitted: string[] } {
  const next: OptionValues = { ...options };
  const omitted: string[] = [];

  for (const id of catalogue.secretIds()) {
    if (id in next) {
      omitted.push(catalogue.require(id).label);
      delete next[id];
    }
    delete next[encodingOptionId(id)];
  }

  return { options: next, omitted };
}

export function buildShareLink(
  baseUrl: string,
  toolId: string,
  catalogue: OptionCatalogue,
  spec: ToolSpecBase,
  input: InputState,
  outputEncoding: OutputEncoding,
): ShareLinkResult {
  const { options, omitted } = stripSecrets(catalogue, spec.options);
  const { options: _options, ...rest } = spec;

  const shareInput =
    input.mode !== "file" && input.text.length <= MAX_SHARED_INPUT_CHARS && input.text !== "";

  const payload: SharePayload = {
    v: VERSION,
    t: toolId,
    s: rest as Record<string, unknown>,
    o: options,
    e: outputEncoding,
    ...(shareInput ? { i: { m: input.mode, t: input.text, x: input.textEncoding } } : {}),
  };

  const url = `${baseUrl.replace(/#.*$/, "")}#${encodePayload(payload)}`;

  return {
    url,
    omittedSecrets: omitted,
    omittedInput: !shareInput && (input.mode === "file" || input.text !== ""),
  };
}

export interface ParsedShare {
  toolId: string;
  /** Merged back into the tool's own `createSpec()` result by the caller, so unknown fields cannot poison a spec. */
  specFields: Record<string, unknown>;
  options: OptionValues;
  outputEncoding?: string;
  input?: { mode: string; text: string; textEncoding: string };
}

/**
 * Reads a share payload out of a URL hash.
 *
 * Everything here is attacker-controlled — a link is the one input to this app
 * that someone else wrote — so this returns loose `string`/`Record` types and
 * validates nothing beyond the envelope. The caller narrows each field against
 * the tool's own schema and the real enums; anything unrecognised is dropped
 * rather than trusted.
 */
export function parseShareLink(hash: string): ParsedShare | undefined {
  const encoded = hash.replace(/^#/, "");
  if (encoded === "") return undefined;

  let payload: SharePayload;
  try {
    payload = decodePayload(encoded);
  } catch {
    return undefined;
  }

  if (payload?.v !== VERSION || typeof payload.t !== "string") return undefined;

  return {
    toolId: payload.t,
    specFields: isRecord(payload.s) ? payload.s : {},
    options: isRecord(payload.o) ? (payload.o as OptionValues) : {},
    outputEncoding: typeof payload.e === "string" ? payload.e : undefined,
    input:
      isRecord(payload.i) &&
      typeof payload.i.m === "string" &&
      typeof payload.i.t === "string" &&
      typeof payload.i.x === "string"
        ? { mode: payload.i.m, text: payload.i.t, textEncoding: payload.i.x }
        : undefined,
  };
}

// Base64url over UTF-8 JSON. Not compression — a link is short enough that the
// dependency would cost more than it saves — but it does keep the payload out of
// the URL's reserved-character space without percent-encoding every brace.
function encodePayload(payload: SharePayload): string {
  const json = JSON.stringify(payload);
  const utf8 = new TextEncoder().encode(json);
  let binary = "";
  for (const byte of utf8) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodePayload(encoded: string): SharePayload {
  const standard = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const padded = standard.padEnd(Math.ceil(standard.length / 4) * 4, "=");
  const binary = atob(padded);
  const utf8 = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) utf8[i] = binary.charCodeAt(i);
  return JSON.parse(new TextDecoder().decode(utf8)) as SharePayload;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
