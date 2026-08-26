import { base64 } from "@scure/base";

/**
 * The PHC string format, as used by Argon2 and scrypt.
 *
 * `$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA`
 *
 * Parsing it is what makes Verify mode possible: every parameter needed to recompute the
 * hash is in the string, so checking a password requires nothing but the string and the
 * password. That is also the reason PBKDF2 and HKDF have no Verify mode — they have no such
 * format, and their parameters live somewhere else entirely.
 *
 * The base64 here is the PHC variant: standard alphabet, no padding. `@scure/base`'s
 * decoder is strict about padding, so it is added back before decoding rather than the
 * input being loosened.
 */
export interface PhcString {
  id: string;
  version?: number;
  params: Record<string, string>;
  salt: Uint8Array;
  hash: Uint8Array;
}

export type PhcResult = { ok: true; value: PhcString } | { ok: false; error: string };

function decodePhcBase64(text: string): Uint8Array {
  const padded = text.padEnd(Math.ceil(text.length / 4) * 4, "=");
  return base64.decode(padded);
}

function encodePhcBase64(bytes: Uint8Array): string {
  return base64.encode(bytes).replace(/=+$/, "");
}

export function parsePhc(input: string): PhcResult {
  const trimmed = input.trim();
  if (!trimmed.startsWith("$")) {
    return { ok: false, error: "A PHC hash starts with a dollar sign." };
  }

  // Leading empty field from the initial "$".
  const parts = trimmed.split("$").slice(1);
  if (parts.length < 2) {
    return { ok: false, error: "This does not look like a PHC-format hash." };
  }

  const id = parts[0]!;
  let index = 1;
  let version: number | undefined;

  if (parts[index]?.startsWith("v=")) {
    version = Number(parts[index]!.slice(2));
    if (!Number.isInteger(version)) {
      return { ok: false, error: "The version field is not a number." };
    }
    index += 1;
  }

  const params: Record<string, string> = {};
  // The parameter field is optional and identified by containing "=".
  if (parts[index]?.includes("=")) {
    for (const pair of parts[index]!.split(",")) {
      const [key, value] = pair.split("=", 2);
      if (!key || value === undefined) {
        return { ok: false, error: `Malformed parameter: ${pair}` };
      }
      params[key] = value;
    }
    index += 1;
  }

  const saltText = parts[index];
  const hashText = parts[index + 1];
  if (saltText === undefined || hashText === undefined) {
    return { ok: false, error: "The hash is missing its salt or digest field." };
  }

  try {
    return {
      ok: true,
      value: {
        id,
        version,
        params,
        salt: decodePhcBase64(saltText),
        hash: decodePhcBase64(hashText),
      },
    };
  } catch {
    return { ok: false, error: "The salt or digest is not valid PHC base64." };
  }
}

export function formatPhc(value: PhcString): string {
  const fields = [value.id];
  if (value.version !== undefined) fields.push(`v=${value.version}`);
  const params = Object.entries(value.params);
  if (params.length > 0) fields.push(params.map(([k, v]) => `${k}=${v}`).join(","));
  fields.push(encodePhcBase64(value.salt), encodePhcBase64(value.hash));
  return `$${fields.join("$")}`;
}

/** Reads a numeric PHC parameter, or undefined if absent or unparseable. */
export function phcNumber(value: PhcString, key: string): number | undefined {
  const raw = value.params[key];
  if (raw === undefined) return undefined;
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}
