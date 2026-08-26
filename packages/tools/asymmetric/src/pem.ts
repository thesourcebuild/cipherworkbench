import { base64 } from "@scure/base";

/**
 * PEM and JWK handling for the RSA tool.
 *
 * Both formats exist here because both are what people actually have. PEM comes out of
 * OpenSSL, ssh-keygen and every certificate tool; JWK comes out of an OIDC discovery
 * document or a JWKS endpoint. Neither is derivable from the other by eye, and the whole
 * point of pasting a key into a tool like this is that you did not generate it here.
 */

export type PemLabel = "PRIVATE KEY" | "PUBLIC KEY";

const LINE_LENGTH = 64;

export function encodePem(label: PemLabel, der: Uint8Array): string {
  const body = base64.encode(der);
  const lines: string[] = [];
  for (let i = 0; i < body.length; i += LINE_LENGTH) {
    lines.push(body.slice(i, i + LINE_LENGTH));
  }
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

export interface PemBlock {
  label: string;
  der: Uint8Array;
}

export type PemResult = { ok: true; block: PemBlock } | { ok: false; error: string };

const BEGIN = /-----BEGIN ([A-Z0-9 ]+)-----/;
const END = /-----END ([A-Z0-9 ]+)-----/;

/**
 * Reads one PEM block, and says something useful when it cannot.
 *
 * The failure messages carry most of this function's value. The two things that actually
 * go wrong are pasting a PKCS#1 block (`BEGIN RSA PRIVATE KEY`) where PKCS#8 is expected,
 * and pasting an encrypted key. Both are valid PEM, so a generic "could not parse" would
 * send the user looking in the wrong place.
 */
export function decodePem(text: string): PemResult {
  const trimmed = text.trim();
  if (trimmed === "") return { ok: false, error: "No key given." };

  if (/Proc-Type:\s*4,ENCRYPTED/i.test(trimmed) || trimmed.includes("BEGIN ENCRYPTED")) {
    return {
      ok: false,
      error:
        "That key is passphrase-encrypted. There is nowhere here to ask for the passphrase, so decrypt it first: openssl pkcs8 -topk8 -nocrypt -in key.pem -out plain.pem",
    };
  }

  const begin = BEGIN.exec(trimmed);
  const end = END.exec(trimmed);
  if (!begin || !end) {
    return {
      ok: false,
      error:
        "Not a PEM block and not a JWK. A PEM key starts with a BEGIN line and ends with a matching END line; a JWK is a JSON object with a kty member.",
    };
  }
  if (begin[1] !== end[1]) {
    return { ok: false, error: `The BEGIN and END lines disagree: ${begin[1]} and ${end[1]}.` };
  }

  const label = begin[1]!;
  if (label === "RSA PRIVATE KEY" || label === "RSA PUBLIC KEY") {
    return {
      ok: false,
      error: `${label} is the old PKCS#1 form, which WebCrypto cannot import. Convert it: openssl pkcs8 -topk8 -nocrypt -in key.pem -out pkcs8.pem`,
    };
  }

  const body = trimmed
    .slice(trimmed.indexOf(begin[0]) + begin[0].length, trimmed.indexOf(end[0]))
    // Base64 in PEM is wrapped, and pasted PEM picks up stray whitespace either way.
    .replace(/\s+/g, "");

  try {
    return { ok: true, block: { label, der: base64.decode(body) } };
  } catch {
    return { ok: false, error: `The Base64 body of that ${label} block is not valid.` };
  }
}

export type KeyInputKind = "empty" | "pem" | "jwk" | "unknown";

/** What the user pasted, decided before anything tries to parse it properly. */
export function keyInputKind(text: string): KeyInputKind {
  const trimmed = text.trim();
  if (trimmed === "") return "empty";
  if (trimmed.startsWith("-----BEGIN")) return "pem";
  if (trimmed.startsWith("{")) return "jwk";
  return "unknown";
}

export type JwkResult =
  { ok: true; jwk: Record<string, unknown> } | { ok: false; error: string };

/**
 * Parses a JWK and strips the members that would fight with the algorithm being imported.
 *
 * `alg`, `key_ops` and `use` are the problem: a JWK exported from a PKCS#1-v1.5 key carries
 * `alg: "RS256"`, and importing it as RSA-PSS or RSA-OAEP is then rejected for inconsistency
 * even though the key material is identical and perfectly usable. Removing them lets one
 * pasted key serve whichever operation is selected, which is what a user of this tool
 * expects. `ext` goes too, since it constrains exportability we are about to set ourselves.
 */
export function parseJwk(text: string): JwkResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return {
      ok: false,
      error: `That is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, error: "A JWK must be a JSON object." };
  }

  const jwk = { ...(parsed as Record<string, unknown>) };
  if (jwk.kty !== "RSA") {
    return {
      ok: false,
      error:
        jwk.kty === undefined
          ? "That JSON object has no kty member, so it is not a JWK."
          : `That is a ${String(jwk.kty)} key. This tool wants an RSA one; for an EC or OKP key use the ECDSA, Ed25519 or ECDH tool with the raw key bytes.`,
    };
  }
  if (typeof jwk.n !== "string" || typeof jwk.e !== "string") {
    return { ok: false, error: "An RSA JWK needs at least its n and e members." };
  }

  delete jwk.alg;
  delete jwk.key_ops;
  delete jwk.use;
  delete jwk.ext;

  return { ok: true, jwk };
}

/** True when a JWK carries private key material. */
export function isPrivateJwk(jwk: Record<string, unknown>): boolean {
  return typeof jwk.d === "string";
}

/** A JWK as pretty JSON, for the result panel. */
export function formatJwk(jwk: Record<string, unknown>): string {
  return JSON.stringify(jwk, null, 2);
}
