import { decodeBytesOption, type BytesResult } from "@ocs/engine";
import { optString } from "@ocs/contracts/pure";
import { asymmetricCatalogueFor } from "./catalogue/options";
import {
  ED25519_CURVE,
  getCurve,
  getParamSet,
  PQ_PARAM_SETS,
  requireAsymmetricTool,
  RSA_OAEP_HASHES,
  type AsymmetricOperation,
  type AsymmetricToolMeta,
  type CurveMeta,
  type PqParamSet,
} from "./catalogue/tool-meta";
import { keyInputKind } from "./pem";
import {
  OPTION_HASH,
  OPTION_OAEP_LABEL,
  OPTION_PRIVATE_KEY,
  OPTION_PUBLIC_KEY,
  OPTION_PARAM_SET,
  OPTION_SIGNATURE,
  readCurve,
  readHash,
  readModulusLength,
  readOperation,
  readParamSet,
  readScheme,
  readSignatureFormat,
  type RsaScheme,
  type SignatureFormat,
} from "./pure";
import type { AsymmetricSpec } from "./spec";

export interface ResolvedAsymmetric {
  tool: AsymmetricToolMeta;
  operation: AsymmetricOperation;
  /** Present for ECDSA and ECDH; the other curve tools have no curve to choose. */
  curve: CurveMeta | undefined;
  /** Present for the three post-quantum tools, and the source of every length they check. */
  paramSet: PqParamSet | undefined;
  /** WebCrypto spelling, e.g. "SHA-256". Unused by Ed25519, which fixes SHA-512. */
  hash: string;
  scheme: RsaScheme;
  modulusBits: number;
  signatureFormat: SignatureFormat;
  /** Raw key bytes, for the three curve tools. Empty for RSA. */
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  signature: Uint8Array;
  oaepLabel: Uint8Array;
  /** PEM or JWK text, for RSA. Empty for the curve tools. */
  privateKeyText: string;
  publicKeyText: string;
}

export type ResolveResult =
  { ok: true; resolved: ResolvedAsymmetric } | { ok: false; problem: string; optionId: string };

/** Public-key byte lengths this curve accepts: compressed, and uncompressed where it exists. */
export function acceptedPublicKeyLengths(curve: CurveMeta): number[] {
  return curve.uncompressedLen === undefined
    ? [curve.publicLen]
    : [curve.publicLen, curve.uncompressedLen];
}

function problem(optionId: string, text: string): ResolveResult {
  return { ok: false, problem: text, optionId };
}

/** A text option's value, or the empty string. */
function readText(spec: AsymmetricSpec, id: string): string {
  return optString(spec.options, id) ?? "";
}

/** A `bytes` option decoded through the encoding its companion selector holds. */
function readBytes(spec: AsymmetricSpec, id: string): BytesResult {
  return decodeBytesOption(asymmetricCatalogueFor(spec.variant), spec.options, id);
}

/**
 * Turns a spec into everything the compute path needs, or names exactly what is wrong.
 *
 * Synchronous, which is what forces the division of labour with `compute`. RSA keys can only
 * be genuinely validated by `crypto.subtle.importKey`, and that returns a promise -- but the
 * lint rules that surface these problems in the UI are synchronous by contract. So this
 * checks everything checkable without awaiting: that a key is present, that it looks like PEM
 * or a JWK, that raw key bytes are the right length for the selected curve. Whether the DER
 * inside a PEM block is well-formed is left to compute, which can await the import and report
 * the real reason it failed.
 */
export function resolveAsymmetric(spec: AsymmetricSpec): ResolveResult {
  const tool = requireAsymmetricTool(spec.variant);
  const operation = readOperation(spec.options, tool.operations);
  const catalogue = asymmetricCatalogueFor(spec.variant);

  const curve =
    spec.variant === "ecdsa" || spec.variant === "ecdh"
      ? getCurve(spec.variant, readCurve(spec.options, spec.variant))
      : undefined;

  const isPq = PQ_PARAM_SETS[spec.variant] !== undefined;
  const paramSet = isPq
    ? getParamSet(spec.variant, readParamSet(spec.options, spec.variant))
    : undefined;
  // A share link or stale saved state can name a set this tool does not offer.
  if (isPq && !paramSet) {
    return problem(OPTION_PARAM_SET, `${tool.label} does not offer that parameter set.`);
  }

  // A share link can name a curve this tool does not offer.
  if ((spec.variant === "ecdsa" || spec.variant === "ecdh") && !curve) {
    return problem("curve", `${tool.label} does not offer that curve.`);
  }

  const base: ResolvedAsymmetric = {
    tool,
    operation,
    curve,
    paramSet,
    hash: readHash(spec.options),
    scheme: readScheme(spec.options),
    modulusBits: readModulusLength(spec.options),
    signatureFormat: readSignatureFormat(spec.options),
    privateKey: new Uint8Array(0),
    publicKey: new Uint8Array(0),
    signature: new Uint8Array(0),
    oaepLabel: new Uint8Array(0),
    privateKeyText: "",
    publicKeyText: "",
  };

  // Generating a keypair reads nothing else, and refusing it for a missing key would make
  // the one operation that fixes a missing key unreachable.
  if (operation === "generate") return { ok: true, resolved: base };

  const labelResult = decodeBytesOption(catalogue, spec.options, OPTION_OAEP_LABEL);
  if (!labelResult.ok) return problem(OPTION_OAEP_LABEL, labelResult.error);
  base.oaepLabel = labelResult.bytes;

  /**
   * OAEP is WebCrypto-only, so the hash list is narrower for encryption than for signing.
   *
   * One `hash` option serves all five RSA operations — `ToolDefinition.catalogue` is resolved
   * once per tool, so a second entry sharing the id would collapse in the catalogue's map.
   * The catalogue therefore offers the union and the specific constraint is enforced here,
   * where the message can name the operation and say *why* rather than just refusing.
   *
   * The reason it is not simply implemented: OAEP's unpadding has to be constant-time, and a
   * padding oracle in RSA decryption is Bleichenbacher's attack rather than a caveat. Getting
   * that right in `bigint` arithmetic is not something to do for interop with hashes no
   * deployment of OAEP uses.
   */
  if (
    tool.usesPem &&
    (operation === "encrypt" || operation === "decrypt") &&
    !RSA_OAEP_HASHES.some((h) => h.id === base.hash)
  ) {
    return problem(
      OPTION_HASH,
      `OAEP is available with ${RSA_OAEP_HASHES.map((h) => h.label).join(", ")} only — those are the hashes WebCrypto implements, and the only ones any deployment of OAEP uses. ${base.hash} works for signatures.`,
    );
  }

  if (paramSet) return resolvePqKeys(spec, base, paramSet);

  return tool.usesPem
    ? resolvePemKeys(spec, base)
    : // Ed25519 has no curve option, so its fixed lengths stand in as one.
      resolveRawKeys(spec, base, curve ?? ED25519_CURVE);
}

/** Which key each operation needs, so one table drives the requirement checks. */
const NEEDS_PRIVATE: readonly AsymmetricOperation[] = ["sign", "decrypt", "derive"];
const NEEDS_PUBLIC: readonly AsymmetricOperation[] = ["verify", "encrypt", "derive"];

/**
 * RSA: the keys are text, and only their shape is checked here.
 *
 * Verify and encrypt accept an empty public-key field when a private key is present, because
 * the public key is recoverable from the private one and checking a signature you just made
 * is the commonest thing anyone does in a tool like this. Derive never applies -- RSA does no
 * key agreement.
 */
function resolvePemKeys(spec: AsymmetricSpec, base: ResolvedAsymmetric): ResolveResult {
  const privateText = readText(spec, OPTION_PRIVATE_KEY);
  const publicText = readText(spec, OPTION_PUBLIC_KEY);

  const privateKind = keyInputKind(privateText);
  const publicKind = keyInputKind(publicText);

  if (privateKind === "unknown") {
    return problem(
      OPTION_PRIVATE_KEY,
      "That is neither a PEM block nor a JWK. A PEM key begins with -----BEGIN PRIVATE KEY-----; a JWK begins with {.",
    );
  }
  if (publicKind === "unknown") {
    return problem(
      OPTION_PUBLIC_KEY,
      "That is neither a PEM block nor a JWK. A PEM key begins with -----BEGIN PUBLIC KEY-----; a JWK begins with {.",
    );
  }

  if (NEEDS_PRIVATE.includes(base.operation) && privateKind === "empty") {
    return problem(
      OPTION_PRIVATE_KEY,
      base.operation === "sign"
        ? "Signing needs a private key. Switch to Generate keypair to make one."
        : "Decrypting needs the private key matching whichever public key encrypted this.",
    );
  }

  if (
    NEEDS_PUBLIC.includes(base.operation) &&
    publicKind === "empty" &&
    privateKind === "empty"
  ) {
    return problem(
      OPTION_PUBLIC_KEY,
      base.operation === "verify"
        ? "Verifying needs a public key -- or a private key, from which it will be taken."
        : "Encrypting needs the recipient's public key.",
    );
  }

  if (base.operation === "verify") {
    const signature = readBytes(spec, OPTION_SIGNATURE);
    if (!signature.ok) return problem(OPTION_SIGNATURE, signature.error);
    if (signature.bytes.length === 0) {
      return problem(OPTION_SIGNATURE, "Paste the signature to check.");
    }
    base.signature = signature.bytes;
  }

  return {
    ok: true,
    resolved: { ...base, privateKeyText: privateText, publicKeyText: publicText },
  };
}

/**
 * ECDSA, Ed25519 and ECDH: raw key bytes, checked against the selected curve.
 *
 * The length checks live here rather than in each option's `bytesLength` for the same reason
 * the AES nonce's did: one catalogue serves all four curves, so the declared set is the union
 * and the curve-specific requirement is enforced where the curve is known. The payoff is the
 * message, which can say which curve wanted what.
 */
function resolveRawKeys(
  spec: AsymmetricSpec,
  base: ResolvedAsymmetric,
  curve: CurveMeta,
): ResolveResult {
  if (NEEDS_PRIVATE.includes(base.operation)) {
    const result = readBytes(spec, OPTION_PRIVATE_KEY);
    if (!result.ok) return problem(OPTION_PRIVATE_KEY, result.error);
    if (result.bytes.length === 0) {
      return problem(
        OPTION_PRIVATE_KEY,
        base.operation === "sign"
          ? "Signing needs a private key. Switch to Generate keypair to make one."
          : "Deriving needs your own private key.",
      );
    }
    if (result.bytes.length !== curve.secretLen) {
      return problem(
        OPTION_PRIVATE_KEY,
        `${curve.label} private keys are ${curve.secretLen} bytes; this one is ${result.bytes.length}.`,
      );
    }
    base.privateKey = result.bytes;
  }

  /**
   * Verify may take its public key from the private one, so the private key is read here --
   * before the public-key check that depends on knowing whether one is available.
   *
   * An earlier ordering did this afterwards, and the fallback could therefore never fire: the
   * public-key branch saw `base.privateKey` still empty and refused. Reading it first is the
   * fix; a wrong length is not fatal at this point, since the public key may well have been
   * supplied, so it is only taken when usable.
   */
  if (base.operation === "verify") {
    const result = readBytes(spec, OPTION_PRIVATE_KEY);
    if (result.ok && result.bytes.length === curve.secretLen) base.privateKey = result.bytes;
  }

  if (NEEDS_PUBLIC.includes(base.operation)) {
    const result = readBytes(spec, OPTION_PUBLIC_KEY);
    if (!result.ok) return problem(OPTION_PUBLIC_KEY, result.error);
    const accepted = acceptedPublicKeyLengths(curve);

    if (result.bytes.length === 0) {
      /**
       * Verifying with the public-key field empty falls back to the private key.
       *
       * Deriving does not, and must not: agreement with your own public key succeeds and
       * produces a secret shared with nobody. Silently defaulting there would turn the
       * commonest mistake in this family into the default behaviour.
       */
      if (base.operation === "derive") {
        return problem(
          OPTION_PUBLIC_KEY,
          "Deriving needs the other party's public key. Using your own would compute a secret you share with no one.",
        );
      }
      if (base.privateKey.length === 0) {
        return problem(
          OPTION_PUBLIC_KEY,
          `Verifying needs a public key (${accepted.join(" or ")} bytes for ${curve.label}), or a private key to take it from.`,
        );
      }
    } else if (!accepted.includes(result.bytes.length)) {
      return problem(
        OPTION_PUBLIC_KEY,
        `${curve.label} public keys are ${accepted.join(" or ")} bytes; this one is ${result.bytes.length}.`,
      );
    }
    base.publicKey = result.bytes;
  }

  if (base.operation === "verify") {
    const result = readBytes(spec, OPTION_SIGNATURE);
    if (!result.ok) return problem(OPTION_SIGNATURE, result.error);
    if (result.bytes.length === 0) {
      return problem(OPTION_SIGNATURE, "Paste the signature to check.");
    }
    if (base.signatureFormat === "compact" && spec.variant !== "ed25519") {
      if (result.bytes.length !== curve.signatureLen) {
        return problem(
          OPTION_SIGNATURE,
          `A compact ${curve.label} signature is ${curve.signatureLen} bytes; this one is ${result.bytes.length}. If it came from OpenSSL, switch the format to DER.`,
        );
      }
    }
    base.signature = result.bytes;
  }

  return { ok: true, resolved: base };
}

/**
 * ML-KEM, ML-DSA and SLH-DSA: raw keys again, but sized by the parameter set rather than by a curve.
 *
 * Structurally the same job as `resolveRawKeys` and deliberately not folded into it. The two differ in
 * every particular -- which operations need which key, whether a public key can be derived from a
 * private one, what the material field holds -- and the shared parts are three length comparisons. A
 * merged function would need a `curve ?? paramSet` union threaded through every branch, and the
 * messages would end up generic, which is the one thing these resolvers exist to avoid.
 */
function resolvePqKeys(
  spec: AsymmetricSpec,
  base: ResolvedAsymmetric,
  set: PqParamSet,
): ResolveResult {
  const isKem = spec.variant === "mlkem";
  const needsPrivate = isKem ? base.operation === "decapsulate" : base.operation === "sign";
  const needsPublic = isKem ? base.operation === "encapsulate" : base.operation === "verify";

  if (needsPrivate) {
    const result = readBytes(spec, OPTION_PRIVATE_KEY);
    if (!result.ok) return problem(OPTION_PRIVATE_KEY, result.error);
    if (result.bytes.length === 0) {
      return problem(
        OPTION_PRIVATE_KEY,
        isKem
          ? "Decapsulating needs your decapsulation key -- the private half of the keypair whose public key produced this ciphertext."
          : "Signing needs a private key. Switch to Generate keypair to make one.",
      );
    }
    if (result.bytes.length !== set.secretKeyLen) {
      /**
       * The message names the set, which is the whole reason the check is here rather than in the
       * option's `bytesLength`: SLH-DSA's twelve sets take 64, 96 or 128 bytes, and "expected one of
       * 64, 96, 128" tells a user nothing about which one *this* configuration wants.
       */
      return problem(
        OPTION_PRIVATE_KEY,
        `${set.label} private keys are ${set.secretKeyLen} bytes; this one is ${result.bytes.length}. A key from a different parameter set will not work under this one.`,
      );
    }
    base.privateKey = result.bytes;
  }

  /**
   * Verifying can take the public key from the private one, exactly as the curve tools do -- checking
   * a signature you have just produced is the commonest thing anyone does here. Encapsulating cannot,
   * and must not: a KEM ciphertext addressed to your own public key carries a secret shared with
   * nobody, which is the same trap ECDH's "Their public key" field is named for.
   */
  if (base.operation === "verify") {
    const result = readBytes(spec, OPTION_PRIVATE_KEY);
    if (result.ok && result.bytes.length === set.secretKeyLen) base.privateKey = result.bytes;
  }

  if (needsPublic) {
    const result = readBytes(spec, OPTION_PUBLIC_KEY);
    if (!result.ok) return problem(OPTION_PUBLIC_KEY, result.error);
    if (result.bytes.length === 0) {
      if (isKem) {
        return problem(
          OPTION_PUBLIC_KEY,
          "Encapsulating needs the recipient's public key. Switch to Generate keypair to make a pair to try it with.",
        );
      }
      if (base.privateKey.length === 0) {
        return problem(
          OPTION_PUBLIC_KEY,
          `Verifying needs a public key (${set.publicKeyLen} bytes for ${set.label}), or a private key to take it from.`,
        );
      }
    } else if (result.bytes.length !== set.publicKeyLen) {
      return problem(
        OPTION_PUBLIC_KEY,
        `${set.label} public keys are ${set.publicKeyLen} bytes; this one is ${result.bytes.length}.`,
      );
    }
    base.publicKey = result.bytes;
  }

  if (base.operation === "verify") {
    const result = readBytes(spec, OPTION_SIGNATURE);
    if (!result.ok) return problem(OPTION_SIGNATURE, result.error);
    if (result.bytes.length === 0) {
      return problem(OPTION_SIGNATURE, "Paste the signature to check.");
    }
    if (result.bytes.length !== set.signatureLen) {
      return problem(
        OPTION_SIGNATURE,
        `A ${set.label} signature is exactly ${set.signatureLen} bytes; this one is ${result.bytes.length}. Post-quantum signatures are fixed-length, so a different length means a different parameter set.`,
      );
    }
    base.signature = result.bytes;
  }

  return { ok: true, resolved: base };
}
