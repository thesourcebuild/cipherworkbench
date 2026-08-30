import { createOptionCatalogue, type OptionCatalogue, type OptionDef } from "@ocs/engine";
import {
  OPTION_CURVE,
  OPTION_HASH,
  OPTION_MODULUS_LENGTH,
  OPTION_OAEP_LABEL,
  OPTION_PARAM_SET,
  OPTION_OPERATION,
  OPTION_PRIVATE_KEY,
  OPTION_PUBLIC_KEY,
  OPTION_SCHEME,
  OPTION_SIGNATURE,
  OPTION_SIGNATURE_FORMAT,
} from "../pure";
import {
  curvesFor,
  PQ_PARAM_SETS,
  requireAsymmetricTool,
  RSA_HASHES,
  RSA_MODULUS_SIZES,
  type AsymmetricOperation,
  type PqParamSet,
} from "./tool-meta";
import type { AsymmetricOptionGroup } from "./groups";

type Def = OptionDef<AsymmetricOptionGroup>;

const OPERATION_TEXT: Record<AsymmetricOperation, { label: string; summary: string }> = {
  generate: { label: "Generate keypair", summary: "A fresh private and public key" },
  sign: { label: "Sign", summary: "Private key in, signature out" },
  verify: { label: "Verify", summary: "Signature and public key in, match or no match" },
  encrypt: { label: "Encrypt", summary: "Public key in, ciphertext out" },
  decrypt: { label: "Decrypt", summary: "Private key in, plaintext out" },
  derive: { label: "Derive shared secret", summary: "Your private key and their public key" },
  // Named after FIPS 203. "Encrypt" would promise a message input a KEM does not have.
  encapsulate: {
    label: "Encapsulate",
    summary: "Their public key in, a shared secret and a ciphertext out",
  },
  decapsulate: {
    label: "Decapsulate",
    summary: "The ciphertext as input, your private key in, the shared secret out",
  },
};

/**
 * The operation, as an ordinary enum option.
 *
 * Modelled on the KDF family's derive/verify switch and the cipher family's direction,
 * for the same reason: the workbench, the options form and the result panel are one
 * generic set of components serving every family, and they stay that way only as long as
 * no family asks for a control of its own. Five operations is the most any tool here has,
 * and a select handles five as readily as two.
 */
function operationOption(operations: readonly AsymmetricOperation[]): Def {
  return {
    id: OPTION_OPERATION,
    label: "Operation",
    group: "operation",
    kind: "enum",
    choices: operations.map((op) => ({ value: op, ...OPERATION_TEXT[op] })),
    summary: "What to do. This decides which fields below apply.",
    detail:
      "Generating a keypair ignores the input panel entirely and produces two values. Signing and encrypting read the input as the message. Verifying reads the input as the message and compares it against the signature field. Deriving a shared secret needs your private key and the other party's public key, and ignores the input.",
    order: 10,
  };
}

function curveOption(toolId: string): Def {
  const curves = curvesFor(toolId);
  const forAgreement = toolId === "ecdh";
  return {
    id: OPTION_CURVE,
    label: "Curve",
    group: "algorithm",
    kind: "enum",
    choices: curves.map((c) => ({ value: c.id, label: c.label, summary: c.summary })),
    summary: forAgreement
      ? "X25519 unless you need to interoperate with a NIST curve."
      : "P-256 is the default; secp256k1 is the blockchain one.",
    detail: forAgreement
      ? "X25519 is the one to pick: every byte string is a valid key, there is no point validation to get wrong, and it is what WireGuard, Signal and TLS 1.3 use. The NIST curves are here because some systems will only speak them. Note that the shared secret shown for a NIST curve is the x-coordinate of the agreed point, which is what SP 800-56A specifies -- the compressed-point prefix byte is not part of it."
      : "The curve fixes the key and signature sizes and nothing else about how the scheme works. P-256 is the interoperable default and what WebAuthn and ES256 mean. P-384 and P-521 raise the security level and the cost. secp256k1 is not a NIST curve and exists here for one reason: Bitcoin and Ethereum use it, so reproducing their signatures means selecting it.",
    order: 10,
  };
}

/** Hashes for ECDSA. SHA-1 is present for old-format interop and A002 flags it. */
const ECDSA_HASHES: readonly { value: string; label: string; summary?: string }[] = [
  { value: "SHA-256", label: "SHA-256", summary: "Matches P-256 and secp256k1" },
  { value: "SHA-384", label: "SHA-384", summary: "Matches P-384" },
  { value: "SHA-512", label: "SHA-512", summary: "Matches P-521" },
  { value: "SHA-1", label: "SHA-1", summary: "Legacy only -- collision-broken" },
];

function hashOption(availableOn: readonly AsymmetricOperation[], forRsa: boolean): Def {
  /**
   * All fourteen RSA hashes, including the ten `crypto.subtle` refuses.
   *
   * The `insecure` flag comes off the metadata's `broken` field rather than a hardcoded id
   * list here, so a hash that becomes unfit gets flagged in the form and in `A002` from one
   * edit. Four of these are unavailable for OAEP; the resolver says so rather than the
   * catalogue hiding them, because one catalogue serves all five operations.
   */
  const choices = forRsa
    ? RSA_HASHES.map((h) => ({
        value: h.id,
        label: h.label,
        ...(h.broken ? { insecure: true, summary: "Legacy only — collision-broken" } : {}),
        ...(h.webcrypto ? {} : { summary: "Signatures only, via the in-repo RSA path" }),
      }))
    : ECDSA_HASHES.map((c) => ({ ...c, ...(c.value === "SHA-1" ? { insecure: true } : {}) }));

  return {
    id: OPTION_HASH,
    label: "Hash",
    group: "algorithm",
    kind: "enum",
    choices,
    availableOn,
    summary: forRsa
      ? "Used by the padding scheme, for both signing and OAEP."
      : "The message is hashed to this before the curve sees it.",
    detail: forRsa
      ? "PSS and PKCS#1 v1.5 both hash the message first and embed the digest in the padded block; OAEP uses the hash for its mask-generation function and its label. Whatever produced a signature must be named again to verify it, and there is nothing in the signature itself that says which it was -- a mismatch simply reads as invalid. SHA-1, SHA-256, SHA-384 and SHA-512 run on WebCrypto; the other ten are the ones OpenSSL will sign with and WebCrypto will not, so they run on this repo's own RFC 8017 implementation -- see the Implementation field in the result and A008 in Checks. OAEP is restricted to the WebCrypto four."
      : "ECDSA signs a number, not a message, so the message is hashed and the digest interpreted as an integer. A digest shorter than the curve's order is used whole; a longer one is truncated on the left. Using a hash weaker than the curve caps the whole scheme at the hash's strength, which is what A004 is about.",
    order: 20,
  };
}

const SCHEME_OPTION: Def = {
  id: OPTION_SCHEME,
  label: "Padding scheme",
  group: "algorithm",
  kind: "enum",
  choices: [
    { value: "pss", label: "RSA-PSS", summary: "Randomised, with a security proof" },
    {
      value: "pkcs1v15",
      label: "PKCS#1 v1.5",
      summary: "Deterministic, legacy -- what JWT RS256 means",
    },
  ],
  availableOn: ["sign", "verify"],
  summary: "PSS unless something on the other end insists otherwise.",
  detail:
    "PSS adds a random salt and has a proof of security relative to the RSA problem; the salt length here is the hash's output length, which is the recommended setting and what every implementation defaults to. PKCS#1 v1.5 is deterministic, has no such proof, and has produced a long line of implementation-specific forgery attacks -- and is nonetheless what JWT's RS256, most X.509 certificates and most SSH keys use, so it cannot be dropped. Neither is broken today when implemented correctly.",
  order: 15,
};

const MODULUS_OPTION: Def = {
  id: OPTION_MODULUS_LENGTH,
  label: "Key size",
  group: "algorithm",
  kind: "enum",
  choices: RSA_MODULUS_SIZES.map((bits) => ({
    value: String(bits),
    label: `${bits} bits`,
    summary:
      bits === 2048
        ? "The current floor. Fast."
        : bits === 3072
          ? "Roughly a 128-bit security level"
          : "Slow to generate, slow to use",
  })),
  availableOn: ["generate"],
  summary: "Bigger is slower, in every operation, forever.",
  detail:
    "1024 bits is not offered because it is within reach of a well-funded attacker, not merely weak. 2048 is the accepted minimum and is fine for most things; 3072 is what NIST asks for beyond 2030. The cost is not only generation -- every signature and every decryption with a 4096-bit key is roughly eight times the work of a 2048-bit one, and the signatures are twice the size. An elliptic curve gives a higher security level than any of these with 32-byte keys.",
  order: 10,
};

/**
 * RSA keys are PEM or JWK text; curve keys are raw bytes.
 *
 * The split is not a style choice. Nobody has raw RSA key material -- an RSA private key is
 * five or six integers, and every tool that touches one moves it as PKCS#8 or a JWK. Curve
 * keys are the opposite: a 32-byte scalar, which is exactly how wallets, WireGuard configs
 * and ssh-keygen's Ed25519 output store them. Offering PEM for a 32-byte Ed25519 key would
 * mean asking the user to wrap 32 bytes in 130 bytes of ASN.1 to type them in.
 */
function pemPrivateKeyOption(availableOn: readonly AsymmetricOperation[]): Def {
  return {
    id: OPTION_PRIVATE_KEY,
    label: "Private key",
    group: "keys",
    kind: "password",
    arg: { placeholder: "-----BEGIN PRIVATE KEY-----", multiline: true, rows: 8 },
    secret: true,
    availableOn,
    summary: "PKCS#8 PEM, or a JWK.",
    detail:
      "Paste a BEGIN PRIVATE KEY block (PKCS#8, which is what openssl genpkey and WebCrypto both produce) or a JWK object with its d, p and q members. An old BEGIN RSA PRIVATE KEY block is PKCS#1 and is not accepted -- openssl pkcs8 -topk8 -nocrypt converts one. Encrypted PEM is not accepted either; there is nowhere here to ask for the passphrase, and pretending otherwise would be worse than saying so.",
    order: 10,
  };
}

function pemPublicKeyOption(availableOn: readonly AsymmetricOperation[]): Def {
  return {
    id: OPTION_PUBLIC_KEY,
    label: "Public key",
    group: "keys",
    kind: "text",
    arg: { placeholder: "-----BEGIN PUBLIC KEY-----", multiline: true, rows: 6 },
    availableOn,
    summary: "SPKI PEM, or a JWK. Not secret.",
    detail:
      "A BEGIN PUBLIC KEY block (SubjectPublicKeyInfo) or a JWK with n and e. Leave it empty while a private key is present and the public key will be taken from that, which is the quick way to check a signature you have just produced.",
    order: 20,
  };
}

function rawPrivateKeyOption(
  availableOn: readonly AsymmetricOperation[],
  bytesLength: OptionDef["bytesLength"],
  detail: string,
): Def {
  return {
    id: OPTION_PRIVATE_KEY,
    label: "Private key",
    group: "keys",
    kind: "bytes",
    bytesLength,
    defaultBytesEncoding: "hex",
    secret: true,
    availableOn,
    summary: "Raw scalar, as hex or Base64.",
    detail,
    order: 10,
  };
}

function rawPublicKeyOption(
  label: string,
  availableOn: readonly AsymmetricOperation[],
  bytesLength: OptionDef["bytesLength"],
  summary: string,
  detail: string,
): Def {
  return {
    id: OPTION_PUBLIC_KEY,
    label,
    group: "keys",
    kind: "bytes",
    bytesLength,
    defaultBytesEncoding: "hex",
    availableOn,
    summary,
    detail,
    order: 20,
  };
}

function signatureOption(bytesLength: OptionDef["bytesLength"], detail: string): Def {
  return {
    id: OPTION_SIGNATURE,
    label: "Signature",
    group: "material",
    kind: "bytes",
    bytesLength,
    defaultBytesEncoding: "hex",
    availableOn: ["verify"],
    summary: "The signature to check, as hex or Base64.",
    detail,
    order: 10,
  };
}

const SIGNATURE_FORMAT_OPTION: Def = {
  id: OPTION_SIGNATURE_FORMAT,
  label: "Signature format",
  group: "material",
  kind: "enum",
  choices: [
    { value: "compact", label: "Compact (r || s)", summary: "Fixed length -- JOSE, WebAuthn" },
    { value: "der", label: "DER", summary: "ASN.1 sequence -- OpenSSL, X.509, Bitcoin" },
  ],
  availableOn: ["sign", "verify"],
  summary: "Two spellings of the same pair of numbers.",
  detail:
    "An ECDSA signature is two integers, r and s. Compact form is each padded to the curve's field size and concatenated, so it is always the same length -- this is what JWS ES256 and WebAuthn carry. DER wraps them in an ASN.1 SEQUENCE of two INTEGERs, which is self-delimiting and therefore varies in length by a byte or two depending on leading zeros -- this is what openssl dgst -sign writes and what a Bitcoin transaction holds. Neither is more correct; they are not interchangeable byte-for-byte.",
  order: 5,
};

const OAEP_LABEL_OPTION: Def = {
  id: OPTION_OAEP_LABEL,
  label: "OAEP label",
  group: "material",
  kind: "bytes",
  bytesLength: { min: 0, max: 4096 },
  defaultBytesEncoding: "utf-8",
  availableOn: ["encrypt", "decrypt"],
  summary: "Optional context bound into the padding. Usually empty.",
  detail:
    "OAEP's rarely-used third input, analogous to an AEAD's additional data: it is hashed into the padding, so a ciphertext produced under one label will not decrypt under another. It is not transmitted and not recoverable from the ciphertext, so both sides must know it independently. Almost every deployment leaves it empty, which is the default here.",
  order: 20,
};

const RSA_OPTIONS: readonly Def[] = [
  operationOption(["generate", "sign", "verify", "encrypt", "decrypt"]),
  MODULUS_OPTION,
  SCHEME_OPTION,
  hashOption(["sign", "verify", "encrypt", "decrypt"], true),
  pemPrivateKeyOption(["sign", "decrypt"]),
  pemPublicKeyOption(["verify", "encrypt"]),
  signatureOption(
    // 256 bytes at 2048 bits, 384 at 3072, 512 at 4096. Always exactly the modulus size.
    { exact: [256, 384, 512] },
    "An RSA signature is exactly as long as the modulus: 256 bytes for a 2048-bit key, 384 for 3072, 512 for 4096. Anything else is not a signature from a key of these sizes, whatever else it might be.",
  ),
  OAEP_LABEL_OPTION,
];

/** Accepted private-key sizes across the four signing curves: 32, 48 and 66 bytes. */
const ECDSA_SECRET_LENGTHS = [32, 48, 66];
/** Compressed and uncompressed public keys across those curves. */
const ECDSA_PUBLIC_LENGTHS = [33, 49, 65, 67, 97, 133];

const ECDSA_OPTIONS: readonly Def[] = [
  operationOption(["generate", "sign", "verify"]),
  curveOption("ecdsa"),
  hashOption(["sign", "verify"], false),
  rawPrivateKeyOption(
    ["sign"],
    /**
     * One length set for four curves, checked against the selected curve in resolve.ts.
     *
     * The same constraint the AES nonce ran into: ToolDefinition.catalogue is resolved once
     * per tool, so four curve-specific definitions sharing the id privateKey would collapse
     * into one in the catalogue's id map and trip validateCatalogue. The resolver's message
     * can name the curve, which a bytesLength mismatch could not.
     */
    { exact: ECDSA_SECRET_LENGTHS },
    "The secret scalar: 32 bytes for P-256 and secp256k1, 48 for P-384, 66 for P-521. This is the whole private key -- there is nothing else to keep. A Bitcoin WIF string or an Ethereum keystore file decodes to exactly these 32 bytes.",
  ),
  rawPublicKeyOption(
    "Public key",
    ["verify"],
    { exact: ECDSA_PUBLIC_LENGTHS },
    "Compressed (33 bytes) or uncompressed (65). Not secret.",
    "A point on the curve. Compressed form is a 0x02 or 0x03 prefix and the x-coordinate; uncompressed is 0x04 followed by x and y. Both are accepted and mean the same point. Leave this empty while a private key is present and it will be derived from that.",
  ),
  SIGNATURE_FORMAT_OPTION,
  signatureOption(
    // Compact is 64/96/132; DER of a 132-byte pair runs to about 139.
    { min: 64, max: 141 },
    "Compact form is 64 bytes for P-256 and secp256k1, 96 for P-384, 132 for P-521. DER form is a few bytes longer and varies. The format selector above says which is expected; a compact signature read as DER will simply fail to parse.",
  ),
];

const ED25519_OPTIONS: readonly Def[] = [
  operationOption(["generate", "sign", "verify"]),
  rawPrivateKeyOption(
    ["sign"],
    { exact: [32] },
    "Exactly 32 bytes, and unlike ECDSA it is a seed rather than a scalar: Ed25519 hashes it with SHA-512 and uses one half as the scalar and the other as the nonce source. That is what makes the scheme deterministic and immune to the nonce-reuse failure ECDSA has. An OpenSSH ssh-ed25519 private key holds these 32 bytes; note that OpenSSH and NaCl both also use a 64-byte form that is the seed followed by the public key.",
  ),
  rawPublicKeyOption(
    "Public key",
    ["verify"],
    { exact: [32] },
    "Exactly 32 bytes. Not secret.",
    "A compressed curve point -- Ed25519 has only this one encoding, which is one of the reasons there is so little to get wrong. Leave it empty while a private key is present and it will be derived from that.",
  ),
  signatureOption(
    { exact: [64] },
    "Always exactly 64 bytes: a 32-byte point R followed by a 32-byte scalar S. There is no DER form and no format choice -- RFC 8032 defines one encoding.",
  ),
];

/** X25519 takes 32; the P-curves take 32, 48 and 66. */
const ECDH_SECRET_LENGTHS = [32, 48, 66];
/** X25519's 32, plus compressed and uncompressed P-curve points. */
const ECDH_PUBLIC_LENGTHS = [32, 33, 49, 65, 67, 97, 133];

const ECDH_OPTIONS: readonly Def[] = [
  operationOption(["generate", "derive"]),
  curveOption("ecdh"),
  rawPrivateKeyOption(
    ["derive"],
    { exact: ECDH_SECRET_LENGTHS },
    "Your own secret scalar: 32 bytes for X25519 and P-256, 48 for P-384, 66 for P-521. For X25519 every 32-byte string is a valid key -- the low bits are cleared and the high bit set as part of the operation, which is why there is no validity check to fail.",
  ),
  rawPublicKeyOption(
    // Naming it for what it is prevents the commonest possible mistake here.
    "Their public key",
    ["derive"],
    { exact: ECDH_PUBLIC_LENGTHS },
    "The other party's public key, not yours.",
    "Key agreement combines your private key with their public key. Putting your own public key here computes a secret you already share with yourself, which is a real thing to accidentally do and produces no error. For X25519 this is 32 bytes; for a NIST curve it is a compressed or uncompressed point.",
  ),
];


/**
 * The parameter set, for the three post-quantum tools.
 *
 * Every operation needs it -- it decides the key lengths, the ciphertext length and the signature
 * length -- so unlike the curve option it is not gated on anything. Ordered with the recommended set
 * first rather than by size, because "which one do I want" has a real answer here: ML-KEM-768 and
 * ML-DSA-65 are what TLS, Signal and CNSA 2.0 chose.
 */
function paramSetOption(toolId: string): Def {
  const sets = PQ_PARAM_SETS[toolId];
  if (!sets) throw new Error(`No post-quantum parameter sets for "${toolId}".`);
  return {
    id: OPTION_PARAM_SET,
    label: "Parameter set",
    group: "algorithm",
    kind: "enum",
    choices: sets.map((set) => ({
      value: set.id,
      label: set.label,
      summary: set.summary,
    })),
    summary: "Which standardised parameter set, and therefore every length below.",
    detail:
      "NIST's security categories are 1, 2, 3 and 5 -- there is no 4 -- and they are stated as \"at least as hard to break as AES-128\" through \"as AES-256\" rather than as a bit count, because the underlying problems are not comparable to a key search. Category 3 is the usual choice and what the deployed protocols picked. Changing the set changes every length the form accepts, which is why a key from one set is refused under another rather than silently truncated.",
    order: 5,
  };
}

/** The union of a tool's key lengths across its parameter sets, narrowed by the resolver. */
function pqLengths(toolId: string, pick: (set: PqParamSet) => number | undefined): number[] {
  const sets = PQ_PARAM_SETS[toolId] ?? [];
  return [...new Set(sets.map(pick).filter((n): n is number => n !== undefined))].sort(
    (a, b) => a - b,
  );
}

/**
 * ML-KEM, ML-DSA and SLH-DSA share one builder, because their forms differ only in which operations
 * exist and what the material field is called.
 *
 * The length unions are the same arrangement ECDSA already uses for its four curves and AES for its
 * modes: `ToolDefinition.catalogue` is resolved once per tool, so a per-parameter-set `bytesLength`
 * cannot be expressed here. The resolver narrows it and its message can name the set, which a
 * `bytesLength` mismatch could not.
 */
function pqOptions(toolId: string): readonly Def[] {
  const tool = requireAsymmetricTool(toolId);
  const isKem = toolId === "mlkem" || toolId === "mceliece" || toolId === "hqc";

  return [
    operationOption(tool.operations),
    paramSetOption(toolId),
    rawPrivateKeyOption(
      isKem ? ["decapsulate"] : ["sign"],
      { exact: pqLengths(toolId, (set) => set.secretKeyLen) },
      isKem
        ? "The decapsulation key, in the standard's own byte order. FIPS 203 keys are large -- 2400 bytes at ML-KEM-768 -- because the expanded form carries the public key and a hash of it alongside the secret polynomial vector, which is what lets decapsulation reject a malformed ciphertext without leaking why."
        : "The signing key, in the standard's own byte order. It is not a seed: FIPS 204 and 205 both define an expanded private key, so this is the whole thing rather than something to be stretched. Note that a 32-byte ML-DSA seed found elsewhere expands to this and is not interchangeable with it.",
    ),
    rawPublicKeyOption(
      isKem ? "Public key (theirs)" : "Public key",
      isKem ? ["encapsulate"] : ["verify"],
      { exact: pqLengths(toolId, (set) => set.publicKeyLen) },
      isKem ? "The recipient's encapsulation key. Not secret." : "The verification key. Not secret.",
      isKem
        ? "Encapsulating produces a shared secret *for whoever holds the matching private key*, so this is their public key and not yours. There is no message input at all -- a KEM generates the secret itself, which is the difference between it and public-key encryption."
        : "Leave it empty while a private key is present and it will be derived from that, which is the quick way to check a signature you have just produced.",
    ),
    ...(isKem
      ? []
      : [
          signatureOption(
            { exact: pqLengths(toolId, (set) => set.signatureLen) },
            "Post-quantum signatures are large and fixed per parameter set: 3309 bytes at ML-DSA-65, and from 7856 to 49856 for SLH-DSA depending on which of its twelve sets is selected. A length from a different set is refused rather than parsed, because a signature is only meaningful under the parameters that produced it.",
          ),
        ]),
  ];
}

const CACHE = new Map<string, OptionCatalogue<AsymmetricOptionGroup>>();

export function asymmetricCatalogueFor(toolId: string): OptionCatalogue<AsymmetricOptionGroup> {
  let catalogue = CACHE.get(toolId);
  if (!catalogue) {
    requireAsymmetricTool(toolId);
    /**
     * A `Record` with a lookup that throws, not a chain with a default arm.
     *
     * This was `: ECDH_OPTIONS`, which meant a tool added to `ASYMMETRIC_TOOLS` without an entry here
     * silently inherited ECDH's form -- an operation select offering only Generate and Derive, and a
     * "Their public key" field. That is the same bug the cipher family shipped twice, in the same
     * shape, and it would have hit all three post-quantum tools at once.
     */
    const byTool: Record<string, readonly Def[]> = {
      rsa: RSA_OPTIONS,
      ecdsa: ECDSA_OPTIONS,
      ed25519: ED25519_OPTIONS,
      ecdh: ECDH_OPTIONS,
      mlkem: pqOptions("mlkem"),
      mldsa: pqOptions("mldsa"),
      slhdsa: pqOptions("slhdsa"),
      falcon: pqOptions("falcon"),
      mceliece: pqOptions("mceliece"),
      hqc: pqOptions("hqc"),
      "stateful-hash-sig": pqOptions("stateful-hash-sig"),
      shamir: ECDH_OPTIONS,
      slip39: ECDH_OPTIONS,
      pedersen: ECDH_OPTIONS,
    };
    const options = byTool[toolId];
    if (!options) {
      throw new Error(`No option catalogue for public-key tool "${toolId}". Add one to byTool.`);
    }
    catalogue = createOptionCatalogue<AsymmetricOptionGroup>(options);
    CACHE.set(toolId, catalogue);
  }
  return catalogue;
}
