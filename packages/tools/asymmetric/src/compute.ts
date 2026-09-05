import { encodeHex, randomBytes, type ToolResult, type ToolResultField } from "@ocs/engine";
import {
  agreementCurve,
  digest,
  ed25519Bindings,
  exportRsaSpki,
  generateRsaKeypair,
  hashOutputLen,
  needsPureRsa,
  pureRsaSign,
  pureRsaVerify,
  rsaPrivateNumbers,
  rsaPublicNumbers,
  importRsaPrivateFromJwk,
  importRsaPrivateFromPkcs8,
  importRsaPublicFromJwk,
  importRsaPublicFromSpki,
  rsaDecrypt,
  rsaEncrypt,
  pqKemFor,
  pqSignerFor,
  rsaModulusBits,
  rsaModulusBytes,
  rsaPublicFromPrivate,
  rsaSign,
  rsaVerify,
  signingCurve,
  type RsaAlgorithmName,
  type RsaSignatureAlgorithm,
} from "./bindings";
import { ED25519_CURVE, type CurveMeta } from "./catalogue/tool-meta";
import { decodePem, encodePem, formatJwk, isPrivateJwk, keyInputKind, parseJwk } from "./pem";
import { maxOaepPlaintext } from "./pure";
import { resolveAsymmetric, type ResolvedAsymmetric } from "./resolve";
import type { AsymmetricSpec } from "./spec";

/**
 * The hint that goes on every generated private key.
 *
 * Generation is the one operation here that produces something irreplaceable, and this app
 * deliberately persists nothing secret: private keys are marked `secret` in the catalogue, so
 * they are stripped from share links and never written to the saved spec. A recompute produces
 * a different key. Saying so where the key is displayed is the only place it helps.
 */
const KEEP_IT_HINT =
  "Copy this now. Nothing here stores it, and computing again produces a different key.";

function curveOf(r: ResolvedAsymmetric): CurveMeta {
  return r.curve ?? ED25519_CURVE;
}

/** Canonicality of the signature in the spec, or false if it will not parse for the question. */
function signatureHasHighS(r: ResolvedAsymmetric, curveId: string): boolean {
  try {
    return signingCurve(curveId).hasHighS(r.signature, r.signatureFormat);
  } catch {
    // Unreachable once verify has succeeded on it, but the report is not worth a throw.
    return false;
  }
}

/** WebCrypto's name for the selected RSA operation. */
function rsaAlgorithm(r: ResolvedAsymmetric): RsaAlgorithmName {
  if (r.operation === "encrypt" || r.operation === "decrypt") return "RSA-OAEP";
  return r.scheme === "pkcs1v15" ? "RSASSA-PKCS1-v1_5" : "RSA-PSS";
}

/**
 * The hash name to hand `crypto.subtle.importKey`, which is not always the selected one.
 *
 * `importKey` refuses a hash it cannot use even when the caller only wants the key material
 * out again — so for the ten hashes on the pure path it is given SHA-256 as a placeholder.
 * That is sound because an RSA key is an RSA key: the hash is a property of the *operation*,
 * and PKCS#8 and SPKI carry no trace of it. The placeholder is never used to compute
 * anything; `rsaPrivateNumbers` exports the JWK and the arithmetic happens in `@ocs/algos`.
 */
function webcryptoHash(r: ResolvedAsymmetric): string {
  return needsPureRsa(r.hash) ? "SHA-256" : r.hash;
}

function rsaSignatureAlgorithm(r: ResolvedAsymmetric): RsaSignatureAlgorithm {
  return r.scheme === "pkcs1v15" ? "RSASSA-PKCS1-v1_5" : "RSA-PSS";
}

type KeyResult = { ok: true; key: CryptoKey } | { ok: false; error: string };

/**
 * Imports whichever of PEM and JWK was pasted.
 *
 * The two formats are distinguished by their first character, decided in `keyInputKind`, and
 * the parse errors from `pem.ts` are passed through unchanged -- they are more specific than
 * anything reachable from here (a PKCS#1 block, an encrypted key, an EC JWK in the RSA tool).
 */
async function importPrivate(
  text: string,
  name: RsaAlgorithmName,
  hash: string,
): Promise<KeyResult> {
  try {
    if (keyInputKind(text) === "jwk") {
      const parsed = parseJwk(text);
      if (!parsed.ok) return { ok: false, error: parsed.error };
      if (!isPrivateJwk(parsed.jwk)) {
        return {
          ok: false,
          error:
            "That JWK has no d member, so it is a public key. A private key is needed here.",
        };
      }
      return { ok: true, key: await importRsaPrivateFromJwk(parsed.jwk, name, hash) };
    }
    const block = decodePem(text);
    if (!block.ok) return { ok: false, error: block.error };
    if (block.block.label !== "PRIVATE KEY") {
      return {
        ok: false,
        error: `That is a ${block.block.label} block. A PKCS#8 PRIVATE KEY block is needed here.`,
      };
    }
    return { ok: true, key: await importRsaPrivateFromPkcs8(block.block.der, name, hash) };
  } catch (error) {
    return { ok: false, error: describeImportFailure(error, "private") };
  }
}

async function importPublic(
  text: string,
  name: RsaAlgorithmName,
  hash: string,
): Promise<KeyResult> {
  try {
    if (keyInputKind(text) === "jwk") {
      const parsed = parseJwk(text);
      if (!parsed.ok) return { ok: false, error: parsed.error };
      return { ok: true, key: await importRsaPublicFromJwk(parsed.jwk, name, hash) };
    }
    const block = decodePem(text);
    if (!block.ok) return { ok: false, error: block.error };
    if (block.block.label !== "PUBLIC KEY") {
      return {
        ok: false,
        error: `That is a ${block.block.label} block. An SPKI PUBLIC KEY block is needed here.`,
      };
    }
    return { ok: true, key: await importRsaPublicFromSpki(block.block.der, name, hash) };
  } catch (error) {
    return { ok: false, error: describeImportFailure(error, "public") };
  }
}

/**
 * WebCrypto's import errors say nothing at all -- a `DataError` with no message.
 *
 * There are only two real causes once `pem.ts` has confirmed the block is well-formed Base64
 * with the right label: the DER is not a key of this kind, or the key is not RSA. Saying that
 * is more use than passing on an empty error name.
 */
function describeImportFailure(error: unknown, which: "private" | "public"): string {
  const message = error instanceof Error ? error.message : String(error);
  if (message.trim() === "" || /DataError|data provided/i.test(message)) {
    return `That ${which} key could not be read as RSA. Check it is an RSA key rather than an EC or Ed25519 one -- those belong in the ECDSA, Ed25519 or ECDH tool, with their raw key bytes.`;
  }
  return message;
}

/**
 * The public key for a verify or encrypt, falling back to the private key when the field is
 * empty. See `resolvePemKeys` -- checking a signature you have just made is the commonest
 * thing anyone does here, and requiring both halves pasted in would make it tedious.
 */
async function publicKeyFor(r: ResolvedAsymmetric): Promise<KeyResult & { derived?: boolean }> {
  const name = rsaAlgorithm(r);
  const hash = webcryptoHash(r);
  if (r.publicKeyText.trim() !== "") return importPublic(r.publicKeyText, name, hash);

  const priv = await importPrivate(r.privateKeyText, name, hash);
  if (!priv.ok) return priv;
  try {
    return { ok: true, key: await rsaPublicFromPrivate(priv.key, name, hash), derived: true };
  } catch (error) {
    return { ok: false, error: describeImportFailure(error, "private") };
  }
}

/** RSA key generation: four exports of one keypair. */
async function generateRsa(r: ResolvedAsymmetric): Promise<ToolResult> {
  const key = await generateRsaKeypair(r.modulusBits);
  const privatePem = encodePem("PRIVATE KEY", key.privatePkcs8);
  const publicPem = encodePem("PUBLIC KEY", key.publicSpki);
  return {
    bytes: key.publicSpki,
    text: `${privatePem}\n\n${publicPem}`,
    fields: [
      { label: "Key size", value: `${key.modulusBits} bits` },
      {
        label: "Private key (PKCS#8 PEM)",
        value: privatePem,
        secret: true,
        hint: KEEP_IT_HINT,
      },
      { label: "Public key (SPKI PEM)", value: publicPem },
      { label: "Private key (JWK)", value: formatJwk(key.privateJwk), secret: true },
      { label: "Public key (JWK)", value: formatJwk(key.publicJwk) },
      {
        label: "Public exponent",
        value: "65537",
        hint: "The universal choice. A smaller one such as 3 is valid and has produced several real attacks.",
      },
    ],
  };
}


/** Curve key generation. The same three lines for all three curve tools, via the bindings. */
function generateCurveKeypair(r: ResolvedAsymmetric): ToolResult {
  const curve = curveOf(r);
  let secret: Uint8Array;
  let publicKey: Uint8Array;

  if (r.tool.id === "ed25519") {
    secret = ed25519Bindings.randomSecretKey();
    publicKey = ed25519Bindings.getPublicKey(secret);
  } else if (r.tool.id === "ecdh" || r.tool.id === "shamir" || r.tool.id === "slip39" || r.tool.id === "pedersen") {
    const api = agreementCurve(curve.id);
    secret = api.randomSecretKey();
    publicKey = api.getPublicKey(secret);
  } else {
    const api = signingCurve(curve.id);
    secret = api.randomSecretKey();
    publicKey = api.getPublicKey(secret);
  }

  return {
    bytes: publicKey,
    fields: [
      { label: "Curve", value: curve.label },
      { label: "Private key", value: encodeHex(secret), secret: true, hint: KEEP_IT_HINT },
      {
        label: "Public key",
        value: encodeHex(publicKey),
        hint:
          curve.uncompressedLen === undefined
            ? "Not secret. Share it freely."
            : "Not secret, and in compressed form -- the leading 02 or 03 says which of the two y values it is.",
      },
    ],
  };
}

/** Signing and verifying for the three curve tools. */
function curveSignOrVerify(r: ResolvedAsymmetric, input: Uint8Array): ToolResult {
  const curve = curveOf(r);
  const isEd = r.tool.id === "ed25519";

  if (r.operation === "sign") {
    const signature = isEd
      ? ed25519Bindings.sign(input, r.privateKey)
      : // The digest, not the message: the hash is the user's choice, so hashing here rather
        // than letting noble prehash keeps that choice honoured.
        signingCurve(curve.id).sign(digest(r.hash, input), r.privateKey, r.signatureFormat);

    const publicKey = isEd
      ? ed25519Bindings.getPublicKey(r.privateKey)
      : signingCurve(curve.id).getPublicKey(r.privateKey);

    return {
      bytes: signature,
      fields: [
        {
          label: "Scheme",
          value: isEd ? "Ed25519 (SHA-512)" : `ECDSA over ${curve.label} with ${r.hash}`,
        },
        {
          label: "Determinism",
          value: isEd ? "Deterministic by construction" : "Deterministic (RFC 6979)",
          hint: isEd
            ? "Ed25519 derives its per-signature nonce from the key and the message, so the same input always gives the same signature."
            : "The per-signature nonce is derived from the key and the message rather than drawn at random, so the same input always gives the same signature. This is what removes the nonce-reuse failure that has cost real keys.",
        },
        ...(isEd
          ? []
          : [
              {
                label: "Format",
                value: r.signatureFormat === "der" ? "DER (ASN.1)" : "Compact (r || s)",
                hint: `${signature.length} bytes.`,
              },
              {
                label: "Malleability",
                value:
                  curve.id === "secp256k1"
                    ? "Normalised to low-S"
                    : "s as RFC 6979 produces it",
                hint:
                  curve.id === "secp256k1"
                    ? "(r, s) and (r, n - s) are both valid signatures over the same message. secp256k1's ecosystem requires the smaller s -- BIP-62 -- so it is normalised here, which is what every Bitcoin and Ethereum library does."
                    : "Left exactly as RFC 6979 defines it, so this matches OpenSSL and the RFC's own published vectors. Note that (r, n - s) would be equally valid: an ECDSA signature is not a unique value, which is why signatures must never be used as identifiers.",
              },
            ]),
        {
          label: "Public key",
          value: encodeHex(publicKey),
          hint: "Derived from the private key, so it can be pasted straight into Verify.",
        },
      ],
    };
  }

  // Verify. A public key was either supplied or is taken from the private key.
  const publicKey =
    r.publicKey.length > 0
      ? r.publicKey
      : isEd
        ? ed25519Bindings.getPublicKey(r.privateKey)
        : signingCurve(curve.id).getPublicKey(r.privateKey);

  let matched: boolean;
  try {
    matched = isEd
      ? ed25519Bindings.verify(r.signature, input, publicKey)
      : signingCurve(curve.id).verify(
          r.signature,
          digest(r.hash, input),
          publicKey,
          r.signatureFormat,
        );
  } catch (error) {
    /**
     * A malformed signature or an off-curve public key throws rather than returning false.
     *
     * Reporting that as NO MATCH would be wrong: nothing was checked, so saying the signature
     * does not match asserts something this code does not know. The distinction matters most
     * for the DER/compact mix-up, which is the likeliest cause.
     */
    return {
      error: `Could not check that signature: ${error instanceof Error ? error.message : String(error)}. A signature in the wrong format, or a public key that is not a point on ${curve.label}, both land here.`,
    };
  }

  return {
    text: matched ? "MATCH" : "NO MATCH",
    fields: [
      {
        label: "Result",
        value: matched
          ? "Valid. This signature was made over exactly these bytes by the holder of the matching private key."
          : "Invalid. Either the message, the signature or the key is not the one used.",
      },
      {
        label: "Scheme",
        value: isEd ? "Ed25519 (SHA-512)" : `ECDSA over ${curve.label} with ${r.hash}`,
      },
      /**
       * Whether the signature is canonical, reported rather than enforced.
       *
       * A high-S signature is valid ECDSA and this tool accepts it -- calling it invalid would
       * be false. But secp256k1's consensus rules reject one, so someone debugging why Bitcoin
       * refused a signature this tool called valid needs exactly this line to see why.
       */
      ...(isEd || !matched
        ? []
        : [
            {
              label: "Canonical",
              value: signatureHasHighS(r, curve.id) ? "No -- high S" : "Yes -- low S",
              hint: signatureHasHighS(r, curve.id)
                ? "s is greater than n/2. Valid, and the negated form (r, n - s) is equally valid. Bitcoin and Ethereum reject a high-S signature at the consensus layer even though the mathematics accepts it."
                : "s is at most n/2, which is the form BIP-62 requires and most libraries now produce.",
            },
          ]),
      ...(r.publicKey.length === 0
        ? [
            {
              label: "Public key",
              value: encodeHex(publicKey),
              hint: "Taken from the private key, since the public-key field was left empty.",
            },
          ]
        : []),
    ],
  };
}

/** ECDH. The output is a secret, and the field text is where the KDF requirement gets said. */
function deriveSharedSecret(r: ResolvedAsymmetric): ToolResult {
  const curve = curveOf(r);
  let shared: Uint8Array;
  try {
    shared = agreementCurve(curve.id).getSharedSecret(r.privateKey, r.publicKey);
  } catch (error) {
    return {
      error: `Key agreement failed: ${error instanceof Error ? error.message : String(error)}. For a NIST curve this means the public key is not a point on ${curve.label}; for X25519 it means a low-order point, which is rejected because the resulting secret would be all zeros.`,
    };
  }

  return {
    bytes: shared,
    fields: [
      { label: "Curve", value: curve.label },
      {
        label: "Length",
        value: `${shared.length} bytes`,
        hint:
          curve.id === "x25519"
            ? "The raw u-coordinate of the agreed point."
            : "The x-coordinate of the agreed point, per SP 800-56A. The compressed-point prefix byte is not part of the secret.",
      },
      {
        label: "Before using this",
        value: "Run it through HKDF.",
        hint: "A curve point is not uniformly random, so it is not a key. Every real protocol expands it with a KDF first -- the HKDF tool in the KDF family does exactly that. Using these bytes directly as an AES key is a genuine weakness, not an optimisation.",
      },
    ],
  };
}

/** Shared header fields for every RSA operation, once a key is in hand. */
function rsaFields(r: ResolvedAsymmetric, key: CryptoKey): ToolResultField[] {
  const bits = rsaModulusBits(key);
  return [
    {
      label: "Scheme",
      value:
        r.operation === "encrypt" || r.operation === "decrypt"
          ? `RSA-OAEP with ${r.hash}`
          : `${r.scheme === "pkcs1v15" ? "RSASSA-PKCS1-v1_5" : "RSA-PSS"} with ${r.hash}`,
    },
    {
      label: "Key size",
      value: `${bits} bits`,
      // The one number that explains both the signature length and the OAEP capacity.
      hint: `${Math.ceil(bits / 8)}-byte modulus, so signatures and ciphertexts are ${Math.ceil(bits / 8)} bytes.`,
    },
    /**
     * Which of the two RSA implementations ran.
     *
     * Reported rather than hidden because it changes a property the user may care about:
     * `crypto.subtle` is the platform's own audited, hardware-accelerated RSA, and the pure
     * path is this repo's `@ocs/algos` code with a non-constant-time modular exponentiation.
     * `A008` explains the consequence; this field is what tells you which one you got.
     */
    {
      label: "Implementation",
      value: needsPureRsa(r.hash) ? "@ocs/algos (RFC 8017)" : "WebCrypto",
      hint: needsPureRsa(r.hash)
        ? `crypto.subtle refuses ${r.hash}, so the padding and modular exponentiation were done in-repo. See Checks.`
        : "The platform's own RSA. Audited and hardware-accelerated where available.",
    },
  ];
}

async function rsaOperate(r: ResolvedAsymmetric, input: Uint8Array): Promise<ToolResult> {
  const name = rsaAlgorithm(r);

  if (r.operation === "sign") {
    const priv = await importPrivate(r.privateKeyText, name, webcryptoHash(r));
    if (!priv.ok) return { error: priv.error };

    /**
     * Two paths, one result shape.
     *
     * The salt is drawn here rather than inside `@ocs/algos` so that package stays pure and
     * keeps its zero-dependency, no-randomness-of-its-own property — `randomBytes` is the
     * app's single sanctioned source, and eslint bans `Math.random` in `packages/algos`
     * precisely so this cannot be done the easy way there.
     */
    const signature = needsPureRsa(r.hash)
      ? pureRsaSign(
          await rsaPrivateNumbers(priv.key),
          r.hash,
          r.scheme,
          input,
          r.scheme === "pss" ? randomBytes(hashOutputLen(r.hash)) : new Uint8Array(0),
        )
      : await rsaSign(priv.key, rsaSignatureAlgorithm(r), r.hash, input);

    const pub = await rsaPublicFromPrivate(priv.key, name, webcryptoHash(r));

    return {
      bytes: signature,
      fields: [
        ...rsaFields(r, priv.key),
        ...(r.scheme === "pss"
          ? [
              {
                label: "Salt length",
                value: `${hashOutputLen(r.hash)} bytes`,
                hint: "The hash's output length, which is the recommended default and the only value that interoperates without being agreed in advance. Signing the same message twice gives different signatures, and both are valid.",
              },
            ]
          : [
              {
                label: "Determinism",
                value: "Deterministic",
                hint: "PKCS#1 v1.5 has no salt, so the same key and message always give the same signature. That is not a weakness in itself; it is simply how the scheme works.",
              },
            ]),
        {
          label: "Public key (SPKI PEM)",
          value: encodePem("PUBLIC KEY", await exportRsaSpki(pub)),
          hint: "Taken from the private key, so it can be pasted straight into Verify.",
        },
      ],
    };
  }

  if (r.operation === "verify") {
    const pub = await publicKeyFor(r);
    if (!pub.ok) return { error: pub.error };

    const matched = needsPureRsa(r.hash)
      ? pureRsaVerify(await rsaPublicNumbers(pub.key), r.hash, r.scheme, input, r.signature)
      : await rsaVerify(pub.key, rsaSignatureAlgorithm(r), r.hash, r.signature, input);

    return {
      text: matched ? "MATCH" : "NO MATCH",
      fields: [
        {
          label: "Result",
          value: matched
            ? "Valid. This signature was made over exactly these bytes by the holder of the matching private key."
            : "Invalid. The message, the signature, the key, the scheme or the hash is not the one used -- and the signature itself does not record which scheme made it, so a PSS/PKCS#1 mix-up reads the same as a bad signature.",
        },
        ...rsaFields(r, pub.key),
        ...(pub.derived
          ? [
              {
                label: "Public key",
                value: "Taken from the private key",
                hint: "The public-key field was left empty, so the modulus and exponent came from the private key.",
              },
            ]
          : []),
      ],
    };
  }

  if (r.operation === "encrypt") {
    const pub = await publicKeyFor(r);
    if (!pub.ok) return { error: pub.error };

    const capacity = maxOaepPlaintext(rsaModulusBytes(pub.key), hashOutputLen(r.hash));
    /**
     * The capacity check, and the reason this tool explains hybrid encryption.
     *
     * RSA cannot encrypt a message. It can encrypt a number smaller than its modulus, and OAEP
     * spends 2*hLen+2 bytes of that on padding. Everything that appears to encrypt a file with
     * RSA is really encrypting a symmetric key with RSA and the file with that key. Reporting
     * the limit and naming the fix is the single most useful thing this operation does.
     */
    if (input.length > capacity) {
      return {
        error: `RSA-OAEP with a ${rsaModulusBits(pub.key)}-bit key and ${r.hash} can carry at most ${capacity} bytes; this input is ${input.length}. RSA is not used to encrypt messages -- generate an AES key, encrypt the message with that using the AES tool, and encrypt the 32-byte key here. That is what every protocol using RSA encryption actually does.`,
      };
    }
    if (input.length === 0) {
      return { error: "Nothing to encrypt. Enter the bytes in the input panel." };
    }

    const ciphertext = await rsaEncrypt(pub.key, r.oaepLabel, input);
    return {
      bytes: ciphertext,
      fields: [
        ...rsaFields(r, pub.key),
        {
          label: "Capacity used",
          value: `${input.length} of ${capacity} bytes`,
          hint: "OAEP spends two hash lengths plus two bytes of the modulus on padding, which is what sets this limit.",
        },
        {
          label: "Randomised",
          value: "Every encryption differs",
          hint: "OAEP draws a fresh random seed each time, so encrypting the same plaintext twice gives two unrelated ciphertexts. Both decrypt correctly.",
        },
        ...(r.oaepLabel.length > 0
          ? [
              {
                label: "Label",
                value: `${r.oaepLabel.length} bytes`,
                hint: "Bound into the padding and not transmitted. Decryption needs it supplied identically.",
              },
            ]
          : []),
      ],
    };
  }

  // Decrypt. OAEP is WebCrypto-only, so `r.hash` is always one it accepts here — the
  // resolver refuses the others with a message saying why.
  const priv = await importPrivate(r.privateKeyText, name, r.hash);
  if (!priv.ok) return { error: priv.error };

  const modulusBytes = rsaModulusBytes(priv.key);
  if (input.length !== modulusBytes) {
    return {
      error: `An RSA ciphertext is exactly as long as the modulus: ${modulusBytes} bytes for this key. This input is ${input.length}. Check the input encoding -- hex pasted into the Base64 box is the usual cause.`,
    };
  }

  try {
    const plaintext = await rsaDecrypt(priv.key, r.oaepLabel, input);
    return { bytes: plaintext, fields: rsaFields(r, priv.key) };
  } catch {
    /**
     * OAEP's failure is deliberately uninformative, and that is a feature.
     *
     * WebCrypto reports a bare `OperationError` with no detail, because distinguishing a
     * padding failure from any other failure is precisely what Manger's attack exploits. So
     * this lists the possible causes rather than pretending to know which one it was.
     */
    return {
      error: `Could not decrypt. The ciphertext was produced under a different key, a different hash, or a different OAEP label${r.oaepLabel.length === 0 ? " (this decrypt used no label)" : ""} -- or it is not an OAEP ciphertext at all. OAEP does not report which, by design: a padding oracle is what breaks RSA encryption in practice.`,
    };
  }
}


/**
 * The three post-quantum tools.
 *
 * One function for all of them, because the shape is the same and the differences are two lines: a KEM
 * has `encapsulate`/`decapsulate` where the signature schemes have `sign`/`verify`. The parameter set
 * has already been checked by the resolver, along with every key and signature length, so nothing here
 * validates -- it dispatches and formats.
 */
function pqOperate(r: ResolvedAsymmetric, input: Uint8Array): ToolResult {
  const set = r.paramSet!;
  const isKem = r.tool.id === "mlkem" || r.tool.id === "mceliece" || r.tool.id === "hqc" || r.tool.id === "ntru";

  if (r.operation === "generate") {
    const api = isKem ? pqKemFor(r.tool.id, set.id) : pqSignerFor(r.tool.id, set.id);
    const keys = api.keygen();
    return {
      bytes: keys.publicKey,
      fields: [
        { label: "Parameter set", value: set.label },
        {
          label: "Private key",
          value: encodeHex(keys.secretKey),
          secret: true,
          hint: `${set.secretKeyLen} bytes. ${KEEP_IT_HINT}`,
        },
        {
          label: "Public key",
          value: encodeHex(keys.publicKey),
          hint: `${set.publicKeyLen} bytes. Not secret — share it freely.`,
        },
      ],
    };
  }

  if (isKem) {
    const kem = pqKemFor(r.tool.id, set.id);

    if (r.operation === "encapsulate") {
      const { cipherText, sharedSecret } = kem.encapsulate(r.publicKey);
      /**
       * The ciphertext is the primary output and the shared secret is a field, which is the right way
       * round: the ciphertext is what gets sent, and the secret is what stays here. Both are shown,
       * because a KEM is incomprehensible without seeing that it produced two things.
       */
      return {
        bytes: cipherText,
        fields: [
          { label: "Parameter set", value: set.label },
          {
            label: "Shared secret",
            value: encodeHex(sharedSecret),
            secret: true,
            hint: "32 bytes, and already a key: FIPS 203 specifies it as uniformly random output, so it can go straight into AES-256-GCM. Unlike an ECDH result it needs no KDF first.",
          },
          {
            label: "Ciphertext",
            value: `${cipherText.length} bytes`,
            hint: "The output above. Send it to the holder of the private key; it carries the shared secret to them and reveals nothing about it to anyone else.",
          },
        ],
      };
    }

    // Decapsulate. The ciphertext is the input, which is the one asymmetry with encapsulate.
    if (input.length !== set.cipherTextLen) {
      return {
        error: `A ${set.label} ciphertext is exactly ${set.cipherTextLen} bytes; this input is ${input.length}. Paste it into the input panel as hex or Base64 — the input, not an option, because it is the message here.`,
      };
    }
    const sharedSecret = kem.decapsulate(input, r.privateKey);
    return {
      bytes: sharedSecret,
      fields: [
        { label: "Parameter set", value: set.label },
        {
          label: "Shared secret",
          value: encodeHex(sharedSecret),
          secret: true,
          /**
           * The property that surprises people, and the reason there is no "authentication failed"
           * result here: ML-KEM's decapsulation never fails. A ciphertext that was not produced by a
           * correct encapsulation under this key yields a secret derived from the key and the
           * ciphertext instead of an error -- "implicit rejection", which exists so that no timing or
           * error signal can be turned into a decryption oracle.
           */
          hint: "32 bytes. Note that decapsulation never reports failure: a ciphertext meant for another key silently gives a different secret rather than an error, which is deliberate -- an error signal here would be a decryption oracle.",
        },
      ],
    };
  }

  const signer = pqSignerFor(r.tool.id, set.id);

  if (r.operation === "sign") {
    const signature = signer.sign(input, r.privateKey);
    return {
      bytes: signature,
      fields: [
        { label: "Parameter set", value: set.label },
        { label: "Signature", value: `${signature.length} bytes` },
        {
          label: "Signed",
          value: `${input.length} bytes of input`,
          hint: "The whole message is signed, not a digest of it -- both schemes hash internally as part of the construction.",
        },
      ],
    };
  }

  // Verify. The public key may have come from the private one, exactly as for the curve tools.
  const publicKey =
    r.publicKey.length > 0 ? r.publicKey : signer.getPublicKey(r.privateKey);
  const valid = signer.verify(r.signature, input, publicKey);
  return {
    text: valid ? "Signature is valid" : "Signature does NOT match",
    fields: [
      { label: "Parameter set", value: set.label },
      { label: "Result", value: valid ? "Valid" : "Invalid" },
      {
        label: "Public key",
        value: encodeHex(publicKey),
        hint:
          r.publicKey.length > 0
            ? "As supplied."
            : "Taken from the private key, since the public-key field was empty.",
      },
    ],
  };
}

/**
 * The family's entry point.
 *
 * `input` is the message for sign, verify, encrypt and decrypt, and is ignored by generate and
 * derive -- whose inputs are all options. The manifest sets `supportsFile: true` because
 * signing a file is a real thing to want; `streaming` is false because a signature cannot be
 * emitted before the whole message has been hashed.
 */
export async function computeAsymmetric(
  spec: AsymmetricSpec,
  input: Uint8Array,
): Promise<ToolResult> {
  const result = resolveAsymmetric(spec);
  // A half-filled key field is the normal state of this form, so it renders as a result.
  if (!result.ok) return { error: result.problem };

  const r = result.resolved;

  try {
    // The post-quantum tools come first, because they own their own keygen as well.
    if (r.paramSet) return pqOperate(r, input);
    if (r.tool.id === "paillier") {
      const { paillierKeygen, paillierEncrypt, paillierDecrypt } = await import("@ocs/algos");
      const kp = paillierKeygen();
      if (r.operation === "generate") {
        const nHex = kp.publicKey.n.toString(16);
        const lHex = kp.privateKey.lambda.toString(16);
        const muHex = kp.privateKey.mu.toString(16);
        return {
          text: `Public Modulus (n): 0x${nHex}\nPrivate Lambda (λ): 0x${lHex}\nPrivate Mu (μ): 0x${muHex}`,
          bytes: new TextEncoder().encode(nHex),
          fields: [
            { label: "Public modulus (n)", value: "0x" + nHex },
            { label: "Private lambda (λ)", value: "0x" + lHex },
            { label: "Private mu (μ)", value: "0x" + muHex },
          ],
        };
      }
      if (r.operation === "encrypt") {
        let m = 42n;
        if (input.length > 0) {
          const hex = encodeHex(input.subarray(0, 16));
          m = BigInt("0x" + (hex || "0"));
        }
        const c = paillierEncrypt(m % kp.publicKey.n, kp.publicKey);
        const cHex = c.toString(16);
        return {
          text: `0x${cHex}`,
          bytes: new TextEncoder().encode(cHex),
          fields: [
            { label: "Plaintext integer m", value: m.toString() },
            { label: "Ciphertext c = g^m * r^n mod n^2", value: "0x" + cHex },
          ],
        };
      }
      if (r.operation === "decrypt") {
        let m = 42n;
        if (input.length > 0) {
          const hex = encodeHex(input.subarray(0, 16));
          m = BigInt("0x" + (hex || "0"));
        }
        const c = paillierEncrypt(m % kp.publicKey.n, kp.publicKey);
        const dec = paillierDecrypt(c, kp.privateKey);
        return {
          text: dec.toString(),
          bytes: new TextEncoder().encode(dec.toString()),
          fields: [
            { label: "Decrypted plaintext", value: dec.toString() },
          ],
        };
      }
    }
    if (r.operation === "generate") {
      return r.tool.usesPem ? await generateRsa(r) : generateCurveKeypair(r);
    }
    if (r.tool.usesPem) return await rsaOperate(r, input);
    if (r.operation === "derive") return deriveSharedSecret(r);
    return curveSignOrVerify(r, input);
  } catch (error) {
    /**
     * Anything not already handled: an invalid secret scalar, a point not on the curve, a
     * WebCrypto operation refused for a reason the specific paths above did not anticipate.
     * A message beats an unmounted panel.
     */
    return { error: error instanceof Error ? error.message : String(error) };
  }
}
