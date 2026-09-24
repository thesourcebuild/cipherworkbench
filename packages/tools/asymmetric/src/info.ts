import type { ToolResultField } from "@ocs/engine";
import { requireAsymmetricTool } from "./catalogue/tool-meta";
import { resolveAsymmetric } from "./resolve";
import type { AsymmetricSpec } from "./spec";

/**
 * Returns spec-derived metadata fields for the Info panel in the workbench right sidebar.
 * These rows explain what the settings are and what parameters are in effect.
 */
export function asymmetricInfo(spec: AsymmetricSpec): ToolResultField[] {
  let meta;
  try {
    meta = requireAsymmetricTool(spec.variant);
  } catch {
    return [];
  }

  const result = resolveAsymmetric(spec);
  if (!result.ok) return [];

  const r = result.resolved;
  const fields: ToolResultField[] = [];

  // 1. RSA
  if (spec.variant === "rsa") {
    fields.push(
      {
        label: "Algorithm",
        value: "RSA (Rivest–Shamir–Adleman)",
        hint: "Asymmetric cipher based on the integer factorization problem.",
      },
      {
        label: "Modulus length",
        value: `${r.modulusBits} bits (${Math.ceil(r.modulusBits / 8)} bytes)`,
        hint: `Modulus n = p × q. Signature and ciphertext size is exactly ${Math.ceil(r.modulusBits / 8)} bytes.`,
      },
      {
        label: "Public exponent (e)",
        value: `${r.publicExponent} (0x${r.publicExponent.toString(16)})`,
        hint:
          r.publicExponent === 65537
            ? "The 4th Fermat prime F₄ = 2¹⁶ + 1. Industry standard exponent chosen for speed (16 squarings + 1 multiplication) and security against low-exponent attacks."
            : r.publicExponent === 3
              ? "The 1st Fermat prime F₁ = 2¹ + 1. Smallest valid odd exponent with fastest verification (1 squaring + 1 multiplication). Vulnerable to small-exponent attacks (Coppersmith, Håstad) if padding is absent or weak."
              : r.publicExponent === 17
                ? "The 2nd Fermat prime F₂ = 2⁴ + 1. Historical compromise exponent providing fast verification (4 squarings + 1 multiplication)."
                : r.publicExponent === 257
                  ? "The 3rd Fermat prime F₃ = 2⁸ + 1. Intermediate exponent (8 squarings + 1 multiplication)."
                  : `Custom public exponent 0x${r.publicExponent.toString(16)}.`,
      },
      {
        label: "Operation",
        value:
          r.operation === "generate"
            ? "Keypair Generation"
            : r.operation === "sign"
              ? "Digital Signature"
              : r.operation === "verify"
                ? "Signature Verification"
                : r.operation === "encrypt"
                  ? "Asymmetric Encryption"
                  : "Asymmetric Decryption",
      },
    );

    if (r.operation === "sign" || r.operation === "verify") {
      fields.push(
        {
          label: "Padding scheme",
          value:
            r.scheme === "pkcs1v15"
              ? "RSASSA-PKCS1-v1_5 (Deterministic)"
              : "RSA-PSS (Probabilistic Signature Scheme)",
          hint:
            r.scheme === "pkcs1v15"
              ? "Deterministic padding without salt (RFC 8017 Section 8.2)."
              : "Randomized salt-based signature scheme with provable security bounds (RFC 8017 Section 8.1).",
        },
        {
          label: "Hash function",
          value: r.hash,
          hint: "Cryptographic hash function used to digest input message before padding.",
        },
      );
    } else if (r.operation === "encrypt" || r.operation === "decrypt") {
      fields.push(
        {
          label: "Padding scheme",
          value: "RSA-OAEP (Optimal Asymmetric Encryption Padding)",
          hint: "Randomized Feistel padding construction with MGF1 (RFC 8017 Section 7.1).",
        },
        {
          label: "Hash function",
          value: r.hash,
          hint: "Hash used inside OAEP data padding and mask generation.",
        },
      );
    }

    fields.push({
      label: "Standards",
      value: "RFC 8017 (PKCS#1 v2.2), NIST FIPS 186-4 / SP 800-56B",
    });

    return fields;
  }

  // 2. Post-quantum tools (ML-KEM, ML-DSA, SLH-DSA, Falcon, etc.)
  if (r.paramSet) {
    const set = r.paramSet;
    fields.push(
      {
        label: "Algorithm",
        value: meta.label,
        hint: meta.summary,
      },
      {
        label: "Parameter set",
        value: set.label,
      },
      {
        label: "Public key length",
        value: `${set.publicKeyLen} bytes`,
      },
      {
        label: "Secret key length",
        value: `${set.secretKeyLen} bytes`,
      },
    );

    if (set.cipherTextLen !== undefined) {
      fields.push({
        label: "Ciphertext length",
        value: `${set.cipherTextLen} bytes`,
        hint: "Size of encapsulated shared secret ciphertext.",
      });
    }

    if (set.signatureLen !== undefined) {
      fields.push({
        label: "Signature length",
        value: `${set.signatureLen} bytes`,
        hint: "Size of generated post-quantum signature.",
      });
    }

    fields.push({
      label: "Standard",
      value:
        spec.variant === "mlkem"
          ? "NIST FIPS 203 (ML-KEM)"
          : spec.variant === "mldsa"
            ? "NIST FIPS 204 (ML-DSA)"
            : spec.variant === "slhdsa"
              ? "NIST FIPS 205 (SLH-DSA)"
              : "NIST Post-Quantum Cryptography Standardization",
    });

    return fields;
  }

  // 3. Curve tools (ECDSA, Ed25519, ECDH)
  if (spec.variant === "ed25519") {
    fields.push(
      {
        label: "Algorithm",
        value: "Ed25519 (EdDSA)",
        hint: "Edwards-curve Digital Signature Algorithm.",
      },
      {
        label: "Curve",
        value: "Curve25519 / Edwards25519",
        hint: "Twisted Edwards curve -x² + y² = 1 - (121665/121666)x²y² over 2²⁵⁵ - 19.",
      },
      {
        label: "Key size",
        value: "256 bits (32 bytes private, 32 bytes public)",
      },
      {
        label: "Signature size",
        value: "64 bytes (r || s)",
      },
      {
        label: "Hash function",
        value: "SHA-512 (RFC 8032)",
        hint: "Fixed by specification for deterministic nonce derivation and hashing.",
      },
      {
        label: "Standards",
        value: "RFC 8032, NIST FIPS 186-5",
      },
    );
    return fields;
  }

  if (spec.variant === "ecdsa" || spec.variant === "ecdh") {
    const curve = r.curve;
    fields.push(
      {
        label: "Algorithm",
        value: spec.variant === "ecdsa" ? "ECDSA" : "ECDH (Key Agreement)",
        hint: meta.summary,
      },
      {
        label: "Curve",
        value: curve ? `${curve.label} (${curve.id})` : "Elliptic Curve",
      },
    );

    if (curve?.id === "secp256k1") {
      fields.push(
        {
          label: "Curve equation",
          value: "y² = x³ + 7 mod p (Koblitz curve)",
        },
        {
          label: "Ecosystem standard",
          value: "SEC 2, BIP-62 (Bitcoin, Ethereum)",
        },
      );
    } else if (curve?.id === "x25519") {
      fields.push({
        label: "Curve equation",
        value: "Montgomery curve v² = u³ + 486662u² + u mod (2²⁵⁵ - 19)",
      });
    }

    if (spec.variant === "ecdsa") {
      fields.push(
        {
          label: "Hash function",
          value: r.hash,
        },
        {
          label: "Signature format",
          value: r.signatureFormat === "der" ? "ASN.1 DER sequence" : "Compact (r || s)",
        },
        {
          label: "Nonce generation",
          value: "RFC 6979 deterministic nonce (no RNG failure vulnerability)",
        },
      );
    }

    fields.push({
      label: "Standards",
      value:
        spec.variant === "ecdsa"
          ? "NIST FIPS 186-4, ANSI X9.62, SEC 1 / SEC 2"
          : "NIST SP 800-56A Rev. 3, RFC 7748",
    });

    return fields;
  }

  // 4. Paillier
  if (spec.variant === "paillier") {
    fields.push(
      {
        label: "Algorithm",
        value: "Paillier Cryptosystem",
        hint: "Additive homomorphic asymmetric encryption.",
      },
      {
        label: "Homomorphic property",
        value: "D(E(m₁) · E(m₂) mod n²) = m₁ + m₂ mod n",
        hint: "Multiplying two ciphertexts yields the encrypted sum of their plaintexts.",
      },
      {
        label: "Modulus",
        value: "2048-bit composite modulus n = p × q",
      },
    );
    return fields;
  }

  return fields;
}
