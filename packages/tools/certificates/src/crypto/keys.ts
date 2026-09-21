import { ed25519 } from "@noble/curves/ed25519.js";
import { sha1 } from "@noble/hashes/legacy.js";
import {
  encodeDerBitString,
  encodeDerInteger,
  encodeDerNull,
  encodeDerOctetString,
  encodeDerOid,
  encodeDerSequence,
  ecdsaP1363ToDer,
} from "../asn1/encoder";
import { parseAsn1 } from "../asn1/asn1";
import { encodePem } from "../asn1/pem";

export type KeyAlgorithmType =
  | "rsa-2048"
  | "rsa-3072"
  | "rsa-4096"
  | "ecdsa-p256"
  | "ecdsa-p384"
  | "ecdsa-p521"
  | "ed25519";

export type HashAlgorithmType = "sha256" | "sha384" | "sha512";

export interface GeneratedKeyBundle {
  algorithmType: KeyAlgorithmType;
  hashType: HashAlgorithmType;
  spkiBytes: Uint8Array;
  pkcs8Bytes: Uint8Array;
  privateKeyPem: string;
  publicKeyPem: string;
  signatureAlgorithmOid: string;
  signatureAlgorithmDer: Uint8Array;
  ski: Uint8Array;
  signTbs: (tbsBytes: Uint8Array) => Promise<Uint8Array>;
}

/**
 * Returns the signature algorithm OID and DER-encoded AlgorithmIdentifier for the given key and hash.
 */
export function getSignatureAlgorithmInfo(
  keyType: KeyAlgorithmType,
  hashType: HashAlgorithmType,
): { oid: string; der: Uint8Array } {
  if (keyType.startsWith("rsa")) {
    let oid = "1.2.840.113549.1.1.11"; // sha256WithRSAEncryption
    if (hashType === "sha384") oid = "1.2.840.113549.1.1.12";
    if (hashType === "sha512") oid = "1.2.840.113549.1.1.13";
    const der = encodeDerSequence([encodeDerOid(oid), encodeDerNull()]);
    return { oid, der };
  }

  if (keyType.startsWith("ecdsa")) {
    let oid = "1.2.840.10045.4.3.2"; // ecdsa-with-SHA256
    if (hashType === "sha384") oid = "1.2.840.10045.4.3.3";
    if (hashType === "sha512") oid = "1.2.840.10045.4.3.4";
    // ECDSA algorithm identifier omits parameters (RFC 5480)
    const der = encodeDerSequence([encodeDerOid(oid)]);
    return { oid, der };
  }

  if (keyType === "ed25519") {
    const oid = "1.3.101.112"; // id-Ed25519
    const der = encodeDerSequence([encodeDerOid(oid)]);
    return { oid, der };
  }

  throw new Error(`Unsupported key algorithm: ${keyType}`);
}

/**
 * Derives the Subject Key Identifier (SKI) from SPKI bytes according to RFC 5280 §4.2.1.2.
 * SHA-1 of the BIT STRING subjectPublicKey value (excluding tag, length, and unused bits).
 */
export function deriveSki(spkiBytes: Uint8Array): Uint8Array {
  const node = parseAsn1(spkiBytes);
  // SPKI = SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
  const bitStringNode = node.children[1];
  if (!bitStringNode) {
    throw new Error("Invalid SPKI: missing subjectPublicKey bit string");
  }
  const { bytes: pubKeyRaw } = bitStringNode.asBitString();
  return sha1(pubKeyRaw);
}

/**
 * Generates an Ed25519 key pair and exports SPKI and PKCS#8.
 */
function generateEd25519Bundle(hashType: HashAlgorithmType): GeneratedKeyBundle {
  const privKey = ed25519.utils.randomSecretKey();
  const pubKey = ed25519.getPublicKey(privKey);

  // SPKI: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING pubKey }
  const algId = encodeDerSequence([encodeDerOid("1.3.101.112")]);
  const pubKeyBitString = encodeDerBitString(pubKey, 0);
  const spkiBytes = encodeDerSequence([algId, pubKeyBitString]);

  // PKCS#8: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING (OCTET STRING privKey) }
  const version = encodeDerInteger(0);
  const privOctet = encodeDerOctetString(encodeDerOctetString(privKey));
  const pkcs8Bytes = encodeDerSequence([version, algId, privOctet]);

  const { oid, der } = getSignatureAlgorithmInfo("ed25519", hashType);
  const ski = deriveSki(spkiBytes);

  return {
    algorithmType: "ed25519",
    hashType,
    spkiBytes,
    pkcs8Bytes,
    privateKeyPem: encodePem("PRIVATE KEY", pkcs8Bytes),
    publicKeyPem: encodePem("PUBLIC KEY", spkiBytes),
    signatureAlgorithmOid: oid,
    signatureAlgorithmDer: der,
    ski,
    signTbs: async (tbsBytes: Uint8Array) => {
      return ed25519.sign(tbsBytes, privKey);
    },
  };
}

/**
 * Generates a cryptographic key pair (RSA, ECDSA, or Ed25519) and prepares signing mechanisms.
 */
export async function generateKeyBundle(
  keyType: KeyAlgorithmType,
  hashType: HashAlgorithmType = "sha256",
): Promise<GeneratedKeyBundle> {
  if (keyType === "ed25519") {
    return generateEd25519Bundle(hashType);
  }

  const { oid, der } = getSignatureAlgorithmInfo(keyType, hashType);
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("WebCrypto API (crypto.subtle) is not available in this environment.");
  }

  let keyPair: CryptoKeyPair;

  if (keyType.startsWith("rsa")) {
    const modulusLength =
      keyType === "rsa-4096" ? 4096 : keyType === "rsa-3072" ? 3072 : 2048;
    const hashName = hashType === "sha512" ? "SHA-512" : hashType === "sha384" ? "SHA-384" : "SHA-256";
    keyPair = await subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: hashName,
      },
      true,
      ["sign", "verify"],
    );

    const spkiBuffer = await subtle.exportKey("spki", keyPair.publicKey);
    const pkcs8Buffer = await subtle.exportKey("pkcs8", keyPair.privateKey);
    const spkiBytes = new Uint8Array(spkiBuffer);
    const pkcs8Bytes = new Uint8Array(pkcs8Buffer);
    const ski = deriveSki(spkiBytes);

    return {
      algorithmType: keyType,
      hashType,
      spkiBytes,
      pkcs8Bytes,
      privateKeyPem: encodePem("PRIVATE KEY", pkcs8Bytes),
      publicKeyPem: encodePem("PUBLIC KEY", spkiBytes),
      signatureAlgorithmOid: oid,
      signatureAlgorithmDer: der,
      ski,
      signTbs: async (tbsBytes: Uint8Array) => {
        const sig = await subtle.sign(
          "RSASSA-PKCS1-v1_5",
          keyPair.privateKey,
          tbsBytes as unknown as BufferSource,
        );
        return new Uint8Array(sig);
      },
    };
  }

  if (keyType.startsWith("ecdsa")) {
    const namedCurve =
      keyType === "ecdsa-p384" ? "P-384" : keyType === "ecdsa-p521" ? "P-521" : "P-256";
    const hashName =
      hashType === "sha512"
        ? "SHA-512"
        : hashType === "sha384" || keyType === "ecdsa-p384"
          ? "SHA-384"
          : "SHA-256";

    keyPair = await subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve,
      },
      true,
      ["sign", "verify"],
    );

    const spkiBuffer = await subtle.exportKey("spki", keyPair.publicKey);
    const pkcs8Buffer = await subtle.exportKey("pkcs8", keyPair.privateKey);
    const spkiBytes = new Uint8Array(spkiBuffer);
    const pkcs8Bytes = new Uint8Array(pkcs8Buffer);
    const ski = deriveSki(spkiBytes);

    return {
      algorithmType: keyType,
      hashType,
      spkiBytes,
      pkcs8Bytes,
      privateKeyPem: encodePem("PRIVATE KEY", pkcs8Bytes),
      publicKeyPem: encodePem("PUBLIC KEY", spkiBytes),
      signatureAlgorithmOid: oid,
      signatureAlgorithmDer: der,
      ski,
      signTbs: async (tbsBytes: Uint8Array) => {
        const rawSig = await subtle.sign(
          { name: "ECDSA", hash: { name: hashName } },
          keyPair.privateKey,
          tbsBytes as unknown as BufferSource,
        );
        return ecdsaP1363ToDer(new Uint8Array(rawSig));
      },
    };
  }

  throw new Error(`Unsupported key algorithm: ${keyType}`);
}
