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
import { parseAsn1, UniversalTag } from "../asn1/asn1";
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

export interface CaSigner {
  issuerDnDer: Uint8Array;
  issuerSki: Uint8Array;
  signatureAlgorithmDer: Uint8Array;
  signTbs: (tbsBytes: Uint8Array) => Promise<Uint8Array>;
  issuerDnString: string;
}

/**
 * Imports an existing Certificate Authority certificate and private key (RSA, ECDSA, or Ed25519)
 * and prepares a reusable CaSigner to issue child certificates.
 */
export async function importCaSigner(
  caCertDer: Uint8Array,
  caKeyDer: Uint8Array,
): Promise<CaSigner> {
  const root = parseAsn1(caCertDer);
  if (root.tagNumber !== UniversalTag.Sequence || root.children.length < 3) {
    throw new Error("Invalid CA certificate ASN.1 structure: expected X.509 SEQUENCE");
  }

  const tbs = root.children[0]!;
  let tbsIdx = 0;
  if (tbs.children[0]?.tagNumber === 0) tbsIdx++; // skip version if present
  tbsIdx++; // skip serial
  tbsIdx++; // skip sigAlg
  tbsIdx++; // skip issuer
  tbsIdx++; // skip validity
  const subjectNode = tbs.children[tbsIdx++];
  const spkiNode = tbs.children[tbsIdx++];
  if (!subjectNode || !spkiNode) {
    throw new Error("Failed to extract Subject DN and SPKI from CA certificate");
  }

  const issuerDnDer = subjectNode.raw;
  const issuerSki = deriveSki(spkiNode.raw);

  // Extract human-readable DN string
  let issuerDnString = "CA Authority";
  try {
    const parts: string[] = [];
    for (const rdnSet of subjectNode.children) {
      for (const attrSeq of rdnSet.children) {
        const oid = attrSeq.children[0]?.asOid();
        const val = attrSeq.children[1]?.asString();
        if (oid && val) {
          const name = oid === "2.5.4.3" ? "CN" : oid === "2.5.4.10" ? "O" : oid === "2.5.4.6" ? "C" : oid;
          parts.push(`${name}=${val}`);
        }
      }
    }
    if (parts.length > 0) issuerDnString = parts.join(", ");
  } catch {
    // fallback
  }

  // Parse private key
  let keyDer = caKeyDer;
  let keyNode = parseAsn1(keyDer);

  // If PKCS#1 RSA private key (starts with INTEGER 0, then INTEGER modulus...)
  if (
    keyNode.children.length > 3 &&
    keyNode.children[0]?.tagNumber === UniversalTag.Integer &&
    keyNode.children[1]?.tagNumber === UniversalTag.Integer &&
    keyNode.children[2]?.tagNumber === UniversalTag.Integer
  ) {
    const rsaAlgId = encodeDerSequence([encodeDerOid("1.2.840.113549.1.1.1"), encodeDerNull()]);
    keyDer = encodeDerSequence([
      encodeDerInteger(0),
      rsaAlgId,
      encodeDerOctetString(caKeyDer),
    ]);
    keyNode = parseAsn1(keyDer);
  }

  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("WebCrypto API is not available");

  const algSeq = keyNode.children[1];
  if (!algSeq || algSeq.children.length === 0) {
    throw new Error("Invalid PKCS#8 private key: missing algorithm identifier");
  }
  const algOid = algSeq.children[0]!.asOid();

  if (algOid === "1.2.840.113549.1.1.1") {
    // RSA
    const privKey = await subtle.importKey(
      "pkcs8",
      keyDer as unknown as BufferSource,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signatureAlgorithmDer = encodeDerSequence([
      encodeDerOid("1.2.840.113549.1.1.11"), // sha256WithRSAEncryption
      encodeDerNull(),
    ]);
    return {
      issuerDnDer,
      issuerSki,
      signatureAlgorithmDer,
      signTbs: async (tbs: Uint8Array) => {
        const sig = await subtle.sign("RSASSA-PKCS1-v1_5", privKey, tbs as unknown as BufferSource);
        return new Uint8Array(sig);
      },
      issuerDnString,
    };
  }

  if (algOid === "1.2.840.10045.2.1") {
    // ECDSA
    const curveOid = algSeq.children[1]?.asOid();
    const namedCurve = curveOid === "1.3.132.0.34" ? "P-384" : curveOid === "1.3.132.0.35" ? "P-521" : "P-256";
    const hashName = namedCurve === "P-384" ? "SHA-384" : namedCurve === "P-521" ? "SHA-512" : "SHA-256";
    const sigOid = namedCurve === "P-384" ? "1.2.840.10045.4.3.3" : namedCurve === "P-521" ? "1.2.840.10045.4.3.4" : "1.2.840.10045.4.3.2";

    const privKey = await subtle.importKey(
      "pkcs8",
      keyDer as unknown as BufferSource,
      { name: "ECDSA", namedCurve },
      false,
      ["sign"],
    );
    const signatureAlgorithmDer = encodeDerSequence([encodeDerOid(sigOid)]);
    return {
      issuerDnDer,
      issuerSki,
      signatureAlgorithmDer,
      signTbs: async (tbs: Uint8Array) => {
        const raw = await subtle.sign(
          { name: "ECDSA", hash: { name: hashName } },
          privKey,
          tbs as unknown as BufferSource,
        );
        return ecdsaP1363ToDer(new Uint8Array(raw));
      },
      issuerDnString,
    };
  }

  if (algOid === "1.3.101.112") {
    // Ed25519
    const privOctet = keyNode.children[2]?.asOctetString();
    let rawSecret: Uint8Array;
    if (privOctet && privOctet.length === 34 && privOctet[0] === 0x04 && privOctet[1] === 0x20) {
      rawSecret = privOctet.slice(2);
    } else if (privOctet && privOctet.length === 32) {
      rawSecret = privOctet;
    } else {
      rawSecret = keyDer.slice(-32);
    }
    const signatureAlgorithmDer = encodeDerSequence([encodeDerOid("1.3.101.112")]);
    return {
      issuerDnDer,
      issuerSki,
      signatureAlgorithmDer,
      signTbs: async (tbs: Uint8Array) => ed25519.sign(tbs, rawSecret),
      issuerDnString,
    };
  }

  throw new Error(`Unsupported CA key algorithm OID: ${algOid}`);
}

