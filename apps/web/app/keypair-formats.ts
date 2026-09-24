import {
  encodeDerBitString,
  encodeDerInteger,
  encodeDerOctetString,
  encodeDerOid,
  encodeDerSequence,
  encodeDerTlv,
  encodePem,
  parseAllPem,
  TagClass,
} from "@ocs/certificates";
import type { ToolManifest, ToolResultField } from "@ocs/engine";
import { PUBLIC_KEY_HINT } from "@ocs/asymmetric/pure";
import { downloadBinaryFile, downloadTextFile } from "./export-json";

export type KeypairFormat = "hex" | "base64" | "pem" | "jwk" | "raw";

export interface KeypairFormatOption {
  id: KeypairFormat;
  label: string;
  description: string;
}

export interface ResolvedKeypairData {
  rawPrivate?: Uint8Array;
  rawPublic?: Uint8Array;
  privatePem?: string;
  publicPem?: string;
  privateJwk?: string;
  publicJwk?: string;
  privateHex?: string;
  publicHex?: string;
  privateBase64?: string;
  publicBase64?: string;
  curveOrType?: string;
  hasJwk: boolean;
  hasPem: boolean;
  defaultFormat: KeypairFormat;
  availableFormats: KeypairFormatOption[];
}

export function hexToBytes(hexStr: string): Uint8Array {
  const clean = hexStr.replace(/^0x/i, "").replace(/[\s\r\n:]+/g, "");
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    return new Uint8Array(0);
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}

export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let res = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) res = (res * base) % mod;
    base = (base * base) % mod;
    exp /= 2n;
  }
  return res;
}

function bigintToFixedBytes(val: bigint, length: number): Uint8Array {
  let hex = val.toString(16);
  if (hex.length % 2 !== 0) hex = "0" + hex;
  const raw = hexToBytes(hex);
  if (raw.length === length) return raw;
  const out = new Uint8Array(length);
  if (raw.length < length) {
    out.set(raw, length - raw.length);
  } else {
    out.set(raw.subarray(raw.length - length));
  }
  return out;
}

/**
 * Decompresses an elliptic curve point on secp256k1 or P-256 (P = 3 mod 4).
 */
function decompressPoint(
  pubBytes: Uint8Array,
  curve: "secp256k1" | "p-256",
): { x: Uint8Array; y: Uint8Array } | undefined {
  if (pubBytes.length === 65 && pubBytes[0] === 0x04) {
    return {
      x: pubBytes.subarray(1, 33),
      y: pubBytes.subarray(33, 65),
    };
  }

  if (pubBytes.length === 33 && (pubBytes[0] === 0x02 || pubBytes[0] === 0x03)) {
    const prefix = pubBytes[0];
    const xBytes = pubBytes.subarray(1, 33);
    const x = BigInt("0x" + bytesToHex(xBytes));

    let p: bigint;
    let ySquared: bigint;

    if (curve === "secp256k1") {
      p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
      ySquared = (x * x * x + 7n) % p;
    } else {
      p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
      const a = p - 3n;
      const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
      ySquared = (x * x * x + a * x + b) % p;
    }

    if (ySquared < 0n) ySquared += p;

    // Euler's criterion square root for p = 3 mod 4
    let y = modPow(ySquared, (p + 1n) / 4n, p);
    const isOdd = y % 2n === 1n;
    if ((prefix === 0x03 && !isOdd) || (prefix === 0x02 && isOdd)) {
      y = p - y;
    }

    return {
      x: xBytes,
      y: bigintToFixedBytes(y, 32),
    };
  }

  return undefined;
}

export function resolveKeypairData(
  fields: readonly ToolResultField[],
  manifest?: Partial<ToolManifest>,
): ResolvedKeypairData {
  const privatePemField = fields.find(
    (f) => f.label.includes("Private key (PKCS#8") || f.label === "Private key (PEM)",
  );
  const publicPemField = fields.find(
    (f) => f.label.includes("Public key (SPKI") || f.label === "Public key (PEM)",
  );
  const privateJwkField = fields.find((f) => f.label.includes("Private key (JWK)"));
  const publicJwkField = fields.find((f) => f.label.includes("Public key (JWK)"));

  const genericPrivateField = fields.find(
    (f) =>
      f.label.toLowerCase() === "private key" ||
      f.label.toLowerCase() === "secret key" ||
      f.secret ||
      f.label.toLowerCase().includes("private lambda"),
  );
  const genericPublicField = fields.find(
    (f) =>
      (f.label.toLowerCase() === "public key" || f.label.toLowerCase().includes("public modulus")) &&
      !f.label.includes("JWK") &&
      !f.label.includes("PEM"),
  );

  const curveField = fields.find((f) => f.label === "Curve")?.value.toLowerCase() ?? "";
  const paramField = fields.find((f) => f.label === "Parameter set")?.value.toLowerCase() ?? "";
  const toolId = manifest?.id?.toLowerCase() ?? "";

  const isRsa = Boolean(privatePemField && privateJwkField) || toolId.includes("rsa");
  const isEd25519 = toolId === "ed25519" || curveField.includes("ed25519");
  const isX25519 = toolId === "x25519" || curveField.includes("x25519");
  const isSecp256k1 = toolId === "secp256k1" || curveField.includes("secp256k1");
  const isP256 =
    curveField.includes("p-256") ||
    curveField.includes("prime256v1") ||
    curveField.includes("secp256r1");
  const isP384 = curveField.includes("p-384") || curveField.includes("secp384r1");
  const isP521 = curveField.includes("p-521") || curveField.includes("secp521r1");

  let rawPrivate: Uint8Array | undefined;
  let rawPublic: Uint8Array | undefined;

  let privatePem = privatePemField?.value;
  let publicPem = publicPemField?.value;
  let privateJwk = privateJwkField?.value;
  let publicJwk = publicJwkField?.value;

  // Extract raw bytes
  if (genericPrivateField) {
    const clean = genericPrivateField.value.replace(/^0x/i, "");
    if (/^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0) {
      rawPrivate = hexToBytes(clean);
    }
  } else if (privatePem) {
    const blocks = parseAllPem(privatePem);
    if (blocks[0]) rawPrivate = blocks[0].bytes;
  }

  if (genericPublicField) {
    const clean = genericPublicField.value.replace(/^0x/i, "");
    if (/^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0) {
      rawPublic = hexToBytes(clean);
    }
  } else if (publicPem) {
    const blocks = parseAllPem(publicPem);
    if (blocks[0]) rawPublic = blocks[0].bytes;
  }

  // Derive PEM if not already in fields
  if (!privatePem && rawPrivate && rawPublic) {
    try {
      if (isEd25519 || isX25519) {
        const oid = isEd25519 ? "1.3.101.112" : "1.3.101.110";
        const algId = encodeDerSequence([encodeDerOid(oid)]);
        const spkiBytes = encodeDerSequence([algId, encodeDerBitString(rawPublic, 0)]);
        publicPem = encodePem("PUBLIC KEY", spkiBytes);

        const version = encodeDerInteger(0);
        const privOctet = encodeDerOctetString(encodeDerOctetString(rawPrivate));
        const pkcs8Bytes = encodeDerSequence([version, algId, privOctet]);
        privatePem = encodePem("PRIVATE KEY", pkcs8Bytes);
      } else if (isP256 || isP384 || isP521 || isSecp256k1) {
        const curveOid = isP256
          ? "1.2.840.10045.3.1.7"
          : isP384
            ? "1.3.132.0.34"
            : isP521
              ? "1.3.132.0.35"
              : "1.3.132.0.10"; // secp256k1
        const algId = encodeDerSequence([
          encodeDerOid("1.2.840.10045.2.1"),
          encodeDerOid(curveOid),
        ]);
        const spkiBytes = encodeDerSequence([algId, encodeDerBitString(rawPublic, 0)]);
        publicPem = encodePem("PUBLIC KEY", spkiBytes);

        const ecPrivKey = encodeDerSequence([
          encodeDerInteger(1),
          encodeDerOctetString(rawPrivate),
          encodeDerTlv(0, TagClass.ContextSpecific, true, encodeDerOid(curveOid)),
          encodeDerTlv(1, TagClass.ContextSpecific, true, encodeDerBitString(rawPublic, 0)),
        ]);
        const pkcs8Bytes = encodeDerSequence([
          encodeDerInteger(0),
          algId,
          encodeDerOctetString(ecPrivKey),
        ]);
        privatePem = encodePem("PRIVATE KEY", pkcs8Bytes);
      } else {
        privatePem = encodePem("PRIVATE KEY", rawPrivate);
        publicPem = encodePem("PUBLIC KEY", rawPublic);
      }
    } catch {
      // Fallback
      privatePem = encodePem("PRIVATE KEY", rawPrivate);
      publicPem = encodePem("PUBLIC KEY", rawPublic);
    }
  }

  // Derive JWK if not already in fields
  if (!privateJwk && rawPrivate && rawPublic) {
    try {
      if (isEd25519 || isX25519) {
        const crv = isEd25519 ? "Ed25519" : "X25519";
        publicJwk = JSON.stringify(
          {
            kty: "OKP",
            crv,
            x: base64UrlEncode(rawPublic),
          },
          null,
          2,
        );
        privateJwk = JSON.stringify(
          {
            kty: "OKP",
            crv,
            x: base64UrlEncode(rawPublic),
            d: base64UrlEncode(rawPrivate),
          },
          null,
          2,
        );
      } else if (isP256 || isSecp256k1) {
        const decomp = decompressPoint(rawPublic, isP256 ? "p-256" : "secp256k1");
        if (decomp) {
          const crv = isP256 ? "P-256" : "secp256k1";
          publicJwk = JSON.stringify(
            {
              kty: "EC",
              crv,
              x: base64UrlEncode(decomp.x),
              y: base64UrlEncode(decomp.y),
            },
            null,
            2,
          );
          privateJwk = JSON.stringify(
            {
              kty: "EC",
              crv,
              x: base64UrlEncode(decomp.x),
              y: base64UrlEncode(decomp.y),
              d: base64UrlEncode(rawPrivate),
            },
            null,
            2,
          );
        }
      }
    } catch {
      // Ignore JWK synthesis error
    }
  }

  const privateHex = rawPrivate ? bytesToHex(rawPrivate) : genericPrivateField?.value ?? "";
  const publicHex = rawPublic ? bytesToHex(rawPublic) : genericPublicField?.value ?? "";

  const privateBase64 = rawPrivate ? bytesToBase64(rawPrivate) : "";
  const publicBase64 = rawPublic ? bytesToBase64(rawPublic) : "";

  const hasJwk = Boolean(privateJwk && publicJwk);
  const hasPem = Boolean(privatePem && publicPem);

  const defaultFormat: KeypairFormat = isRsa ? "pem" : "hex";

  const availableFormats: KeypairFormatOption[] = [
    {
      id: "hex",
      label: "Hex",
      description: "Standard hexadecimal encoding",
    },
    {
      id: "base64",
      label: "Base64",
      description: "Raw Base64 string",
    },
    {
      id: "pem",
      label: "PEM (PKCS#8 / SPKI)",
      description: "Standard PEM format with header lines",
    },
  ];

  if (hasJwk) {
    availableFormats.push({
      id: "jwk",
      label: "JWK (JSON Web Key)",
      description: "RFC 7517 / RFC 8037 JSON structure",
    });
  }

  availableFormats.push({
    id: "raw",
    label: "Raw Binary (.bin)",
    description: "Raw binary bytes file",
  });

  return {
    rawPrivate,
    rawPublic,
    privatePem,
    publicPem,
    privateJwk,
    publicJwk,
    privateHex,
    publicHex,
    privateBase64,
    publicBase64,
    curveOrType: curveField || paramField || toolId,
    hasJwk,
    hasPem,
    defaultFormat,
    availableFormats,
  };
}

export interface KeypairViewValues {
  privateVal: string;
  publicVal: string;
  privateLabel: string;
  publicLabel: string;
  privateHint?: string;
  publicHint?: string;
  fileExt: string;
  mimeType: string;
}

export function cleanKeyLabel(label: string): string {
  return label.replace(/\s*\([^)]*\)/g, "").trim() || label;
}

export function getKeypairView(
  format: KeypairFormat,
  data: ResolvedKeypairData,
  basePrivateLabel = "Private key",
  basePublicLabel = "Public key",
): KeypairViewValues {
  const privLabel = cleanKeyLabel(basePrivateLabel);
  const pubLabel = cleanKeyLabel(basePublicLabel);

  switch (format) {
    case "hex":
      return {
        privateVal: data.privateHex ?? "",
        publicVal: data.publicHex ?? "",
        privateLabel: `${privLabel} (Hex)`,
        publicLabel: `${pubLabel} (Hex)`,
        privateHint: data.rawPrivate ? `${data.rawPrivate.length} bytes secret scalar / seed` : undefined,
        publicHint: PUBLIC_KEY_HINT,
        fileExt: "hex",
        mimeType: "text/plain",
      };

    case "base64":
      return {
        privateVal: data.privateBase64 ?? "",
        publicVal: data.publicBase64 ?? "",
        privateLabel: `${privLabel} (Base64)`,
        publicLabel: `${pubLabel} (Base64)`,
        privateHint: data.rawPrivate ? `${data.rawPrivate.length} bytes encoded in Base64` : undefined,
        publicHint: PUBLIC_KEY_HINT,
        fileExt: "b64",
        mimeType: "text/plain",
      };

    case "pem":
      return {
        privateVal: data.privatePem ?? data.privateHex ?? "",
        publicVal: data.publicPem ?? data.publicHex ?? "",
        privateLabel: `${privLabel} (PKCS#8 PEM)`,
        publicLabel: `${pubLabel} (SPKI PEM)`,
        privateHint: "Standard RFC PKCS#8 PEM format (Base64 ASCII).",
        publicHint: PUBLIC_KEY_HINT,
        fileExt: "pem",
        mimeType: "application/x-pem-file",
      };

    case "jwk":
      return {
        privateVal: data.privateJwk ?? data.privateHex ?? "",
        publicVal: data.publicJwk ?? data.publicHex ?? "",
        privateLabel: `${privLabel} (JWK)`,
        publicLabel: `${pubLabel} (JWK)`,
        privateHint: "JSON Web Key (JWK) private structure.",
        publicHint: PUBLIC_KEY_HINT,
        fileExt: "jwk.json",
        mimeType: "application/json",
      };

    case "raw":
      return {
        privateVal: data.rawPrivate
          ? `[Raw binary data: ${data.rawPrivate.length} bytes / ${data.rawPrivate.length * 8} bits]\nHex: ${data.privateHex}`
          : data.privateHex ?? "",
        publicVal: data.rawPublic
          ? `[Raw binary data: ${data.rawPublic.length} bytes / ${data.rawPublic.length * 8} bits]\nHex: ${data.publicHex}`
          : data.publicHex ?? "",
        privateLabel: `${privLabel} (Raw Binary)`,
        publicLabel: `${pubLabel} (Raw Binary)`,
        privateHint: "Raw binary bytes. Use the download button to save as a .bin file.",
        publicHint: PUBLIC_KEY_HINT,
        fileExt: "bin",
        mimeType: "application/octet-stream",
      };
  }
}

export function downloadActiveKeypairFiles(
  baseFilename: string,
  format: KeypairFormat,
  data: ResolvedKeypairData,
): void {
  const view = getKeypairView(format, data);

  if (format === "raw") {
    if (data.rawPrivate) {
      downloadBinaryFile(`${baseFilename}-private.bin`, data.rawPrivate);
    }
    if (data.rawPublic) {
      setTimeout(() => {
        downloadBinaryFile(`${baseFilename}-public.bin`, data.rawPublic!);
      }, 150);
    }
  } else {
    downloadTextFile(`${baseFilename}-private.${view.fileExt}`, view.privateVal, view.mimeType);
    setTimeout(() => {
      downloadTextFile(`${baseFilename}-public.${view.fileExt}`, view.publicVal, view.mimeType);
    }, 150);
  }
}

export function downloadPemPairFiles(baseFilename: string, data: ResolvedKeypairData): void {
  if (!data.privatePem || !data.publicPem) return;
  downloadTextFile(`${baseFilename}-private.pem`, data.privatePem, "application/x-pem-file");
  setTimeout(() => {
    downloadTextFile(`${baseFilename}-public.pem`, data.publicPem!, "application/x-pem-file");
  }, 150);
}

export function downloadRawBinaryPairFiles(baseFilename: string, data: ResolvedKeypairData): void {
  if (data.rawPrivate) {
    downloadBinaryFile(`${baseFilename}-private.bin`, data.rawPrivate);
  }
  if (data.rawPublic) {
    setTimeout(() => {
      downloadBinaryFile(`${baseFilename}-public.bin`, data.rawPublic!);
    }, 150);
  }
}

export function downloadJwkPairFiles(baseFilename: string, data: ResolvedKeypairData): void {
  if (!data.privateJwk || !data.publicJwk) return;
  downloadTextFile(`${baseFilename}-private.jwk.json`, data.privateJwk, "application/json");
  setTimeout(() => {
    downloadTextFile(`${baseFilename}-public.jwk.json`, data.publicJwk!, "application/json");
  }, 150);
}

export function downloadKeypairBundleFiles(baseFilename: string, data: ResolvedKeypairData): void {
  let delay = 0;

  // 1. Download PEM pair
  if (data.privatePem && data.publicPem) {
    setTimeout(() => {
      downloadTextFile(`${baseFilename}-private.pem`, data.privatePem!, "application/x-pem-file");
    }, delay);
    delay += 150;
    setTimeout(() => {
      downloadTextFile(`${baseFilename}-public.pem`, data.publicPem!, "application/x-pem-file");
    }, delay);
    delay += 150;
  }

  // 2. Download Raw Binary pair
  if (data.rawPrivate && data.rawPublic) {
    setTimeout(() => {
      downloadBinaryFile(`${baseFilename}-private.bin`, data.rawPrivate!);
    }, delay);
    delay += 150;
    setTimeout(() => {
      downloadBinaryFile(`${baseFilename}-public.bin`, data.rawPublic!);
    }, delay);
    delay += 150;
  }

  // 3. Download JWK pair if available
  if (data.privateJwk && data.publicJwk) {
    setTimeout(() => {
      downloadTextFile(`${baseFilename}-private.jwk.json`, data.privateJwk!, "application/json");
    }, delay);
    delay += 150;
    setTimeout(() => {
      downloadTextFile(`${baseFilename}-public.jwk.json`, data.publicJwk!, "application/json");
    }, delay);
    delay += 150;
  }

  // 4. Download Hex pair if available
  if (data.privateHex && data.publicHex) {
    setTimeout(() => {
      downloadTextFile(`${baseFilename}-private.hex`, data.privateHex!, "text/plain");
    }, delay);
    delay += 150;
    setTimeout(() => {
      downloadTextFile(`${baseFilename}-public.hex`, data.publicHex!, "text/plain");
    }, delay);
  }
}
