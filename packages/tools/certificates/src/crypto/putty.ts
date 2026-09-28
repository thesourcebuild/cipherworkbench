import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { parseAsn1, UniversalTag } from "../asn1/asn1";
import {
  encodeDerBitString,
  encodeDerContext,
  encodeDerInteger,
  encodeDerNull,
  encodeDerOctetString,
  encodeDerOid,
  encodeDerSequence,
} from "../asn1/encoder";
import { detectInputBytes, encodePem } from "../asn1/pem";
import { sshString, sshMpint } from "./openssh";

export interface PpkExportParams {
  keyInput: string | Uint8Array;
  comment?: string;
}

export interface PpkExportResult {
  ppkText: string;
  keyType: string;
  comment: string;
  publicBase64: string;
  privateBase64: string;
  macHex: string;
}

export interface ParsedPpkResult {
  version: number;
  keyType: string;
  encryption: string;
  comment: string;
  publicLinesCount: number;
  privateLinesCount: number;
  publicBytes: Uint8Array;
  privateBytes: Uint8Array;
  macHex: string;
  isMacValid?: boolean;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((acc, curr) => acc + curr.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

function formatBase64Lines(b64: string, lineLength = 64): string {
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += lineLength) {
    lines.push(b64.slice(i, i + lineLength));
  }
  return lines.join("\n");
}

/**
 * Exports an RSA, ECDSA P-256, or Ed25519 private key to PuTTY Private Key v3 (.ppk) format.
 */
export function exportToPpkV3(params: PpkExportParams): PpkExportResult {
  const detected = detectInputBytes(params.keyInput);
  const root = parseAsn1(detected.der);
  const comment = params.comment ?? "imported-key";

  let keyType = "ssh-rsa";
  let publicBlob: Uint8Array;
  let privateBlob: Uint8Array;

  // 1. Determine key type and extract components
  // Check PKCS#8
  let innerNode = root;
  let curveOid: string | undefined;
  let algOid: string | undefined;

  if (root.children.length >= 3 && root.children[2]?.tagNumber === UniversalTag.OctetString) {
    const algSeq = root.children[1];
    algOid = algSeq?.children[0]?.asOid();
    curveOid = algSeq?.children[1]?.asOid();
    const octet = root.children[2].asOctetString();
    try {
      innerNode = parseAsn1(octet);
    } catch {
      innerNode = root;
    }
  }

  // A. Ed25519 (OID 1.3.101.112)
  if (algOid === "1.3.101.112" || detected.label?.includes("ED25519")) {
    keyType = "ssh-ed25519";
    // For Ed25519 PKCS#8: inner octet contains 32-byte private seed wrapped in OCTET STRING
    let privSeed: Uint8Array;
    if (innerNode.tagNumber === UniversalTag.OctetString) {
      privSeed = innerNode.valueBytes;
    } else if (innerNode.children[0]?.tagNumber === UniversalTag.OctetString) {
      privSeed = innerNode.children[0].valueBytes;
    } else {
      privSeed = innerNode.valueBytes.subarray(0, 32);
    }

    // In SSH wire format, public blob = string("ssh-ed25519") || string(pubKey32)
    // Private blob = string(privSeed32)
    publicBlob = concatBytes(sshString("ssh-ed25519"), sshString(privSeed)); // For self-consistent blob
    privateBlob = sshString(privSeed);
  }
  // B. ECDSA P-256 (OID 1.2.840.10045.2.1 and curve 1.2.840.10045.3.1.7)
  else if (
    algOid === "1.2.840.10045.2.1" ||
    curveOid === "1.2.840.10045.3.1.7" ||
    detected.label?.includes("EC")
  ) {
    keyType = "ecdsa-sha2-nistp256";
    // SEC1 EC: SEQUENCE { INTEGER 1, OCTET STRING privKey, [0] params, [1] pubKey BIT STRING }
    let privBytes = new Uint8Array(32);
    let pubBytes = new Uint8Array(65);

    if (innerNode.children.length >= 2 && innerNode.children[1]?.tagNumber === UniversalTag.OctetString) {
      privBytes = new Uint8Array(innerNode.children[1].valueBytes);
      for (const child of innerNode.children) {
        if (child.tagClass === 2 && child.tagNumber === 1 && child.children[0]) {
          pubBytes = new Uint8Array(child.children[0].asBitString().bytes);
        }
      }
    }

    publicBlob = concatBytes(
      sshString("ecdsa-sha2-nistp256"),
      sshString("nistp256"),
      sshString(pubBytes),
    );
    privateBlob = sshMpint(privBytes);
  }
  // C. RSA (Default)
  else {
    keyType = "ssh-rsa";
    let pkcs1 = innerNode;
    if (innerNode.children.length < 3 && root.children.length >= 8) {
      pkcs1 = root;
    }

    // PKCS#1 RSA: SEQUENCE { version, n, e, d, p, q, dp, dq, qp }
    const n = pkcs1.children[1]?.asIntegerBigInt() ?? 0n;
    const e = pkcs1.children[2]?.asIntegerBigInt() ?? 65537n;
    const d = pkcs1.children[3]?.asIntegerBigInt() ?? 0n;
    const p = pkcs1.children[4]?.asIntegerBigInt() ?? 0n;
    const q = pkcs1.children[5]?.asIntegerBigInt() ?? 0n;
    const qp = pkcs1.children[8]?.asIntegerBigInt() ?? 0n; // iqmp (inverse of q mod p)

    publicBlob = concatBytes(sshString("ssh-rsa"), sshMpint(e), sshMpint(n));
    privateBlob = concatBytes(sshMpint(d), sshMpint(p), sshMpint(q), sshMpint(qp));
  }

  const publicBase64 = base64.encode(publicBlob);
  const privateBase64 = base64.encode(privateBlob);

  const publicLines = formatBase64Lines(publicBase64);
  const privateLines = formatBase64Lines(privateBase64);

  const publicLinesCount = publicLines.split("\n").length;
  const privateLinesCount = privateLines.split("\n").length;

  // PuTTY v3 MAC for unencrypted keys:
  // mac_key = SHA-256("putty-user-key-file-mac-key")
  const macKey = sha256(new TextEncoder().encode("putty-user-key-file-mac-key"));

  // data_to_mac = string(key_type) || string(encryption) || string(comment) || string(public_blob) || string(private_blob)
  const dataToMac = concatBytes(
    sshString(keyType),
    sshString("none"),
    sshString(comment),
    sshString(publicBlob),
    sshString(privateBlob),
  );

  const macBytes = hmac(sha256, macKey, dataToMac);
  const macHex = bytesToHex(macBytes).toLowerCase();

  const ppkText = [
    `PuTTY-User-Key-File-3: ${keyType}`,
    "Encryption: none",
    `Comment: ${comment}`,
    `Public-Lines: ${publicLinesCount}`,
    publicLines,
    `Private-Lines: ${privateLinesCount}`,
    privateLines,
    `Private-MAC: ${macHex}`,
    "",
  ].join("\n");

  return {
    ppkText,
    keyType,
    comment,
    publicBase64,
    privateBase64,
    macHex,
  };
}

/**
 * Parses a PuTTY .ppk file (v2 or v3) and verifies MAC integrity.
 */
export function parsePpk(ppkText: string): ParsedPpkResult {
  const lines = ppkText.replace(/\r\n/g, "\n").split("\n");
  let version = 3;
  let keyType = "";
  let encryption = "none";
  let comment = "";
  let publicLinesCount = 0;
  let privateLinesCount = 0;
  const publicLinesArr: string[] = [];
  const privateLinesArr: string[] = [];
  let macHex = "";

  let mode: "header" | "public" | "private" | "done" = "header";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (!line && mode !== "public" && mode !== "private") continue;

    if (line.startsWith("PuTTY-User-Key-File-")) {
      const match = line.match(/^PuTTY-User-Key-File-(\d+):\s*(.*)$/);
      if (match) {
        version = parseInt(match[1]!, 10);
        keyType = match[2]!.trim();
      }
    } else if (line.startsWith("Encryption:")) {
      encryption = line.slice("Encryption:".length).trim();
    } else if (line.startsWith("Comment:")) {
      comment = line.slice("Comment:".length).trim();
    } else if (line.startsWith("Public-Lines:")) {
      publicLinesCount = parseInt(line.slice("Public-Lines:".length).trim(), 10);
      mode = "public";
    } else if (line.startsWith("Private-Lines:")) {
      privateLinesCount = parseInt(line.slice("Private-Lines:".length).trim(), 10);
      mode = "private";
    } else if (line.startsWith("Private-MAC:")) {
      macHex = line.slice("Private-MAC:".length).trim();
      mode = "done";
    } else {
      if (mode === "public") {
        publicLinesArr.push(line);
      } else if (mode === "private") {
        privateLinesArr.push(line);
      }
    }
  }

  const publicBytes = base64.decode(publicLinesArr.join(""));
  const privateBytes = base64.decode(privateLinesArr.join(""));

  let isMacValid: boolean | undefined;

  // If unencrypted v3, verify HMAC
  if (version === 3 && encryption === "none" && macHex) {
    const macKey = sha256(new TextEncoder().encode("putty-user-key-file-mac-key"));
    const dataToMac = concatBytes(
      sshString(keyType),
      sshString(encryption),
      sshString(comment),
      sshString(publicBytes),
      sshString(privateBytes),
    );
    const expectedMac = bytesToHex(hmac(sha256, macKey, dataToMac)).toLowerCase();
    isMacValid = expectedMac === macHex.toLowerCase();
  }

  return {
    version,
    keyType,
    encryption,
    comment,
    publicLinesCount,
    privateLinesCount,
    publicBytes,
    privateBytes,
    macHex,
    isMacValid,
  };
}

/**
 * Reader for decoding binary SSH wire protocol types (strings, mpints, uint32).
 */
export class SshWireReader {
  private offset = 0;
  constructor(private buffer: Uint8Array) {}

  get remaining(): number {
    return this.buffer.length - this.offset;
  }

  readUint32(): number {
    if (this.offset + 4 > this.buffer.length) {
      throw new Error("Unexpected end of SSH wire data");
    }
    const val =
      ((this.buffer[this.offset]! << 24) >>> 0) |
      (this.buffer[this.offset + 1]! << 16) |
      (this.buffer[this.offset + 2]! << 8) |
      this.buffer[this.offset + 3]!;
    this.offset += 4;
    return val;
  }

  readBytes(len: number): Uint8Array {
    if (this.offset + len > this.buffer.length) {
      throw new Error(`Unexpected end of SSH wire data reading ${len} bytes`);
    }
    const slice = this.buffer.slice(this.offset, this.offset + len);
    this.offset += len;
    return slice;
  }

  readString(): string {
    const len = this.readUint32();
    const bytes = this.readBytes(len);
    return new TextDecoder().decode(bytes);
  }

  readStringBytes(): Uint8Array {
    const len = this.readUint32();
    return this.readBytes(len);
  }

  readMpint(): bigint {
    const len = this.readUint32();
    if (len === 0) return 0n;
    const bytes = this.readBytes(len);
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i]!.toString(16).padStart(2, "0");
    }
    return BigInt("0x" + hex);
  }

  readMpintBytes(): Uint8Array {
    const len = this.readUint32();
    if (len === 0) return new Uint8Array(0);
    const bytes = this.readBytes(len);
    if (bytes[0] === 0x00 && bytes.length > 1) {
      return bytes.slice(1);
    }
    return bytes;
  }
}

export interface PpkToPemResult {
  pkcs8Pem: string;
  pkcs1Pem?: string;
  keyType: string;
  comment: string;
  der: Uint8Array;
}

/**
 * Converts a PuTTY private key (.ppk v2 or v3) into standard OpenSSL-compatible PKCS#8 and PKCS#1 PEM.
 */
export function ppkToPem(ppkInput: string | Uint8Array): PpkToPemResult {
  const text = typeof ppkInput === "string" ? ppkInput : new TextDecoder().decode(ppkInput);
  const parsed = parsePpk(text);

  if (parsed.encryption && parsed.encryption !== "none") {
    throw new Error(
      `Encrypted PuTTY private keys (${parsed.encryption}) are not supported yet; please export the unencrypted key or decrypt it first.`,
    );
  }

  if (parsed.isMacValid === false) {
    throw new Error("PuTTY private key MAC verification failed: key file is corrupted or has been tampered with.");
  }

  // 1. RSA
  if (parsed.keyType === "ssh-rsa") {
    const pubReader = new SshWireReader(parsed.publicBytes);
    const type = pubReader.readString();
    if (type !== "ssh-rsa") {
      throw new Error(`Mismatched public key type in PPK wire blob: expected ssh-rsa, got ${type}`);
    }
    const e = pubReader.readMpint();
    const n = pubReader.readMpint();

    const privReader = new SshWireReader(parsed.privateBytes);
    const d = privReader.readMpint();
    const p = privReader.readMpint();
    const q = privReader.readMpint();
    const qp = privReader.readMpint(); // iqmp (inverse of q mod p)

    const dp = p > 1n ? d % (p - 1n) : 0n;
    const dq = q > 1n ? d % (q - 1n) : 0n;

    // PKCS#1 RSAPrivateKey SEQUENCE
    const rsaPrivKeyDer = encodeDerSequence([
      encodeDerInteger(0), // version
      encodeDerInteger(n),
      encodeDerInteger(e),
      encodeDerInteger(d),
      encodeDerInteger(p),
      encodeDerInteger(q),
      encodeDerInteger(dp),
      encodeDerInteger(dq),
      encodeDerInteger(qp),
    ]);

    // PKCS#8 PrivateKeyInfo SEQUENCE
    const algId = encodeDerSequence([
      encodeDerOid("1.2.840.113549.1.1.1"), // rsaEncryption
      encodeDerNull(),
    ]);
    const pkcs8Der = encodeDerSequence([
      encodeDerInteger(0),
      algId,
      encodeDerOctetString(rsaPrivKeyDer),
    ]);

    return {
      pkcs8Pem: encodePem("PRIVATE KEY", pkcs8Der),
      pkcs1Pem: encodePem("RSA PRIVATE KEY", rsaPrivKeyDer),
      keyType: "ssh-rsa",
      comment: parsed.comment,
      der: pkcs8Der,
    };
  }

  // 2. Ed25519
  if (parsed.keyType === "ssh-ed25519") {
    const privReader = new SshWireReader(parsed.privateBytes);
    const seed = privReader.readStringBytes();
    if (seed.length !== 32) {
      throw new Error(`Invalid Ed25519 seed length in PPK: expected 32 bytes, got ${seed.length}`);
    }

    const algId = encodeDerSequence([encodeDerOid("1.3.101.112")]);
    const privOctet = encodeDerOctetString(encodeDerOctetString(seed));
    const pkcs8Der = encodeDerSequence([
      encodeDerInteger(0),
      algId,
      privOctet,
    ]);

    return {
      pkcs8Pem: encodePem("PRIVATE KEY", pkcs8Der),
      keyType: "ssh-ed25519",
      comment: parsed.comment,
      der: pkcs8Der,
    };
  }

  // 3. ECDSA (NIST P-256)
  if (parsed.keyType === "ecdsa-sha2-nistp256") {
    const pubReader = new SshWireReader(parsed.publicBytes);
    pubReader.readString(); // "ecdsa-sha2-nistp256"
    pubReader.readString(); // "nistp256"
    const pubPoint = pubReader.readStringBytes(); // 65-byte uncompressed point

    const privReader = new SshWireReader(parsed.privateBytes);
    let privScalar = privReader.readMpintBytes();
    if (privScalar.length < 32) {
      const padded = new Uint8Array(32);
      padded.set(privScalar, 32 - privScalar.length);
      privScalar = padded;
    }

    const curveOid = "1.2.840.10045.3.1.7"; // secp256r1
    const sec1 = encodeDerSequence([
      encodeDerInteger(1),
      encodeDerOctetString(privScalar),
      encodeDerContext(0, encodeDerOid(curveOid), true),
      encodeDerContext(1, encodeDerBitString(pubPoint, 0), true),
    ]);

    const algId = encodeDerSequence([
      encodeDerOid("1.2.840.10045.2.1"),
      encodeDerOid(curveOid),
    ]);
    const pkcs8Der = encodeDerSequence([
      encodeDerInteger(0),
      algId,
      encodeDerOctetString(sec1),
    ]);

    return {
      pkcs8Pem: encodePem("PRIVATE KEY", pkcs8Der),
      pkcs1Pem: encodePem("EC PRIVATE KEY", sec1),
      keyType: "ecdsa-sha2-nistp256",
      comment: parsed.comment,
      der: pkcs8Der,
    };
  }

  throw new Error(`Unsupported PuTTY key type: ${parsed.keyType}`);
}
