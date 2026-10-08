import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { md5 } from "@noble/hashes/legacy.js";
import { ctr } from "@noble/ciphers/aes.js";
import { base64, base64urlnopad } from "@scure/base";
import { deriveBcryptPbkdf } from "./bcrypt-pbkdf-wrapper";

export function writeUint32Be(num: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (num >>> 24) & 0xff;
  buf[1] = (num >>> 16) & 0xff;
  buf[2] = (num >>> 8) & 0xff;
  buf[3] = num & 0xff;
  return buf;
}

export function sshString(val: string | Uint8Array): Uint8Array {
  const bytes = typeof val === "string" ? new TextEncoder().encode(val) : val;
  const lenBuf = writeUint32Be(bytes.length);
  const out = new Uint8Array(4 + bytes.length);
  out.set(lenBuf, 0);
  out.set(bytes, 4);
  return out;
}

export function sshMpint(val: Uint8Array): Uint8Array {
  let start = 0;
  while (start < val.length - 1 && val[start] === 0) {
    start++;
  }
  const slice = val.subarray(start);
  if (slice.length === 0 || (slice.length === 1 && slice[0] === 0)) {
    return writeUint32Be(0);
  }

  const needsZero = (slice[0]! & 0x80) !== 0;
  const len = slice.length + (needsZero ? 1 : 0);
  const out = new Uint8Array(4 + len);
  out.set(writeUint32Be(len), 0);
  if (needsZero) {
    out[4] = 0x00;
    out.set(slice, 5);
  } else {
    out.set(slice, 4);
  }
  return out;
}

export function concatSshChunks(...chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) {
    total += c.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

export function uint8ArrayToBase64(bytes: Uint8Array): string {
  return base64.encode(bytes);
}

/**
 * Bubblebabble encoding of binary data according to the Bubblebabble draft specification.
 * Matches `ssh-keygen -B`.
 */
export function calculateBubblebabble(bytes: Uint8Array): string {
  const vowels = ["a", "e", "i", "o", "u", "y"];
  const consonants = [
    "b",
    "c",
    "d",
    "f",
    "g",
    "h",
    "k",
    "l",
    "m",
    "n",
    "p",
    "r",
    "s",
    "t",
    "v",
    "z",
    "x",
  ];
  let seed = 1;
  let result = "x";
  const len = bytes.length;
  let i = 0;

  while (i < len) {
    const byte1 = bytes[i]!;
    if (i + 1 < len) {
      const byte2 = bytes[i + 1]!;
      const v1 = (((byte1 >> 6) & 3) + seed) % 6;
      const c1 = (byte1 >> 2) & 15;
      const v2 = ((byte1 & 3) + Math.floor(seed / 6)) % 6;
      result += vowels[v1]! + consonants[c1]! + vowels[v2]!;
      const c2 = (byte2 >> 4) & 15;
      const c3 = byte2 & 15;
      result += consonants[c2]! + "-" + consonants[c3]!;
      seed = (seed * 5 + byte1 * 7 + byte2) % 36;
      i += 2;
    } else {
      const v1 = (((byte1 >> 6) & 3) + seed) % 6;
      const c1 = (byte1 >> 2) & 15;
      const v2 = ((byte1 & 3) + Math.floor(seed / 6)) % 6;
      result += vowels[v1]! + consonants[c1]! + vowels[v2]!;
      i += 1;
      break;
    }
  }

  const finalV = seed % 6;
  const finalC = 16;
  const finalV2 = Math.floor(seed / 6);
  result += vowels[finalV]! + consonants[finalC]! + vowels[finalV2]! + "x";
  return result;
}

/**
 * Calculates hex-formatted MD5 fingerprint for an SSH public key blob.
 * Matches `ssh-keygen -l -E md5`.
 */
export function calculateMd5Fingerprint(wireBlob: Uint8Array): string {
  const digest = md5(wireBlob);
  const parts: string[] = [];
  for (let i = 0; i < digest.length; i++) {
    parts.push(digest[i]!.toString(16).padStart(2, "0"));
  }
  return `MD5:${parts.join(":")}`;
}

/**
 * Simulates the OpenSSH "Drunken Bishop" random walk algorithm across a 17x9 grid.
 * Matches `ssh-keygen -l -v` and `ssh-keygen -lv`.
 */
export function generateDrunkenBishopRandomart(
  digest: Uint8Array,
  keyTypeLabel: string,
  hashAlg: string = "SHA256",
): string {
  const WIDTH = 17;
  const HEIGHT = 9;
  const board: number[][] = Array.from({ length: HEIGHT }, () =>
    new Array<number>(WIDTH).fill(0),
  );

  let x = 8;
  let y = 4;
  const startX = 8;
  const startY = 4;

  for (let i = 0; i < digest.length; i++) {
    let b = digest[i]!;
    for (let shift = 0; shift < 4; shift++) {
      const bit0 = b & 1;
      const bit1 = (b >> 1) & 1;
      b >>= 2;

      x += bit0 ? 1 : -1;
      y += bit1 ? 1 : -1;

      if (x < 0) x = 0;
      if (x >= WIDTH) x = WIDTH - 1;
      if (y < 0) y = 0;
      if (y >= HEIGHT) y = HEIGHT - 1;

      if (board[y]![x]! < 14) {
        board[y]![x]!++;
      }
    }
  }

  const symbols = [
    " ",
    ".",
    "o",
    "+",
    "=",
    "*",
    "B",
    "O",
    "X",
    "@",
    "%",
    "&",
    "#",
    "/",
    "^",
  ];

  const lines: string[] = [];
  const topTitle = `[${keyTypeLabel}]`;
  const topPadTotal = Math.max(0, WIDTH - topTitle.length);
  const topPadLeft = Math.floor(topPadTotal / 2);
  const topPadRight = topPadTotal - topPadLeft;
  lines.push(`+${"-".repeat(topPadLeft)}${topTitle}${"-".repeat(topPadRight)}+`);

  for (let r = 0; r < HEIGHT; r++) {
    let rowStr = "|";
    for (let c = 0; c < WIDTH; c++) {
      if (r === startY && c === startX) {
        rowStr += "S";
      } else if (r === y && c === x) {
        rowStr += "E";
      } else {
        const val = board[r]![c]!;
        rowStr += symbols[val] ?? " ";
      }
    }
    rowStr += "|";
    lines.push(rowStr);
  }

  const bottomTitle = `[${hashAlg}]`;
  const botPadTotal = Math.max(0, WIDTH - bottomTitle.length);
  const botPadLeft = Math.floor(botPadTotal / 2);
  const botPadRight = botPadTotal - botPadLeft;
  lines.push(`+${"-".repeat(botPadLeft)}${bottomTitle}${"-".repeat(botPadRight)}+`);

  return lines.join("\n");
}

export function formatRfc4716PublicKey(wireBlob: Uint8Array, comment: string): string {
  const b64 = uint8ArrayToBase64(wireBlob);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 70) {
    lines.push(b64.slice(i, i + 70));
  }
  return [
    "---- BEGIN SSH2 PUBLIC KEY ----",
    `Comment: "${comment.replace(/"/g, "")}"`,
    ...lines,
    "---- END SSH2 PUBLIC KEY ----",
  ].join("\n");
}

function encodeDerLength(length: number): Uint8Array {
  if (length < 128) {
    return new Uint8Array([length]);
  }
  const bytes: number[] = [];
  let temp = length;
  while (temp > 0) {
    bytes.unshift(temp & 0xff);
    temp >>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function encodeDerSequence(contents: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of contents) total += c.length;
  const lenBuf = encodeDerLength(total);
  const out = new Uint8Array(1 + lenBuf.length + total);
  out[0] = 0x30;
  out.set(lenBuf, 1);
  let offset = 1 + lenBuf.length;
  for (const c of contents) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function encodeDerInteger(val: number): Uint8Array {
  return new Uint8Array([0x02, 0x01, val & 0x7f]);
}

function encodeDerOctetString(val: Uint8Array): Uint8Array {
  const lenBuf = encodeDerLength(val.length);
  const out = new Uint8Array(1 + lenBuf.length + val.length);
  out[0] = 0x04;
  out.set(lenBuf, 1);
  out.set(val, 1 + lenBuf.length);
  return out;
}

function encodeDerOid(oidStr: string): Uint8Array {
  const parts = oidStr.split(".").map(Number);
  const bytes: number[] = [parts[0]! * 40 + parts[1]!];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i]!;
    if (v < 128) {
      bytes.push(v);
    } else {
      const stack: number[] = [];
      stack.push(v & 0x7f);
      v >>= 7;
      while (v > 0) {
        stack.push(0x80 | (v & 0x7f));
        v >>= 7;
      }
      while (stack.length) bytes.push(stack.pop()!);
    }
  }
  return new Uint8Array([0x06, bytes.length, ...bytes]);
}

function encodePem(label: string, der: Uint8Array): string {
  const b64 = uint8ArrayToBase64(der);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`].join("\n");
}

export interface EncodeOpenSshPrivateKeyParams {
  pubWire: Uint8Array;
  privPayload: Uint8Array;
  passphrase?: string;
  rounds?: number;
}

/**
 * Encodes an OpenSSH private key in the openssh-key-v1 format.
 * Supports AES-256-CTR encryption with bcrypt-PBKDF if a passphrase is provided.
 */
export function encodeOpenSshPrivateKey(params: EncodeOpenSshPrivateKeyParams): string {
  const { pubWire, privPayload, passphrase, rounds = 16 } = params;
  const isEncrypted = typeof passphrase === "string" && passphrase.length > 0;

  const magic = new Uint8Array([
    0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x76,
    0x31, 0x00,
  ]); // "openssh-key-v1\0"

  const cipherName = isEncrypted ? "aes256-ctr" : "none";
  const kdfName = isEncrypted ? "bcrypt" : "none";
  const blockSize = isEncrypted ? 16 : 8;

  let kdfOpts: Uint8Array = new Uint8Array(0);
  let finalPriv: Uint8Array;

  const padLen = (blockSize - (privPayload.length % blockSize)) % blockSize || blockSize;
  const paddedPriv = new Uint8Array(privPayload.length + padLen);
  paddedPriv.set(privPayload, 0);
  for (let i = 0; i < padLen; i++) {
    paddedPriv[privPayload.length + i] = i + 1;
  }

  if (isEncrypted) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    kdfOpts = concatSshChunks(sshString(salt), writeUint32Be(rounds));

    const derived = deriveBcryptPbkdf(passphrase, salt, 48, rounds);
    const key = derived.subarray(0, 32);
    const iv = derived.subarray(32, 48);

    const cipher = ctr(key, iv);
    finalPriv = cipher.encrypt(paddedPriv);
  } else {
    finalPriv = paddedPriv;
  }

  const numKeys = writeUint32Be(1);
  const fullBlob = concatSshChunks(
    magic,
    sshString(cipherName),
    sshString(kdfName),
    sshString(kdfOpts),
    numKeys,
    sshString(pubWire),
    sshString(finalPriv),
  );

  const b64 = uint8ArrayToBase64(fullBlob);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 70) {
    lines.push(b64.slice(i, i + 70));
  }

  return [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    ...lines,
    "-----END OPENSSH PRIVATE KEY-----",
  ].join("\n");
}

export type SshKeyAlgorithm =
  | "ed25519"
  | "rsa-2048"
  | "rsa-4096"
  | "ecdsa-p256"
  | "ecdsa-p384"
  | "ecdsa-p521";

export interface SshKeygenOptions {
  keyType?: SshKeyAlgorithm;
  comment?: string;
  passphrase?: string;
  rounds?: number;
  filename?: string;
}

export interface OpenSshSuiteResult {
  keyType: SshKeyAlgorithm;
  algorithmLabel: string;
  bits: number;
  comment: string;
  isEncrypted: boolean;
  kdfRounds: number;
  authorizedKeysLine: string;
  opensshPrivateKeyPem: string;
  pkcs8PrivateKeyPem: string;
  rfc4716Format: string;
  sha256Fingerprint: string;
  md5Fingerprint: string;
  bubblebabble: string;
  randomart: string;
  wireBlob: Uint8Array;
  defaultFilename: string;
  sshConfig: string;
  knownHostsExample: string;
}

/**
 * Generates a full OpenSSH key pair suite including public key line,
 * openssh-key-v1 private key, PKCS#8 PEM, RFC 4716 SECSH format, fingerprints,
 * Drunken Bishop randomart, and client configs.
 */
export async function generateOpenSshSuite(
  options: SshKeygenOptions = {},
): Promise<OpenSshSuiteResult> {
  const keyType: SshKeyAlgorithm = options.keyType ?? "ed25519";
  const comment = options.comment?.trim() || "user@cipherworkbench";
  const passphrase = options.passphrase?.trim() || "";
  const rounds = options.rounds && options.rounds > 0 ? options.rounds : 16;
  const isEncrypted = passphrase.length > 0;

  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("WebCrypto (crypto.subtle) is required for key generation");
  }

  const checkintVal = crypto.getRandomValues(new Uint32Array(1))[0]!;
  const checkintBuf = writeUint32Be(checkintVal);

  let pubWire: Uint8Array;
  let privPayload: Uint8Array;
  let pkcs8Pem: string;
  let algorithmLabel: string;
  let defaultFilename: string;
  let bits = 256;
  let randomartLabel = "ED25519 256";

  if (keyType === "ed25519") {
    bits = 256;
    algorithmLabel = "Ed25519 (256-bit Edwards Curve)";
    defaultFilename = options.filename?.trim() || "id_ed25519";
    randomartLabel = "ED25519 256";

    const privSeed = ed25519.utils.randomSecretKey();
    const pubRaw = ed25519.getPublicKey(privSeed);

    pubWire = concatSshChunks(sshString("ssh-ed25519"), sshString(pubRaw));

    privPayload = concatSshChunks(
      checkintBuf,
      checkintBuf,
      sshString("ssh-ed25519"),
      sshString(pubRaw),
      sshString(concatSshChunks(privSeed, pubRaw)),
      sshString(comment),
    );

    const algId = encodeDerSequence([encodeDerOid("1.3.101.112")]);
    const version = encodeDerInteger(0);
    const privOctet = encodeDerOctetString(encodeDerOctetString(privSeed));
    const pkcs8Der = encodeDerSequence([version, algId, privOctet]);
    pkcs8Pem = encodePem("PRIVATE KEY", pkcs8Der);
  } else if (keyType.startsWith("rsa-")) {
    const modulusBits = keyType === "rsa-4096" ? 4096 : 2048;
    bits = modulusBits;
    algorithmLabel = `RSA ${modulusBits}-bit`;
    defaultFilename = options.filename?.trim() || "id_rsa";
    randomartLabel = `RSA ${modulusBits}`;

    const keyPair = await subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: modulusBits,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );

    const jwk = await subtle.exportKey("jwk", keyPair.privateKey);
    const pkcs8Buf = await subtle.exportKey("pkcs8", keyPair.privateKey);
    pkcs8Pem = encodePem("PRIVATE KEY", new Uint8Array(pkcs8Buf));

    const nBytes = base64urlnopad.decode(jwk.n!);
    const eBytes = base64urlnopad.decode(jwk.e!);
    const dBytes = base64urlnopad.decode(jwk.d!);
    const pBytes = base64urlnopad.decode(jwk.p!);
    const qBytes = base64urlnopad.decode(jwk.q!);
    const qiBytes = base64urlnopad.decode(jwk.qi!);

    pubWire = concatSshChunks(
      sshString("ssh-rsa"),
      sshMpint(eBytes),
      sshMpint(nBytes),
    );

    privPayload = concatSshChunks(
      checkintBuf,
      checkintBuf,
      sshString("ssh-rsa"),
      sshMpint(nBytes),
      sshMpint(eBytes),
      sshMpint(dBytes),
      sshMpint(qiBytes),
      sshMpint(pBytes),
      sshMpint(qBytes),
      sshString(comment),
    );
  } else if (keyType.startsWith("ecdsa-")) {
    const namedCurve =
      keyType === "ecdsa-p384" ? "P-384" : keyType === "ecdsa-p521" ? "P-521" : "P-256";
    const curveName =
      keyType === "ecdsa-p384" ? "nistp384" : keyType === "ecdsa-p521" ? "nistp521" : "nistp256";
    bits = keyType === "ecdsa-p384" ? 384 : keyType === "ecdsa-p521" ? 521 : 256;
    algorithmLabel = `ECDSA ${namedCurve} (${bits}-bit)`;
    defaultFilename = options.filename?.trim() || "id_ecdsa";
    randomartLabel = `ECDSA ${bits}`;

    const keyPair = await subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve,
      },
      true,
      ["sign", "verify"],
    );

    const jwk = await subtle.exportKey("jwk", keyPair.privateKey);
    const pkcs8Buf = await subtle.exportKey("pkcs8", keyPair.privateKey);
    pkcs8Pem = encodePem("PRIVATE KEY", new Uint8Array(pkcs8Buf));

    const dBytes = base64urlnopad.decode(jwk.d!);
    const xBytes = base64urlnopad.decode(jwk.x!);
    const yBytes = base64urlnopad.decode(jwk.y!);

    const pubPoint = new Uint8Array(1 + xBytes.length + yBytes.length);
    pubPoint[0] = 0x04;
    pubPoint.set(xBytes, 1);
    pubPoint.set(yBytes, 1 + xBytes.length);

    const sshKeyType = `ecdsa-sha2-${curveName}`;

    pubWire = concatSshChunks(
      sshString(sshKeyType),
      sshString(curveName),
      sshString(pubPoint),
    );

    privPayload = concatSshChunks(
      checkintBuf,
      checkintBuf,
      sshString(sshKeyType),
      sshString(curveName),
      sshString(pubPoint),
      sshMpint(dBytes),
      sshString(comment),
    );
  } else {
    throw new Error(`Unsupported SSH key algorithm: ${keyType}`);
  }

  const opensshPrivateKeyPem = encodeOpenSshPrivateKey({
    pubWire,
    privPayload,
    passphrase,
    rounds,
  });

  const b64 = uint8ArrayToBase64(pubWire);
  const typeStr =
    keyType === "ed25519"
      ? "ssh-ed25519"
      : keyType.startsWith("rsa")
        ? "ssh-rsa"
        : `ecdsa-sha2-${keyType === "ecdsa-p384" ? "nistp384" : keyType === "ecdsa-p521" ? "nistp521" : "nistp256"}`;
  const authorizedKeysLine = `${typeStr} ${b64} ${comment}`;

  const digest = sha256(pubWire);
  const fpB64 = uint8ArrayToBase64(digest).replace(/=+$/, "");
  const sha256Fingerprint = `SHA256:${fpB64}`;
  const md5Fingerprint = calculateMd5Fingerprint(pubWire);
  const bubblebabble = calculateBubblebabble(pubWire);
  const rfc4716Format = formatRfc4716PublicKey(pubWire, comment);
  const randomart = generateDrunkenBishopRandomart(digest, randomartLabel, "SHA256");

  const sshConfig = [
    `# Append to ~/.ssh/config`,
    `Host my-server`,
    `  HostName 192.0.2.1`,
    `  User ubuntu`,
    `  IdentityFile ~/.ssh/${defaultFilename}`,
    `  IdentitiesOnly yes`,
  ].join("\n");

  const knownHostsExample = [
    `# Authorize this key on remote server:`,
    `# ssh-copy-id -i ~/.ssh/${defaultFilename}.pub user@hostname`,
    `# OR append directly:`,
    `cat ~/.ssh/${defaultFilename}.pub >> ~/.ssh/authorized_keys`,
    `chmod 600 ~/.ssh/authorized_keys`,
  ].join("\n");

  return {
    keyType,
    algorithmLabel,
    bits,
    comment,
    isEncrypted,
    kdfRounds: rounds,
    authorizedKeysLine,
    opensshPrivateKeyPem,
    pkcs8PrivateKeyPem: pkcs8Pem,
    rfc4716Format,
    sha256Fingerprint,
    md5Fingerprint,
    bubblebabble,
    randomart,
    wireBlob: pubWire,
    defaultFilename,
    sshConfig,
    knownHostsExample,
  };
}
