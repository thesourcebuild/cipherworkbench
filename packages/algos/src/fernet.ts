/**
 * Fernet -- symmetric authenticated encryption recipe.
 *
 * Implements version 0x80 of the Fernet specification (https://github.com/fernet/spec/blob/master/Spec.md).
 * Uses AES-128-CBC with PKCS#7 padding for encryption and HMAC-SHA256 for authentication over:
 *   Version (1 byte: 0x80) || Timestamp (8 bytes uint64 BE) || IV (16 bytes) || Ciphertext (variable, 16-byte blocks)
 *
 * Token format (Base64url encoded):
 *   0x80 (1 byte) || Timestamp (8 bytes) || IV (16 bytes) || Ciphertext (16*k bytes) || HMAC (32 bytes)
 *
 * Key format:
 *   32 bytes: Signing-key (16 bytes) || Encryption-key (16 bytes)
 */

export const FERNET_VERSION = 0x80;
export const FERNET_KEY_LENGTH = 32;
export const FERNET_MIN_TOKEN_LENGTH = 57; // 1 + 8 + 16 + 0 + 32

export interface FernetCrypto {
  aesCbcEncrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array;
  aesCbcDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array;
  hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array;
}

export interface FernetEncryptOptions {
  /** Explicit timestamp (seconds since Unix epoch). Defaults to current time. */
  timestamp?: number | bigint;
  /** Explicit 16-byte IV. Defaults to CSPRNG generated random bytes. */
  iv?: Uint8Array;
}

export interface FernetDecryptOptions {
  /** Optional TTL in seconds. Decryption fails if token age exceeds this value. */
  ttl?: number;
  /** Current time override (seconds since epoch) for TTL testing. Defaults to Date.now() / 1000. */
  now?: number;
}

export interface FernetTokenDetails {
  version: number;
  timestamp: number;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  hmac: Uint8Array;
}

/** Constant-time comparison for byte arrays. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

/** Reads a 64-bit unsigned big-endian integer from a byte array. */
export function readBigUint64BE(bytes: Uint8Array, offset = 0): bigint {
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 8);
  return view.getBigUint64(0, false);
}

/** Writes a 64-bit unsigned big-endian integer to a byte array. */
export function writeBigUint64BE(value: bigint | number, out: Uint8Array, offset = 0): void {
  const view = new DataView(out.buffer, out.byteOffset + offset, 8);
  view.setBigUint64(0, BigInt(value), false);
}

/**
 * Splits a 32-byte Fernet key into its 16-byte signing key and 16-byte encryption key.
 */
export function fernetSplitKey(key: Uint8Array): {
  signingKey: Uint8Array;
  encryptionKey: Uint8Array;
} {
  if (key.length !== FERNET_KEY_LENGTH) {
    throw new Error(
      `Fernet key must be exactly ${FERNET_KEY_LENGTH} bytes; received ${key.length} bytes.`,
    );
  }
  const signingKey = key.slice(0, 16);
  const encryptionKey = key.slice(16, 32);
  return { signingKey, encryptionKey };
}

/**
 * Extracts and parses the header & fields from raw Fernet token bytes.
 */
export function fernetParseToken(token: Uint8Array): FernetTokenDetails {
  if (token.length < FERNET_MIN_TOKEN_LENGTH) {
    throw new Error(
      `Fernet token is too short: minimum length is ${FERNET_MIN_TOKEN_LENGTH} bytes, received ${token.length} bytes.`,
    );
  }
  const payloadLen = token.length - 32;
  const ctLen = payloadLen - 25; // 1 version + 8 timestamp + 16 IV = 25
  if (ctLen % 16 !== 0) {
    throw new Error(
      `Fernet ciphertext length (${ctLen} bytes) is not a multiple of AES block size (16 bytes).`,
    );
  }
  const version = token[0]!;
  const timestamp = Number(readBigUint64BE(token, 1));
  const iv = token.slice(9, 25);
  const ciphertext = token.slice(25, payloadLen);
  const hmac = token.slice(payloadLen);

  return { version, timestamp, iv, ciphertext, hmac };
}

/**
 * Encrypts a message into a raw Fernet token byte array.
 */
export function fernetEncryptBytes(
  crypto: FernetCrypto,
  key: Uint8Array,
  plaintext: Uint8Array,
  options: FernetEncryptOptions = {},
): {
  token: Uint8Array;
  version: number;
  timestamp: number;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  hmac: Uint8Array;
} {
  const { signingKey, encryptionKey } = fernetSplitKey(key);

  const iv = options.iv ?? new Uint8Array(16);
  if (options.iv) {
    if (options.iv.length !== 16) {
      throw new Error(`Fernet IV must be exactly 16 bytes; received ${options.iv.length} bytes.`);
    }
  } else {
    // Generate random IV
    if (typeof globalThis.crypto?.getRandomValues === "function") {
      globalThis.crypto.getRandomValues(iv);
    } else {
      throw new Error("No CSPRNG available to generate Fernet IV.");
    }
  }

  const timestampNum =
    options.timestamp !== undefined
      ? Number(options.timestamp)
      : Math.floor(Date.now() / 1000);

  const ciphertext = crypto.aesCbcEncrypt(encryptionKey, iv, plaintext);

  // Payload: Version (1) || Timestamp (8) || IV (16) || Ciphertext
  const payload = new Uint8Array(25 + ciphertext.length);
  payload[0] = FERNET_VERSION;
  writeBigUint64BE(timestampNum, payload, 1);
  payload.set(iv, 9);
  payload.set(ciphertext, 25);

  const hmac = crypto.hmacSha256(signingKey, payload);

  const token = new Uint8Array(payload.length + hmac.length);
  token.set(payload, 0);
  token.set(hmac, payload.length);

  return {
    token,
    version: FERNET_VERSION,
    timestamp: timestampNum,
    iv,
    ciphertext,
    hmac,
  };
}

/**
 * Decrypts a raw Fernet token byte array.
 */
export function fernetDecryptBytes(
  crypto: FernetCrypto,
  key: Uint8Array,
  token: Uint8Array,
  options: FernetDecryptOptions = {},
): {
  plaintext: Uint8Array;
  version: number;
  timestamp: number;
  iv: Uint8Array;
  hmac: Uint8Array;
} {
  const { signingKey, encryptionKey } = fernetSplitKey(key);
  const parsed = fernetParseToken(token);

  if (parsed.version !== FERNET_VERSION) {
    throw new Error(
      `Unsupported Fernet version 0x${parsed.version.toString(16)} (expected 0x${FERNET_VERSION.toString(16)}).`,
    );
  }

  // Authenticate before decrypting
  const payload = token.subarray(0, token.length - 32);
  const expectedHmac = crypto.hmacSha256(signingKey, payload);

  if (!constantTimeEqual(parsed.hmac, expectedHmac)) {
    throw new Error("Invalid Fernet token: HMAC signature verification failed.");
  }

  // TTL freshness verification if requested
  if (options.ttl !== undefined && options.ttl > 0) {
    const now = options.now !== undefined ? options.now : Math.floor(Date.now() / 1000);
    if (now - parsed.timestamp > options.ttl) {
      throw new Error(
        `Fernet token expired: created at ${parsed.timestamp}, current time is ${now} (TTL: ${options.ttl}s).`,
      );
    }
    // Check against clock skew in the future (max 60s)
    if (parsed.timestamp > now + 60) {
      throw new Error(
        `Fernet token timestamp (${parsed.timestamp}) is in the future relative to current time (${now}).`,
      );
    }
  }

  const plaintext = crypto.aesCbcDecrypt(encryptionKey, parsed.iv, parsed.ciphertext);

  return {
    plaintext,
    version: parsed.version,
    timestamp: parsed.timestamp,
    iv: parsed.iv,
    hmac: parsed.hmac,
  };
}
