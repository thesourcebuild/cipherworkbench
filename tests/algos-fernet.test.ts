import { describe, expect, it } from "vitest";
import {
  fernetEncryptBytes,
  fernetDecryptBytes,
  fernetSplitKey,
  fernetParseToken,
  FERNET_VERSION,
  FERNET_KEY_LENGTH,
} from "@ocs/algos";
import { fernetOperation, fernetCrypto } from "@ocs/cipher/definition";
import { base64url } from "@scure/base";

const ascii = (str: string) => new TextEncoder().encode(str);

describe("Fernet Specification & Test Vectors", () => {
  // Official test vector from fernet/spec generate.json
  const vectorGenerate = {
    token:
      "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
    now: "1985-10-26T01:20:00-07:00",
    timestamp: 499162800,
    iv: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    src: "hello",
    secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
  };

  // Official test vector from fernet/spec verify.json
  const vectorVerify = {
    token:
      "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
    now: "1985-10-26T01:20:01-07:00",
    ttl_sec: 60,
    src: "hello",
    secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
  };

  it("splits key into 16-byte signing and 16-byte encryption keys", () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i;
    const { signingKey, encryptionKey } = fernetSplitKey(key);
    expect(signingKey.length).toBe(16);
    expect(encryptionKey.length).toBe(16);
    expect(signingKey[0]).toBe(0);
    expect(signingKey[15]).toBe(15);
    expect(encryptionKey[0]).toBe(16);
    expect(encryptionKey[15]).toBe(31);
  });

  it("parses valid Fernet tokens into structured fields", () => {
    const tokenBytes = base64url.decode(vectorGenerate.token);
    const parsed = fernetParseToken(tokenBytes);
    expect(parsed.version).toBe(FERNET_VERSION);
    expect(parsed.timestamp).toBe(vectorGenerate.timestamp);
    expect(parsed.iv).toEqual(new Uint8Array(vectorGenerate.iv));
    expect(parsed.ciphertext.length).toBe(16);
    expect(parsed.hmac.length).toBe(32);
  });

  it("refuses keys that are not exactly 32 bytes", () => {
    expect(FERNET_KEY_LENGTH).toBe(32);
    expect(() => fernetSplitKey(new Uint8Array(16))).toThrow(
      /Fernet key must be exactly 32 bytes/,
    );
    expect(() => fernetSplitKey(new Uint8Array(64))).toThrow(
      /Fernet key must be exactly 32 bytes/,
    );
  });

  it("encrypts matching official generate.json vector", () => {
    const key = base64url.decode(vectorGenerate.secret);
    const plaintext = ascii(vectorGenerate.src);
    const iv = new Uint8Array(vectorGenerate.iv);
    const timestamp = vectorGenerate.timestamp;

    const result = fernetEncryptBytes(fernetCrypto, key, plaintext, {
      iv,
      timestamp,
    });

    expect(result.version).toBe(FERNET_VERSION);
    expect(result.timestamp).toBe(timestamp);
    expect(result.iv).toEqual(iv);

    // Encode to base64url
    const encodedToken = base64url.encode(result.token);
    expect(encodedToken).toBe(vectorGenerate.token);

    // Decrypt it back
    const decrypted = fernetDecryptBytes(fernetCrypto, key, result.token);
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe(vectorGenerate.src);
  });

  it("decrypts matching official verify.json vector with TTL check", () => {
    const key = base64url.decode(vectorVerify.secret);
    const tokenBytes = base64url.decode(vectorVerify.token);

    const decrypted = fernetDecryptBytes(fernetCrypto, key, tokenBytes, {
      now: 499162801,
      ttl: vectorVerify.ttl_sec,
    });
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe(vectorVerify.src);
    expect(decrypted.timestamp).toBe(499162800);
  });

  it("enforces TTL expiration", () => {
    const key = base64url.decode(vectorVerify.secret);
    const tokenBytes = base64url.decode(vectorVerify.token);

    // Expired TTL (now = 499162800 + 100 > 60)
    expect(() =>
      fernetDecryptBytes(fernetCrypto, key, tokenBytes, {
        now: 499162800 + 100,
        ttl: 60,
      }),
    ).toThrow(/Fernet token expired/);
  });

  it("rejects timestamps too far in the future", () => {
    const key = base64url.decode(vectorVerify.secret);
    const tokenBytes = base64url.decode(vectorVerify.token);

    // Now is before timestamp by 200 seconds
    expect(() =>
      fernetDecryptBytes(fernetCrypto, key, tokenBytes, {
        now: 499162800 - 200,
        ttl: 60,
      }),
    ).toThrow(/in the future/);
  });

  it("detects tampered ciphertext and HMAC signatures", () => {
    const key = base64url.decode(vectorVerify.secret);
    const tokenBytes = base64url.decode(vectorVerify.token);

    // Tamper with ciphertext byte
    const tamperedCt = new Uint8Array(tokenBytes);
    tamperedCt[30]! ^= 0x01;
    expect(() => fernetDecryptBytes(fernetCrypto, key, tamperedCt)).toThrow(
      /HMAC signature verification failed/,
    );

    // Tamper with HMAC byte
    const tamperedHmac = new Uint8Array(tokenBytes);
    tamperedHmac[tamperedHmac.length - 1]! ^= 0x01;
    expect(() => fernetDecryptBytes(fernetCrypto, key, tamperedHmac)).toThrow(
      /HMAC signature verification failed/,
    );
  });

  it("detects unsupported token versions", () => {
    const key = base64url.decode(vectorVerify.secret);
    const tokenBytes = base64url.decode(vectorVerify.token);

    const badVersion = new Uint8Array(tokenBytes);
    badVersion[0] = 0x81;
    expect(() => fernetDecryptBytes(fernetCrypto, key, badVersion)).toThrow(
      /Unsupported Fernet version/,
    );
  });

  it("detects truncated tokens", () => {
    const key = base64url.decode(vectorVerify.secret);
    expect(() => fernetDecryptBytes(fernetCrypto, key, new Uint8Array(40))).toThrow(
      /Fernet token is too short/,
    );
  });

  it("operates through cipher fernetOperation binding", () => {
    const key = base64url.decode(vectorGenerate.secret);
    const op = fernetOperation(key, {
      timestamp: vectorGenerate.timestamp,
      iv: new Uint8Array(vectorGenerate.iv),
    });

    const ct = op.encrypt(ascii("Cipher Workbench Fernet Support"));
    const pt = op.decrypt(ct);
    expect(new TextDecoder().decode(pt)).toBe("Cipher Workbench Fernet Support");
  });

  // Invalid vectors from invalid.json
  it("rejects invalid tokens from official invalid.json suite", () => {
    const secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=";
    const key = base64url.decode(secret);

    // 1. incorrect mac
    const invalidMac = base64url.decode(
      "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykQUFBQUFBQUFBQQ==",
    );
    expect(() => fernetDecryptBytes(fernetCrypto, key, invalidMac)).toThrow(
      /HMAC signature verification failed/,
    );

    // 2. too short
    const tooShort = base64url.decode("gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPA==");
    expect(() => fernetDecryptBytes(fernetCrypto, key, tooShort)).toThrow(
      /Fernet token is too short/,
    );

    // 3. payload size not multiple of block size
    // (Notice token is not a multiple of 16)
    const badBlockSize = base64url.decode(
      "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPOm73QeoCk9uGib28Xe5vz6oxq5nmxbx_v7mrfyudzUm",
    );
    expect(() => fernetDecryptBytes(fernetCrypto, key, badBlockSize)).toThrow();

    // 4. payload padding error
    const paddingError = base64url.decode(
      "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0ODz4LEpdELGQAad7aNEHbf-JkLPIpuiYRLQ3RtXatOYREu2FWke6CnJNYIbkuKNqOhw==",
    );
    expect(() => fernetDecryptBytes(fernetCrypto, key, paddingError)).toThrow();

    // 5. far-future TS (unacceptable clock skew)
    const farFuture = base64url.decode(
      "gAAAAAAdwStRAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAnja1xKYyhd-Y6mSkTOyTGJmw2Xc2a6kBd-iX9b_qXQcw==",
    );
    expect(() =>
      fernetDecryptBytes(fernetCrypto, key, farFuture, { now: 499162801, ttl: 60 }),
    ).toThrow(/in the future/);

    // 6. expired TTL
    const expiredTtl = base64url.decode(
      "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==",
    );
    expect(() =>
      fernetDecryptBytes(fernetCrypto, key, expiredTtl, { now: 499162800 + 91, ttl: 60 }),
    ).toThrow(/Fernet token expired/);
  });
});
