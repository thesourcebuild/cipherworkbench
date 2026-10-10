import { describe, it, expect } from "vitest";
import { Buffer } from "node:buffer";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  formatAgeIdentity,
  formatAgeRecipient,
  parseAgeIdentity,
  parseAgeRecipient,
  ageEncrypt,
  ageDecrypt,
  AgeDecryptor,
  AgeEncryptor,
  AGE_CHUNK_SIZE,
  AGE_MAX_HEADER_SIZE,
  AGE_PAYLOAD_NONCE_SIZE,
  AGE_TAG_SIZE,
  armorAge,
  dearmorAge,
  isArmoredAge,
} from "@ocs/algos";
import { ageCrypto, ageOperation } from "@ocs/cipher/definition";
import { computeCipher } from "@ocs/cipher/definition";
import { createSpec } from "@ocs/cipher/definition";
import { x25519 } from "@noble/curves/ed25519.js";

describe("age (RFC age-encryption.org/v1) container format", () => {
  // Test keypair
  const testPrivKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) testPrivKey[i] = (i * 7 + 13) & 0xff;
  const testPubKey = x25519.getPublicKey(testPrivKey);
  const testRecipient = formatAgeRecipient(testPubKey);
  const testIdentity = formatAgeIdentity(testPrivKey);
  const deterministicOptions = {
    recipients: [testRecipient],
    fileKey: Uint8Array.from({ length: 16 }, (_, i) => i + 1),
    ephemeralKey: Uint8Array.from({ length: 32 }, (_, i) => 255 - i),
    payloadNonce: Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i),
  };

  // C2SP/CCTV age testkit fixtures, fetched from blobs eb8726b (X25519) and
  // 57dd08f (scrypt). The fixture metadata is followed by the binary age file.
  const c2spX25519 =
    "ZXhwZWN0OiBzdWNjZXNzCnBheWxvYWQ6IDAxM2Y1NDQwMGM4MmRhMDgwMzc3NTlhZGE5MDdhOGI4NjRlOTdkZTgxYzA4OGExODIwNjJjNGI1NjIyZmQyYWIKZmlsZSBrZXk6IDU5NDU0YzRjNGY1NzIwNTM1NTQyNGQ0MTUyNDk0ZTQ1CmlkZW50aXR5OiBBR0UtU0VDUkVULUtFWS0xRUdUWlZGRlYyMDgzNU5XWVY2MjcwTFhZVksyVktOWDJNTURLV1lLTE1HUjQ4VUFXWDQwUTJQMkxNMAoKYWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBURWlGMHlwcXIrYnB2Y3FYTnlDVkpwTDdPdXdQZFZ3UEw3S1FFYkZET0NjCmhqYWJHWHdTTFE5YzNTNkx3MmkrUzJUdTJmaXdRSEhzbGJCTjZCNDFGTEUKLS0tIFd5SnA5Ri85Rk9aaDdnSmRoZXEyV0lKY3dIZ1ljOE5JVmgzZGR3aHJjTmcK7s9ix86RtDMnTmjU8vkTTLdMW/73vqpSyPC8DpksHoMx+2Y=";
  const c2spScrypt =
    "ZXhwZWN0OiBzdWNjZXNzCnBheWxvYWQ6IDAxM2Y1NDQwMGM4MmRhMDgwMzc3NTlhZGE5MDdhOGI4NjRlOTdkZTgxYzA4OGExODIwNjJjNGI1NjIyZmQyYWIKZmlsZSBrZXk6IDU5NDU0YzRjNGY1NzIwNTM1NTQyNGQ0MTUyNDk0ZTQ1CnBhc3NwaHJhc2U6IHBhc3N3b3JkCgphZ2UtZW5jcnlwdGlvbi5vcmcvdjEKLT4gc2NyeXB0IHJGMC9Od2JsVUhIVHBnUWdScGU1Q1EgMTAKZ1VqRXltRktNVlhRRUtkTU1ITDI0b1lleGpFM1RJQzBPMHpHU3FKMmFVWQotLS0gSU9YaVFZU3Rrb1QxbXZaVzJ0Rk9xWmRoUlZ2ajU4ZWdBQngvc1dmWlFiYwobNcbmh90A2jrDeayfdCwh/RhaG5497XOdFKxqmlASTbhm2A==";
  const c2spPayloadHash = "013f54400c82da08037759ada907a8b864e97de81c088a182062c4b5622fd2ab";

  function concat(chunks: Uint8Array[]): Uint8Array {
    const output = new Uint8Array(chunks.reduce((length, chunk) => length + chunk.length, 0));
    let offset = 0;
    for (const chunk of chunks) {
      output.set(chunk, offset);
      offset += chunk.length;
    }
    return output;
  }

  function headerLength(container: Uint8Array): number {
    const header = new TextDecoder().decode(container.subarray(0, 1024));
    const marker = header.indexOf("\n--- ");
    return header.indexOf("\n", marker + 5) + 1;
  }

  function payloadOffset(container: Uint8Array): number {
    return headerLength(container) + AGE_PAYLOAD_NONCE_SIZE;
  }

  function testkitContainer(encodedFixture: string): Uint8Array {
    const fixture = new Uint8Array(Buffer.from(encodedFixture, "base64"));
    for (let i = 0; i < fixture.length - 1; i++) {
      if (fixture[i] === 0x0a && fixture[i + 1] === 0x0a) return fixture.slice(i + 2);
    }
    throw new Error("Malformed embedded C2SP fixture.");
  }

  function hex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function replaceAscii(input: Uint8Array, search: string, replacement: string): Uint8Array {
    expect(replacement).toHaveLength(search.length);
    const output = new Uint8Array(input);
    const searchBytes = new TextEncoder().encode(search);
    const replacementBytes = new TextEncoder().encode(replacement);
    outer: for (let i = 0; i <= output.length - searchBytes.length; i++) {
      for (let j = 0; j < searchBytes.length; j++) {
        if (output[i + j] !== searchBytes[j]) continue outer;
      }
      output.set(replacementBytes, i);
      return output;
    }
    throw new Error(`Could not find '${search}' in fixture.`);
  }

  function incrementalEncrypt(plaintext: Uint8Array, chunkSizes: number[]): Uint8Array {
    const encryptor = new AgeEncryptor(ageCrypto, deterministicOptions);
    const output: Uint8Array[] = [];
    let offset = 0;
    let chunkIndex = 0;
    while (offset < plaintext.length) {
      const end = Math.min(
        offset + chunkSizes[chunkIndex++ % chunkSizes.length]!,
        plaintext.length,
      );
      output.push(encryptor.update(plaintext.subarray(offset, end)));
      offset = end;
    }
    output.push(encryptor.finalize());
    return concat(output);
  }

  function incrementalDecrypt(container: Uint8Array, chunkSizes: number[]): Uint8Array {
    const decryptor = new AgeDecryptor(ageCrypto, { identities: [testIdentity] });
    const output: Uint8Array[] = [];
    let offset = 0;
    let chunkIndex = 0;
    while (offset < container.length) {
      const end = Math.min(
        offset + chunkSizes[chunkIndex++ % chunkSizes.length]!,
        container.length,
      );
      output.push(decryptor.update(container.subarray(offset, end)));
      offset = end;
    }
    output.push(decryptor.finalize());
    return concat(output);
  }

  it("formats and parses age recipients and identities with Bech32", () => {
    expect(testRecipient.startsWith("age1")).toBe(true);
    expect(testIdentity.startsWith("AGE-SECRET-KEY-1")).toBe(true);

    const parsedPub = parseAgeRecipient(testRecipient);
    expect(parsedPub).toEqual(testPubKey);

    const parsedPriv = parseAgeIdentity(testIdentity);
    expect(parsedPriv).toEqual(testPrivKey);
  });

  it("parses 64-character hex strings as keys", () => {
    const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const bytes = parseAgeRecipient(hex);
    expect(bytes.length).toBe(32);
    expect(bytes[0]).toBe(0x01);
  });

  it("throws on corrupted or malformed recipient and identity keys", () => {
    expect(() => parseAgeRecipient("age1invalidchecksum")).toThrow();
    expect(() => parseAgeIdentity("AGE-SECRET-KEY-1INVALID")).toThrow();
    expect(() => parseAgeRecipient("short")).toThrow();
  });

  it("decrypts independent C2SP testkit X25519 and scrypt vectors", () => {
    const x25519Plaintext = ageDecrypt(ageCrypto, testkitContainer(c2spX25519), {
      identities: [
        "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0",
      ],
    });
    const scryptPlaintext = ageDecrypt(ageCrypto, testkitContainer(c2spScrypt), {
      passphrase: "password",
    });

    expect(hex(sha256(x25519Plaintext))).toBe(c2spPayloadHash);
    expect(hex(sha256(scryptPlaintext))).toBe(c2spPayloadHash);
  });

  it("encrypts and decrypts with an X25519 recipient stanza", () => {
    const plaintext = new TextEncoder().encode("Hello, actually good encryption!");
    const container = ageEncrypt(ageCrypto, plaintext, {
      recipients: [testRecipient],
    });

    const header = new TextDecoder().decode(container.subarray(0, 100));
    expect(header).toContain("age-encryption.org/v1");
    expect(header).toContain("-> X25519 ");

    const decrypted = ageDecrypt(ageCrypto, container, {
      identities: [testIdentity],
    });
    expect(new TextDecoder().decode(decrypted)).toBe("Hello, actually good encryption!");
  });

  it("encrypts and decrypts with a scrypt passphrase stanza", () => {
    const plaintext = new TextEncoder().encode("Passphrase-protected age secret!");
    const passphrase = "correct horse battery staple";
    const container = ageEncrypt(ageCrypto, plaintext, {
      passphrase,
      scryptLogN: 10, // faster for unit tests
    });

    const header = new TextDecoder().decode(container.subarray(0, 100));
    expect(header).toContain("age-encryption.org/v1");
    expect(header).toContain("-> scrypt ");

    const decrypted = ageDecrypt(ageCrypto, container, {
      passphrase,
    });
    expect(new TextDecoder().decode(decrypted)).toBe("Passphrase-protected age secret!");
  });

  it("emits a 16-byte payload nonce and uses it as the payload HKDF salt", () => {
    const plaintext = new TextEncoder().encode("payload nonce test");
    const container = ageEncrypt(ageCrypto, plaintext, deterministicOptions);
    const headerEnd = headerLength(container);

    expect(container.subarray(headerEnd, payloadOffset(container))).toEqual(
      deterministicOptions.payloadNonce,
    );

    const changedNonce = Uint8Array.from(
      deterministicOptions.payloadNonce,
      (byte) => byte ^ 0xff,
    );
    const changed = ageEncrypt(ageCrypto, plaintext, {
      ...deterministicOptions,
      payloadNonce: changedNonce,
    });
    expect(changed.subarray(0, headerEnd)).toEqual(container.subarray(0, headerEnd));
    expect(changed.subarray(payloadOffset(changed))).not.toEqual(
      container.subarray(payloadOffset(container)),
    );
  });

  it("rejects malformed native stanzas and excessive scrypt work before invoking scrypt", () => {
    const fixture = testkitContainer(c2spScrypt);
    let scryptInvoked = false;
    const guardedCrypto = {
      ...ageCrypto,
      scrypt() {
        scryptInvoked = true;
        throw new Error("scrypt must not be invoked");
      },
    };

    const excessive = replaceAscii(fixture, " 10\n", " 23\n");
    expect(() => ageDecrypt(guardedCrypto, excessive, { passphrase: "password" })).toThrow(
      /work factor exceeds/i,
    );
    expect(scryptInvoked).toBe(false);

    const nonCanonicalSalt = replaceAscii(
      fixture,
      "rF0/NwblUHHTpgQgRpe5CQ",
      "rF0/NwblUHHTpgQgRpe5CR",
    );
    expect(() =>
      ageDecrypt(guardedCrypto, nonCanonicalSalt, { passphrase: "password" }),
    ).toThrow(/scrypt salt/i);
    expect(scryptInvoked).toBe(false);

    const extraArgument = replaceAscii(fixture, " 10\n", " 10X");
    expect(() => ageDecrypt(guardedCrypto, extraArgument, { passphrase: "password" })).toThrow(
      /recipient stanza|work factor/i,
    );
    expect(scryptInvoked).toBe(false);

    const x25519Fixture = testkitContainer(c2spX25519);
    const identity =
      "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";
    const nonCanonicalShare = replaceAscii(
      x25519Fixture,
      "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc",
      "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCd",
    );
    expect(() => ageDecrypt(ageCrypto, nonCanonicalShare, { identities: [identity] })).toThrow(
      /ephemeral share/i,
    );

    const lowOrderShare = replaceAscii(
      x25519Fixture,
      "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc",
      "A".repeat(43),
    );
    expect(() => ageDecrypt(ageCrypto, lowOrderShare, { identities: [identity] })).toThrow(
      /X25519/i,
    );
  });

  it("caps an incomplete incremental header", () => {
    const decryptor = new AgeDecryptor(ageCrypto, { identities: [testIdentity] });
    expect(() => decryptor.update(new Uint8Array(AGE_MAX_HEADER_SIZE + 1).fill(0x41))).toThrow(
      /header exceeds/i,
    );
  });

  it("encrypts and decrypts across multiple 64 KiB chunks (streaming framing)", () => {
    // 100,000 bytes spans 2 chunks (64 KiB + ~34 KiB)
    const largeData = new Uint8Array(100_000);
    for (let i = 0; i < largeData.length; i++) largeData[i] = (i * 31) & 0xff;

    const container = ageEncrypt(ageCrypto, largeData, {
      recipients: [testRecipient],
    });

    const decrypted = ageDecrypt(ageCrypto, container, {
      identities: [testIdentity],
    });
    expect(decrypted.length).toBe(largeData.length);
    expect(decrypted).toEqual(largeData);
  });

  it("holds a full final frame and emits only authenticated incremental frames", () => {
    const plaintext = Uint8Array.from(
      { length: AGE_CHUNK_SIZE * 2 },
      (_, i) => (i * 31 + 7) & 0xff,
    );
    const oneShot = ageEncrypt(ageCrypto, plaintext, deterministicOptions);
    const encryptor = new AgeEncryptor(ageCrypto, deterministicOptions);

    const headerOnly = encryptor.update(plaintext.subarray(0, AGE_CHUNK_SIZE));
    expect(new TextDecoder().decode(headerOnly)).toContain("age-encryption.org/v1");
    const firstFrame = encryptor.update(plaintext.subarray(AGE_CHUNK_SIZE));
    expect(firstFrame).toHaveLength(AGE_CHUNK_SIZE + AGE_TAG_SIZE);
    const finalFrame = encryptor.finalize();
    expect(finalFrame).toHaveLength(AGE_CHUNK_SIZE + AGE_TAG_SIZE);
    expect(concat([headerOnly, firstFrame, finalFrame])).toEqual(oneShot);

    const encryptedPayloadOffset = payloadOffset(oneShot);
    const decryptor = new AgeDecryptor(ageCrypto, { identities: [testIdentity] });
    expect(
      decryptor.update(
        oneShot.subarray(0, encryptedPayloadOffset + AGE_CHUNK_SIZE + AGE_TAG_SIZE),
      ),
    ).toHaveLength(0);
    expect(
      decryptor.update(
        oneShot.subarray(
          encryptedPayloadOffset + AGE_CHUNK_SIZE + AGE_TAG_SIZE,
          encryptedPayloadOffset + AGE_CHUNK_SIZE + AGE_TAG_SIZE + 1,
        ),
      ),
    ).toEqual(plaintext.subarray(0, AGE_CHUNK_SIZE));
    expect(
      decryptor.update(
        oneShot.subarray(encryptedPayloadOffset + AGE_CHUNK_SIZE + AGE_TAG_SIZE + 1),
      ),
    ).toHaveLength(0);
    expect(decryptor.finalize()).toEqual(plaintext.subarray(AGE_CHUNK_SIZE));

    const tampered = new Uint8Array(oneShot);
    tampered[encryptedPayloadOffset + AGE_CHUNK_SIZE + AGE_TAG_SIZE - 1]! ^= 1;
    const rejecting = new AgeDecryptor(ageCrypto, { identities: [testIdentity] });
    expect(() =>
      rejecting.update(
        tampered.subarray(0, encryptedPayloadOffset + AGE_CHUNK_SIZE + AGE_TAG_SIZE + 1),
      ),
    ).toThrow();
  });

  it("matches one-shot output across arbitrary boundaries for an approximately 3 MiB payload", () => {
    const plaintext = Uint8Array.from(
      { length: 3 * 1024 * 1024 + 317 },
      (_, i) => (i * 17 + (i >>> 8)) & 0xff,
    );
    const oneShot = ageEncrypt(ageCrypto, plaintext, deterministicOptions);
    const incremental = incrementalEncrypt(plaintext, [1, 65535, 7, 131089, 4093, 262144]);
    expect(incremental).toEqual(oneShot);
    expect(incrementalDecrypt(incremental, [2, 101, 65551, 3, 200003, 8191])).toEqual(
      plaintext,
    );

    const encryptedPayloadOffset = payloadOffset(incremental);
    const frameSize = AGE_CHUNK_SIZE + AGE_TAG_SIZE;
    const tampered = new Uint8Array(incremental);
    tampered[encryptedPayloadOffset + frameSize + 1234]! ^= 0x80;
    const decryptor = new AgeDecryptor(ageCrypto, { identities: [testIdentity] });
    expect(
      decryptor.update(tampered.subarray(0, encryptedPayloadOffset + frameSize + 1)),
    ).toEqual(plaintext.subarray(0, AGE_CHUNK_SIZE));
    expect(() =>
      decryptor.update(tampered.subarray(encryptedPayloadOffset + frameSize + 1)),
    ).toThrow();
  });

  it("rejects an authenticated empty final frame after a prior frame", () => {
    const plaintext = Uint8Array.from(
      { length: AGE_CHUNK_SIZE },
      (_, i) => (i * 13 + 5) & 0xff,
    );
    const valid = ageEncrypt(ageCrypto, plaintext, deterministicOptions);
    const prefix = valid.subarray(0, payloadOffset(valid));
    const payloadKey = ageCrypto.hkdfSha256(
      deterministicOptions.fileKey,
      deterministicOptions.payloadNonce,
      "payload",
      32,
    );
    const nonFinalNonce = new Uint8Array(12);
    const finalNonce = new Uint8Array(12);
    finalNonce[10] = 1;
    finalNonce[11] = 1;
    const malformed = concat([
      prefix,
      ageCrypto.chacha20poly1305Encrypt(payloadKey, nonFinalNonce, plaintext),
      ageCrypto.chacha20poly1305Encrypt(payloadKey, finalNonce, new Uint8Array(0)),
    ]);

    const decryptor = new AgeDecryptor(ageCrypto, { identities: [testIdentity] });
    expect(decryptor.update(malformed)).toEqual(plaintext);
    expect(() => decryptor.finalize()).toThrow(/empty after prior frames/i);
  });

  it("explicitly rejects armor in incremental mode", () => {
    expect(() => new AgeEncryptor(ageCrypto, { ...deterministicOptions, armor: true })).toThrow(
      /does not support armored output/i,
    );

    const raw = ageEncrypt(ageCrypto, new Uint8Array([1, 2, 3]), deterministicOptions);
    const decryptor = new AgeDecryptor(ageCrypto, { identities: [testIdentity] });
    expect(() => decryptor.update(new TextEncoder().encode(armorAge(raw)))).toThrow(
      /does not support armored input/i,
    );
  });

  it("detects header tampering and refuses decryption", () => {
    const plaintext = new TextEncoder().encode("Tamper resistance test");
    const container = ageEncrypt(ageCrypto, plaintext, {
      recipients: [testRecipient],
    });

    // Flip a byte in the header
    const tampered = new Uint8Array(container);
    tampered[10]! ^= 0x01;

    expect(() =>
      ageDecrypt(ageCrypto, tampered, {
        identities: [testIdentity],
      }),
    ).toThrow();
  });

  it("detects payload tampering and refuses decryption", () => {
    const plaintext = new TextEncoder().encode("Chunk authentication test");
    const container = ageEncrypt(ageCrypto, plaintext, {
      recipients: [testRecipient],
    });

    // Flip a byte in the payload (last byte)
    const tampered = new Uint8Array(container);
    tampered[tampered.length - 1]! ^= 0x01;

    expect(() =>
      ageDecrypt(ageCrypto, tampered, {
        identities: [testIdentity],
      }),
    ).toThrow();
  });

  it("refuses decryption with the wrong identity or wrong passphrase", () => {
    const plaintext = new TextEncoder().encode("Access control test");
    const container = ageEncrypt(ageCrypto, plaintext, {
      passphrase: "secret-password",
      scryptLogN: 10,
    });

    expect(() =>
      ageDecrypt(ageCrypto, container, {
        passphrase: "wrong-password",
      }),
    ).toThrow(/no matching identity or correct passphrase/i);
  });

  it("supports ASCII armor format", () => {
    const plaintext = new TextEncoder().encode("Armored age container text");
    const rawContainer = ageEncrypt(ageCrypto, plaintext, { recipients: [testRecipient] });
    const armored = armorAge(rawContainer);
    expect(isArmoredAge(armored)).toBe(true);
    const dearmored = dearmorAge(armored);
    expect(dearmored).toEqual(rawContainer);
    expect(dearmorAge(` \n${armored}\t`)).toEqual(rawContainer);
    expect(() => dearmorAge(`junk\n${armored}`)).toThrow(/missing begin or end markers/i);
    expect(() => dearmorAge(`${armored}junk`)).toThrow(/missing begin or end markers/i);
    expect(() => dearmorAge(armored.replace("\n", "\n\n"))).toThrow(/non-canonical/i);

    const op = ageOperation({
      recipient: testRecipient,
      identity: testIdentity,
      armor: true,
    });

    const armoredBytes = op.encrypt(plaintext);
    const armoredText = new TextDecoder().decode(armoredBytes);

    expect(isArmoredAge(armoredBytes)).toBe(true);
    expect(isArmoredAge(armoredText)).toBe(true);
    expect(armoredText).toContain("-----BEGIN AGE ENCRYPTED FILE-----");
    expect(armoredText).toContain("-----END AGE ENCRYPTED FILE-----");

    const decrypted = op.decrypt(armoredBytes);
    expect(new TextDecoder().decode(decrypted)).toBe("Armored age container text");
  });

  it("integrates seamlessly into computeCipher workbench execution", async () => {
    const spec = createSpec({ variant: "age" });
    spec.options["ageRecipient"] = testRecipient;
    spec.options["ageIdentity"] = testIdentity;
    spec.options["ageArmor"] = false;

    const input = new TextEncoder().encode("Workbench age execution test");
    const encRes = await computeCipher(spec, input);
    expect(encRes.error).toBeUndefined();
    expect(encRes.bytes).toBeDefined();

    // Verify fields
    const formatField = encRes.fields?.find((f) => f.label === "Container format");
    expect(formatField?.value).toBe("age-encryption.org/v1");

    // Decrypt direction
    const decSpec = {
      ...spec,
      options: {
        ...spec.options,
        direction: "decrypt",
      },
    };
    const decRes = await computeCipher(decSpec, encRes.bytes!);
    expect(decRes.error).toBeUndefined();
    expect(new TextDecoder().decode(decRes.bytes)).toBe("Workbench age execution test");
  });
});
