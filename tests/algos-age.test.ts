import { describe, it, expect } from "vitest";
import {
  formatAgeIdentity,
  formatAgeRecipient,
  parseAgeIdentity,
  parseAgeRecipient,
  ageEncrypt,
  ageDecrypt,
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
