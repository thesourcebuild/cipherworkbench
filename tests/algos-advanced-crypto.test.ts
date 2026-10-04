import { describe, it, expect } from "vitest";
import {
  bls12381Keygen,
  bls12381Sign,
  bls12381Verify,
  bls12381AggregateSignatures,
  bls12381VerifyFastAggregate,
  bip340Keygen,
  bip340Sign,
  bip340Verify,
  hpkeKeygen,
  hpkeSeal,
  hpkeOpen,
  HPKE_KEM_X25519_SHA256,
  HPKE_KEM_P256_SHA256,
  HPKE_AEAD_CHACHA20_POLY1305,
  HPKE_AEAD_AES_128_GCM,
  HPKE_AEAD_AES_256_GCM,
} from "@ocs/algos";
import { computeAsymmetric } from "../packages/tools/asymmetric/src/compute";

describe("BLS12-381 (RFC 9380)", () => {
  it("generates 32-byte secret key and 48-byte G1 compressed public key", () => {
    const kp = bls12381Keygen();
    expect(kp.secretKey.length).toBe(32);
    expect(kp.publicKey.length).toBe(48);
  });

  it("signs message producing 96-byte G2 signature and verifies", () => {
    const kp = bls12381Keygen();
    const msg = new TextEncoder().encode("Antigravity BLS12-381 signature test");
    const sig = bls12381Sign(msg, kp.secretKey);
    expect(sig.length).toBe(96);

    const valid = bls12381Verify(sig, msg, kp.publicKey);
    expect(valid).toBe(true);

    const tamperedMsg = new TextEncoder().encode("Antigravity BLS12-381 tampered");
    expect(bls12381Verify(sig, tamperedMsg, kp.publicKey)).toBe(false);
  });

  it("aggregates multiple signatures across distinct signers", () => {
    const msg = new TextEncoder().encode("Consensus multi-sig payload");
    const kp1 = bls12381Keygen();
    const kp2 = bls12381Keygen();
    const kp3 = bls12381Keygen();

    const sig1 = bls12381Sign(msg, kp1.secretKey);
    const sig2 = bls12381Sign(msg, kp2.secretKey);
    const sig3 = bls12381Sign(msg, kp3.secretKey);

    const aggSig = bls12381AggregateSignatures([sig1, sig2, sig3]);
    expect(aggSig.length).toBe(96);

    const verified = bls12381VerifyFastAggregate(aggSig, msg, [kp1.publicKey, kp2.publicKey, kp3.publicKey]);
    expect(verified).toBe(true);

    // Tampered public key should fail
    const wrongKp = bls12381Keygen();
    expect(bls12381VerifyFastAggregate(aggSig, msg, [kp1.publicKey, wrongKp.publicKey, kp3.publicKey])).toBe(false);
  });

  it("computes through @ocs/asymmetric workbench definition", async () => {
    const genRes = await computeAsymmetric(
      { specVersion: 1, variant: "bls12-381", options: { operation: "generate" } },
      new Uint8Array(0),
    );
    expect(genRes.error).toBeUndefined();
    expect(genRes.bytes?.length).toBe(48);

    const skField = genRes.fields?.find((f) => f.label === "Secret key");
    const pkField = genRes.fields?.find((f) => f.label === "Public key (G1)");
    expect(skField).toBeDefined();
    expect(pkField).toBeDefined();

    const msg = new TextEncoder().encode("Workbench verification test");
    const signRes = await computeAsymmetric(
      {
        specVersion: 1,
        variant: "bls12-381",
        options: {
          operation: "sign",
          privateKey: skField!.value,
        },
      },
      msg,
    );
    expect(signRes.error).toBeUndefined();
    expect(signRes.bytes?.length).toBe(96);

    const verifyRes = await computeAsymmetric(
      {
        specVersion: 1,
        variant: "bls12-381",
        options: {
          operation: "verify",
          publicKey: pkField!.value,
          signature: Buffer.from(signRes.bytes!).toString("hex"),
        },
      },
      msg,
    );
    expect(verifyRes.error).toBeUndefined();
    expect(verifyRes.text).toBe("BLS SIGNATURE VALID");
  });
});

describe("BIP-340 Schnorr Signatures (secp256k1 Taproot)", () => {
  it("generates 32-byte secret key and 32-byte x-only public key", () => {
    const kp = bip340Keygen();
    expect(kp.secretKey.length).toBe(32);
    expect(kp.publicKey.length).toBe(32);
  });

  it("signs message producing 64-byte signature and verifies", () => {
    const kp = bip340Keygen();
    const msg = new TextEncoder().encode("Bitcoin Taproot BIP-340 Schnorr");
    const sig = bip340Sign(msg, kp.secretKey);
    expect(sig.length).toBe(64);

    const valid = bip340Verify(sig, msg, kp.publicKey);
    expect(valid).toBe(true);

    const tampered = new TextEncoder().encode("Bitcoin Taproot BIP-340 Schnorr (altered)");
    expect(bip340Verify(sig, tampered, kp.publicKey)).toBe(false);
  });

  it("computes through @ocs/asymmetric workbench definition", async () => {
    const genRes = await computeAsymmetric(
      { specVersion: 1, variant: "bip340-schnorr", options: { operation: "generate" } },
      new Uint8Array(0),
    );
    expect(genRes.error).toBeUndefined();
    expect(genRes.bytes?.length).toBe(32);

    const skField = genRes.fields?.find((f) => f.label === "Secret key");
    const pkField = genRes.fields?.find((f) => f.label === "Public key (x-only)");
    expect(skField).toBeDefined();
    expect(pkField).toBeDefined();

    const msg = new TextEncoder().encode("Schnorr workbench test");
    const signRes = await computeAsymmetric(
      {
        specVersion: 1,
        variant: "bip340-schnorr",
        options: {
          operation: "sign",
          privateKey: skField!.value,
        },
      },
      msg,
    );
    expect(signRes.error).toBeUndefined();
    expect(signRes.bytes?.length).toBe(64);

    const verifyRes = await computeAsymmetric(
      {
        specVersion: 1,
        variant: "bip340-schnorr",
        options: {
          operation: "verify",
          publicKey: pkField!.value,
          signature: Buffer.from(signRes.bytes!).toString("hex"),
        },
      },
      msg,
    );
    expect(verifyRes.error).toBeUndefined();
    expect(verifyRes.text).toBe("SCHNORR SIGNATURE VALID");
  });
});

describe("HPKE (RFC 9180)", () => {
  it("encapsulates and decapsulates across X25519 and ChaCha20-Poly1305", () => {
    const kpR = hpkeKeygen(HPKE_KEM_X25519_SHA256);
    const plaintext = new TextEncoder().encode("Secret HPKE payload for ECH/MLS");
    const info = new TextEncoder().encode("custom-protocol-v1");
    const aad = new TextEncoder().encode("authenticated-headers");

    const sealed = hpkeSeal({
      recipientPublicKey: kpR.publicKey,
      plaintext,
      info,
      aad,
      kemId: HPKE_KEM_X25519_SHA256,
      aeadId: HPKE_AEAD_CHACHA20_POLY1305,
    });

    expect(sealed.encapsulatedKey.length).toBe(32);
    expect(sealed.ciphertext.length).toBe(plaintext.length + 16);

    const opened = hpkeOpen({
      recipientSecretKey: kpR.secretKey,
      encapsulatedKey: sealed.encapsulatedKey,
      ciphertext: sealed.ciphertext,
      info,
      aad,
      kemId: HPKE_KEM_X25519_SHA256,
      aeadId: HPKE_AEAD_CHACHA20_POLY1305,
    });

    expect(Buffer.from(opened).toString("utf8")).toBe("Secret HPKE payload for ECH/MLS");
  });

  it("supports P-256 and AES-GCM suites", () => {
    const kpR = hpkeKeygen(HPKE_KEM_P256_SHA256);
    const plaintext = new TextEncoder().encode("NIST suite payload");

    const sealed = hpkeSeal({
      recipientPublicKey: kpR.publicKey,
      plaintext,
      kemId: HPKE_KEM_P256_SHA256,
      aeadId: HPKE_AEAD_AES_128_GCM,
    });

    expect(sealed.encapsulatedKey.length).toBe(65);
    expect(sealed.ciphertext.length).toBe(plaintext.length + 16);

    const opened = hpkeOpen({
      recipientSecretKey: kpR.secretKey,
      encapsulatedKey: sealed.encapsulatedKey,
      ciphertext: sealed.ciphertext,
      kemId: HPKE_KEM_P256_SHA256,
      aeadId: HPKE_AEAD_AES_128_GCM,
    });

    expect(Buffer.from(opened).toString("utf8")).toBe("NIST suite payload");
  });

  it("detects container tampering and decrypts from combined container bytes", () => {
    const kpR = hpkeKeygen(HPKE_KEM_X25519_SHA256);
    const plaintext = new TextEncoder().encode("Container-mode test");

    const sealed = hpkeSeal({
      recipientPublicKey: kpR.publicKey,
      plaintext,
      kemId: HPKE_KEM_X25519_SHA256,
      aeadId: HPKE_AEAD_AES_256_GCM,
    });

    // Valid container decryption
    const opened = hpkeOpen({
      recipientSecretKey: kpR.secretKey,
      container: sealed.container,
      kemId: HPKE_KEM_X25519_SHA256,
      aeadId: HPKE_AEAD_AES_256_GCM,
    });
    expect(Buffer.from(opened).toString("utf8")).toBe("Container-mode test");

    // Tampered container ciphertext byte
    const tampered = new Uint8Array(sealed.container);
    tampered[tampered.length - 1]! ^= 0x01;
    expect(() =>
      hpkeOpen({
        recipientSecretKey: kpR.secretKey,
        container: tampered,
        kemId: HPKE_KEM_X25519_SHA256,
        aeadId: HPKE_AEAD_AES_256_GCM,
      }),
    ).toThrow();
  });
});
