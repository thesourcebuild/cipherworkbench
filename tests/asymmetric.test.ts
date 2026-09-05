import { describe, expect, it } from "vitest";
import {
  ASYMMETRIC_MANIFESTS,
  ASYMMETRIC_TOOLS,
  ECDH_CURVES,
  ECDSA_CURVES,
  matchingHashFor,
  OPTION_CURVE,
  OPTION_HASH,
  OPTION_MODULUS_LENGTH,
  OPTION_OAEP_LABEL,
  OPTION_OPERATION,
  OPTION_PARAM_SET,
  OPTION_PRIVATE_KEY,
  OPTION_PUBLIC_KEY,
  OPTION_SCHEME,
  DEFAULT_PARAM_SETS,
  PQ_PARAM_SETS,
  OPTION_SIGNATURE,
  OPTION_SIGNATURE_FORMAT,
  requireAsymmetricTool,
  type AsymmetricSpec,
} from "@ocs/asymmetric";
import {
  acceptedPublicKeyLengths,
  applyAllFixes,
  asymmetricCatalogueFor,
  asymmetricToolDefinition,
  createSpec,
  decodePem,
  describeSpec,
  lint,
  resolveAsymmetric,
} from "@ocs/asymmetric/definition";
import { encodeHex, validateCatalogue } from "@ocs/engine";

const ascii = (text: string) => new TextEncoder().encode(text);
const fromHex = (hex: string) =>
  hex === ""
    ? new Uint8Array(0)
    : Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));

function specFor(variant: string, options: AsymmetricSpec["options"] = {}): AsymmetricSpec {
  const base = createSpec({ variant });
  return { ...base, options: { ...base.options, ...options } };
}

async function run(
  variant: string,
  options: AsymmetricSpec["options"],
  input: Uint8Array = new Uint8Array(0),
) {
  const tool = asymmetricToolDefinition(variant);
  const result = await tool.compute(specFor(variant, options), input);
  expect(result.error, `${variant} reported: ${result.error}`).toBeUndefined();
  return result;
}

/** A raw key option as its `bytes` control stores it: the text plus its encoding. */
function keys(privateHex?: string, publicHex?: string): AsymmetricSpec["options"] {
  return {
    ...(privateHex === undefined
      ? {}
      : { [OPTION_PRIVATE_KEY]: privateHex, privateKeyEncoding: "hex" }),
    ...(publicHex === undefined
      ? {}
      : { [OPTION_PUBLIC_KEY]: publicHex, publicKeyEncoding: "hex" }),
  };
}

// ── Ed25519: RFC 8032 section 7.1 ───────────────────────────────────────────

/**
 * The four published vectors, and the reason this file exists.
 *
 * A round-trip test — sign then verify — passes for an implementation that is wrong in exactly
 * the same way twice, which is not a hypothetical: the first version of this family hashed the
 * message before handing it to noble's ECDSA, which hashes by default, and every round-trip
 * test passed while the output matched nothing else in the world. Published vectors are what
 * caught it.
 */
const RFC8032 = [
  {
    name: "TEST 1 — empty message",
    secret: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    message: "",
    signature:
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  },
  {
    name: "TEST 2 — one byte",
    secret: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    message: "72",
    signature:
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  },
  {
    name: "TEST 3 — two bytes",
    secret: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    message: "af82",
    signature:
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  },
] as const;

describe("Ed25519 — RFC 8032 test vectors", () => {
  for (const vector of RFC8032) {
    it(`${vector.name}: signs to the published value`, async () => {
      const result = await run(
        "ed25519",
        { [OPTION_OPERATION]: "sign", ...keys(vector.secret) },
        fromHex(vector.message),
      );
      expect(encodeHex(result.bytes!)).toBe(vector.signature);
    });

    it(`${vector.name}: derives the published public key`, async () => {
      const result = await run(
        "ed25519",
        { [OPTION_OPERATION]: "sign", ...keys(vector.secret) },
        fromHex(vector.message),
      );
      const field = result.fields!.find((f) => f.label === "Public key");
      expect(field?.value).toBe(vector.public);
    });

    it(`${vector.name}: verifies against the published public key`, async () => {
      const result = await run(
        "ed25519",
        {
          [OPTION_OPERATION]: "verify",
          ...keys(undefined, vector.public),
          [OPTION_SIGNATURE]: vector.signature,
          signatureEncoding: "hex",
        },
        fromHex(vector.message),
      );
      expect(result.text).toBe("MATCH");
    });

    it(`${vector.name}: rejects the signature over a different message`, async () => {
      const result = await run(
        "ed25519",
        {
          [OPTION_OPERATION]: "verify",
          ...keys(undefined, vector.public),
          [OPTION_SIGNATURE]: vector.signature,
          signatureEncoding: "hex",
        },
        ascii("something else"),
      );
      expect(result.text).toBe("NO MATCH");
    });
  }

  it("rejects a signature with a single bit flipped", async () => {
    const vector = RFC8032[1];
    const tampered = fromHex(vector.signature);
    tampered[10] = (tampered[10] ?? 0) ^ 1;
    const result = await run(
      "ed25519",
      {
        [OPTION_OPERATION]: "verify",
        ...keys(undefined, vector.public),
        [OPTION_SIGNATURE]: encodeHex(tampered),
        signatureEncoding: "hex",
      },
      fromHex(vector.message),
    );
    expect(result.text).toBe("NO MATCH");
  });
});

// ── ECDSA: RFC 6979 deterministic vectors ───────────────────────────────────

/**
 * RFC 6979 appendix A.2.5 — P-256, SHA-256, over the message "sample".
 *
 * This is the vector that caught the double-hashing bug described above, and it also pins the
 * low-S decision: noble normalises s by default, and with normalisation on, s comes back as
 * n - s and does not match the RFC. Both values are valid signatures over the same message,
 * which is the point — an ECDSA signature is not a unique value.
 */
const RFC6979_P256 = {
  secret: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  // Ux ‖ Uy from the RFC, as an uncompressed point.
  publicUncompressed:
    "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
  message: "sample",
  r: "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
  s: "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
} as const;

describe("ECDSA — RFC 6979 appendix A.2.5", () => {
  it('P-256 with SHA-256 over "sample" gives the published (r, s)', async () => {
    const result = await run(
      "ecdsa",
      {
        [OPTION_OPERATION]: "sign",
        [OPTION_CURVE]: "p256",
        [OPTION_HASH]: "SHA-256",
        [OPTION_SIGNATURE_FORMAT]: "compact",
        ...keys(RFC6979_P256.secret),
      },
      ascii(RFC6979_P256.message),
    );
    expect(encodeHex(result.bytes!)).toBe(RFC6979_P256.r + RFC6979_P256.s);
  });

  it("is deterministic — the same input signs to the same bytes twice", async () => {
    const options = {
      [OPTION_OPERATION]: "sign",
      [OPTION_CURVE]: "p256",
      [OPTION_HASH]: "SHA-256",
      ...keys(RFC6979_P256.secret),
    };
    const first = await run("ecdsa", options, ascii("sample"));
    const second = await run("ecdsa", options, ascii("sample"));
    expect(encodeHex(second.bytes!)).toBe(encodeHex(first.bytes!));
  });

  it("derives the RFC's public key from the RFC's private key", async () => {
    const result = await run(
      "ecdsa",
      { [OPTION_OPERATION]: "sign", [OPTION_CURVE]: "p256", ...keys(RFC6979_P256.secret) },
      ascii("sample"),
    );
    const field = result.fields!.find((f) => f.label === "Public key");
    // Ours is compressed; the RFC prints the affine coordinates.
    expect(field?.value).toBe("03" + RFC6979_P256.publicUncompressed.slice(2, 66));
  });

  it("verifies the published signature against the RFC's uncompressed public key", async () => {
    const result = await run(
      "ecdsa",
      {
        [OPTION_OPERATION]: "verify",
        [OPTION_CURVE]: "p256",
        [OPTION_HASH]: "SHA-256",
        [OPTION_SIGNATURE_FORMAT]: "compact",
        ...keys(undefined, RFC6979_P256.publicUncompressed),
        [OPTION_SIGNATURE]: RFC6979_P256.r + RFC6979_P256.s,
        signatureEncoding: "hex",
      },
      ascii(RFC6979_P256.message),
    );
    expect(result.text).toBe("MATCH");
    // The RFC's own s is above n/2, so this is the case the report must call out.
    expect(result.fields!.find((f) => f.label === "Canonical")?.value).toContain("high S");
  });

  it("accepts a high-S signature rather than calling it invalid", async () => {
    // Same assertion as above, stated as the property it protects: a valid signature is never
    // reported as a mismatch merely for being non-canonical.
    const result = await run(
      "ecdsa",
      {
        [OPTION_OPERATION]: "verify",
        [OPTION_CURVE]: "p256",
        ...keys(undefined, RFC6979_P256.publicUncompressed),
        [OPTION_SIGNATURE]: RFC6979_P256.r + RFC6979_P256.s,
        signatureEncoding: "hex",
      },
      ascii("sample"),
    );
    expect(result.text).not.toBe("NO MATCH");
  });
});

// ── ECDSA: the other three curves, and the two signature formats ────────────

describe("ECDSA — curves and formats", () => {
  for (const curve of ECDSA_CURVES) {
    it(`${curve.label} round-trips, with the documented key and signature sizes`, async () => {
      const generated = await run("ecdsa", {
        [OPTION_OPERATION]: "generate",
        [OPTION_CURVE]: curve.id,
      });
      const secret = generated.fields!.find((f) => f.label === "Private key")!.value;
      const publicKey = generated.fields!.find((f) => f.label === "Public key")!.value;

      expect(secret.length / 2).toBe(curve.secretLen);
      expect(publicKey.length / 2).toBe(curve.publicLen);

      const hash = matchingHashFor(curve.id);
      const signed = await run(
        "ecdsa",
        {
          [OPTION_OPERATION]: "sign",
          [OPTION_CURVE]: curve.id,
          [OPTION_HASH]: hash,
          [OPTION_SIGNATURE_FORMAT]: "compact",
          ...keys(secret),
        },
        ascii("a message"),
      );
      expect(signed.bytes!.length).toBe(curve.signatureLen);

      const verified = await run(
        "ecdsa",
        {
          [OPTION_OPERATION]: "verify",
          [OPTION_CURVE]: curve.id,
          [OPTION_HASH]: hash,
          [OPTION_SIGNATURE_FORMAT]: "compact",
          ...keys(undefined, publicKey),
          [OPTION_SIGNATURE]: encodeHex(signed.bytes!),
          signatureEncoding: "hex",
        },
        ascii("a message"),
      );
      expect(verified.text).toBe("MATCH");
    });
  }

  it("normalises s to low-S for secp256k1 and leaves it alone for P-256", async () => {
    // The RFC 6979 P-256 vector has a high s; the same key and message over secp256k1 must not.
    const signed = await run(
      "ecdsa",
      {
        [OPTION_OPERATION]: "sign",
        [OPTION_CURVE]: "secp256k1",
        [OPTION_HASH]: "SHA-256",
        ...keys(RFC6979_P256.secret),
      },
      ascii("sample"),
    );
    expect(signed.fields!.find((f) => f.label === "Malleability")?.value).toContain("low-S");

    const verified = await run(
      "ecdsa",
      {
        [OPTION_OPERATION]: "verify",
        [OPTION_CURVE]: "secp256k1",
        [OPTION_HASH]: "SHA-256",
        ...keys(RFC6979_P256.secret),
        [OPTION_SIGNATURE]: encodeHex(signed.bytes!),
        signatureEncoding: "hex",
      },
      ascii("sample"),
    );
    expect(verified.fields!.find((f) => f.label === "Canonical")?.value).toContain("low S");
  });

  it("DER form is longer than compact and verifies as DER", async () => {
    const options = {
      [OPTION_CURVE]: "p256",
      [OPTION_HASH]: "SHA-256",
      ...keys(RFC6979_P256.secret),
    };
    const compact = await run(
      "ecdsa",
      { ...options, [OPTION_OPERATION]: "sign", [OPTION_SIGNATURE_FORMAT]: "compact" },
      ascii("sample"),
    );
    const der = await run(
      "ecdsa",
      { ...options, [OPTION_OPERATION]: "sign", [OPTION_SIGNATURE_FORMAT]: "der" },
      ascii("sample"),
    );
    expect(der.bytes!.length).toBeGreaterThan(compact.bytes!.length);
    // 0x30 SEQUENCE, then the length byte.
    expect(der.bytes![0]).toBe(0x30);

    const verified = await run(
      "ecdsa",
      {
        ...options,
        [OPTION_OPERATION]: "verify",
        [OPTION_SIGNATURE_FORMAT]: "der",
        [OPTION_SIGNATURE]: encodeHex(der.bytes!),
        signatureEncoding: "hex",
      },
      ascii("sample"),
    );
    expect(verified.text).toBe("MATCH");
  });

  it("refuses a compact signature of the wrong length before trying to verify it", () => {
    const result = resolveAsymmetric(
      specFor("ecdsa", {
        [OPTION_OPERATION]: "verify",
        [OPTION_CURVE]: "p256",
        [OPTION_SIGNATURE_FORMAT]: "compact",
        ...keys(undefined, RFC6979_P256.publicUncompressed),
        // A DER signature pasted while the format says compact — the likeliest mistake.
        [OPTION_SIGNATURE]: "30" + "44".repeat(35),
        signatureEncoding: "hex",
      }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.problem).toContain("DER");
  });
});

// ── ECDH ────────────────────────────────────────────────────────────────────

/** RFC 7748 section 6.1 — the X25519 example exchange. */
const RFC7748 = {
  alicePrivate: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  alicePublic: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  bobPrivate: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  bobPublic: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  shared: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
} as const;

describe("ECDH — RFC 7748 section 6.1", () => {
  it("Alice's private key derives her published public key", async () => {
    const result = await run("ecdh", {
      [OPTION_OPERATION]: "derive",
      [OPTION_CURVE]: "x25519",
      ...keys(RFC7748.alicePrivate, RFC7748.bobPublic),
    });
    expect(encodeHex(result.bytes!)).toBe(RFC7748.shared);
  });

  it("reaches the same secret from Bob's side", async () => {
    const result = await run("ecdh", {
      [OPTION_OPERATION]: "derive",
      [OPTION_CURVE]: "x25519",
      ...keys(RFC7748.bobPrivate, RFC7748.alicePublic),
    });
    expect(encodeHex(result.bytes!)).toBe(RFC7748.shared);
  });

  it("says the shared secret needs a KDF", async () => {
    const result = await run("ecdh", {
      [OPTION_OPERATION]: "derive",
      [OPTION_CURVE]: "x25519",
      ...keys(RFC7748.alicePrivate, RFC7748.bobPublic),
    });
    expect(result.fields!.some((f) => f.value.includes("HKDF"))).toBe(true);

    const diagnostics = lint(
      specFor("ecdh", {
        [OPTION_OPERATION]: "derive",
        [OPTION_CURVE]: "x25519",
        ...keys(RFC7748.alicePrivate, RFC7748.bobPublic),
      }),
    );
    expect(diagnostics.diagnostics.map((d) => d.code)).toContain("A005");
  });

  it("rejects an all-zero X25519 public key rather than returning a zero secret", async () => {
    const tool = asymmetricToolDefinition("ecdh");
    const result = await tool.compute(
      specFor("ecdh", {
        [OPTION_OPERATION]: "derive",
        [OPTION_CURVE]: "x25519",
        ...keys(RFC7748.alicePrivate, "00".repeat(32)),
      }),
      new Uint8Array(0),
    );
    expect(result.error).toBeDefined();
    expect(result.error).toContain("low-order");
  });

  for (const curve of ECDH_CURVES) {
    it(`${curve.label} agrees between two generated keypairs`, async () => {
      const a = await run("ecdh", { [OPTION_OPERATION]: "generate", [OPTION_CURVE]: curve.id });
      const b = await run("ecdh", { [OPTION_OPERATION]: "generate", [OPTION_CURVE]: curve.id });
      const aPriv = a.fields!.find((f) => f.label === "Private key")!.value;
      const aPub = a.fields!.find((f) => f.label === "Public key")!.value;
      const bPriv = b.fields!.find((f) => f.label === "Private key")!.value;
      const bPub = b.fields!.find((f) => f.label === "Public key")!.value;

      const first = await run("ecdh", {
        [OPTION_OPERATION]: "derive",
        [OPTION_CURVE]: curve.id,
        ...keys(aPriv, bPub),
      });
      const second = await run("ecdh", {
        [OPTION_OPERATION]: "derive",
        [OPTION_CURVE]: curve.id,
        ...keys(bPriv, aPub),
      });
      expect(encodeHex(second.bytes!)).toBe(encodeHex(first.bytes!));
      // The x-coordinate alone, so the length is the field size and not the compressed point.
      expect(first.bytes!.length).toBe(curve.secretLen);
    });
  }

  it("refuses to derive without the other party's public key", () => {
    const result = resolveAsymmetric(
      specFor("ecdh", {
        [OPTION_OPERATION]: "derive",
        [OPTION_CURVE]: "x25519",
        ...keys(RFC7748.alicePrivate),
      }),
    );
    expect(result.ok).toBe(false);
    // Specifically: it must not quietly fall back to our own public key.
    if (!result.ok) expect(result.problem).toContain("share with no one");
  });
});

// ── RSA ─────────────────────────────────────────────────────────────────────

/**
 * One 2048-bit keypair for the whole RSA suite.
 *
 * Generation is the slowest thing in this file by two orders of magnitude, and there is no
 * published RSA keypair to use instead — RSA vectors come as raw moduli and exponents, which
 * WebCrypto cannot import without wrapping them in DER first. So the properties tested below
 * are round-trips and sizes rather than fixed values, and the fixed-value assurance for this
 * family comes from Ed25519, ECDSA and ECDH above.
 */
let cachedKey:
  Promise<{ privatePem: string; publicPem: string; privateJwk: string }> | undefined;

function rsaKey() {
  cachedKey ??= (async () => {
    const generated = await run("rsa", {
      [OPTION_OPERATION]: "generate",
      [OPTION_MODULUS_LENGTH]: "2048",
    });
    const field = (label: string) => generated.fields!.find((f) => f.label === label)!.value;
    return {
      privatePem: field("Private key (PKCS#8 PEM)"),
      publicPem: field("Public key (SPKI PEM)"),
      privateJwk: field("Private key (JWK)"),
    };
  })();
  return cachedKey;
}

describe("RSA — key generation", () => {
  it("exports a PKCS#8 private key and an SPKI public key, both parseable", async () => {
    const key = await rsaKey();

    const priv = decodePem(key.privatePem);
    expect(priv.ok).toBe(true);
    if (priv.ok) expect(priv.block.label).toBe("PRIVATE KEY");

    const pub = decodePem(key.publicPem);
    expect(pub.ok).toBe(true);
    if (pub.ok) {
      expect(pub.block.label).toBe("PUBLIC KEY");
      // 294 bytes is the fixed size of a 2048-bit RSA SPKI with exponent 65537.
      expect(pub.block.der.length).toBe(294);
    }
  });

  it("marks the private key secret and the public key not", async () => {
    const generated = await run("rsa", {
      [OPTION_OPERATION]: "generate",
      [OPTION_MODULUS_LENGTH]: "2048",
    });
    const priv = generated.fields!.find((f) => f.label === "Private key (PKCS#8 PEM)");
    const pub = generated.fields!.find((f) => f.label === "Public key (SPKI PEM)");
    expect(priv?.secret).toBe(true);
    expect(pub?.secret).toBeUndefined();
  });

  it("uses 65537 as the public exponent", async () => {
    const generated = await run("rsa", {
      [OPTION_OPERATION]: "generate",
      [OPTION_MODULUS_LENGTH]: "2048",
    });
    expect(generated.fields!.find((f) => f.label === "Public exponent")?.value).toBe("65537");
  });

  it("supports generating 512-bit and 1024-bit legacy keypairs and signing/verifying with them", async () => {
    for (const bits of [512, 1024] as const) {
      const generated = await run("rsa", {
        [OPTION_OPERATION]: "generate",
        [OPTION_MODULUS_LENGTH]: String(bits),
      });
      expect(generated.text).toContain("-----BEGIN PRIVATE KEY-----");
      expect(generated.text).toContain("-----BEGIN PUBLIC KEY-----");
      expect(generated.fields!.find((f) => f.label === "Key size")?.value).toBe(`${bits} bits`);

      const privPem = generated.fields!.find((f) => f.label === "Private key (PKCS#8 PEM)")!.value;
      const pubPem = generated.fields!.find((f) => f.label === "Public key (SPKI PEM)")!.value;

      const priv = decodePem(privPem);
      const pub = decodePem(pubPem);
      expect(priv.ok, `${bits}-bit private PEM`).toBe(true);
      expect(pub.ok, `${bits}-bit public PEM`).toBe(true);

      const signed = await run(
        "rsa",
        {
          [OPTION_OPERATION]: "sign",
          [OPTION_SCHEME]: "pkcs1v15",
          [OPTION_HASH]: "SHA-256",
          [OPTION_PRIVATE_KEY]: privPem,
        },
        ascii("legacy test"),
      );
      expect(signed.bytes!.length).toBe(bits / 8);

      const verified = await run(
        "rsa",
        {
          [OPTION_OPERATION]: "verify",
          [OPTION_SCHEME]: "pkcs1v15",
          [OPTION_HASH]: "SHA-256",
          [OPTION_PUBLIC_KEY]: pubPem,
          [OPTION_SIGNATURE]: encodeHex(signed.bytes!),
          signatureEncoding: "hex",
        },
        ascii("legacy test"),
      );
      expect(verified.text).toBe("MATCH");
    }
  });
});

describe("RSA — signatures", () => {
  it("PSS signs to the modulus length and verifies", async () => {
    const key = await rsaKey();
    const signed = await run(
      "rsa",
      {
        [OPTION_OPERATION]: "sign",
        [OPTION_SCHEME]: "pss",
        [OPTION_HASH]: "SHA-256",
        [OPTION_PRIVATE_KEY]: key.privatePem,
      },
      ascii("attack at dawn"),
    );
    expect(signed.bytes!.length).toBe(256);

    const verified = await run(
      "rsa",
      {
        [OPTION_OPERATION]: "verify",
        [OPTION_SCHEME]: "pss",
        [OPTION_HASH]: "SHA-256",
        [OPTION_PUBLIC_KEY]: key.publicPem,
        [OPTION_SIGNATURE]: encodeHex(signed.bytes!),
        signatureEncoding: "hex",
      },
      ascii("attack at dawn"),
    );
    expect(verified.text).toBe("MATCH");
  });

  it("PSS is randomised — two signatures over one message differ and both verify", async () => {
    const key = await rsaKey();
    const options = {
      [OPTION_OPERATION]: "sign",
      [OPTION_SCHEME]: "pss",
      [OPTION_PRIVATE_KEY]: key.privatePem,
    };
    const first = await run("rsa", options, ascii("same message"));
    const second = await run("rsa", options, ascii("same message"));
    expect(encodeHex(second.bytes!)).not.toBe(encodeHex(first.bytes!));

    for (const signature of [first.bytes!, second.bytes!]) {
      const verified = await run(
        "rsa",
        {
          [OPTION_OPERATION]: "verify",
          [OPTION_SCHEME]: "pss",
          [OPTION_PUBLIC_KEY]: key.publicPem,
          [OPTION_SIGNATURE]: encodeHex(signature),
          signatureEncoding: "hex",
        },
        ascii("same message"),
      );
      expect(verified.text).toBe("MATCH");
    }
  });

  it("PKCS#1 v1.5 is deterministic", async () => {
    const key = await rsaKey();
    const options = {
      [OPTION_OPERATION]: "sign",
      [OPTION_SCHEME]: "pkcs1v15",
      [OPTION_PRIVATE_KEY]: key.privatePem,
    };
    const first = await run("rsa", options, ascii("same message"));
    const second = await run("rsa", options, ascii("same message"));
    expect(encodeHex(second.bytes!)).toBe(encodeHex(first.bytes!));
  });

  it("a PSS signature does not verify as PKCS#1 v1.5", async () => {
    const key = await rsaKey();
    const signed = await run(
      "rsa",
      {
        [OPTION_OPERATION]: "sign",
        [OPTION_SCHEME]: "pss",
        [OPTION_PRIVATE_KEY]: key.privatePem,
      },
      ascii("hello"),
    );
    const verified = await run(
      "rsa",
      {
        [OPTION_OPERATION]: "verify",
        [OPTION_SCHEME]: "pkcs1v15",
        [OPTION_PUBLIC_KEY]: key.publicPem,
        [OPTION_SIGNATURE]: encodeHex(signed.bytes!),
        signatureEncoding: "hex",
      },
      ascii("hello"),
    );
    expect(verified.text).toBe("NO MATCH");
  });

  it("takes the public key from the private one when the field is empty", async () => {
    const key = await rsaKey();
    const signed = await run(
      "rsa",
      { [OPTION_OPERATION]: "sign", [OPTION_PRIVATE_KEY]: key.privatePem },
      ascii("hello"),
    );
    const verified = await run(
      "rsa",
      {
        [OPTION_OPERATION]: "verify",
        [OPTION_PRIVATE_KEY]: key.privatePem,
        [OPTION_SIGNATURE]: encodeHex(signed.bytes!),
        signatureEncoding: "hex",
      },
      ascii("hello"),
    );
    expect(verified.text).toBe("MATCH");
    expect(verified.fields!.some((f) => f.value === "Taken from the private key")).toBe(true);
  });

  it("accepts a JWK private key as well as a PEM one", async () => {
    const key = await rsaKey();
    const fromPem = await run(
      "rsa",
      {
        [OPTION_OPERATION]: "sign",
        [OPTION_SCHEME]: "pkcs1v15",
        [OPTION_PRIVATE_KEY]: key.privatePem,
      },
      ascii("hello"),
    );
    const fromJwk = await run(
      "rsa",
      {
        [OPTION_OPERATION]: "sign",
        [OPTION_SCHEME]: "pkcs1v15",
        [OPTION_PRIVATE_KEY]: key.privateJwk,
      },
      ascii("hello"),
    );
    // PKCS#1 v1.5 is deterministic, so the two forms of one key must agree byte for byte.
    expect(encodeHex(fromJwk.bytes!)).toBe(encodeHex(fromPem.bytes!));
  });

  it("rejects a signature over a different message", async () => {
    const key = await rsaKey();
    const signed = await run(
      "rsa",
      { [OPTION_OPERATION]: "sign", [OPTION_PRIVATE_KEY]: key.privatePem },
      ascii("hello"),
    );
    const verified = await run(
      "rsa",
      {
        [OPTION_OPERATION]: "verify",
        [OPTION_PUBLIC_KEY]: key.publicPem,
        [OPTION_SIGNATURE]: encodeHex(signed.bytes!),
        signatureEncoding: "hex",
      },
      ascii("hellp"),
    );
    expect(verified.text).toBe("NO MATCH");
  });
});

describe("RSA — OAEP encryption", () => {
  it("round-trips a 32-byte key", async () => {
    const key = await rsaKey();
    const secret = fromHex("ab".repeat(32));
    const encrypted = await run(
      "rsa",
      { [OPTION_OPERATION]: "encrypt", [OPTION_PUBLIC_KEY]: key.publicPem },
      secret,
    );
    expect(encrypted.bytes!.length).toBe(256);

    const decrypted = await run(
      "rsa",
      { [OPTION_OPERATION]: "decrypt", [OPTION_PRIVATE_KEY]: key.privatePem },
      encrypted.bytes!,
    );
    expect(encodeHex(decrypted.bytes!)).toBe(encodeHex(secret));
  });

  it("is randomised — the same plaintext gives different ciphertexts", async () => {
    const key = await rsaKey();
    const options = { [OPTION_OPERATION]: "encrypt", [OPTION_PUBLIC_KEY]: key.publicPem };
    const first = await run("rsa", options, ascii("same"));
    const second = await run("rsa", options, ascii("same"));
    expect(encodeHex(second.bytes!)).not.toBe(encodeHex(first.bytes!));
  });

  it("carries 190 bytes with SHA-256 and refuses 191, naming hybrid encryption", async () => {
    const key = await rsaKey();
    const tool = asymmetricToolDefinition("rsa");
    const options = {
      [OPTION_OPERATION]: "encrypt",
      [OPTION_HASH]: "SHA-256",
      [OPTION_PUBLIC_KEY]: key.publicPem,
    };

    const atLimit = await run("rsa", options, new Uint8Array(190));
    expect(atLimit.bytes!.length).toBe(256);

    const overLimit = await tool.compute(specFor("rsa", options), new Uint8Array(191));
    expect(overLimit.error).toContain("190");
    expect(overLimit.error).toContain("AES");
  });

  it("a label bound at encryption is required at decryption", async () => {
    const key = await rsaKey();
    const tool = asymmetricToolDefinition("rsa");
    const encrypted = await run(
      "rsa",
      {
        [OPTION_OPERATION]: "encrypt",
        [OPTION_PUBLIC_KEY]: key.publicPem,
        [OPTION_OAEP_LABEL]: "session-42",
        oaepLabelEncoding: "utf-8",
      },
      ascii("secret"),
    );

    const withLabel = await run(
      "rsa",
      {
        [OPTION_OPERATION]: "decrypt",
        [OPTION_PRIVATE_KEY]: key.privatePem,
        [OPTION_OAEP_LABEL]: "session-42",
        oaepLabelEncoding: "utf-8",
      },
      encrypted.bytes!,
    );
    expect(new TextDecoder().decode(withLabel.bytes!)).toBe("secret");

    const withoutLabel = await tool.compute(
      specFor("rsa", {
        [OPTION_OPERATION]: "decrypt",
        [OPTION_PRIVATE_KEY]: key.privatePem,
      }),
      encrypted.bytes!,
    );
    expect(withoutLabel.error).toContain("label");
  });

  it("refuses a ciphertext that is not the modulus length", async () => {
    const key = await rsaKey();
    const tool = asymmetricToolDefinition("rsa");
    const result = await tool.compute(
      specFor("rsa", { [OPTION_OPERATION]: "decrypt", [OPTION_PRIVATE_KEY]: key.privatePem }),
      new Uint8Array(200),
    );
    expect(result.error).toContain("256 bytes");
  });

  it("a tampered ciphertext fails without saying which part was wrong", async () => {
    const key = await rsaKey();
    const tool = asymmetricToolDefinition("rsa");
    const encrypted = await run(
      "rsa",
      { [OPTION_OPERATION]: "encrypt", [OPTION_PUBLIC_KEY]: key.publicPem },
      ascii("secret"),
    );
    const tampered = Uint8Array.from(encrypted.bytes!);
    tampered[100] = (tampered[100] ?? 0) ^ 1;

    const result = await tool.compute(
      specFor("rsa", { [OPTION_OPERATION]: "decrypt", [OPTION_PRIVATE_KEY]: key.privatePem }),
      tampered,
    );
    expect(result.error).toBeDefined();
    // The padding-oracle point: no detail about which of the causes it was.
    expect(result.error).toContain("does not report which");
  });
});

// ── Key parsing: the errors that have to be specific ────────────────────────

describe("PEM and JWK parsing", () => {
  it("names PKCS#1 and the conversion command for an RSA PRIVATE KEY block", () => {
    const result = decodePem(
      "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj3\n-----END RSA PRIVATE KEY-----",
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("PKCS#1");
      expect(result.error).toContain("openssl pkcs8 -topk8");
    }
  });

  it("says a key is passphrase-encrypted rather than unparseable", () => {
    const result = decodePem(
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBOBgkq\n-----END ENCRYPTED PRIVATE KEY-----",
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("passphrase");
  });

  it("notices mismatched BEGIN and END labels", () => {
    const result = decodePem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PRIVATE KEY-----");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("disagree");
  });

  it("tolerates the whitespace pasted PEM picks up", async () => {
    const key = await rsaKey();
    const mangled = `\n\n  ${key.publicPem.replace(/\n/g, "\n   ")}  \n`;
    const strict = decodePem(key.publicPem);
    const loose = decodePem(mangled);
    expect(loose.ok).toBe(true);
    if (strict.ok && loose.ok) {
      expect(encodeHex(loose.block.der)).toBe(encodeHex(strict.block.der));
    }
  });

  it("points an EC JWK at the right tool instead of failing obscurely", async () => {
    const tool = asymmetricToolDefinition("rsa");
    const result = await tool.compute(
      specFor("rsa", {
        [OPTION_OPERATION]: "sign",
        [OPTION_PRIVATE_KEY]: '{"kty":"EC","crv":"P-256","d":"aaa","x":"bbb","y":"ccc"}',
      }),
      ascii("hello"),
    );
    expect(result.error).toContain("ECDSA");
  });

  it("refuses a public JWK where a private key is needed", async () => {
    const tool = asymmetricToolDefinition("rsa");
    const result = await tool.compute(
      specFor("rsa", {
        [OPTION_OPERATION]: "sign",
        [OPTION_PRIVATE_KEY]: '{"kty":"RSA","n":"abc","e":"AQAB"}',
      }),
      ascii("hello"),
    );
    expect(result.error).toContain("d member");
  });

  it("refuses something that is neither PEM nor JSON at resolve time", () => {
    const result = resolveAsymmetric(
      specFor("rsa", { [OPTION_OPERATION]: "sign", [OPTION_PRIVATE_KEY]: "hunter2" }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.optionId).toBe(OPTION_PRIVATE_KEY);
  });
});

// ── Lint rules ──────────────────────────────────────────────────────────────

describe("lint rules", () => {
  it("A002 fires on SHA-1 and its fix silences it", () => {
    const spec = specFor("ecdsa", {
      [OPTION_OPERATION]: "sign",
      [OPTION_HASH]: "SHA-1",
      ...keys(RFC6979_P256.secret),
    });
    const before = lint(spec).diagnostics.find((d) => d.code === "A002");
    expect(before?.level).toBe("insecure");
    expect(lint(applyAllFixes(spec)).diagnostics.some((d) => d.code === "A002")).toBe(false);
  });

  it("A003 fires on PKCS#1 v1.5 signing but not on verifying", async () => {
    const key = await rsaKey();
    const signing = specFor("rsa", {
      [OPTION_OPERATION]: "sign",
      [OPTION_SCHEME]: "pkcs1v15",
      [OPTION_PRIVATE_KEY]: key.privatePem,
    });
    expect(lint(signing).diagnostics.some((d) => d.code === "A003")).toBe(true);

    const verifying = specFor("rsa", {
      [OPTION_OPERATION]: "verify",
      [OPTION_SCHEME]: "pkcs1v15",
      [OPTION_PUBLIC_KEY]: key.publicPem,
      [OPTION_SIGNATURE]: "00".repeat(256),
      signatureEncoding: "hex",
    });
    expect(lint(verifying).diagnostics.some((d) => d.code === "A003")).toBe(false);
  });

  it("A004 fires when the hash is smaller than the curve, and its fix matches them", () => {
    const spec = specFor("ecdsa", {
      [OPTION_OPERATION]: "sign",
      [OPTION_CURVE]: "p521",
      [OPTION_HASH]: "SHA-256",
      ...keys("11".repeat(66)),
    });
    const diagnostic = lint(spec).diagnostics.find((d) => d.code === "A004");
    expect(diagnostic?.message).toContain("P-521");

    const fixed = applyAllFixes(spec);
    expect(lint(fixed).diagnostics.some((d) => d.code === "A004")).toBe(false);
    expect(String(fixed.options[OPTION_HASH])).toBe(matchingHashFor("p521"));
  });

  it("A004 stays quiet when the hash matches the curve", () => {
    for (const curve of ECDSA_CURVES) {
      const spec = specFor("ecdsa", {
        [OPTION_OPERATION]: "sign",
        [OPTION_CURVE]: curve.id,
        [OPTION_HASH]: matchingHashFor(curve.id),
        ...keys("11".repeat(curve.secretLen)),
      });
      expect(
        lint(spec).diagnostics.some((d) => d.code === "A004"),
        `A004 fired for ${curve.label} with ${matchingHashFor(curve.id)}`,
      ).toBe(false);
    }
  });

  it("A006 explains the OAEP ceiling before an attempt is made", async () => {
    const key = await rsaKey();
    const spec = specFor("rsa", {
      [OPTION_OPERATION]: "encrypt",
      [OPTION_HASH]: "SHA-256",
      [OPTION_PUBLIC_KEY]: key.publicPem,
    });
    const diagnostic = lint(spec).diagnostics.find((d) => d.code === "A006");
    expect(diagnostic?.message).toContain("190");
  });

  it("A007 warns that a generated key is not stored, for every tool", () => {
    for (const tool of ASYMMETRIC_TOOLS) {
      const spec = specFor(tool.id, { [OPTION_OPERATION]: "generate" });
      expect(
        lint(spec).diagnostics.some((d) => d.code === "A007"),
        `A007 missing for ${tool.id}`,
      ).toBe(true);
    }
  });

  it("applyAllFixes always leaves a spec the resolver accepts", () => {
    const specs = [
      specFor("ecdsa", {
        [OPTION_OPERATION]: "sign",
        [OPTION_CURVE]: "p521",
        [OPTION_HASH]: "SHA-1",
        ...keys("11".repeat(66)),
      }),
      specFor("ecdsa", {
        [OPTION_OPERATION]: "sign",
        [OPTION_CURVE]: "secp256k1",
        [OPTION_HASH]: "SHA-1",
        ...keys("22".repeat(32)),
      }),
    ];
    for (const spec of specs) {
      const fixed = applyAllFixes(spec);
      expect(resolveAsymmetric(fixed).ok, describeSpec(fixed)).toBe(true);
    }
  });
});

// ── Catalogue and manifests ─────────────────────────────────────────────

describe("catalogue integrity", () => {
  for (const tool of ASYMMETRIC_TOOLS) {
    it(`${tool.id} has a well-formed option catalogue`, () => {
      const catalogue = asymmetricCatalogueFor(tool.id);
      expect(validateCatalogue(catalogue.options)).toEqual([]);
    });

    it(`${tool.id} marks its private key secret`, () => {
      const catalogue = asymmetricCatalogueFor(tool.id);
      const privateKey = catalogue.get(OPTION_PRIVATE_KEY);
      expect(privateKey?.secret).toBe(true);
      expect(catalogue.secretIds()).toContain(OPTION_PRIVATE_KEY);
      // The public key must NOT be secret — it is meant to be shared, and stripping it from a
      // share link would break the one thing a share link is for here.
      expect(catalogue.get(OPTION_PUBLIC_KEY)?.secret).toBeUndefined();
    });

    it(`${tool.id} restricts every option to operations the tool actually has`, () => {
      const catalogue = asymmetricCatalogueFor(tool.id);
      for (const option of catalogue.options) {
        for (const tag of option.availableOn ?? []) {
          expect(
            tool.operations as readonly string[],
            `${tool.id}/${option.id} is gated on ${tag}`,
          ).toContain(tag);
        }
      }
    });

    it(`${tool.id} shows at least one option for every operation it offers`, () => {
      const definition = asymmetricToolDefinition(tool.id);
      for (const operation of tool.operations) {
        const spec = specFor(tool.id, { [OPTION_OPERATION]: operation });
        expect(definition.variantTag!(spec)).toBe(operation);
      }
    });

    it(`${tool.id} declares readsInputForSpec false only for keypair generation`, () => {
      const definition = asymmetricToolDefinition(tool.id);
      expect(definition.readsInputForSpec).toBeDefined();
      for (const operation of tool.operations) {
        const spec = specFor(tool.id, { [OPTION_OPERATION]: operation });
        if (operation === "generate") {
          expect(definition.readsInputForSpec!(spec)).toBe(false);
        } else {
          expect(definition.readsInputForSpec!(spec)).toBe(true);
        }
      }
    });
  }


  it("every multiline option is a text or password kind", () => {
    for (const tool of ASYMMETRIC_TOOLS) {
      for (const option of asymmetricCatalogueFor(tool.id).options) {
        if (!option.arg?.multiline) continue;
        expect(["text", "password"], `${tool.id}/${option.id}`).toContain(option.kind);
      }
    }
  });
});

describe("manifests", () => {
  it("registers one manifest per tool, all in the asymmetric family", () => {
    expect(ASYMMETRIC_MANIFESTS.length).toBe(ASYMMETRIC_TOOLS.length);
    for (const manifest of ASYMMETRIC_MANIFESTS) {
      expect(manifest.family).toBe("asymmetric");
      expect(requireAsymmetricTool(manifest.id).label).toBe(manifest.label);
    }
  });

  it("declares no streaming, since no signature can be emitted mid-message", () => {
    for (const manifest of ASYMMETRIC_MANIFESTS) {
      expect(manifest.streaming).toBe(false);
      expect(asymmetricToolDefinition(manifest.id).createStream).toBeUndefined();
    }
  });

  it("marks ECDH forward-only and the signing tools both ways", () => {
    const byId = new Map(ASYMMETRIC_MANIFESTS.map((m) => [m.id, m]));
    expect(byId.get("ecdh")!.directions).toEqual(["forward"]);
    for (const id of ["rsa", "ecdsa", "ed25519"]) {
      expect(byId.get(id)!.directions).toEqual(["forward", "inverse"]);
    }
  });
});

describe("describe", () => {
  it("says something specific for every operation of every tool", () => {
    for (const tool of ASYMMETRIC_TOOLS) {
      for (const operation of tool.operations) {
        const text = describeSpec(specFor(tool.id, { [OPTION_OPERATION]: operation }));
        expect(text.length, `${tool.id}/${operation}`).toBeGreaterThan(20);
        expect(text.endsWith("."), `${tool.id}/${operation}: ${text}`).toBe(true);
      }
    }
  });

  it("mentions the KDF requirement when describing a derivation", () => {
    const text = describeSpec(
      specFor("ecdh", {
        [OPTION_OPERATION]: "derive",
        ...keys(RFC7748.alicePrivate, RFC7748.bobPublic),
      }),
    );
    expect(text).toContain("HKDF");
  });
});

describe("acceptedPublicKeyLengths", () => {
  it("offers both encodings for the NIST curves and one for X25519", () => {
    for (const curve of ECDSA_CURVES) {
      expect(acceptedPublicKeyLengths(curve)).toEqual([
        curve.publicLen,
        2 * curve.secretLen + 1,
      ]);
    }
    expect(acceptedPublicKeyLengths(ECDH_CURVES[0]!)).toEqual([32]);
  });
});

/**
 * The three post-quantum tools, driven through the family rather than through the library.
 *
 * `tests/postquantum-parity.test.ts` settles the byte-level question: every one of the eighteen
 * parameter sets agrees with OpenSSL 3.5, in both directions. What is checked here is the wiring that
 * sits above it -- the operation enum, the parameter-set option, the length rules, the fields the
 * panel reads and the diagnostics. That is where this family's bugs have historically
 * been, and none of them would fail a parity test.
 */
describe("the post-quantum tools", () => {
  const PQ_TOOLS = ASYMMETRIC_TOOLS.filter((t) => t.category === "Post-quantum");

  it("registers post-quantum schemes including ML-KEM, ML-DSA, SLH-DSA, Falcon, McEliece, HQC, and Stateful Hash Signatures", () => {
    expect(PQ_TOOLS.map((t) => t.id).sort()).toEqual([
      "falcon",
      "hqc",
      "mceliece",
      "mldsa",
      "mlkem",
      "ntru",
      "slhdsa",
      "sqisign",
      "stateful-hash-sig",
    ]);
    // And every one of them declares a parameter set list, which everything else reads from.
    for (const tool of PQ_TOOLS) {
      expect(PQ_PARAM_SETS[tool.id]?.length, tool.id).toBeGreaterThan(0);
      expect(DEFAULT_PARAM_SETS[tool.id], tool.id).toBeDefined();
      expect(
        PQ_PARAM_SETS[tool.id]!.some((set) => set.id === DEFAULT_PARAM_SETS[tool.id]),
        `${tool.id} default is a real set`,
      ).toBe(true);
    }
  });

  it("names a KEM's operations after the standard rather than encrypt and decrypt", () => {
    /**
     * The distinction the whole tool hangs on: `encapsulate` reads no message. Calling it "encrypt"
     * would put an input panel in front of someone and then ignore it, which is worse than an error.
     */
    const kem = requireAsymmetricTool("mlkem");
    expect(kem.operations).toEqual(["generate", "encapsulate", "decapsulate"]);
    expect(kem.operations).not.toContain("encrypt");
  });

  it("generates a keypair of the right size at every parameter set", async () => {
    for (const tool of PQ_TOOLS) {
      for (const set of PQ_PARAM_SETS[tool.id]!) {
        // Only the fast sets, so twelve SLH-DSA keygens do not add half a minute here; signing at
        // every set is the parity file's job.
        if (set.id.endsWith("s") && tool.id === "slhdsa" && set.id !== "sha2-128s") continue;

        const result = await run(tool.id, {
          [OPTION_OPERATION]: "generate",
          [OPTION_PARAM_SET]: set.id,
        });
        const label = `${tool.id}/${set.id}`;
        expect(result.bytes!.length, `${label} public`).toBe(set.publicKeyLen);

        const privateField = result.fields?.find((f) => f.label === "Private key");
        expect(privateField?.secret, `${label} marked secret`).toBe(true);
        expect(privateField!.value.length / 2, `${label} private`).toBe(set.secretKeyLen);
        expect(
          result.fields?.find((f) => f.label === "Parameter set")?.value,
          label,
        ).toBe(set.label);
      }
    }
  });

  it("round-trips ML-KEM through encapsulate and decapsulate", async () => {
    for (const set of PQ_PARAM_SETS.mlkem!) {
      const label = set.label;
      const generated = await run("mlkem", {
        [OPTION_OPERATION]: "generate",
        [OPTION_PARAM_SET]: set.id,
      });
      const secretKey = generated.fields!.find((f) => f.label === "Private key")!.value;
      const publicKey = encodeHex(generated.bytes!);

      const sealed = await run("mlkem", {
        [OPTION_OPERATION]: "encapsulate",
        [OPTION_PARAM_SET]: set.id,
        ...keys(undefined, publicKey),
      });
      expect(sealed.bytes!.length, `${label} ciphertext`).toBe(set.cipherTextLen);
      const sentSecret = sealed.fields!.find((f) => f.label === "Shared secret")!;
      expect(sentSecret.secret, `${label} secret is secret`).toBe(true);
      expect(sentSecret.value.length / 2, `${label} secret length`).toBe(32);

      /**
       * The ciphertext is the *input* to decapsulation, not an option -- which is the one asymmetry
       * between the two operations and the thing a user has to understand to use the tool.
       */
      const opened = await run(
        "mlkem",
        { [OPTION_OPERATION]: "decapsulate", [OPTION_PARAM_SET]: set.id, ...keys(secretKey) },
        sealed.bytes!,
      );
      expect(encodeHex(opened.bytes!), label).toBe(sentSecret.value);
    }
  });

  it("says what a ciphertext of the wrong length is, instead of failing obscurely", async () => {
    const result = await asymmetricToolDefinition("mlkem").compute(
      specFor("mlkem", {
        [OPTION_OPERATION]: "decapsulate",
        [OPTION_PARAM_SET]: "768",
        ...keys("11".repeat(2400)),
      }),
      ascii("far too short"),
    );
    expect(result.bytes).toBeUndefined();
    // The number matters: 1088 for ML-KEM-768, and naming it is what makes the message actionable.
    expect(result.error).toMatch(/1088/);
  });

  it("signs and verifies through the two signature tools", async () => {
    const message = ascii("post-quantum signatures are large");
    for (const [toolId, setId] of [
      ["mldsa", "65"],
      ["mldsa", "44"],
      ["slhdsa", "sha2-128f"],
      ["slhdsa", "shake-128f"],
    ] as const) {
      const set = PQ_PARAM_SETS[toolId]!.find((s) => s.id === setId)!;
      const label = set.label;

      const generated = await run(toolId, {
        [OPTION_OPERATION]: "generate",
        [OPTION_PARAM_SET]: setId,
      });
      const privateKey = generated.fields!.find((f) => f.label === "Private key")!.value;
      const publicKey = encodeHex(generated.bytes!);

      const signed = await run(
        toolId,
        { [OPTION_OPERATION]: "sign", [OPTION_PARAM_SET]: setId, ...keys(privateKey) },
        message,
      );
      expect(signed.bytes!.length, label).toBe(set.signatureLen);

      const verified = await run(
        toolId,
        {
          [OPTION_OPERATION]: "verify",
          [OPTION_PARAM_SET]: setId,
          ...keys(undefined, publicKey),
          [OPTION_SIGNATURE]: encodeHex(signed.bytes!),
          signatureEncoding: "hex",
        },
        message,
      );
      expect(verified.text, label).toMatch(/valid/i);

      // And a changed message fails, so the check above is not passing for a trivial reason.
      const altered = await run(
        toolId,
        {
          [OPTION_OPERATION]: "verify",
          [OPTION_PARAM_SET]: setId,
          ...keys(undefined, publicKey),
          [OPTION_SIGNATURE]: encodeHex(signed.bytes!),
          signatureEncoding: "hex",
        },
        ascii("post-quantum signatures are LARGE"),
      );
      expect(altered.text, `${label} tampered`).toMatch(/does NOT match/);
    }
  });

  it("takes the public key from the private one when verifying, as the curve tools do", async () => {
    const message = ascii("no public key field");
    const generated = await run("mldsa", {
      [OPTION_OPERATION]: "generate",
      [OPTION_PARAM_SET]: "65",
    });
    const privateKey = generated.fields!.find((f) => f.label === "Private key")!.value;
    const signed = await run(
      "mldsa",
      { [OPTION_OPERATION]: "sign", [OPTION_PARAM_SET]: "65", ...keys(privateKey) },
      message,
    );

    const verified = await run(
      "mldsa",
      {
        [OPTION_OPERATION]: "verify",
        [OPTION_PARAM_SET]: "65",
        ...keys(privateKey),
        [OPTION_SIGNATURE]: encodeHex(signed.bytes!),
        signatureEncoding: "hex",
      },
      message,
    );
    expect(verified.text).toMatch(/valid/i);
    expect(verified.fields?.find((f) => f.label === "Public key")?.hint).toMatch(
      /Taken from the private key/,
    );
  });

  it("refuses a key or signature from a different parameter set, and names the set", () => {
    /**
     * The reason the lengths are checked in the resolver rather than in the option's `bytesLength`:
     * one catalogue serves all twelve SLH-DSA sets, so the declared set is the union, and only the
     * resolver knows which set is selected. "Expected one of 64, 96, 128" would tell a user nothing.
     */
    const wrongPrivate = resolveAsymmetric(
      specFor("mldsa", {
        [OPTION_OPERATION]: "sign",
        [OPTION_PARAM_SET]: "65",
        // A perfectly good ML-DSA-44 private key, and wrong here.
        ...keys("11".repeat(2560)),
      }),
    );
    expect(wrongPrivate.ok).toBe(false);
    if (!wrongPrivate.ok) {
      expect(wrongPrivate.problem).toMatch(/ML-DSA-65/);
      expect(wrongPrivate.problem).toMatch(/4032/);
    }

    const wrongSignature = resolveAsymmetric(
      specFor("slhdsa", {
        [OPTION_OPERATION]: "verify",
        [OPTION_PARAM_SET]: "sha2-128s",
        ...keys(undefined, "22".repeat(32)),
        // 17088 is the `f` variant's length; `s` is 7856.
        [OPTION_SIGNATURE]: "33".repeat(17088),
        signatureEncoding: "hex",
      }),
    );
    expect(wrongSignature.ok).toBe(false);
    if (!wrongSignature.ok) expect(wrongSignature.problem).toMatch(/7856/);
  });

  it("refuses a parameter set the tool does not offer", () => {
    // A share link or stale saved state is the way this happens.
    const result = resolveAsymmetric(
      specFor("mlkem", { [OPTION_OPERATION]: "generate", [OPTION_PARAM_SET]: "65" }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.problem).toMatch(/does not offer/);
  });

  it("will not encapsulate to an empty public key, and says why", () => {
    /**
     * The same trap ECDH's "Their public key" label exists for: encapsulating to your own key
     * succeeds and produces a secret shared with nobody, so there is deliberately no fallback to a
     * private key here even though verify has one.
     */
    const result = resolveAsymmetric(
      specFor("mlkem", {
        [OPTION_OPERATION]: "encapsulate",
        [OPTION_PARAM_SET]: "768",
        ...keys("11".repeat(2400)),
      }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.problem).toMatch(/recipient/i);
  });

  it("explains that a KEM does not encrypt the message", () => {
    const spec = specFor("mlkem", {
      [OPTION_OPERATION]: "encapsulate",
      [OPTION_PARAM_SET]: "768",
      ...keys(undefined, "22".repeat(1184)),
    });
    const found = lint(spec).diagnostics.find((d) => d.code === "A009");
    expect(found).toBeDefined();
    expect(found!.level).toBe("info");
    // And it names what to do with the secret, which is the actionable half.
    expect(found!.detail).toMatch(/AES-256-GCM|ChaCha20-Poly1305/);
    // It stays quiet for the two signature tools, which do read the message.
    expect(
      lint(specFor("mldsa", { [OPTION_OPERATION]: "sign" })).diagnostics.some(
        (d) => d.code === "A009",
      ),
    ).toBe(false);
  });

  it("warns about a slow signing set and offers the fast one", () => {
    const spec = specFor("slhdsa", {
      [OPTION_OPERATION]: "sign",
      [OPTION_PARAM_SET]: "sha2-256s",
      ...keys("11".repeat(128)),
    });
    const found = lint(spec).diagnostics.find((d) => d.code === "A010");
    expect(found).toBeDefined();
    expect(found!.fix).toBeDefined();

    // The fix reads the set from the spec it is handed, so it lands on the matching `f` variant.
    const fixed = found!.fix!.apply(spec);
    expect(fixed.options[OPTION_PARAM_SET]).toBe("sha2-256f");
    expect(lint(fixed).diagnostics.some((d) => d.code === "A010")).toBe(false);
    // And it is quiet for the `f` sets and for ML-DSA, which is fast at every set.
    expect(
      lint(specFor("mldsa", { [OPTION_OPERATION]: "sign" })).diagnostics.some(
        (d) => d.code === "A010",
      ),
    ).toBe(false);
  });

  it("states the signature size where a signature is being produced", () => {
    for (const [toolId, setId] of [["mldsa", "65"], ["slhdsa", "sha2-128f"]] as const) {
      const found = lint(
        specFor(toolId, { [OPTION_OPERATION]: "generate", [OPTION_PARAM_SET]: setId }),
      ).diagnostics.find((d) => d.code === "A011");
      expect(found, toolId).toBeDefined();
      expect(found!.level, toolId).toBe("info");
      expect(found!.message, toolId).toMatch(/Ed25519/);
    }
    // ML-KEM has no signature, so there is no size to compare and the rule stays quiet.
    expect(
      lint(specFor("mlkem", { [OPTION_OPERATION]: "generate" })).diagnostics.some(
        (d) => d.code === "A011",
      ),
    ).toBe(false);
  });

  it("describes itself in terms of the sizes, which is what people want to know", () => {
    expect(
      describeSpec(specFor("mlkem", { [OPTION_OPERATION]: "generate", [OPTION_PARAM_SET]: "768" })),
    ).toMatch(/1184/);
    expect(
      describeSpec(
        specFor("slhdsa", {
          [OPTION_OPERATION]: "sign",
          [OPTION_PARAM_SET]: "sha2-256f",
          ...keys("11".repeat(128)),
        }),
      ),
    ).toMatch(/49856/);
  });

  it("keeps a clean option catalogue for each tool", () => {
    for (const tool of PQ_TOOLS) {
      expect(validateCatalogue(asymmetricCatalogueFor(tool.id).options), tool.id).toEqual([]);
    }
  });

  it("marks the private key secret, so it never reaches a share link", () => {
    for (const tool of PQ_TOOLS) {
      const option = asymmetricCatalogueFor(tool.id).require(OPTION_PRIVATE_KEY);
      expect(option.secret, tool.id).toBe(true);
    }
  });
});
