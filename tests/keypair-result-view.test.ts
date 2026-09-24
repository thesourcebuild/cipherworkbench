import { describe, expect, it } from "vitest";
import {
  resolveKeypairData,
  getKeypairView,
  hexToBytes,
  bytesToHex,
  bytesToBase64,
} from "../apps/web/app/keypair-formats";

describe("Keypair Formats and Result View Resolution", () => {
  it("resolves secp256k1 keypair and converts across Hex, Base64, PEM, JWK, and Raw Binary", () => {
    // 32-byte secret scalar and 33-byte compressed public key
    const privHex = "7c5f238b0c959ccc6ed51ce60f159f7a0fa42cfd7af7cb1dcb752a2e8af14583";
    const pubHex = "035272acec9369972944190ecd799b358ddb2357bfa471e11c29c184a2e5a6cf54";

    const fields = [
      { label: "Curve", value: "secp256k1" },
      { label: "Private key", value: privHex, secret: true },
      { label: "Public key", value: pubHex },
    ];

    const data = resolveKeypairData(fields, { id: "secp256k1" });

    expect(data.defaultFormat).toBe("hex");
    expect(data.availableFormats.map((f) => f.id)).toContain("hex");
    expect(data.availableFormats.map((f) => f.id)).toContain("base64");
    expect(data.availableFormats.map((f) => f.id)).toContain("pem");
    expect(data.availableFormats.map((f) => f.id)).toContain("jwk");
    expect(data.availableFormats.map((f) => f.id)).toContain("raw");

    // Hex view
    const hexView = getKeypairView("hex", data);
    expect(hexView.privateVal).toBe(privHex);
    expect(hexView.publicVal).toBe(pubHex);
    expect(hexView.publicHint).toBe("Not a secret — share it freely.");
    expect(hexView.fileExt).toBe("hex");

    // Base64 view
    const b64View = getKeypairView("base64", data);
    expect(b64View.privateVal).toBe(bytesToBase64(hexToBytes(privHex)));
    expect(b64View.publicVal).toBe(bytesToBase64(hexToBytes(pubHex)));
    expect(b64View.publicHint).toBe("Not a secret — share it freely.");
    expect(b64View.fileExt).toBe("b64");

    // PEM view
    const pemView = getKeypairView("pem", data);
    expect(pemView.privateVal).toContain("-----BEGIN PRIVATE KEY-----");
    expect(pemView.privateVal).toContain("-----END PRIVATE KEY-----");
    expect(pemView.publicVal).toContain("-----BEGIN PUBLIC KEY-----");
    expect(pemView.publicVal).toContain("-----END PUBLIC KEY-----");
    expect(pemView.publicHint).toBe("Not a secret — share it freely.");
    expect(pemView.fileExt).toBe("pem");

    // JWK view (secp256k1 decompresses compressed public key into x and y)
    const jwkView = getKeypairView("jwk", data);
    const privJwk = JSON.parse(jwkView.privateVal);
    const pubJwk = JSON.parse(jwkView.publicVal);
    expect(privJwk.kty).toBe("EC");
    expect(privJwk.crv).toBe("secp256k1");
    expect(privJwk.x).toBeDefined();
    expect(privJwk.y).toBeDefined();
    expect(privJwk.d).toBeDefined();
    expect(pubJwk.kty).toBe("EC");
    expect(pubJwk.crv).toBe("secp256k1");
    expect(pubJwk.x).toBe(privJwk.x);
    expect(pubJwk.y).toBe(privJwk.y);
    expect(jwkView.publicHint).toBe("Not a secret — share it freely.");

    // Raw binary view
    const rawView = getKeypairView("raw", data);
    expect(rawView.fileExt).toBe("bin");
    expect(rawView.mimeType).toBe("application/octet-stream");
    expect(rawView.publicHint).toBe("Not a secret — share it freely.");
    expect(data.rawPrivate).toBeDefined();
    expect(data.rawPublic).toBeDefined();
    expect(bytesToHex(data.rawPrivate!)).toBe(privHex);
    expect(bytesToHex(data.rawPublic!)).toBe(pubHex);
  });

  it("resolves Ed25519 keypair and creates RFC 8410 PKCS#8 & SPKI PEM and RFC 8037 JWK", () => {
    const privHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const pubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    const fields = [
      { label: "Curve", value: "Ed25519" },
      { label: "Private key", value: privHex, secret: true },
      { label: "Public key", value: pubHex },
    ];

    const data = resolveKeypairData(fields, { id: "ed25519" });

    expect(data.hasPem).toBe(true);
    expect(data.hasJwk).toBe(true);

    const pemView = getKeypairView("pem", data);
    expect(pemView.privateVal).toContain("-----BEGIN PRIVATE KEY-----");
    expect(pemView.publicVal).toContain("-----BEGIN PUBLIC KEY-----");

    const jwkView = getKeypairView("jwk", data);
    const pubJwk = JSON.parse(jwkView.publicVal);
    const privJwk = JSON.parse(jwkView.privateVal);
    expect(pubJwk.kty).toBe("OKP");
    expect(pubJwk.crv).toBe("Ed25519");
    expect(privJwk.d).toBeDefined();
  });

  it("resolves RSA keypair preserving PEM as default and providing Hex, Base64, and Raw DER formats", () => {
    const privPem =
      "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----";
    const pubPem =
      "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----";
    const privJwk = JSON.stringify({ kty: "RSA", n: "abc", e: "AQAB", d: "xyz" });
    const pubJwk = JSON.stringify({ kty: "RSA", n: "abc", e: "AQAB" });

    const fields = [
      { label: "Key size", value: "2048 bits" },
      { label: "Private key (PKCS#8 PEM)", value: privPem, secret: true },
      { label: "Public key (SPKI PEM)", value: pubPem },
      { label: "Private key (JWK)", value: privJwk, secret: true },
      { label: "Public key (JWK)", value: pubJwk },
    ];

    const data = resolveKeypairData(fields, { id: "rsa" });

    expect(data.defaultFormat).toBe("pem");
    expect(data.hasPem).toBe(true);
    expect(data.hasJwk).toBe(true);

    // PEM matches original field and does not duplicate format names
    const pemView = getKeypairView("pem", data, "Private key (PKCS#8 PEM)", "Public key (SPKI PEM)");
    expect(pemView.privateVal).toBe(privPem);
    expect(pemView.publicVal).toBe(pubPem);
    expect(pemView.privateLabel).toBe("Private key (PKCS#8 PEM)");
    expect(pemView.publicLabel).toBe("Public key (SPKI PEM)");

    // JWK matches original field and has clean label
    const jwkView = getKeypairView("jwk", data, "Private key (PKCS#8 PEM)", "Public key (SPKI PEM)");
    expect(jwkView.privateVal).toBe(privJwk);
    expect(jwkView.publicVal).toBe(pubJwk);
    expect(jwkView.privateLabel).toBe("Private key (JWK)");
    expect(jwkView.publicLabel).toBe("Public key (JWK)");
  });
});
