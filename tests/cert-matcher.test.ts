import { describe, expect, it } from "vitest";
import { verifyCertificateKeyPair } from "../packages/tools/certificates/src/asn1/cert-matcher";
import {
  RSA_CERTIFICATE_PEM,
  RSA_PRIVATE_KEY_PEM,
  ECDSA_CSR_PEM,
  SAMPLE_2TIER_SERVER_PEM,
} from "../packages/tools/certificates/src/samples";

const ECDSA_PRIVATE_KEY_PEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHQ0wpuVlKSk2Km1bpTgu9KS/Bwaj+YE0korERF8peMboAoGCCqGSM49
AwEHoUQDQgAEu4zkVetOyHpKJ4havpZLLKxPTmyMIGZbbPpD5u/8NBF4u521WVid
sIneiexrRGMMxF7qgXi4t0fLGvW31SFASg==
-----END EC PRIVATE KEY-----`;

describe("Certificate & Key Matcher", () => {
  it("matches an RSA certificate with its valid matching private key (separate arguments)", async () => {
    const result = await verifyCertificateKeyPair(RSA_CERTIFICATE_PEM, RSA_PRIVATE_KEY_PEM);

    expect(result.matches).toBe(true);
    expect(result.targetType).toBe("certificate");
    expect(result.keyType).toBe("RSA");
    expect(result.details.probeVerified).toBe(true);
    expect(result.fingerprints.certOrCsrPublicKeySha256).toBeDefined();
    expect(result.fingerprints.privateKeyDerivedPublicKeySha256).toBe(
      result.fingerprints.certOrCsrPublicKeySha256,
    );
    expect(result.errors).toHaveLength(0);
  });

  it("matches an RSA certificate with its matching private key when combined in single PEM text", async () => {
    const combined = `${RSA_CERTIFICATE_PEM}\n\n${RSA_PRIVATE_KEY_PEM}`;
    const result = await verifyCertificateKeyPair(combined);

    expect(result.matches).toBe(true);
    expect(result.targetType).toBe("certificate");
    expect(result.details.probeVerified).toBe(true);
  });

  it("matches an ECDSA CSR with its matching SEC1 EC private key", async () => {
    const result = await verifyCertificateKeyPair(ECDSA_CSR_PEM, ECDSA_PRIVATE_KEY_PEM);

    expect(result.matches).toBe(true);
    expect(result.targetType).toBe("csr");
    expect(result.keyType).toBe("EC");
    expect(result.details.probeVerified).toBe(true);
    expect(result.fingerprints.certOrCsrPublicKeySha256).toBe(
      result.fingerprints.privateKeyDerivedPublicKeySha256,
    );
  });

  it("detects mismatch when RSA private key does not match a different certificate", async () => {
    // SAMPLE_2TIER_SERVER_PEM has a different RSA public key
    const result = await verifyCertificateKeyPair(SAMPLE_2TIER_SERVER_PEM, RSA_PRIVATE_KEY_PEM);

    expect(result.matches).toBe(false);
    expect(result.details.probeVerified).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.fingerprints.certOrCsrPublicKeySha256).not.toBe(
      result.fingerprints.privateKeyDerivedPublicKeySha256,
    );
  });

  it("throws a clear error when input does not contain a certificate or key", async () => {
    await expect(verifyCertificateKeyPair("invalid-data")).rejects.toThrow(
      /No valid X\.509 Certificate or PKCS#10 CSR found/i,
    );
  });
});
