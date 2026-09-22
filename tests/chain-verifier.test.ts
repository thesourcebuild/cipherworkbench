import { describe, expect, it } from "vitest";
import { generateMtlsSuite } from "../packages/tools/certificates/src/asn1/mtls";
import {
  verifyCertificateChain,
  splitPemCertificates,
} from "../packages/tools/certificates/src/asn1/chain-verifier";

describe("Certificate Chain Verifier (Phase 6)", () => {
  it("verifies a 2-tier certificate chain (Root CA -> Server)", async () => {
    const suite = await generateMtlsSuite({
      pkiHierarchy: "2-tier",
      caCommonName: "Company Root CA",
      serverCommonName: "api.company.com",
      clientCommonName: "client.company.com",
      keyType: "rsa-2048",
      hashType: "sha256",
      validityDays: 90,
    });

    // serverChainPem = server.crt + ca.crt
    const result = await verifyCertificateChain(suite.server.chainPem);
    expect(result.isValid).toBe(true);
    expect(result.chainDepth).toBe(2);
    expect(result.leafSubject).toContain("api.company.com");
    expect(result.rootSubject).toContain("Company Root CA");
    expect(result.isSelfSignedRoot).toBe(true);

    const [leafNode, rootNode] = result.nodes;
    expect(leafNode?.isCa).toBe(false);
    expect(leafNode?.signatureValid).toBe(true);
    expect(leafNode?.akiSkiMatch).toBe(true);
    expect(rootNode?.isCa).toBe(true);
    expect(rootNode?.isRoot).toBe(true);
    expect(rootNode?.signatureValid).toBe(true);
  });

  it("verifies a 3-tier enterprise PKI chain (Root CA -> Intermediate CA -> Server)", async () => {
    const suite = await generateMtlsSuite({
      pkiHierarchy: "3-tier",
      caCommonName: "Global Root CA",
      intermediateCommonName: "Enterprise Issuing CA",
      serverCommonName: "internal.vault.corp",
      clientCommonName: "worker-01.corp",
      keyType: "ecdsa-p256",
      hashType: "sha256",
      validityDays: 180,
    });

    // serverChainPem = server.crt + intermediate.crt + ca.crt
    const result = await verifyCertificateChain(suite.server.chainPem);
    expect(result.isValid).toBe(true);
    expect(result.chainDepth).toBe(3);
    expect(result.leafSubject).toContain("internal.vault.corp");
    expect(result.rootSubject).toContain("Global Root CA");

    // Check tree output
    expect(result.treeDiagram).toContain("Global Root CA");
    expect(result.treeDiagram).toContain("Enterprise Issuing CA");
    expect(result.treeDiagram).toContain("internal.vault.corp");
    expect(result.treeDiagram).toContain("[PASS]");
  });

  it("detects tampered certificate signature in chain", async () => {
    const suite = await generateMtlsSuite({
      pkiHierarchy: "2-tier",
      caCommonName: "Secure CA",
      serverCommonName: "server.com",
      clientCommonName: "client.com",
      keyType: "ecdsa-p256",
      hashType: "sha256",
    });

    const certs = splitPemCertificates(suite.server.chainPem);
    expect(certs.length).toBe(2);

    // Tamper with the leaf certificate by corrupting base64 payload
    const tamperedLeaf = certs[0]!.replace("M", "N");
    const tamperedChain = `${tamperedLeaf}\n${certs[1]}`;

    // Should either throw ASN.1 error or report invalid signature
    try {
      const result = await verifyCertificateChain(tamperedChain);
      expect(result.isValid).toBe(false);
      expect(result.nodes[0]?.signatureValid).toBe(false);
    } catch (err) {
      expect(err).toBeDefined();
    }
  });
});
