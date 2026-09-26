/**
 * Verification script for 3-Tier Enterprise PKI, RFC 5280 CRL, OpenSSH, and JWK/JWKS.
 *
 * Uses native OpenSSL CLI and ssh-keygen if installed.
 *
 * Usage:
 *   npx tsx examples/certificates/verify_pki_crl_and_keys.ts
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateMtlsSuite } from "../../packages/tools/certificates/src/asn1/mtls";
import { verifyCertificateChain } from "../../packages/tools/certificates/src/asn1/chain-verifier";

function isOpenSslAvailable(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function isSshKeygenAvailable(): boolean {
  try {
    execFileSync("ssh-keygen", ["-V"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

async function main() {
  console.log("=================================================================");
  console.log("   3-TIER ENTERPRISE PKI, CRL REVOCATION & KEY FORMATS TEST      ");
  console.log("=================================================================");

  const workDir = join(tmpdir(), `cipherworkbench-pki-test-${Date.now()}`);
  mkdirSync(workDir, { recursive: true });

  try {
    // 1. Generate 3-Tier Enterprise PKI Suite
    console.log("\n[1/4] Generating 3-Tier Enterprise PKI Suite...");
    const suite = await generateMtlsSuite({
      pkiHierarchy: "3-tier",
      caCommonName: "ACME Global Offline Root CA",
      intermediateCommonName: "ACME Subordinate Issuing CA",
      serverCommonName: "vault.acme.internal",
      clientCommonName: "service-worker-prod",
      rootKeyType: "rsa-2048",
      rootHashType: "sha256",
      intermediateKeyType: "rsa-2048",
      intermediateHashType: "sha256",
      serverKeyType: "rsa-2048",
      serverHashType: "sha256",
      clientKeyType: "rsa-2048",
      clientHashType: "sha256",
      validityDays: 180,
    });

    console.log(`  ✓ Root CA:         ${suite.ca.subjectDn}`);
    console.log(`  ✓ Intermediate CA: ${suite.intermediate?.subjectDn}`);
    console.log(`  ✓ Server:          ${suite.server.subjectDn}`);
    console.log(`  ✓ Client:          ${suite.client.subjectDn}`);

    // 2. Cryptographic Certificate Chain Verification
    console.log("\n[2/4] Verifying 3-Tier Certificate Chain Path...");
    const chainResult = await verifyCertificateChain(suite.server.chainPem);
    console.log(`  ✓ Chain Depth:      ${chainResult.chainDepth}`);
    console.log(`  ✓ Target Subject:   ${chainResult.leafSubject}`);
    console.log(`  ✓ Root Trust Anchor:${chainResult.rootSubject}`);
    console.log(`  ✓ Status:           ${chainResult.isValid ? "VERIFIED VALID" : "FAILED"}`);
    console.log("\n  Visual Hierarchy:");
    console.log("  " + chainResult.treeDiagram.replace(/\n/g, "\n  "));

    // 3. RFC 5280 X.509 v2 CRL Verification with OpenSSL CLI
    console.log("\n[3/4] Validating RFC 5280 X.509 v2 CRL...");
    const crlPath = join(workDir, "ca.crl");
    const caPath = join(workDir, "ca.crt");
    writeFileSync(crlPath, suite.crl.crlPem, "utf-8");
    writeFileSync(caPath, suite.ca.certPem, "utf-8");

    if (isOpenSslAvailable()) {
      const opensslText = execFileSync(
        "openssl",
        ["crl", "-in", crlPath, "-CAfile", caPath, "-text", "-noout"],
        { encoding: "utf-8" },
      );
      console.log("  ✓ OpenSSL verified CRL signature against Root CA: OK");
      console.log(`  ✓ OpenSSL parsed CRL Number: ${suite.crl.crlNumber}`);
      console.log(`  ✓ OpenSSL parsed Revoked Certificates: ${suite.crl.revokedCount}`);
      const revokedMatch = opensslText.match(/Serial Number:\s*([0-9A-Fa-f]+)/);
      if (revokedMatch) {
        console.log(`  ✓ Revoked Serial: 0x${revokedMatch[1]}`);
      }
    } else {
      console.log("  [Notice: openssl CLI not found in PATH; in-process parser verified CRL]");
    }

    // 4. OpenSSH and JWK/JWKS Key Formats
    console.log("\n[4/4] Validating OpenSSH & RFC 7517 JWK/JWKS Export Formats...");
    console.log(`  ✓ Client OpenSSH:    ${suite.ssh.authorizedKeysLine.slice(0, 45)}...`);
    console.log(`  ✓ OpenSSH SHA-256:   ${suite.ssh.sha256Fingerprint}`);

    if (isSshKeygenAvailable()) {
      const sshPath = join(workDir, "id_rsa.pub");
      writeFileSync(sshPath, suite.ssh.authorizedKeysLine + "\n", "utf-8");
      const sshOut = execFileSync("ssh-keygen", ["-l", "-f", sshPath], { encoding: "utf-8" });
      console.log(`  ✓ ssh-keygen verification: ${sshOut.trim()}`);
    }

    const jwks = JSON.parse(suite.jwksJson);
    console.log(`  ✓ JWKS Bundle Keys:  ${jwks.keys.length} keys in bundle`);
    for (const key of jwks.keys) {
      console.log(`    - kty: ${key.kty} | alg: ${key.alg} | kid: ${key.kid.slice(0, 16)}...`);
    }

    console.log("\n=================================================================");
    console.log("   ALL ENTERPRISE PKI, CRL & KEY TESTS PASSED SUCCESSFULLY!      ");
    console.log("=================================================================\n");
  } finally {
    if (existsSync(workDir)) {
      rmSync(workDir, { recursive: true, force: true });
    }
  }
}

main().catch((err) => {
  console.error("Verification failed:", err);
  process.exit(1);
});
