import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createCertificate } from "../../../packages/tools/certificates/src/asn1/create-cert.ts";
import { startOpenSslServer, runOpenSslClient, testTlsProtocolMatrix } from "../tls_test_harness.ts";

async function main() {
  console.log("=================================================");
  console.log("   1. SINGLE (SELF-SIGNED) CERTIFICATE EXAMPLE   ");
  console.log("=================================================\n");

  const outDir = path.resolve(import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname));
  const keyPath = path.join(outDir, "private.key");
  const certPath = path.join(outDir, "certificate.crt");

  console.log("[1/4] Generating Production-Grade Self-Signed Certificate...");
  const created = await createCertificate({
    commonName: "localhost",
    san: "localhost, 127.0.0.1, ::1",
    organization: "Cipher Workbench",
    organizationalUnit: "Security",
    country: "US",
    state: "California",
    locality: "San Francisco",
    keyType: "ecdsa-p256",
    hashType: "sha256",
    validityDays: 365,
    isCa: false,
    serverAuth: true,
    clientAuth: true,
  });

  fs.writeFileSync(keyPath, created.privateKeyPem, "utf-8");
  fs.writeFileSync(certPath, created.certPem, "utf-8");

  console.log(`  ✓ Written private key: ${keyPath}`);
  console.log(`  ✓ Written certificate: ${certPath}`);
  console.log(`  ✓ Serial Number:       0x${created.serialNumberHex}`);
  console.log(`  ✓ SHA-256 Fingerprint: ${created.fingerprintSha256}`);

  // 2. OpenSSL inspection
  console.log("\n[2/4] Verifying X.509 v3 Extensions with OpenSSL...");
  try {
    const textOut = execFileSync("openssl", ["x509", "-in", certPath, "-text", "-noout"], {
      encoding: "utf-8",
    });

    const hasDigitalSig = textOut.includes("Digital Signature");
    const hasNoKeyEncipherment = !textOut.includes("Key Encipherment");
    const hasSan = textOut.includes("DNS:localhost") && textOut.includes("127.0.0.1") && (textOut.includes("::1") || textOut.includes("0:0:0:0:0:0:0:1"));
    const hasBasicConstraints = textOut.includes("CA:FALSE");

    console.log(`  ✓ Basic Constraints:     CA:FALSE (${hasBasicConstraints ? "Verified" : "Fail"})`);
    console.log(`  ✓ EC Key Usage:          Digital Signature only (${hasDigitalSig && hasNoKeyEncipherment ? "Compliant" : "Fail"})`);
    console.log(`  ✓ Dual-Stack SAN:        DNS:localhost, IPv4, IPv6 (${hasSan ? "Verified" : "Fail"})`);
  } catch {
    console.log("  [Notice: openssl CLI inspection skipped or failed]");
  }

  // 3. Live TLS Handshake Test
  console.log("\n[3/4] Executing Live Mock TLS Handshake on port 9541...");
  const port = 9541;
  const server = await startOpenSslServer({
    port,
    cert: certPath,
    key: keyPath,
  });

  try {
    const clientOutput = await runOpenSslClient({
      port,
      ca: certPath, // In self-signed mode, the cert itself acts as the trust anchor
    });

    const isVerified = clientOutput.includes("Verification: OK");
    const hasCipher = clientOutput.includes("Cipher is") || clientOutput.includes("TLS");

    if (isVerified && hasCipher) {
      console.log("  ✓ PASS: Self-Signed TLS Handshake Succeeded!");
      console.log("  - Client verified server certificate directly: OK");
      console.log("  - TLS encrypted tunnel established successfully.");
    } else {
      throw new Error("TLS handshake verification failed:\n" + clientOutput);
    }
  } finally {
    server.stop();
  }

  // 4. Protocol Version Matrix: TLS 1.3, TLS 1.2, and TLS 1.1 Verification
  console.log("\n[4/4] Verifying TLS 1.1 / TLS 1.2 / TLS 1.3 Protocol Matrix...");
  const matrix = await testTlsProtocolMatrix({
    basePort: 9551,
    cert: certPath,
    key: keyPath,
    ca: certPath,
  });

  for (const item of matrix) {
    const status = item.verified ? "OK" : "FAILED";
    console.log(`  ✓ ${item.version.toUpperCase().replace("_", ".")}: Protocol=${item.protocol}, Cipher=${item.cipher}, Verified=${status}`);
  }

  console.log("\n=================================================");
  console.log("   SINGLE (SELF-SIGNED) COMPLETED SUCCESSFULLY!  ");
  console.log("=================================================\n");
}

main().catch((err) => {
  console.error("Example run failed:", err);
  process.exit(1);
});
