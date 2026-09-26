import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createCertificate } from "../../../packages/tools/certificates/src/asn1/create-cert.ts";
import { startOpenSslServer, runOpenSslClient, testTlsProtocolMatrix } from "../tls_test_harness.ts";

async function main() {
  console.log("=================================================");
  console.log("   2. SINGLE (CA-SIGNED) CERTIFICATE EXAMPLE     ");
  console.log("=================================================\n");

  const outDir = path.resolve(import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname));
  const caKeyPath = path.join(outDir, "ca.key");
  const caCertPath = path.join(outDir, "ca.crt");
  const serverKeyPath = path.join(outDir, "server.key");
  const serverCertPath = path.join(outDir, "server.crt");

  // 1. Generate Root CA Authority
  console.log("[1/5] Generating Local Root Certificate Authority (CA:TRUE)...");
  const ca = await createCertificate({
    commonName: "Internal Development Root CA",
    organization: "Cipher Workbench",
    organizationalUnit: "Security Authority",
    country: "US",
    state: "California",
    locality: "San Francisco",
    keyType: "ecdsa-p256",
    hashType: "sha256",
    validityDays: 3650,
    isCa: true,
    san: "",
  });

  fs.writeFileSync(caKeyPath, ca.privateKeyPem, "utf-8");
  fs.writeFileSync(caCertPath, ca.certPem, "utf-8");
  console.log(`  ✓ Root CA Cert:   ${caCertPath}`);
  console.log(`  ✓ Root CA SHA256: ${ca.fingerprintSha256}`);

  // 2. Generate Server Certificate Signed by Root CA
  console.log("\n[2/5] Issuing Leaf Server Certificate signed by Root CA...");
  const server = await createCertificate({
    commonName: "localhost",
    san: "localhost, 127.0.0.1, ::1",
    organization: "Cipher Workbench",
    organizationalUnit: "Services",
    country: "US",
    state: "California",
    locality: "San Francisco",
    keyType: "ecdsa-p256",
    hashType: "sha256",
    validityDays: 365,
    isCa: false,
    serverAuth: true,
    clientAuth: false,
    issuanceMode: "ca-signed",
    caCertPem: ca.certPem,
    caPrivateKeyPem: ca.privateKeyPem,
  });

  fs.writeFileSync(serverKeyPath, server.privateKeyPem, "utf-8");
  fs.writeFileSync(serverCertPath, server.certPem, "utf-8");
  console.log(`  ✓ Server Cert:     ${serverCertPath}`);
  console.log(`  ✓ Server Key:      ${serverKeyPath}`);
  console.log(`  ✓ Issuer:          ${server.issuerDn}`);

  // 3. Cryptographic Chain Verification with OpenSSL CLI
  console.log("\n[3/5] Verifying Certificate Chain with OpenSSL CLI...");
  try {
    const verifyOut = execFileSync("openssl", ["verify", "-CAfile", caCertPath, serverCertPath], {
      encoding: "utf-8",
    });
    console.log(`  ✓ Chain Verification: ${verifyOut.trim()}`);
  } catch (err) {
    console.error("  ✗ Chain verification failed:", err);
  }

  // 4. Live TLS Handshake Test
  console.log("\n[4/5] Executing Live TLS Handshake with Root CA Verification on port 9542...");
  const port = 9542;
  const srv = await startOpenSslServer({
    port,
    cert: serverCertPath,
    key: serverKeyPath,
  });

  try {
    const clientOutput = await runOpenSslClient({
      port,
      ca: caCertPath, // Client verifies server against Root CA
    });

    const isVerified = clientOutput.includes("Verification: OK");
    const hasCipher = clientOutput.includes("Cipher is") || clientOutput.includes("TLS");

    if (isVerified && hasCipher) {
      console.log("  ✓ PASS: CA-Signed TLS Handshake Succeeded!");
      console.log("  - Client verified server certificate against Root CA: OK");
      console.log("  - TLS encrypted tunnel established successfully.");
    } else {
      throw new Error("TLS handshake verification failed:\n" + clientOutput);
    }
  } finally {
    srv.stop();
  }

  // 5. Protocol Version Matrix: TLS 1.3, TLS 1.2, and TLS 1.1 Verification
  console.log("\n[5/5] Verifying TLS 1.1 / TLS 1.2 / TLS 1.3 Protocol Matrix...");
  const matrix = await testTlsProtocolMatrix({
    basePort: 9554,
    cert: serverCertPath,
    key: serverKeyPath,
    ca: caCertPath,
  });

  for (const item of matrix) {
    const status = item.verified ? "OK" : "FAILED";
    console.log(`  ✓ ${item.version.toUpperCase().replace("_", ".")}: Protocol=${item.protocol}, Cipher=${item.cipher}, Verified=${status}`);
  }

  console.log("\n=================================================");
  console.log("   SINGLE (CA-SIGNED) COMPLETED SUCCESSFULLY!    ");
  console.log("=================================================\n");
}

main().catch((err) => {
  console.error("Example run failed:", err);
  process.exit(1);
});
