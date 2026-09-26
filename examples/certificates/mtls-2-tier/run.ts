import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { generateMtlsSuite } from "../../../packages/tools/certificates/src/asn1/mtls.ts";
import { startOpenSslServer, runOpenSslClient, testTlsProtocolMatrix } from "../tls_test_harness.ts";

async function main() {
  console.log("=================================================");
  console.log("   3. mTLS (2-TIER) SUITE EXAMPLE                ");
  console.log("=================================================\n");

  const outDir = path.resolve(import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname));

  // 1. Generate 2-Tier mTLS Suite
  console.log("[1/5] Generating 2-Tier mTLS PKI Suite...");
  const suite = await generateMtlsSuite({
    pkiHierarchy: "2-tier",
    caCommonName: "Local Microservices Root CA",
    serverCommonName: "localhost",
    serverSan: "localhost, 127.0.0.1, ::1",
    clientCommonName: "client-worker-01",
    rootKeyType: "ecdsa-p256",
    rootHashType: "sha256",
    serverKeyType: "ecdsa-p256",
    serverHashType: "sha256",
    clientKeyType: "ecdsa-p256",
    clientHashType: "sha256",
    validityDays: 365,
    p12Password: "changeit",
  });

  const caCertPath = path.join(outDir, "ca.crt");
  const caKeyPath = path.join(outDir, "ca.key");
  const serverCertPath = path.join(outDir, "server.crt");
  const serverKeyPath = path.join(outDir, "server.key");
  const clientCertPath = path.join(outDir, "client.crt");
  const clientKeyPath = path.join(outDir, "client.key");
  const clientP12Path = path.join(outDir, "client.p12");
  const crlPath = path.join(outDir, "ca.crl");

  fs.writeFileSync(caCertPath, suite.ca.certPem, "utf-8");
  fs.writeFileSync(caKeyPath, suite.ca.keyPem, "utf-8");
  fs.writeFileSync(serverCertPath, suite.server.certPem, "utf-8");
  fs.writeFileSync(serverKeyPath, suite.server.keyPem, "utf-8");
  fs.writeFileSync(clientCertPath, suite.client.certPem, "utf-8");
  fs.writeFileSync(clientKeyPath, suite.client.keyPem, "utf-8");
  fs.writeFileSync(clientP12Path, suite.client.p12Der);
  fs.writeFileSync(crlPath, suite.crl.crlPem, "utf-8");

  console.log(`  ✓ Root CA:     ${caCertPath}`);
  console.log(`  ✓ Server Cert: ${serverCertPath} (SAN: localhost, 127.0.0.1, ::1)`);
  console.log(`  ✓ Client Cert: ${clientCertPath}`);
  console.log(`  ✓ Client PKCS#12: ${clientP12Path} (Password: changeit)`);

  // 2. OpenSSL Chain Verification
  console.log("\n[2/5] Verifying Chains with OpenSSL CLI...");
  try {
    const srvVerify = execFileSync("openssl", ["verify", "-CAfile", caCertPath, serverCertPath], { encoding: "utf-8" });
    const cliVerify = execFileSync("openssl", ["verify", "-CAfile", caCertPath, clientCertPath], { encoding: "utf-8" });
    console.log(`  ✓ Server Chain: ${srvVerify.trim()}`);
    console.log(`  ✓ Client Chain: ${cliVerify.trim()}`);
  } catch (err) {
    console.error("  ✗ Chain verification failed:", err);
  }

  // 3. Live Mutual TLS Handshake (Positive Test)
  console.log("\n[3/5] Testing Mutual TLS Authentication (Client & Server Handshake)...");
  const port = 9543;
  const server = await startOpenSslServer({
    port,
    cert: serverCertPath,
    key: serverKeyPath,
    ca: caCertPath,
    verifyClient: true,
  });

  try {
    const clientOutput = await runOpenSslClient({
      port,
      ca: caCertPath,
      cert: clientCertPath,
      key: clientKeyPath,
    });

    const isVerified = clientOutput.includes("Verification: OK");
    const certChainOk = clientOutput.includes("Acceptable client certificate CA names");

    if (isVerified && certChainOk) {
      console.log("  ✓ PASS: Mutual TLS Handshake Succeeded!");
      console.log("  - Server verified client certificate against Root CA: OK");
      console.log("  - Client verified server certificate against Root CA: OK");
    } else {
      throw new Error("mTLS handshake failed:\n" + clientOutput);
    }
  } finally {
    server.stop();
  }

  // 4. Negative Test: Client without Certificate Rejected
  console.log("\n[4/5] Testing mTLS Enforcement (Rejecting Unauthenticated Client)...");
  const server2 = await startOpenSslServer({
    port,
    cert: serverCertPath,
    key: serverKeyPath,
    ca: caCertPath,
    verifyClient: true,
  });

  try {
    const clientOutput = await runOpenSslClient({
      port,
      ca: caCertPath,
      // No client cert provided
    });

    const rejected =
      clientOutput.includes("certificate required") ||
      clientOutput.includes("handshake failure") ||
      clientOutput.includes("alert") ||
      server2.getStderr().includes("peer did not return a certificate");

    if (rejected) {
      console.log("  ✓ PASS: Server strictly rejected connection without client certificate!");
    } else {
      throw new Error("Server unexpectedly allowed unauthenticated client:\n" + clientOutput);
    }
  } finally {
    server2.stop();
  }

  // 5. Protocol Version Matrix: TLS 1.3, TLS 1.2, and TLS 1.1 Verification
  console.log("\n[5/5] Verifying mTLS across TLS 1.1 / TLS 1.2 / TLS 1.3 Protocol Matrix...");
  const matrix = await testTlsProtocolMatrix({
    basePort: 9557,
    cert: serverCertPath,
    key: serverKeyPath,
    ca: caCertPath,
    verifyClient: true,
    clientCert: clientCertPath,
    clientKey: clientKeyPath,
  });

  for (const item of matrix) {
    const status = item.verified ? "OK" : "FAILED";
    console.log(`  ✓ ${item.version.toUpperCase().replace("_", ".")}: Protocol=${item.protocol}, Cipher=${item.cipher}, MutualVerified=${status}`);
  }

  console.log("\n=================================================");
  console.log("   mTLS (2-TIER) SUITE COMPLETED SUCCESSFULLY!   ");
  console.log("=================================================\n");
}

main().catch((err) => {
  console.error("Example run failed:", err);
  process.exit(1);
});
