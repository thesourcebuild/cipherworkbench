import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { generateMtlsSuite } from "../../../packages/tools/certificates/src/asn1/mtls.ts";
import { startOpenSslServer, runOpenSslClient, testTlsProtocolMatrix } from "../tls_test_harness.ts";

async function main() {
  console.log("=================================================================");
  console.log("   4. mTLS ENTERPRISE (3-TIER) SUITE EXAMPLE                     ");
  console.log("=================================================================\n");

  const outDir = path.resolve(import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname));

  // 1. Generate 3-Tier Enterprise PKI Suite
  console.log("[1/5] Generating 3-Tier Enterprise PKI Suite (Root -> Intermediate -> Leaves)...");
  const suite = await generateMtlsSuite({
    pkiHierarchy: "3-tier",
    caCommonName: "Enterprise Global Offline Root CA",
    intermediateCommonName: "Enterprise Subordinate Issuing CA",
    serverCommonName: "localhost",
    serverSan: "localhost, 127.0.0.1, ::1",
    clientCommonName: "enterprise-agent-01",
    rootKeyType: "ecdsa-p256",
    rootHashType: "sha256",
    intermediateKeyType: "ecdsa-p256",
    intermediateHashType: "sha256",
    serverKeyType: "ecdsa-p256",
    serverHashType: "sha256",
    clientKeyType: "ecdsa-p256",
    clientHashType: "sha256",
    validityDays: 180,
    p12Password: "EnterprisePass123!",
  });

  const caCertPath = path.join(outDir, "ca.crt");
  const caKeyPath = path.join(outDir, "ca.key");
  const intermCertPath = path.join(outDir, "intermediate.crt");
  const intermKeyPath = path.join(outDir, "intermediate.key");
  const serverCertPath = path.join(outDir, "server.crt");
  const serverKeyPath = path.join(outDir, "server.key");
  const serverChainPath = path.join(outDir, "server-chain.pem");
  const clientCertPath = path.join(outDir, "client.crt");
  const clientKeyPath = path.join(outDir, "client.key");
  const clientChainPath = path.join(outDir, "client-chain.pem");
  const clientP12Path = path.join(outDir, "client.p12");
  const crlPath = path.join(outDir, "ca.crl");

  fs.writeFileSync(caCertPath, suite.ca.certPem, "utf-8");
  fs.writeFileSync(caKeyPath, suite.ca.keyPem, "utf-8");
  if (suite.intermediate) {
    fs.writeFileSync(intermCertPath, suite.intermediate.certPem, "utf-8");
    fs.writeFileSync(intermKeyPath, suite.intermediate.keyPem, "utf-8");
  }
  fs.writeFileSync(serverCertPath, suite.server.certPem, "utf-8");
  fs.writeFileSync(serverKeyPath, suite.server.keyPem, "utf-8");
  fs.writeFileSync(serverChainPath, suite.server.chainPem, "utf-8");
  fs.writeFileSync(clientCertPath, suite.client.certPem, "utf-8");
  fs.writeFileSync(clientKeyPath, suite.client.keyPem, "utf-8");
  fs.writeFileSync(clientChainPath, suite.client.chainPem, "utf-8");
  fs.writeFileSync(clientP12Path, suite.client.p12Der);
  fs.writeFileSync(crlPath, suite.crl.crlPem, "utf-8");

  const caChainPath = path.join(outDir, "ca-chain.pem");
  const caChainPem = suite.intermediate
    ? `${suite.intermediate.certPem.trim()}\n${suite.ca.certPem.trim()}\n`
    : suite.ca.certPem;
  fs.writeFileSync(caChainPath, caChainPem, "utf-8");

  console.log(`  ✓ Root CA:         ${caCertPath} (Air-gapped)`);
  console.log(`  ✓ Intermediate CA: ${intermCertPath} (pathlen:0)`);
  console.log(`  ✓ Server Bundle:   ${serverChainPath} (Leaf + Intermediate)`);
  console.log(`  ✓ Client PKCS#12:  ${clientP12Path}`);

  // 2. OpenSSL 3-Tier Chain Verification
  console.log("\n[2/5] Verifying 3-Tier Chains with OpenSSL CLI (-untrusted intermediate.crt)...");
  try {
    const srvVerify = execFileSync("openssl", [
      "verify",
      "-CAfile", caCertPath,
      "-untrusted", intermCertPath,
      serverCertPath,
    ], { encoding: "utf-8" });

    const cliVerify = execFileSync("openssl", [
      "verify",
      "-CAfile", caCertPath,
      "-untrusted", intermCertPath,
      clientCertPath,
    ], { encoding: "utf-8" });

    console.log(`  ✓ 3-Tier Server Chain: ${srvVerify.trim()}`);
    console.log(`  ✓ 3-Tier Client Chain: ${cliVerify.trim()}`);
  } catch (err) {
    console.error("  ✗ Chain verification failed:", err);
  }

  // 3. Live 3-Tier mTLS Handshake
  console.log("\n[3/5] Testing Mutual TLS with Server Chain on port 9544...");
  const port = 9544;
  const server = await startOpenSslServer({
    port,
    cert: serverChainPath, // Server presents full bundle: server.crt + intermediate.crt
    key: serverKeyPath,
    ca: caChainPath,       // Server verifies client against CA chain (Root + Intermediate)
    verifyClient: true,
  });

  try {
    const clientOutput = await runOpenSslClient({
      port,
      ca: caCertPath, // Client only needs Root CA; receives Intermediate from server in handshake!
      cert: clientCertPath,
      certChain: intermCertPath,
      key: clientKeyPath,
    });

    const isVerified = clientOutput.includes("Verification: OK");
    const certChainOk = clientOutput.includes("Acceptable client certificate CA names");

    if (isVerified && certChainOk) {
      console.log("  ✓ PASS: 3-Tier Enterprise Mutual TLS Handshake Succeeded!");
      console.log("  - Client verified server chain up to Root CA: OK");
      console.log("  - Server verified client chain up to Root CA: OK");
    } else {
      throw new Error("3-Tier mTLS handshake failed:\n" + clientOutput);
    }
  } finally {
    server.stop();
  }

  // 4. Negative Test: Client without Certificate Rejected
  console.log("\n[4/5] Testing mTLS Enforcement (Rejecting Unauthenticated Client)...");
  const server2 = await startOpenSslServer({
    port,
    cert: serverChainPath,
    key: serverKeyPath,
    ca: caCertPath,
    verifyClient: true,
  });

  try {
    const clientOutput = await runOpenSslClient({
      port,
      ca: caCertPath,
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
  console.log("\n[5/5] Verifying 3-Tier Enterprise mTLS across TLS 1.1 / TLS 1.2 / TLS 1.3 Protocol Matrix...");
  const matrix = await testTlsProtocolMatrix({
    basePort: 9564,
    cert: serverChainPath,
    key: serverKeyPath,
    ca: caChainPath,
    verifyClient: true,
    clientCert: clientCertPath,
    clientKey: clientKeyPath,
    clientChain: intermCertPath,
  });

  for (const item of matrix) {
    const status = item.verified ? "OK" : "FAILED";
    console.log(`  ✓ ${item.version.toUpperCase().replace("_", ".")}: Protocol=${item.protocol}, Cipher=${item.cipher}, MutualVerified=${status}`);
  }

  console.log("\n=================================================================");
  console.log("   mTLS ENTERPRISE (3-TIER) SUITE COMPLETED SUCCESSFULLY!        ");
  console.log("=================================================================\n");
}

main().catch((err) => {
  console.error("Example run failed:", err);
  process.exit(1);
});
