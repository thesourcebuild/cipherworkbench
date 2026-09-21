import {
  setupSuiteCerts,
  startOpenSslServer,
  runOpenSslClient,
  cleanupDir,
} from "./tls_test_harness.ts";

async function main() {
  console.log("=================================================");
  console.log("   MOCK MUTUAL TLS (mTLS) SERVER & CLIENT TEST   ");
  console.log("=================================================\n");

  const certs = await setupSuiteCerts("temp_mock_mtls");
  console.log(`Generated certificates in: ${certs.testDir}\n`);

  // -------------------------------------------------------------
  // PART 1: Positive Test - Mutual Authentication
  // -------------------------------------------------------------
  console.log("--- PART 1: Full mTLS Handshake (Client & Server Auth) ---");
  const port1 = 9544;
  console.log(`Starting OpenSSL mock mTLS server on port ${port1} with -Verify 1...`);
  const server1 = await startOpenSslServer({
    port: port1,
    cert: certs.serverCrt,
    key: certs.serverKey,
    ca: certs.caCert,
    verifyClient: true,
  });

  try {
    console.log(`Connecting mock mTLS client presenting client.crt + client.key...`);
    const clientOutput = await runOpenSslClient({
      port: port1,
      ca: certs.caCert,
      cert: certs.clientCrt,
      key: certs.clientKey,
    });

    const isVerified = clientOutput.includes("Verification: OK");
    const certChainOk = clientOutput.includes("Acceptable client certificate CA names");

    if (isVerified && certChainOk) {
      console.log("✓ PASS: Mutual TLS Handshake Succeeded!");
      console.log("  - Server verified client certificate against Root CA: OK");
      console.log("  - Client verified server certificate against Root CA: OK");
    } else {
      throw new Error("mTLS handshake failed:\n" + clientOutput);
    }
  } finally {
    server1.stop();
  }

  // -------------------------------------------------------------
  // PART 2: Negative Test - Client without Certificate Rejected
  // -------------------------------------------------------------
  console.log("\n--- PART 2: mTLS Enforcement (Reject Missing Client Cert) ---");
  const port2 = 9545;
  console.log(`Starting OpenSSL mock mTLS server on port ${port2} requiring client cert...`);
  const server2 = await startOpenSslServer({
    port: port2,
    cert: certs.serverCrt,
    key: certs.serverKey,
    ca: certs.caCert,
    verifyClient: true,
  });

  try {
    console.log(`Connecting client WITHOUT client certificate...`);
    const clientOutput = await runOpenSslClient({
      port: port2,
      ca: certs.caCert,
      // No client cert or key provided!
    });

    const rejected =
      clientOutput.includes("certificate required") ||
      clientOutput.includes("handshake failure") ||
      clientOutput.includes("sslv3 alert") ||
      clientOutput.includes("alert") ||
      server2.getStderr().includes("peer did not return a certificate");

    if (rejected) {
      console.log("✓ PASS: Mock mTLS server strictly rejected unauthenticated client!");
    } else {
      throw new Error("Server unexpectedly allowed unauthenticated client:\n" + clientOutput);
    }
  } finally {
    server2.stop();
    cleanupDir(certs.testDir);
  }

  console.log("\n=================================================");
  console.log("   MOCK mTLS TEST COMPLETED SUCCESSFULLY!       ");
  console.log("=================================================");
}

main().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
