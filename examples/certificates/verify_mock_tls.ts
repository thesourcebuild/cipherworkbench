import {
  setupSuiteCerts,
  startOpenSslServer,
  runOpenSslClient,
  cleanupDir,
} from "./tls_test_harness.ts";

async function main() {
  console.log("=================================================");
  console.log("   MOCK ONE-WAY TLS SERVER & CLIENT TEST         ");
  console.log("=================================================\n");

  const certs = await setupSuiteCerts("temp_mock_tls");
  console.log(`Generated certificates in: ${certs.testDir}`);

  const port = 9543;
  console.log(`\nStarting OpenSSL mock TLS server on port ${port}...`);
  const server = await startOpenSslServer({
    port,
    cert: certs.serverCrt,
    key: certs.serverKey,
  });

  try {
    console.log(`Connecting OpenSSL mock TLS client with CA verification...`);
    const clientOutput = await runOpenSslClient({
      port,
      ca: certs.caCert,
    });

    const isVerified = clientOutput.includes("Verification: OK");
    const hasCipher = clientOutput.includes("Cipher is") || clientOutput.includes("TLS");

    if (isVerified && hasCipher) {
      console.log("\n✓ PASS: Mock TLS Server & Client Handshake Succeeded!");
      console.log("  - Client verified server certificate against Root CA: OK");
      console.log("  - TLS encrypted tunnel established successfully.");
    } else {
      throw new Error("TLS handshake verification failed:\n" + clientOutput);
    }
  } finally {
    server.stop();
    cleanupDir(certs.testDir);
  }

  console.log("\n=================================================");
  console.log("   MOCK TLS TEST COMPLETED SUCCESSFULLY!        ");
  console.log("=================================================");
}

main().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
