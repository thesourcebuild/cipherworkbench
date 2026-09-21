import { createCertificate, type CreatedCertificateResult } from "./create-cert";
import { importCaSigner, type HashAlgorithmType, type KeyAlgorithmType } from "../crypto/keys";
import { encodePkcs12Archive } from "./pkcs12";

export interface MtlsSuiteOptions {
  caCommonName?: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
  serverCommonName?: string;
  serverSan?: string;
  clientCommonName?: string;
  keyType?: KeyAlgorithmType;
  hashType?: HashAlgorithmType;
  validityDays?: number;
  p12Password?: string;
}

export interface MtlsSuiteEntity {
  certPem: string;
  certDer: Uint8Array;
  keyPem: string;
  chainPem: string;
  fingerprint: string;
  subjectDn: string;
  issuerDn: string;
}

export interface MtlsSuiteResult {
  ca: MtlsSuiteEntity;
  server: MtlsSuiteEntity & { san: string };
  client: MtlsSuiteEntity & {
    p12Der: Uint8Array;
    p12Base64: string;
    p12Password: string;
  };
  commands: {
    opensslServer: string;
    opensslClient: string;
    curlPem: string;
    curlP12: string;
    nginxConfig: string;
  };
  allInOneText: string;
  rawCa: CreatedCertificateResult;
  rawServer: CreatedCertificateResult;
  rawClient: CreatedCertificateResult;
}

/**
 * Generates an end-to-end Mutual TLS (mTLS) PKI suite:
 * 1. Self-signed Root CA (cA=TRUE, keyCertSign, cRLSign)
 * 2. Server Certificate signed by CA (serverAuth, SANs)
 * 3. Client Certificate signed by CA (clientAuth)
 * 4. Password-encrypted Client PKCS#12 (.p12) container
 * 5. Turnkey verification and server configuration commands
 */
export async function generateMtlsSuite(
  opts: MtlsSuiteOptions = {},
): Promise<MtlsSuiteResult> {
  const org = opts.organization ?? "Cipher Workbench";
  const ou = opts.organizationalUnit ?? "Security";
  const country = opts.country ?? "US";
  const state = opts.state ?? "California";
  const locality = opts.locality ?? "San Francisco";
  const keyType = opts.keyType ?? "ecdsa-p256";
  const hashType = opts.hashType ?? "sha256";
  const validityDays = opts.validityDays ?? 365;
  const p12Password = opts.p12Password ?? "changeit";

  // 1. Generate Root CA
  const caCommonName = opts.caCommonName ?? "Internal Root CA";
  const caValidityDays = Math.max(validityDays * 3, 3650); // CA valid longer
  const caResult = await createCertificate({
    commonName: caCommonName,
    organization: org,
    organizationalUnit: ou,
    country,
    state,
    locality,
    keyType,
    hashType,
    validityDays: caValidityDays,
    isCa: true,
    san: "",
    serverAuth: false,
    clientAuth: false,
  });

  // Prepare reusable CA signer
  const caSigner = await importCaSigner(caResult.certDer, caResult.keyBundle.pkcs8Bytes);

  // 2. Generate Server Certificate signed by Root CA
  const serverCommonName = opts.serverCommonName ?? "localhost";
  const serverSan = opts.serverSan ?? "localhost, 127.0.0.1";
  const serverResult = await createCertificate({
    commonName: serverCommonName,
    organization: org,
    organizationalUnit: ou,
    country,
    state,
    locality,
    keyType,
    hashType,
    validityDays,
    isCa: false,
    san: serverSan,
    serverAuth: true,
    clientAuth: false,
    issuanceMode: "ca-signed",
    caSigner,
    caCertPem: caResult.certPem,
  });

  // 3. Generate Client Certificate signed by Root CA
  const clientCommonName = opts.clientCommonName ?? "client-app-01";
  const clientResult = await createCertificate({
    commonName: clientCommonName,
    organization: org,
    organizationalUnit: ou,
    country,
    state,
    locality,
    keyType,
    hashType,
    validityDays,
    isCa: false,
    san: "",
    serverAuth: false,
    clientAuth: true,
    issuanceMode: "ca-signed",
    caSigner,
    caCertPem: caResult.certPem,
  });

  // 4. Package Client Certificate + Private Key + Root CA into PKCS#12 (.p12) container
  const p12Export = await encodePkcs12Archive({
    certDers: [clientResult.certDer, caResult.certDer],
    privateKeyDer: clientResult.keyBundle.pkcs8Bytes,
    password: p12Password,
    friendlyName: clientCommonName,
  });

  // 5. Verification & Deployment Commands
  const opensslServer = `openssl s_server -key server.key -cert server.crt -CAfile ca.crt -Verify 1 -port 8443`;
  const opensslClient = `openssl s_client -connect localhost:8443 -cert client.crt -key client.key -CAfile ca.crt`;
  const curlPem = `curl --cacert ca.crt --cert client.crt --key client.key https://localhost:8443/`;
  const curlP12 = `curl --cacert ca.crt --cert client.p12:${p12Password} https://localhost:8443/`;
  const nginxConfig = `server {
    listen 8443 ssl;
    server_name ${serverCommonName};

    ssl_certificate         /etc/ssl/certs/server.crt;
    ssl_certificate_key     /etc/ssl/private/server.key;
    ssl_client_certificate  /etc/ssl/certs/ca.crt;
    ssl_verify_client       on;

    location / {
        proxy_set_header X-Client-DN $ssl_client_s_dn;
        proxy_set_header X-Client-Verify $ssl_client_verify;
        proxy_pass http://127.0.0.1:8080;
    }
}`;

  // 6. Assembled All-In-One Text
  const allInOneText = [
    `# ==============================================================================`,
    `# CIPHER WORKBENCH - FULL mTLS PKI SUITE`,
    `# ==============================================================================`,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# 1. ROOT CERTIFICATE AUTHORITY (ca.crt)`,
    `# Subject: ${caResult.subjectDn}`,
    `# SHA-256 Fingerprint: ${caResult.fingerprintSha256}`,
    `# ------------------------------------------------------------------------------`,
    caResult.certPem,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# 2. ROOT CA PRIVATE KEY (ca.key) - KEEP SECRET`,
    `# ------------------------------------------------------------------------------`,
    caResult.privateKeyPem,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# 3. SERVER CERTIFICATE (server.crt) - Signed by Root CA`,
    `# Subject: ${serverResult.subjectDn}`,
    `# SANs: ${serverSan}`,
    `# SHA-256 Fingerprint: ${serverResult.fingerprintSha256}`,
    `# ------------------------------------------------------------------------------`,
    serverResult.certPem,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# 4. SERVER PRIVATE KEY (server.key) - KEEP SECRET`,
    `# ------------------------------------------------------------------------------`,
    serverResult.privateKeyPem,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# 5. SERVER FULL CHAIN (server-chain.pem)`,
    `# ------------------------------------------------------------------------------`,
    serverResult.chainPem ?? `${serverResult.certPem}\n${caResult.certPem}`,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# 6. CLIENT CERTIFICATE (client.crt) - Signed by Root CA`,
    `# Subject: ${clientResult.subjectDn}`,
    `# SHA-256 Fingerprint: ${clientResult.fingerprintSha256}`,
    `# ------------------------------------------------------------------------------`,
    clientResult.certPem,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# 7. CLIENT PRIVATE KEY (client.key) - KEEP SECRET`,
    `# ------------------------------------------------------------------------------`,
    clientResult.privateKeyPem,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# 8. CLIENT PKCS#12 ARCHIVE (client.p12 - Base64) - Password: ${p12Password}`,
    `# ------------------------------------------------------------------------------`,
    p12Export.base64,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# VERIFICATION COMMANDS`,
    `# ------------------------------------------------------------------------------`,
    `# Start mock TLS server requiring client cert:`,
    `#   ${opensslServer}`,
    `# Test connection using cURL:`,
    `#   ${curlPem}`,
    `# Or using PKCS#12:`,
    `#   ${curlP12}`,
  ].join("\n");

  return {
    ca: {
      certPem: caResult.certPem,
      certDer: caResult.certDer,
      keyPem: caResult.privateKeyPem,
      chainPem: caResult.certPem,
      fingerprint: caResult.fingerprintSha256,
      subjectDn: caResult.subjectDn,
      issuerDn: caResult.issuerDn,
    },
    server: {
      certPem: serverResult.certPem,
      certDer: serverResult.certDer,
      keyPem: serverResult.privateKeyPem,
      chainPem: serverResult.chainPem ?? `${serverResult.certPem}\n${caResult.certPem}`,
      fingerprint: serverResult.fingerprintSha256,
      subjectDn: serverResult.subjectDn,
      issuerDn: serverResult.issuerDn,
      san: serverSan,
    },
    client: {
      certPem: clientResult.certPem,
      certDer: clientResult.certDer,
      keyPem: clientResult.privateKeyPem,
      chainPem: clientResult.chainPem ?? `${clientResult.certPem}\n${caResult.certPem}`,
      fingerprint: clientResult.fingerprintSha256,
      subjectDn: clientResult.subjectDn,
      issuerDn: clientResult.issuerDn,
      p12Der: p12Export.der,
      p12Base64: p12Export.base64,
      p12Password,
    },
    commands: {
      opensslServer,
      opensslClient,
      curlPem,
      curlP12,
      nginxConfig,
    },
    allInOneText,
    rawCa: caResult,
    rawServer: serverResult,
    rawClient: clientResult,
  };
}
