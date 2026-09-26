import { createCertificate, type CreatedCertificateResult } from "./create-cert";
import { importCaSigner, type HashAlgorithmType, type KeyAlgorithmType } from "../crypto/keys";
import { encodePkcs12Archive } from "./pkcs12";
import { createCrl, CrlReasonCode, type CreatedCrl } from "./crl";
import { spkiToOpenSsh, type OpenSshKeyResult } from "../crypto/openssh";
import { spkiToJwk, formatJwks, type Jwk } from "../crypto/jwk";

export interface MtlsSuiteOptions {
  caCommonName?: string;
  intermediateCommonName?: string;
  pkiHierarchy?: "2-tier" | "3-tier";
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
  serverCommonName?: string;
  serverSan?: string;
  clientCommonName?: string;
  rootKeyType?: KeyAlgorithmType;
  rootHashType?: HashAlgorithmType;
  intermediateKeyType?: KeyAlgorithmType;
  intermediateHashType?: HashAlgorithmType;
  serverKeyType?: KeyAlgorithmType;
  serverHashType?: HashAlgorithmType;
  clientKeyType?: KeyAlgorithmType;
  clientHashType?: HashAlgorithmType;
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
  keyType: KeyAlgorithmType;
  signatureHash: HashAlgorithmType;
}

export interface MtlsSuiteResult {
  pkiHierarchy: "2-tier" | "3-tier";
  ca: MtlsSuiteEntity;
  intermediate?: MtlsSuiteEntity;
  server: MtlsSuiteEntity & { san: string };
  client: MtlsSuiteEntity & {
    p12Der: Uint8Array;
    p12Base64: string;
    p12Password: string;
  };
  crl: CreatedCrl;
  ssh: OpenSshKeyResult;
  jwksJson: string;
  commands: {
    opensslServer: string;
    opensslClient: string;
    curlPem: string;
    curlP12: string;
    nginxConfig: string;
    k8sSecret: string;
    caddyConfig: string;
    traefikConfig: string;
    haproxyConfig: string;
    envoyConfig: string;
  };
  allInOneText: string;
  rawCa: CreatedCertificateResult;
  rawIntermediate?: CreatedCertificateResult;
  rawServer: CreatedCertificateResult;
  rawClient: CreatedCertificateResult;
}

/**
 * Generates an end-to-end Mutual TLS (mTLS) PKI suite:
 * - 2-tier: Root CA ➔ Server & Client
 * - 3-tier: Root CA ➔ Intermediate Issuing CA ➔ Server & Client
 * - Password-encrypted Client PKCS#12 (.p12) container
 * - Turnkey verification and cloud deployment configs (NGINX, K8s, Caddy, Traefik, HAProxy, Envoy)
 */
export async function generateMtlsSuite(opts: MtlsSuiteOptions = {}): Promise<MtlsSuiteResult> {
  const pkiHierarchy = opts.pkiHierarchy ?? "2-tier";
  const org = opts.organization ?? "Cipher Workbench";
  const ou = opts.organizationalUnit ?? "Security";
  const country = opts.country ?? "US";
  const state = opts.state ?? "California";
  const locality = opts.locality ?? "San Francisco";
  const rootKeyType = opts.rootKeyType ?? "ecdsa-p256";
  const rootHashType = opts.rootHashType ?? "sha256";
  const intermediateKeyType = opts.intermediateKeyType ?? "ecdsa-p256";
  const intermediateHashType = opts.intermediateHashType ?? "sha256";
  const serverKeyType = opts.serverKeyType ?? "ecdsa-p256";
  const serverHashType = opts.serverHashType ?? "sha256";
  const clientKeyType = opts.clientKeyType ?? "ecdsa-p256";
  const clientHashType = opts.clientHashType ?? "sha256";
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
    keyType: rootKeyType,
    hashType: rootHashType,
    validityDays: caValidityDays,
    isCa: true,
    san: "",
    serverAuth: false,
    clientAuth: false,
  });

  let rawIntermediate: CreatedCertificateResult | undefined;
  let intermediateEntity: MtlsSuiteEntity | undefined;
  let issuingCertPem = caResult.certPem;
  let issuingCertDer = caResult.certDer;
  let issuingKeyDer = caResult.keyBundle.pkcs8Bytes;
  let caCertChainForClient = [caResult.certDer];

  // 2. Optional: Generate Intermediate CA (3-tier mode)
  if (pkiHierarchy === "3-tier") {
    const intermediateCommonName = opts.intermediateCommonName ?? "Internal Issuing CA";
    const intermediateValidityDays = Math.max(validityDays * 2, 1825); // 5 years
    const rootCaSigner = await importCaSigner(
      caResult.certDer,
      caResult.keyBundle.pkcs8Bytes,
      intermediateHashType,
    );
    rawIntermediate = await createCertificate({
      commonName: intermediateCommonName,
      organization: org,
      organizationalUnit: ou,
      country,
      state,
      locality,
      keyType: intermediateKeyType,
      hashType: intermediateHashType,
      validityDays: intermediateValidityDays,
      isCa: true,
      pathLenConstraint: 0, // Cannot issue further CAs, only leaf certs
      san: "",
      serverAuth: false,
      clientAuth: false,
      issuanceMode: "ca-signed",
      caSigner: rootCaSigner,
      caCertPem: caResult.certPem,
    });

    issuingCertPem = rawIntermediate.certPem;
    issuingCertDer = rawIntermediate.certDer;
    issuingKeyDer = rawIntermediate.keyBundle.pkcs8Bytes;
    caCertChainForClient = [rawIntermediate.certDer, caResult.certDer];

    intermediateEntity = {
      certPem: rawIntermediate.certPem,
      certDer: rawIntermediate.certDer,
      keyPem: rawIntermediate.privateKeyPem,
      chainPem: `${rawIntermediate.certPem}\n${caResult.certPem}`,
      fingerprint: rawIntermediate.fingerprintSha256,
      subjectDn: rawIntermediate.subjectDn,
      issuerDn: rawIntermediate.issuerDn,
      keyType: intermediateKeyType,
      signatureHash: intermediateHashType,
    };
  }

  // 3. Generate Server Certificate
  const serverCommonName = opts.serverCommonName ?? "localhost";
  const serverSan = opts.serverSan ?? "localhost, 127.0.0.1";
  const serverSigner = await importCaSigner(issuingCertDer, issuingKeyDer, serverHashType);
  const serverResult = await createCertificate({
    commonName: serverCommonName,
    organization: org,
    organizationalUnit: ou,
    country,
    state,
    locality,
    keyType: serverKeyType,
    hashType: serverHashType,
    validityDays,
    isCa: false,
    san: serverSan,
    serverAuth: true,
    clientAuth: false,
    issuanceMode: "ca-signed",
    caSigner: serverSigner,
    caCertPem: issuingCertPem,
  });

  const serverChainPem =
    pkiHierarchy === "3-tier" && rawIntermediate
      ? `${serverResult.certPem}\n${rawIntermediate.certPem}\n${caResult.certPem}`
      : `${serverResult.certPem}\n${caResult.certPem}`;

  // 4. Generate Client Certificate
  const clientCommonName = opts.clientCommonName ?? "client-app-01";
  const clientSigner = await importCaSigner(issuingCertDer, issuingKeyDer, clientHashType);
  const clientResult = await createCertificate({
    commonName: clientCommonName,
    organization: org,
    organizationalUnit: ou,
    country,
    state,
    locality,
    keyType: clientKeyType,
    hashType: clientHashType,
    validityDays,
    isCa: false,
    san: "",
    serverAuth: false,
    clientAuth: true,
    issuanceMode: "ca-signed",
    caSigner: clientSigner,
    caCertPem: issuingCertPem,
  });

  const clientChainPem =
    pkiHierarchy === "3-tier" && rawIntermediate
      ? `${clientResult.certPem}\n${rawIntermediate.certPem}\n${caResult.certPem}`
      : `${clientResult.certPem}\n${caResult.certPem}`;

  // 5. Package Client Certificate + Private Key + CAs into PKCS#12 (.p12) container
  const p12Export = await encodePkcs12Archive({
    certDers: [clientResult.certDer, ...caCertChainForClient],
    privateKeyDer: clientResult.keyBundle.pkcs8Bytes,
    password: p12Password,
    friendlyName: clientCommonName,
  });

  // 6. Verification & Deployment Commands
  const opensslServer = `openssl s_server -key server.key -cert server.crt -CAfile ca.crt -Verify 1 -port 8443`;
  const opensslClient = `openssl s_client -connect localhost:8443 -cert client.crt -key client.key -CAfile ca.crt`;
  const curlPem = `curl --cacert ca.crt --cert client.crt --key client.key https://localhost:8443/`;
  const curlP12 = `curl --cacert ca.crt --cert client.p12:${p12Password} https://localhost:8443/`;

  // Server & Cloud Config Templates
  const nginxConfig = `server {
    listen 8443 ssl;
    server_name ${serverCommonName};

    ssl_certificate         /etc/ssl/certs/server-chain.pem;
    ssl_certificate_key     /etc/ssl/private/server.key;
    ssl_client_certificate  /etc/ssl/certs/ca.crt;
    ssl_verify_client       on;

    location / {
        proxy_set_header X-Client-DN $ssl_client_s_dn;
        proxy_set_header X-Client-Verify $ssl_client_verify;
        proxy_pass http://127.0.0.1:8080;
    }
}`;

  const k8sSecret = `apiVersion: v1
kind: Secret
metadata:
  name: mtls-server-secret
  namespace: default
type: kubernetes.io/tls
data:
  tls.crt: ${btoa(serverChainPem)}
  tls.key: ${btoa(serverResult.privateKeyPem)}
  ca.crt: ${btoa(caResult.certPem)}
---
apiVersion: v1
kind: Secret
metadata:
  name: mtls-client-secret
  namespace: default
type: Opaque
data:
  tls.crt: ${btoa(clientChainPem)}
  tls.key: ${btoa(clientResult.privateKeyPem)}
  ca.crt: ${btoa(caResult.certPem)}
  client.p12: ${p12Export.base64}
`;

  const caddyConfig = `${serverCommonName}:8443 {
    tls /etc/ssl/certs/server-chain.pem /etc/ssl/private/server.key {
        client_auth {
            mode require_and_verify
            trusted_ca_cert_file /etc/ssl/certs/ca.crt
        }
    }
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Client-Cert-Subject {http.request.tls.client.subject}
    }
}`;

  const traefikConfig = `tls:
  options:
    mtls-policy:
      clientAuth:
        caFiles:
          - /etc/ssl/certs/ca.crt
        clientAuthType: RequireAndVerifyClientCert
  certificates:
    - certFile: /etc/ssl/certs/server-chain.pem
      keyFile: /etc/ssl/private/server.key
`;

  const haproxyConfig = `frontend mtls_in
    bind :8443 ssl crt /etc/ssl/certs/server-chain.pem ca-file /etc/ssl/certs/ca.crt verify required
    http-request set-header X-SSL-Client-DN %{+Q}[ssl_c_s_dn]
    default_backend app_servers

backend app_servers
    server app1 127.0.0.1:8080
`;

  const envoyConfig = `static_resources:
  listeners:
  - name: mtls_listener
    address:
      socket_address: { address: 0.0.0.0, port_value: 8443 }
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificates:
            - certificate_chain: { filename: "/etc/ssl/certs/server-chain.pem" }
              private_key: { filename: "/etc/ssl/private/server.key" }
            validation_context:
              trusted_ca: { filename: "/etc/ssl/certs/ca.crt" }
              require_client_certificate: true
`;

  // 7. Assembled All-In-One Text
  const textParts: string[] = [
    `# ==============================================================================`,
    `# CIPHER WORKBENCH - FULL mTLS PKI SUITE (${pkiHierarchy.toUpperCase()})`,
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
  ];

  if (pkiHierarchy === "3-tier" && rawIntermediate) {
    textParts.push(
      `# ------------------------------------------------------------------------------`,
      `# INTERMEDIATE ISSUING CA (intermediate.crt)`,
      `# Subject: ${rawIntermediate.subjectDn}`,
      `# Issuer: ${rawIntermediate.issuerDn}`,
      `# SHA-256 Fingerprint: ${rawIntermediate.fingerprintSha256}`,
      `# ------------------------------------------------------------------------------`,
      rawIntermediate.certPem,
      ``,
      `# ------------------------------------------------------------------------------`,
      `# INTERMEDIATE CA PRIVATE KEY (intermediate.key) - KEEP SECRET`,
      `# ------------------------------------------------------------------------------`,
      rawIntermediate.privateKeyPem,
      ``,
    );
  }

  textParts.push(
    `# ------------------------------------------------------------------------------`,
    `# SERVER CERTIFICATE (server.crt) - Signed by ${pkiHierarchy === "3-tier" ? "Intermediate CA" : "Root CA"}`,
    `# Subject: ${serverResult.subjectDn}`,
    `# SANs: ${serverSan}`,
    `# SHA-256 Fingerprint: ${serverResult.fingerprintSha256}`,
    `# ------------------------------------------------------------------------------`,
    serverResult.certPem,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# SERVER PRIVATE KEY (server.key) - KEEP SECRET`,
    `# ------------------------------------------------------------------------------`,
    serverResult.privateKeyPem,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# SERVER FULL CHAIN (server-chain.pem)`,
    `# ------------------------------------------------------------------------------`,
    serverChainPem,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# CLIENT CERTIFICATE (client.crt) - Signed by ${pkiHierarchy === "3-tier" ? "Intermediate CA" : "Root CA"}`,
    `# Subject: ${clientResult.subjectDn}`,
    `# SHA-256 Fingerprint: ${clientResult.fingerprintSha256}`,
    `# ------------------------------------------------------------------------------`,
    clientResult.certPem,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# CLIENT PRIVATE KEY (client.key) - KEEP SECRET`,
    `# ------------------------------------------------------------------------------`,
    clientResult.privateKeyPem,
    ``,
    `# ------------------------------------------------------------------------------`,
    `# CLIENT PKCS#12 ARCHIVE (client.p12 - Base64) - Password: ${p12Password}`,
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
  );

  // 6. Generate RFC 5280 X.509 v2 CRL for the Root CA
  const crlSigner = await importCaSigner(
    caResult.certDer,
    caResult.keyBundle.pkcs8Bytes,
    rootHashType,
  );
  const crlResult = await createCrl({
    signer: crlSigner,
    crlNumber: 1,
    revokedCertificates: [
      {
        serialNumber: "0xDEADBEEF",
        revocationDate: new Date(),
        reasonCode: CrlReasonCode.KeyCompromise,
      },
    ],
  });

  // 7. Generate OpenSSH and JWK/JWKS representations
  const clientSsh = spkiToOpenSsh(
    clientResult.keyBundle.spkiBytes,
    clientKeyType,
    clientCommonName,
  );
  const jwksList: Jwk[] = [spkiToJwk(caResult.keyBundle.spkiBytes, rootKeyType, "ca-root")];
  if (rawIntermediate) {
    jwksList.push(
      spkiToJwk(rawIntermediate.keyBundle.spkiBytes, intermediateKeyType, "intermediate-ca"),
    );
  }
  jwksList.push(
    spkiToJwk(serverResult.keyBundle.spkiBytes, serverKeyType, "server-tls"),
    spkiToJwk(clientResult.keyBundle.spkiBytes, clientKeyType, "client-app"),
  );
  const jwksJson = formatJwks(jwksList);

  return {
    pkiHierarchy,
    crl: crlResult,
    ssh: clientSsh,
    jwksJson,
    ca: {
      certPem: caResult.certPem,
      certDer: caResult.certDer,
      keyPem: caResult.privateKeyPem,
      chainPem: caResult.certPem,
      fingerprint: caResult.fingerprintSha256,
      subjectDn: caResult.subjectDn,
      issuerDn: caResult.issuerDn,
      keyType: rootKeyType,
      signatureHash: rootHashType,
    },
    intermediate: intermediateEntity,
    server: {
      certPem: serverResult.certPem,
      certDer: serverResult.certDer,
      keyPem: serverResult.privateKeyPem,
      chainPem: serverChainPem,
      fingerprint: serverResult.fingerprintSha256,
      subjectDn: serverResult.subjectDn,
      issuerDn: serverResult.issuerDn,
      keyType: serverKeyType,
      signatureHash: serverHashType,
      san: serverSan,
    },
    client: {
      certPem: clientResult.certPem,
      certDer: clientResult.certDer,
      keyPem: clientResult.privateKeyPem,
      chainPem: clientChainPem,
      fingerprint: clientResult.fingerprintSha256,
      subjectDn: clientResult.subjectDn,
      issuerDn: clientResult.issuerDn,
      keyType: clientKeyType,
      signatureHash: clientHashType,
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
      k8sSecret,
      caddyConfig,
      traefikConfig,
      haproxyConfig,
      envoyConfig,
    },
    allInOneText: textParts.join("\n"),
    rawCa: caResult,
    rawIntermediate,
    rawServer: serverResult,
    rawClient: clientResult,
  };
}
