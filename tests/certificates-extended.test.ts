import { describe, expect, it } from "vitest";
import {
  generateKubernetesTlsSecret,
  generateNginxTlsConfig,
  generateCaddyTlsConfig,
  generateDockerComposeConfig,
  generateApacheTlsConfig,
  generateEnvoyTlsConfig,
  generateHaproxyTlsConfig,
  generateCloudImportCommands,
  generatePkiHierarchyDiagram,
  type PkiGraphNode,
  createCertificate,
  parseX509Certificate,
  createCsr,
  signCsr,
  createCrl,
  parseX509Crl,
  CrlReasonCode,
  importCaSigner,
  createSpec,
} from "@ocs/certificates";
import { loadTool } from "@ocs/registry";

describe("Cloud-Native & Server Config Generators", () => {
  const dummyCertPem =
    "-----BEGIN CERTIFICATE-----\nMIIB...fakeCert...\n-----END CERTIFICATE-----";
  const dummyKeyPem =
    "-----BEGIN PRIVATE KEY-----\nMIIE...fakeKey...\n-----END PRIVATE KEY-----";
  const dummyCaPem =
    "-----BEGIN CERTIFICATE-----\nMIIB...fakeCa...\n-----END CERTIFICATE-----";

  it("generates valid Kubernetes TLS Secret manifests with base64 encoded data and CA ConfigMap", () => {
    const yaml = generateKubernetesTlsSecret({
      certPem: dummyCertPem,
      keyPem: dummyKeyPem,
      caPem: dummyCaPem,
      secretName: "my-service-tls",
      namespace: "production",
      serverName: "api.internal.net",
    });

    expect(yaml).toContain("apiVersion: v1");
    expect(yaml).toContain("kind: Secret");
    expect(yaml).toContain("name: my-service-tls");
    expect(yaml).toContain("namespace: production");
    expect(yaml).toContain("type: kubernetes.io/tls");
    expect(yaml).toContain("tls.crt:");
    expect(yaml).toContain("tls.key:");

    // Verify CA ConfigMap is generated
    expect(yaml).toContain("kind: ConfigMap");
    expect(yaml).toContain("name: my-service-tls-ca");
    expect(yaml).toContain("ca.crt: |");

    // Verify Ingress resource snippet is generated
    expect(yaml).toContain("kind: Ingress");
    expect(yaml).toContain("secretName: my-service-tls");
    expect(yaml).toContain("host: api.internal.net");
  });

  it("generates production-ready Nginx TLS and mTLS reverse proxy configurations", () => {
    // Standard TLS
    const nginxStd = generateNginxTlsConfig({
      serverName: "vault.internal",
      certFilename: "vault.crt",
      keyFilename: "vault.key",
      chainFilename: "chain.pem",
    });
    expect(nginxStd).toContain("server_name vault.internal;");
    expect(nginxStd).toContain("ssl_certificate /etc/nginx/ssl/chain.pem;");
    expect(nginxStd).toContain("ssl_certificate_key /etc/nginx/ssl/vault.key;");
    expect(nginxStd).toContain("ssl_protocols TLSv1.2 TLSv1.3;");
    expect(nginxStd).toContain("Strict-Transport-Security");

    // mTLS
    const nginxMtls = generateNginxTlsConfig({
      serverName: "mtls.internal",
      certFilename: "server.crt",
      keyFilename: "server.key",
      caFilename: "ca.crt",
      isMtls: true,
    });
    expect(nginxMtls).toContain("ssl_client_certificate /etc/nginx/ssl/ca.crt;");
    expect(nginxMtls).toContain("ssl_verify_client on;");
    expect(nginxMtls).toContain("proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;");
  });

  it("generates turnkey Caddyfile configurations with mTLS client_auth", () => {
    const caddy = generateCaddyTlsConfig({
      serverName: "secure.internal",
      certFilename: "server.crt",
      keyFilename: "server.key",
      caFilename: "ca.crt",
      isMtls: true,
    });
    expect(caddy).toContain("secure.internal:443 {");
    expect(caddy).toContain("tls /etc/caddy/ssl/server.crt /etc/caddy/ssl/server.key {");
    expect(caddy).toContain("client_auth {");
    expect(caddy).toContain("mode require_and_verify");
    expect(caddy).toContain("trusted_ca_cert_file /etc/caddy/ssl/ca.crt");
  });

  it("generates turnkey docker-compose.yaml with nginx tls container", () => {
    const compose = generateDockerComposeConfig({
      certFilename: "server.crt",
      keyFilename: "server.key",
      caFilename: "ca.crt",
    });
    expect(compose).toContain("services:");
    expect(compose).toContain("web:");
    expect(compose).toContain("image: nginx:alpine");
    expect(compose).toContain("443:443");
    expect(compose).toContain("./server.crt:/etc/nginx/ssl/server.crt:ro");
    expect(compose).toContain("./server.key:/etc/nginx/ssl/server.key:ro");
    expect(compose).toContain("./ca.crt:/etc/nginx/ssl/ca.crt:ro");
  });

  it("generates Apache httpd-ssl.conf VirtualHost with optional mTLS", () => {
    const apache = generateApacheTlsConfig({
      serverName: "apache.local",
      certFilename: "cert.crt",
      keyFilename: "cert.key",
      chainFilename: "chain.pem",
      caFilename: "ca.crt",
      isMtls: true,
    });
    expect(apache).toContain("<VirtualHost *:443>");
    expect(apache).toContain("ServerName apache.local");
    expect(apache).toContain("SSLEngine on");
    expect(apache).toContain("SSLCertificateFile \"/etc/ssl/certs/chain.pem\"");
    expect(apache).toContain("SSLCertificateKeyFile \"/etc/ssl/private/cert.key\"");
    expect(apache).toContain("SSLCACertificateFile \"/etc/ssl/certs/ca.crt\"");
    expect(apache).toContain("SSLVerifyClient require");
  });

  it("generates Envoy v3 downstream transport socket YAML", () => {
    const envoy = generateEnvoyTlsConfig({
      serverName: "envoy.internal",
      certFilename: "server.crt",
      keyFilename: "server.key",
      chainFilename: "chain.pem",
      caFilename: "ca.crt",
      isMtls: true,
    });
    expect(envoy).toContain("name: envoy.transport_sockets.tls");
    expect(envoy).toContain("DownstreamTlsContext");
    expect(envoy).toContain("certificate_chain: { filename: \"/etc/ssl/certs/chain.pem\" }");
    expect(envoy).toContain("trusted_ca: { filename: \"/etc/ssl/certs/ca.crt\" }");
    expect(envoy).toContain("require_client_certificate: true");
  });

  it("generates HAProxy frontend bind configuration", () => {
    const haproxy = generateHaproxyTlsConfig({
      serverName: "haproxy.internal",
      certFilename: "server.crt",
      keyFilename: "server.key",
      caFilename: "ca.crt",
      isMtls: true,
    });
    expect(haproxy).toContain("frontend https_in");
    expect(haproxy).toContain("bind :443 ssl crt /etc/haproxy/certs/server.crt ca-file /etc/haproxy/certs/ca.crt verify required");
  });

  it("generates cloud import commands for AWS ACM, Vault, GCP, Azure, and Java JKS keytool", () => {
    const script = generateCloudImportCommands({
      certFilename: "app.crt",
      keyFilename: "app.key",
      chainFilename: "chain.pem",
      caFilename: "ca.crt",
      p12Filename: "client.p12",
      p12Password: "secretPass",
      alias: "app-cert",
    });

    // AWS ACM
    expect(script).toContain("aws acm import-certificate");
    expect(script).toContain("--certificate fileb://chain.pem");
    expect(script).toContain("--private-key fileb://app.key");
    expect(script).toContain("--certificate-chain fileb://ca.crt");

    // HashiCorp Vault
    expect(script).toContain("vault write secret/data/tls/app-cert");

    // Google Cloud Certificate Manager
    expect(script).toContain("gcloud certificate-manager certificates create app-cert");

    // Azure Key Vault
    expect(script).toContain("az keyvault certificate import");

    // Java JDK keytool PKCS#12 to JKS conversion
    expect(script).toContain("keytool -importkeystore");
    expect(script).toContain("-srckeystore client.p12");
    expect(script).toContain("-srcstoretype PKCS12");
    expect(script).toContain("-destkeystore keystore.jks");
    expect(script).toContain("-deststoretype JKS");
  });
});

describe("Visual PKI Trust Hierarchy Diagram", () => {
  it("renders 1-tier Self-Signed certificate ASCII diagram", () => {
    const nodes: PkiGraphNode[] = [
      {
        title: "localhost",
        role: "Self-Signed",
        subjectDn: "CN=localhost, O=Acme",
        keyType: "ECDSA-P256",
        fingerprintSha256: "AA:BB:CC:DD:EE:FF:11:22:33:44:55:66",
        validityRange: "365 days",
        san: "localhost, 127.0.0.1",
      },
    ];
    const diagram = generatePkiHierarchyDiagram(nodes);
    expect(diagram).toContain("[Self-Signed Certificate: localhost]");
    expect(diagram).toContain("CN=localhost, O=Acme");
    expect(diagram).toContain("ECDSA-P256");
    expect(diagram).toContain("365 days");
  });

  it("renders 2-tier (Root CA -> Leaf) ASCII diagram", () => {
    const nodes: PkiGraphNode[] = [
      {
        title: "Internal Root CA",
        role: "Root CA",
        subjectDn: "CN=Internal Root CA",
        keyType: "RSA-4096",
        fingerprintSha256: "11:22:33:44:55:66:77:88",
        validityRange: "3650 days",
        isCa: true,
      },
      {
        title: "web-server",
        role: "Server Leaf",
        subjectDn: "CN=web-server",
        keyType: "ECDSA-P256",
        fingerprintSha256: "AA:BB:CC:DD:EE:FF",
        validityRange: "365 days",
        san: "web.internal",
      },
    ];
    const diagram = generatePkiHierarchyDiagram(nodes);
    expect(diagram).toContain("Tier 1: Root Certificate Authority");
    expect(diagram).toContain("[signs]");
    expect(diagram).toContain("End-Entity / Leaf Server: web-server");
  });

  it("renders 3-tier mTLS (Root CA -> Intermediate CA -> Server + Client) diagram", () => {
    const nodes: PkiGraphNode[] = [
      {
        title: "Global Root CA",
        role: "Root CA",
        subjectDn: "CN=Global Root CA",
        keyType: "ECDSA-P384",
        fingerprintSha256: "01:02:03:04:05:06",
        validityRange: "7300 days",
        isCa: true,
      },
      {
        title: "Issuing CA 01",
        role: "Intermediate CA",
        subjectDn: "CN=Issuing CA 01",
        keyType: "ECDSA-P256",
        fingerprintSha256: "07:08:09:0A:0B:0C",
        validityRange: "1825 days",
        isCa: true,
        pathLenConstraint: 0,
      },
      {
        title: "TLS Server",
        role: "Server Leaf",
        subjectDn: "CN=api.service.internal",
        keyType: "ECDSA-P256",
        fingerprintSha256: "10:11:12:13:14:15",
        validityRange: "90 days",
        san: "api.service.internal",
      },
      {
        title: "mTLS Client",
        role: "Client Leaf",
        subjectDn: "CN=workload-agent-01",
        keyType: "ECDSA-P256",
        fingerprintSha256: "20:21:22:23:24:25",
        validityRange: "90 days",
      },
    ];
    const diagram = generatePkiHierarchyDiagram(nodes);
    expect(diagram).toContain("Tier 1: Root Certificate Authority");
    expect(diagram).toContain("Tier 2: Intermediate Issuing CA");
    expect(diagram).toContain("Server Leaf: TLS Server");
    expect(diagram).toContain("Client Leaf: mTLS Client");
  });
});

describe("Advanced Enterprise X.509 v3 Extensions", () => {
  it("encodes and parses RFC 5280 Name Constraints (Critical) permitted and excluded subtrees", async () => {
    const cert = await createCertificate({
      commonName: "Restricted Enterprise Intermediate CA",
      organization: "Enterprise Corp",
      isCa: true,
      keyType: "ecdsa-p256",
      hashType: "sha256",
      validityDays: 730,
      nameConstraintsPermitted: ".corp.internal, .dev.internal",
      nameConstraintsExcluded: "restricted.corp.internal",
    });

    const parsed = parseX509Certificate(cert.certDer);

    // Verify Name Constraints extension is present and marked critical
    const ncExt = parsed.extensions.all.find((e: { oid: string }) => e.oid === "2.5.29.30");
    expect(ncExt).toBeDefined();
    expect(ncExt?.critical).toBe(true);

    expect(parsed.extensions.nameConstraints).toBeDefined();
    expect(parsed.extensions.nameConstraints?.permittedSubtrees).toContain(".corp.internal");
    expect(parsed.extensions.nameConstraints?.permittedSubtrees).toContain(".dev.internal");
    expect(parsed.extensions.nameConstraints?.excludedSubtrees).toContain("restricted.corp.internal");
  });

  it("encodes and parses RFC 5280 Certificate Policies with CPS URL qualifier", async () => {
    const cert = await createCertificate({
      commonName: "TLS Web Server",
      keyType: "ecdsa-p256",
      hashType: "sha256",
      validityDays: 90,
      isCa: false,
      certificatePolicyOid: "2.23.140.1.2.2", // CA/Browser Forum Extended Validation Guidelines
      certificatePolicyCpsUrl: "https://pki.enterprise.org/cps.html",
    });

    const parsed = parseX509Certificate(cert.certDer);

    const cpExt = parsed.extensions.all.find((e: { oid: string }) => e.oid === "2.5.29.32");
    expect(cpExt).toBeDefined();

    expect(parsed.extensions.certificatePolicies).toBeDefined();
    expect(parsed.extensions.certificatePolicies?.length).toBeGreaterThan(0);
    const policy = parsed.extensions.certificatePolicies?.[0];
    expect(policy?.policyOid).toBe("2.23.140.1.2.2");
    expect(policy?.cpsUrl).toBe("https://pki.enterprise.org/cps.html");
  });
});

describe("CSR Signer Micro-CA with Extended Templates & CRL", () => {
  it("signs a CSR, includes ca.crl in exportFiles, and generates complete cloud templates", async () => {
    // 1. Generate CSR
    const csrResult = await createCsr({
      commonName: "payments.internal",
      san: "payments.internal, api.payments.internal",
      organization: "FinTech Corp",
      keyType: "ecdsa-p256",
      hashType: "sha256",
    });

    // 2. Sign CSR using Ephemeral Micro-CA
    const signResult = await signCsr({
      csrInput: csrResult.csrPem,
      caMode: "ephemeral-ca",
      validityDays: 120,
      nameConstraintsPermitted: ".internal",
      certificatePolicyOid: "1.3.6.1.4.1.99999.1",
      certificatePolicyCpsUrl: "https://ca.internal/cps",
    });

    expect(signResult.certPem).toContain("-----BEGIN CERTIFICATE-----");
    expect(signResult.caCertPem).toContain("-----BEGIN CERTIFICATE-----");
    expect(signResult.crlPem).toBeDefined();
    expect(signResult.crlPem).toContain("-----BEGIN X509 CRL-----");

    // Verify files array includes ca.crl
    const caCrlFile = signResult.exportFiles.find((f: { name: string }) => f.name === "ca.crl");
    expect(caCrlFile).toBeDefined();

    // 3. Test through computeCertificate variant: csr-signer
    const tool = await loadTool("csr-signer");
    const spec = createSpec({ variant: "csr-signer" });
    const computeRes = await tool.compute(spec, new TextEncoder().encode(csrResult.csrPem));

    expect(computeRes.error).toBeUndefined();
    expect(computeRes.working).toContain("Visual PKI Trust Hierarchy");
    expect(computeRes.files).toBeDefined();

    const fileNames = computeRes.files!.map((f: { name: string }) => f.name);
    expect(fileNames).toContain("cert.crt");
    expect(fileNames).toContain("ca.crt");
    expect(fileNames).toContain("ca.crl");
    expect(fileNames).toContain("k8s-tls-secret.yaml");
    expect(fileNames).toContain("nginx.conf");
    expect(fileNames).toContain("Caddyfile");
    expect(fileNames).toContain("docker-compose.yaml");
    expect(fileNames).toContain("httpd-ssl.conf");
    expect(fileNames).toContain("cloud-import.sh");
    expect(fileNames).toContain("main.tf");
    expect(fileNames).toContain("deploy-playbook.yaml");
  });

  it("creates and parses CRLs with RFC 5280 revocation reason codes", async () => {
    const ca = await createCertificate({
      commonName: "Micro-CA Root",
      isCa: true,
      keyType: "ecdsa-p256",
      hashType: "sha256",
      validityDays: 365,
    });

    const signer = await importCaSigner(ca.certDer, ca.privateKeyDer);
    const crl = await createCrl({
      signer,
      crlNumber: 42,
      revokedCertificates: [
        {
          serialNumber: "0xABC123",
          reasonCode: CrlReasonCode.KeyCompromise,
        },
        {
          serialNumber: "0xDEF456",
          reasonCode: CrlReasonCode.PrivilegeWithdrawn,
        },
      ],
    });

    expect(crl.crlPem).toContain("-----BEGIN X509 CRL-----");
    const parsed = parseX509Crl(crl.crlDer);
    expect(parsed.crlNumber).toBe(42);
    expect(parsed.revokedCertificates).toHaveLength(2);
    expect(parsed.revokedCertificates[0]?.reasonCode).toBe(CrlReasonCode.KeyCompromise);
    expect(parsed.revokedCertificates[1]?.reasonCode).toBe(CrlReasonCode.PrivilegeWithdrawn);
  });
});

describe("End-to-End cert-creator Tool Execution", () => {
  it("executes single-cert mode and exports cloud-native manifests and hierarchy diagram", async () => {
    const tool = await loadTool("cert-creator");
    const spec = createSpec({ variant: "cert-creator" });
    spec.options["commonName"] = "microservice.prod";
    spec.options["san"] = "microservice.prod, 10.0.0.5";

    const res = await tool.compute(spec, new Uint8Array(0));
    expect(res.error).toBeUndefined();
    expect(res.working).toContain("Visual Trust Hierarchy");
    expect(res.files).toBeDefined();

    const fileNames = res.files!.map((f: { name: string }) => f.name);
    expect(fileNames).toContain("certificate.crt");
    expect(fileNames).toContain("private.key");
    expect(fileNames).toContain("k8s-tls-secret.yaml");
    expect(fileNames).toContain("nginx.conf");
    expect(fileNames).toContain("Caddyfile");
    expect(fileNames).toContain("docker-compose.yaml");
    expect(fileNames).toContain("httpd-ssl.conf");
    expect(fileNames).toContain("cloud-import.sh");
  });

  it("executes mtls-suite mode and exports full cloud bundle, hierarchy diagram, and CRL", async () => {
    const tool = await loadTool("cert-creator");
    const spec = createSpec({ variant: "cert-creator" });
    spec.options["creatorMode"] = "mtls-suite";
    spec.options["pkiHierarchy"] = "3-tier";
    spec.options["caCommonName"] = "Corporate Root CA";
    spec.options["intermediateCommonName"] = "Cluster Issuing CA";
    spec.options["commonName"] = "gateway.service";

    const res = await tool.compute(spec, new Uint8Array(0));
    expect(res.error).toBeUndefined();
    expect(res.working).toContain("Visual PKI Trust Hierarchy");
    expect(res.files).toBeDefined();

    const fileNames = res.files!.map((f: { name: string }) => f.name);
    expect(fileNames).toContain("ca.crt");
    expect(fileNames).toContain("ca.key");
    expect(fileNames).toContain("intermediate.crt");
    expect(fileNames).toContain("intermediate.key");
    expect(fileNames).toContain("server.crt");
    expect(fileNames).toContain("server.key");
    expect(fileNames).toContain("client.crt");
    expect(fileNames).toContain("client.p12");
    expect(fileNames).toContain("ca.crl");
    expect(fileNames).toContain("docker-compose.yaml");
    expect(fileNames).toContain("httpd-ssl.conf");
    expect(fileNames).toContain("cloud-import.sh");
  });
});
