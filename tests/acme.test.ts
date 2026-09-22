import { describe, expect, it } from "vitest";
import {
  calculateAcmeChallenges,
  resolveJwkThumbprint,
} from "../packages/tools/certificates/src/crypto/acme";
import {
  generateTerraformConfig,
  generateAnsiblePlaybook,
} from "../packages/tools/certificates/src/export/iac";
import { createCertificate } from "../packages/tools/certificates/src/asn1/create-cert";
import { parseX509Certificate } from "../packages/tools/certificates/src/asn1/x509";
import {
  RSA_PRIVATE_KEY_PEM,
  RSA_CERTIFICATE_PEM,
} from "../packages/tools/certificates/src/samples";

describe("Phase 4: Cloud-Native, ACME & Zero-Trust", () => {
  describe("ACME Challenge Calculator", () => {
    it("computes accurate RFC 8555 HTTP-01 and DNS-01 parameters", () => {
      const token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
      const thumbprint = "kRLr_6fsVn8_93J9l7Xp89V44W5R5-kZ3v3Y1b2_ABC";

      const res = calculateAcmeChallenges({
        domain: "example.com",
        token,
        accountKeyOrThumbprint: thumbprint,
      });

      expect(res.domain).toBe("example.com");
      expect(res.cleanDomain).toBe("example.com");
      expect(res.token).toBe(token);
      expect(res.jwkThumbprint).toBe(thumbprint);
      expect(res.keyAuthorization).toBe(`${token}.${thumbprint}`);

      // HTTP-01
      expect(res.http01.urlPath).toBe(`/.well-known/acme-challenge/${token}`);
      expect(res.http01.fullUrl).toBe(`http://example.com/.well-known/acme-challenge/${token}`);
      expect(res.http01.keyAuthorization).toBe(`${token}.${thumbprint}`);
      expect(res.http01.curlCommand).toContain(res.http01.fullUrl);
      expect(res.http01.nginxConfig).toContain("/.well-known/acme-challenge/");

      // DNS-01
      expect(res.dns01.recordName).toBe("_acme-challenge.example.com");
      expect(res.dns01.recordType).toBe("TXT");
      expect(res.dns01.recordValue.length).toBe(43); // 32 bytes base64url = 43 chars
      expect(res.dns01.zoneSnippet).toContain('_acme-challenge.example.com. 300 IN TXT "');
      expect(res.dns01.digCommand).toBe("dig +short TXT _acme-challenge.example.com");

      // TLS-ALPN-01
      expect(res.tlsAlpn01.protocol).toBe("acme-tls/1");
      expect(res.tlsAlpn01.extensionOid).toBe("1.3.6.1.5.5.7.1.31");
      expect(res.tlsAlpn01.sha256Hex.length).toBe(64);

      // Unified cross-platform verification scripts
      expect(res.commands.sh).toContain("#!/usr/bin/env bash");
      expect(res.commands.sh).toContain("verify-dns");
      expect(res.commands.sh).toContain("verify-http");
      expect(res.commands.ps1).toContain("Get-Command openssl");
      expect(res.commands.bat).toContain("@echo off");

      // Export files
      const filenames = res.exportFiles.map((f) => f.name);
      expect(filenames).toContain(token);
      expect(filenames).toContain("dns-record.txt");
      expect(filenames).toContain("nginx-acme.conf");
      expect(filenames).toContain("main.tf");
      expect(filenames).toContain("deploy-playbook.yaml");
      expect(filenames).toContain("commands.sh");
      expect(filenames).toContain("commands.ps1");
      expect(filenames).toContain("commands.bat");
    });

    it("correctly strips wildcard prefixes for DNS-01 TXT record name", () => {
      const res = calculateAcmeChallenges({
        domain: "*.subdomain.enterprise.com",
        token: "token-12345",
        accountKeyOrThumbprint: "kRLr_6fsVn8_93J9l7Xp89V44W5R5-kZ3v3Y1b2_ABC",
      });

      expect(res.cleanDomain).toBe("subdomain.enterprise.com");
      expect(res.dns01.recordName).toBe("_acme-challenge.subdomain.enterprise.com");
    });

    it("resolves JWK thumbprint from raw JWK JSON and PEM keys", () => {
      // Direct thumbprint
      const direct = "kRLr_6fsVn8_93J9l7Xp89V44W5R5-kZ3v3Y1b2_ABC";
      expect(resolveJwkThumbprint(direct)).toBe(direct);

      // From RSA PEM private key
      const thumbprintFromPem = resolveJwkThumbprint(RSA_PRIVATE_KEY_PEM);
      expect(thumbprintFromPem.length).toBe(43);

      // From X.509 Certificate PEM (extracts public key SPKI -> JWK)
      const thumbprintFromCert = resolveJwkThumbprint(RSA_CERTIFICATE_PEM);
      expect(thumbprintFromCert.length).toBe(43);

      // The RSA cert and RSA private key in samples match, so their thumbprints MUST match!
      expect(thumbprintFromPem).toBe(thumbprintFromCert);
    });
  });

  describe("Zero-Trust SPIFFE ID Integration", () => {
    it("encodes and parses SPIFFE ID URIs in Subject Alternative Names", async () => {
      const spiffeUri = "spiffe://cluster.local/ns/backend/sa/auth-service";

      const cert = await createCertificate({
        commonName: "auth-service.local",
        san: `DNS:auth-service.local, spiffe:${spiffeUri}`,
        keyType: "ecdsa-p256",
        hashType: "sha256",
        validityDays: 30,
        isCa: false,
      });

      const parsed = parseX509Certificate(cert.certDer);
      expect(parsed.extensions.sans).toContain(`URI:${spiffeUri}`);
      expect(parsed.extensions.spiffeIds).toBeDefined();
      expect(parsed.extensions.spiffeIds).toContain(spiffeUri);
    });
  });

  describe("IaC Templates (Terraform & Ansible)", () => {
    it("generates hardened Terraform TLS deployment config (0644 / 0600)", () => {
      const tf = generateTerraformConfig({
        certFilename: "app.crt",
        keyFilename: "app.key",
        caFilename: "root-ca.crt",
      });

      expect(tf).toContain("resource \"local_file\" \"server_certificate\"");
      expect(tf).toContain("resource \"local_sensitive_file\" \"server_private_key\"");
      expect(tf).toContain("file_permission = \"0644\"");
      expect(tf).toContain("file_permission = \"0600\"");
      expect(tf).toContain("app.crt");
      expect(tf).toContain("app.key");
    });

    it("generates hardened Ansible playbook for certificate deployment", () => {
      const playbook = generateAnsiblePlaybook({
        certFilename: "app.crt",
        keyFilename: "app.key",
      });

      expect(playbook).toContain("mode: \"0644\"");
      expect(playbook).toContain("mode: \"0600\"");
      expect(playbook).toContain("app.crt");
      expect(playbook).toContain("app.key");
      expect(playbook).toContain("openssl x509");
    });
  });
});
