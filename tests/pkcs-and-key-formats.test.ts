import { describe, expect, it } from "vitest";
import {
  encodePkcs7CertBundle,
  decodePkcs7CertBundle,
} from "../packages/tools/certificates/src/asn1/pkcs7";
import {
  convertCertificate,
} from "../packages/tools/certificates/src/asn1/converter";
import {
  spkiToOpenSsh,
  formatRfc4716PublicKey,
  parseRfc4716PublicKey,
  parseOpenSshPublicKey,
  sshMpint,
  sshString,
} from "../packages/tools/certificates/src/crypto/openssh";
import {
  parsePkcs11Uri,
  buildPkcs11Uri,
  validatePkcs11Uri,
  bytesToPkcs11Id,
  pkcs11IdToBytes,
} from "../packages/tools/certificates/src/crypto/pkcs11";
import { decodeUniversalArtifact } from "../packages/tools/certificates/src/asn1/universal-decoder";
import {
  spkiToJwk,
  computeJwkThumbprint,
  toBase64Url,
} from "../packages/tools/certificates/src/crypto/jwk";
import {
  generateKeyBundle,
} from "../packages/tools/certificates/src/crypto/keys";
import {
  parseCsr,
} from "../packages/tools/certificates/src/asn1/csr";
import { detectInputBytes } from "../packages/tools/certificates/src/asn1/pem";
import {
  RSA_CERTIFICATE_PEM,
  CA_CERTIFICATE_PEM,
  RSA_PRIVATE_KEY_PEM,
  ECDSA_CSR_PEM,
  CERTIFICATE_CHAIN_PEM,
} from "../packages/tools/certificates/src/samples";

describe("PKCS and Keystore Formats Comprehensive Suite", () => {
  const rsaCertDer = detectInputBytes(RSA_CERTIFICATE_PEM).der;
  const caCertDer = detectInputBytes(CA_CERTIFICATE_PEM).der;
  const rsaKeyDer = detectInputBytes(RSA_PRIVATE_KEY_PEM).der;

  describe("PKCS#7 / CMS (.p7b / .p7c) SignedData Bundles", () => {
    it("encodes and decodes multi-certificate PKCS#7 bundles", () => {
      const bundle = encodePkcs7CertBundle([rsaCertDer, caCertDer]);
      expect(bundle.count).toBe(2);
      expect(bundle.pem).toContain("-----BEGIN PKCS7-----");
      expect(bundle.pem).toContain("-----END PKCS7-----");
      expect(bundle.der.length).toBeGreaterThan(100);

      // Decode from DER
      const extractedFromDer = decodePkcs7CertBundle(bundle.der);
      expect(extractedFromDer).toHaveLength(2);
      expect(extractedFromDer[0]?.der).toEqual(rsaCertDer);
      expect(extractedFromDer[1]?.der).toEqual(caCertDer);
      expect(extractedFromDer[0]?.pem).toContain("-----BEGIN CERTIFICATE-----");

      // Decode from PEM string
      const extractedFromPem = decodePkcs7CertBundle(new TextEncoder().encode(bundle.pem));
      expect(extractedFromPem).toHaveLength(2);
    });

    it("rejects encoding an empty list of certificates", () => {
      expect(() => encodePkcs7CertBundle([])).toThrow(
        /at least one certificate is required/i,
      );
    });

    it("safely handles malformed and truncated PKCS#7 inputs", () => {
      // Empty input
      expect(() => decodePkcs7CertBundle(new Uint8Array(0))).toThrow();

      // Truncated data
      const bundle = encodePkcs7CertBundle([rsaCertDer]);
      const truncated = bundle.der.slice(0, 20);
      expect(() => decodePkcs7CertBundle(truncated)).toThrow();

      // Valid ASN.1 but not PKCS#7 (passing raw certificate instead of SignedData)
      expect(() => decodePkcs7CertBundle(rsaCertDer)).toThrow(
        /unable to locate SignedData structure/i,
      );

      // Passing raw private key instead of SignedData
      expect(() => decodePkcs7CertBundle(rsaKeyDer)).toThrow(
        /unable to locate SignedData structure/i,
      );
    });
  });

  describe("OpenSSH Wire Formatting & Fingerprints", () => {
    it("formats RSA SPKI into ssh-rsa with valid SHA-256 fingerprint", async () => {
      const rsaKey = await generateKeyBundle("rsa-2048");
      const ssh = spkiToOpenSsh(rsaKey.spkiBytes, "rsa-2048", "admin@workbench");

      expect(ssh.keyType).toBe("ssh-rsa");
      expect(ssh.authorizedKeysLine).toMatch(/^ssh-rsa [A-Za-z0-9+/=]+ admin@workbench$/);
      expect(ssh.sha256Fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/=]+$/);
      expect(ssh.wireBlob.length).toBeGreaterThan(100);
    });

    it("formats ECDSA SPKI (P-256, P-384, P-521) into ecdsa-sha2-* keys", async () => {
      const p256 = await generateKeyBundle("ecdsa-p256");
      const ssh256 = spkiToOpenSsh(p256.spkiBytes, "ecdsa-p256", "p256@workbench");
      expect(ssh256.keyType).toBe("ecdsa-sha2-nistp256");
      expect(ssh256.authorizedKeysLine).toContain("ecdsa-sha2-nistp256 ");

      const p384 = await generateKeyBundle("ecdsa-p384");
      const ssh384 = spkiToOpenSsh(p384.spkiBytes, "ecdsa-p384", "p384@workbench");
      expect(ssh384.keyType).toBe("ecdsa-sha2-nistp384");

      const p521 = await generateKeyBundle("ecdsa-p521");
      const ssh521 = spkiToOpenSsh(p521.spkiBytes, "ecdsa-p521", "p521@workbench");
      expect(ssh521.keyType).toBe("ecdsa-sha2-nistp521");
    });

    it("formats Ed25519 SPKI into ssh-ed25519 keys", async () => {
      const edKey = await generateKeyBundle("ed25519");
      const ssh = spkiToOpenSsh(edKey.spkiBytes, "ed25519", "ed25519@workbench");

      expect(ssh.keyType).toBe("ssh-ed25519");
      expect(ssh.authorizedKeysLine).toMatch(/^ssh-ed25519 [A-Za-z0-9+/=]+ ed25519@workbench$/);
      expect(ssh.sha256Fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/=]+$/);
    });

    it("correctly encodes sshString and sshMpint edge cases (RFC 4251)", () => {
      // sshString encodes 4-byte BE length + data
      const s = sshString("hello");
      expect(s).toEqual(new Uint8Array([0, 0, 0, 5, 104, 101, 108, 108, 111]));

      // sshMpint 0n -> 4 zero bytes (length 0)
      expect(sshMpint(0n)).toEqual(new Uint8Array([0, 0, 0, 0]));

      // Positive integer where MSB >= 0x80 requires prepended 0x00
      const msbSet = new Uint8Array([0x80, 0x01]);
      const mpintMsb = sshMpint(msbSet);
      expect(mpintMsb[0]).toBe(0);
      expect(mpintMsb[1]).toBe(0);
      expect(mpintMsb[2]).toBe(0);
      expect(mpintMsb[3]).toBe(3); // length 3
      expect(mpintMsb[4]).toBe(0x00); // prepended zero
      expect(mpintMsb[5]).toBe(0x80);
      expect(mpintMsb[6]).toBe(0x01);

      // Redundant leading zeroes are trimmed
      const padded = new Uint8Array([0x00, 0x00, 0x12, 0x34]);
      const mpintPadded = sshMpint(padded);
      expect(mpintPadded[3]).toBe(2); // length 2
      expect(mpintPadded[4]).toBe(0x12);
      expect(mpintPadded[5]).toBe(0x34);
    });

    it("throws on malformed SPKI input", () => {
      expect(() => spkiToOpenSsh(new Uint8Array([0x01, 0x02, 0x03]))).toThrow();
      expect(() => spkiToOpenSsh(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]))).toThrow(
        /expected SubjectPublicKeyInfo SEQUENCE/i,
      );
    });
  });

  describe("RFC 7517 / RFC 7638 JSON Web Keys (JWK)", () => {
    it("converts RSA SPKI to JWK and computes canonical thumbprint", async () => {
      const rsa = await generateKeyBundle("rsa-2048");
      const jwk = spkiToJwk(rsa.spkiBytes, "rsa-2048");

      expect(jwk.kty).toBe("RSA");
      if (jwk.kty === "RSA") {
        expect(jwk.alg).toBe("RS256");
        expect(jwk.n).toBeDefined();
        expect(jwk.e).toBeDefined();
        expect(jwk.kid).toBeDefined();

        const thumbprint = computeJwkThumbprint(jwk);
        expect(thumbprint).toBe(jwk.kid);
        expect(thumbprint.length).toBeGreaterThan(20);
      }
    });

    it("converts ECDSA SPKI (P-256) to EC JWK with accurate coordinates", async () => {
      const ec = await generateKeyBundle("ecdsa-p256");
      const jwk = spkiToJwk(ec.spkiBytes, "ecdsa-p256");

      expect(jwk.kty).toBe("EC");
      if (jwk.kty === "EC") {
        expect(jwk.crv).toBe("P-256");
        expect(jwk.alg).toBe("ES256");
        expect(jwk.x).toBeDefined();
        expect(jwk.y).toBeDefined();

        const thumbprint = computeJwkThumbprint(jwk);
        expect(thumbprint).toBe(jwk.kid);
      }
    });

    it("converts Ed25519 SPKI to OKP JWK", async () => {
      const ed = await generateKeyBundle("ed25519");
      const jwk = spkiToJwk(ed.spkiBytes, "ed25519");

      expect(jwk.kty).toBe("OKP");
      if (jwk.kty === "OKP") {
        expect(jwk.crv).toBe("Ed25519");
        expect(jwk.alg).toBe("EdDSA");
        expect(jwk.x).toBeDefined();

        const thumbprint = computeJwkThumbprint(jwk);
        expect(thumbprint).toBe(jwk.kid);
      }
    });

    it("correctly encodes base64url without padding", () => {
      const data = new Uint8Array([0xfb, 0xff, 0xbf]);
      const urlSafe = toBase64Url(data);
      expect(urlSafe).not.toContain("+");
      expect(urlSafe).not.toContain("/");
      expect(urlSafe).not.toContain("=");
    });
  });

  describe("Certificate & Keystore Converter Operations", () => {
    it("converts multi-cert PEM to PKCS#7 and back", async () => {
      const p7 = await convertCertificate(
        new TextEncoder().encode(CERTIFICATE_CHAIN_PEM),
        "pem-to-pkcs7",
      );

      expect(p7.operation).toBe("pem-to-pkcs7");
      expect(p7.text).toContain("-----BEGIN PKCS7-----");
      expect(p7.bytes).toBeDefined();

      const pemBack = await convertCertificate(p7.bytes!, "pkcs7-to-pem");
      expect(pemBack.operation).toBe("pkcs7-to-pem");
      expect(pemBack.text).toContain("Certificate 1");
      expect(pemBack.text).toContain("Certificate 2");
    });

    it("rejects pem-to-pkcs7 when no certificates are present in input", async () => {
      await expect(
        convertCertificate(new TextEncoder().encode(RSA_PRIVATE_KEY_PEM), "pem-to-pkcs7"),
      ).rejects.toThrow(/No certificates found/i);
    });

    it("extracts public key from RSA certificate", async () => {
      const res = await convertCertificate(
        new TextEncoder().encode(RSA_CERTIFICATE_PEM),
        "extract-public-key",
      );
      expect(res.operation).toBe("extract-public-key");
      expect(res.text).toContain("-----BEGIN PUBLIC KEY-----");
    });

    it("inspects PKCS#12 archives via converter", async () => {
      // First package to PKCS#12
      const combinedPem = `${RSA_CERTIFICATE_PEM}\n${RSA_PRIVATE_KEY_PEM}`;
      const pfx = await convertCertificate(
        new TextEncoder().encode(combinedPem),
        "pem-to-pkcs12",
        { password: "inspection-pass" },
      );

      const inspection = await convertCertificate(pfx.bytes!, "pkcs12-inspect");
      expect(inspection.operation).toBe("pkcs12-inspect");
      expect(inspection.text).toContain("PKCS#12 Container Inspection Report");
      expect(inspection.text).toContain("SafeBags Structure (2 bags)");
      expect(inspection.text).toContain("**MAC Present**: YES");
    });

    it("splits certificate chain bundle into distinct subject blocks", async () => {
      const res = await convertCertificate(
        new TextEncoder().encode(CERTIFICATE_CHAIN_PEM),
        "split-chain",
      );
      expect(res.operation).toBe("split-chain");
      expect(res.blocks?.length).toBe(2);
      expect(res.blocks![0]!.subject).toBeDefined();
      expect(res.blocks![1]!.subject).toBeDefined();
    });

    it("auto-detects input formats correctly", async () => {
      // 1. Certificate
      const autoCert = await convertCertificate(new TextEncoder().encode(RSA_CERTIFICATE_PEM), "auto");
      expect(autoCert.detectedType).toBe("X.509 Certificate");

      // 2. CSR
      const autoCsr = await convertCertificate(new TextEncoder().encode(ECDSA_CSR_PEM), "auto");
      expect(autoCsr.detectedType).toBe("PKCS#10 Certificate Request");

      // 3. PKCS#7
      const p7 = await convertCertificate(new TextEncoder().encode(CERTIFICATE_CHAIN_PEM), "pem-to-pkcs7");
      const autoP7 = await convertCertificate(p7.bytes!, "auto");
      expect(autoP7.detectedType).toContain("PKCS#7");
    });
  });

  describe("PKCS#10 Certificate Signing Requests (CSR)", () => {
    it("parses ECDSA CSR attributes, SANs, and signature", async () => {
      const parsed = parseCsr(new TextEncoder().encode(ECDSA_CSR_PEM));
      expect(parsed.subject.commonName).toBe("api.workbench.local");
      expect(parsed.subject.organization).toBe("Cipher Workbench");
      expect(parsed.publicKey.algorithmName).toContain("Elliptic Curve");
      expect(parsed.requestedExtensions.sans).toContain("DNS:api.workbench.local");
      const sigResult = await parsed.verifySelfSignature();
      expect(sigResult.valid).toBe(true);
    });

    it("safely handles malformed and truncated CSRs", () => {
      expect(() => parseCsr(new Uint8Array(0))).toThrow();
      expect(() => parseCsr(new Uint8Array([0x30, 0x05, 0x02, 0x01, 0x00]))).toThrow();
    });
  });

  describe("RFC 4716 SSH2 Public Key Format (SECSH)", () => {
    it("formats and parses RSA-2048 key into RFC 4716 SECSH multi-line format", async () => {
      const rsaKey = await generateKeyBundle("rsa-2048");
      const ssh = spkiToOpenSsh(rsaKey.spkiBytes, "rsa-2048", "admin@workbench");
      const directFormat = formatRfc4716PublicKey(ssh.wireBlob, "admin@workbench");
      expect(directFormat).toBe(ssh.rfc4716Format);

      expect(ssh.rfc4716Format).toContain("---- BEGIN SSH2 PUBLIC KEY ----");
      expect(ssh.rfc4716Format).toContain("---- END SSH2 PUBLIC KEY ----");
      expect(ssh.rfc4716Format).toContain('Comment: "admin@workbench"');

      // Verify line wrapping at <= 70 chars per RFC 4716 §3.3
      const lines = ssh.rfc4716Format.split("\n");
      const base64Lines = lines.slice(2, -1);
      for (const line of base64Lines) {
        expect(line.length).toBeLessThanOrEqual(70);
      }

      // Parse back
      const parsed = parseRfc4716PublicKey(ssh.rfc4716Format);
      expect(parsed.keyType).toBe("ssh-rsa");
      expect(parsed.sha256Fingerprint).toBe(ssh.sha256Fingerprint);
      expect(parsed.authorizedKeysLine).toBe(ssh.authorizedKeysLine);
    });

    it("formats and parses Ed25519 and ECDSA keys into RFC 4716 SECSH format", async () => {
      const edKey = await generateKeyBundle("ed25519");
      const sshEd = spkiToOpenSsh(edKey.spkiBytes, "ed25519", "ed@workbench");
      const parsedEd = parseRfc4716PublicKey(sshEd.rfc4716Format);
      expect(parsedEd.keyType).toBe("ssh-ed25519");
      expect(parsedEd.sha256Fingerprint).toBe(sshEd.sha256Fingerprint);

      const p256Key = await generateKeyBundle("ecdsa-p256");
      const sshP256 = spkiToOpenSsh(p256Key.spkiBytes, "ecdsa-p256", "p256@workbench");
      const parsedP256 = parseRfc4716PublicKey(sshP256.rfc4716Format);
      expect(parsedP256.keyType).toBe("ecdsa-sha2-nistp256");
      expect(parsedP256.sha256Fingerprint).toBe(sshP256.sha256Fingerprint);
    });

    it("parses single-line OpenSSH key and converts to RFC 4716", () => {
      const openSsh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAG9wS9iPqF/uF9+7U5o6WqE0g9W user@host";
      const parsed = parseOpenSshPublicKey(openSsh);
      expect(parsed.keyType).toBe("ssh-ed25519");
      expect(parsed.rfc4716Format).toContain("---- BEGIN SSH2 PUBLIC KEY ----");
      expect(parsed.rfc4716Format).toContain('Comment: "user@host"');
      expect(parsed.sha256Fingerprint).toMatch(/^SHA256:/);
    });

    it("integrates with convertCertificate (pem-to-ssh2, ssh2-to-openssh, openssh-to-ssh2, auto)", async () => {
      // 1. pem-to-ssh2 from RSA cert
      const resSsh2 = await convertCertificate(new TextEncoder().encode(RSA_CERTIFICATE_PEM), "pem-to-ssh2");
      expect(resSsh2.operation).toBe("pem-to-ssh2");
      expect(resSsh2.text).toContain("---- BEGIN SSH2 PUBLIC KEY ----");

      // 2. auto detection of SSH2 SECSH format
      const autoSsh2 = await convertCertificate(new TextEncoder().encode(resSsh2.text!), "auto");
      expect(autoSsh2.detectedType).toContain("SSH2 Public Key");
      expect(autoSsh2.operation).toBe("ssh2-to-openssh");
      expect(autoSsh2.text).toContain("ssh-rsa ");

      // 3. auto detection of OpenSSH format
      const autoOpenSsh = await convertCertificate(
        new TextEncoder().encode("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAG9wS9iPqF/uF9+7U5o6WqE0g9W test@host"),
        "auto",
      );
      expect(autoOpenSsh.detectedType).toContain("OpenSSH");
      expect(autoOpenSsh.operation).toBe("openssh-to-ssh2");
      expect(autoOpenSsh.text).toContain("---- BEGIN SSH2 PUBLIC KEY ----");
    });

    it("integrates with decodeUniversalArtifact (Universal Sniffer)", () => {
      const ssh2Text = [
        "---- BEGIN SSH2 PUBLIC KEY ----",
        'Comment: "test-key"',
        "AAAAC3NzaC1lZDI1NTE5AAAAIAG9wS9iPqF/uF9+7U5o6WqE0g9W7z30b8s0k1l2m3n4",
        "---- END SSH2 PUBLIC KEY ----",
      ].join("\n");

      const decoded = decodeUniversalArtifact(ssh2Text);
      expect(decoded.kind).toBe("ssh-public-key");
      expect(decoded.kindLabel).toContain("SSH2 Public Key");
      expect(decoded.recommendedToolId).toBe("cert-converter");
    });

    it("rejects malformed RFC 4716 keys", () => {
      expect(() => parseRfc4716PublicKey("not an ssh key")).toThrow(/missing '---- BEGIN SSH2 PUBLIC KEY ----'/i);
      expect(() => parseRfc4716PublicKey("---- BEGIN SSH2 PUBLIC KEY ----\n---- END SSH2 PUBLIC KEY ----")).toThrow();
    });
  });

  describe("RFC 7512 PKCS#11 URI Scheme & Integration", () => {
    it("parses complete RFC 7512 PKCS#11 URI path and query components", () => {
      const uriStr =
        "pkcs11:token=My%20YubiKey;manufacturer=Yubico;model=YubiKey%205;serial=123456;object=PIV%20AUTH%20key;type=private;id=%01%02%03;slot-id=1?pin-value=123456&module-path=/usr/lib/opensc-pkcs11.so&module-name=opensc";
      const uri = parsePkcs11Uri(uriStr);

      expect(uri.token).toBe("My YubiKey");
      expect(uri.manufacturer).toBe("Yubico");
      expect(uri.model).toBe("YubiKey 5");
      expect(uri.serial).toBe("123456");
      expect(uri.object).toBe("PIV AUTH key");
      expect(uri.type).toBe("private");
      expect(uri.slotId).toBe(1);
      expect(uri.idHex).toBe("010203");
      expect(uri.idBytes).toEqual(new Uint8Array([0x01, 0x02, 0x03]));
      expect(uri.pinValue).toBe("123456");
      expect(uri.modulePath).toBe("/usr/lib/opensc-pkcs11.so");
      expect(uri.moduleName).toBe("opensc");
    });

    it("builds canonical RFC 7512 URI from attributes and handles percent encoding", () => {
      const canonical = buildPkcs11Uri({
        token: "Hardware Token #1",
        object: "Cert & Key",
        type: "cert",
        idBytes: new Uint8Array([0xaa, 0xbb, 0xcc]),
        pinValue: "secret?pin&value",
        modulePath: "C:\\Program Files\\SoftHSM2\\lib\\softhsm2.dll",
      });

      expect(canonical).toContain("pkcs11:token=Hardware%20Token%20%231");
      expect(canonical).toContain("object=Cert%20%26%20Key");
      expect(canonical).toContain("type=cert");
      expect(canonical).toContain("id=%AA%BB%CC");
      expect(canonical).toContain("pin-value=secret%3Fpin%26value");

      // Verify round-trip parsing
      const reparsed = parsePkcs11Uri(canonical);
      expect(reparsed.token).toBe("Hardware Token #1");
      expect(reparsed.object).toBe("Cert & Key");
      expect(reparsed.type).toBe("cert");
      expect(reparsed.idHex).toBe("aabbcc");
      expect(reparsed.pinValue).toBe("secret?pin&value");
    });

    it("validates PKCS#11 URIs and reports clear errors", () => {
      const valid = validatePkcs11Uri("pkcs11:token=YubiKey;object=MyKey;type=public");
      expect(valid.valid).toBe(true);
      expect(valid.uri?.token).toBe("YubiKey");

      const invalidScheme = validatePkcs11Uri("http://example.com/pkcs11");
      expect(invalidScheme.valid).toBe(false);
      expect(invalidScheme.error).toContain("must begin with 'pkcs11:'");

      const malformedAttr = validatePkcs11Uri("pkcs11:invalid-attr-without-equal");
      expect(malformedAttr.valid).toBe(false);
      expect(malformedAttr.error).toContain("missing '='");
    });

    it("converts byte arrays to and from PKCS#11 CKA_ID representations", () => {
      const original = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const idStr = bytesToPkcs11Id(original);
      expect(idStr).toBe("%DE%AD%BE%EF");

      const decodedBytes = pkcs11IdToBytes(idStr);
      expect(decodedBytes).toEqual(original);
    });

    it("integrates PKCS#11 inspection with convertCertificate", async () => {
      const uri =
        "pkcs11:token=HSM_Partition_1;object=TLS_Private_Key;type=private;slot-id=0?pin-value=password123&module-path=/usr/lib/libCryptoki2.so";
      const res = await convertCertificate(new TextEncoder().encode(uri), "pkcs11-inspect");

      expect(res.operation).toBe("pkcs11-inspect");
      expect(res.detectedType).toContain("PKCS#11 URI");
      expect(res.text).toContain("RFC 7512 PKCS#11 URI Inspection Report");
      expect(res.text).toContain("HSM_Partition_1");
      expect(res.text).toContain("TLS_Private_Key");
      expect(res.text).toContain("******");

      // Test auto-detection
      const autoRes = await convertCertificate(new TextEncoder().encode(uri), "auto");
      expect(autoRes.operation).toBe("pkcs11-inspect");
      expect(autoRes.detectedType).toContain("PKCS#11 URI");
    });

    it("integrates PKCS#11 URI detection into Universal Crypto Sniffer", () => {
      const uri = "pkcs11:token=YubiKey_PIV;object=Card%20Authentication;type=cert;id=%01%02%03%04";
      const sniffer = decodeUniversalArtifact(uri);

      expect(sniffer.kind).toBe("pkcs11-uri");
      expect(sniffer.kindLabel).toBe("PKCS#11 URI (RFC 7512)");
      expect(sniffer.properties.some((p) => p.label === "Token Label" && p.value === "YubiKey_PIV")).toBe(true);
      expect(sniffer.properties.some((p) => p.label === "Object Label" && p.value === "Card Authentication")).toBe(true);
      expect(sniffer.properties.some((p) => p.label === "Object Type" && p.value === "cert")).toBe(true);
      expect(sniffer.properties.some((p) => p.label === "CKA_ID (Hex)" && p.value === "01020304")).toBe(true);
      expect(sniffer.recommendedToolId).toBe("cert-converter");
    });
  });
});
