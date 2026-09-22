import { describe, expect, it } from "vitest";
import { generateKeyBundle } from "../packages/tools/certificates/src/crypto/keys";
import { spkiToOpenSsh, pemToOpenSsh } from "../packages/tools/certificates/src/crypto/openssh";
import { spkiToJwk, pemToJwk, formatJwks, type RsaJwk, type EcJwk, type OkpJwk } from "../packages/tools/certificates/src/crypto/jwk";

describe("OpenSSH (RFC 4253 / RFC 8709) and JWK/JWKS (RFC 7517) Exporters", () => {
  it("exports Ed25519 public key to OpenSSH authorized_keys and JWK OKP", async () => {
    const key = await generateKeyBundle("ed25519");

    // OpenSSH
    const ssh = spkiToOpenSsh(key.spkiBytes, "ed25519", "test@ed25519");
    expect(ssh.keyType).toBe("ssh-ed25519");
    expect(ssh.authorizedKeysLine).toMatch(/^ssh-ed25519 [A-Za-z0-9+/=]+ test@ed25519$/);
    expect(ssh.sha256Fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);

    // From PEM
    const sshFromPem = pemToOpenSsh(key.publicKeyPem, "test@ed25519");
    expect(sshFromPem.authorizedKeysLine).toBe(ssh.authorizedKeysLine);

    // JWK
    const jwk = spkiToJwk(key.spkiBytes, "ed25519") as OkpJwk;
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
    expect(jwk.alg).toBe("EdDSA");
    expect(jwk.x).toBeDefined();
    expect(jwk.kid).toBeDefined();

    const jwkFromPem = pemToJwk(key.publicKeyPem) as OkpJwk;
    expect(jwkFromPem.x).toBe(jwk.x);
    expect(jwkFromPem.kid).toBe(jwk.kid);
  });

  it("exports RSA-2048 public key to OpenSSH authorized_keys and JWK RSA", async () => {
    const key = await generateKeyBundle("rsa-2048", "sha256");

    // OpenSSH
    const ssh = spkiToOpenSsh(key.spkiBytes, "rsa-2048", "admin@server");
    expect(ssh.keyType).toBe("ssh-rsa");
    expect(ssh.authorizedKeysLine).toMatch(/^ssh-rsa [A-Za-z0-9+/=]+ admin@server$/);
    expect(ssh.sha256Fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);

    // JWK
    const jwk = spkiToJwk(key.spkiBytes, "rsa-2048") as RsaJwk;
    expect(jwk.kty).toBe("RSA");
    expect(jwk.alg).toBe("RS256");
    expect(jwk.n).toBeDefined();
    expect(jwk.e).toBeDefined();
    expect(jwk.kid).toBeDefined();
  });

  it("exports ECDSA P-256 public key to OpenSSH and JWK EC, and bundles JWKS", async () => {
    const key = await generateKeyBundle("ecdsa-p256", "sha256");

    // OpenSSH
    const ssh = spkiToOpenSsh(key.spkiBytes, "ecdsa-p256", "ecdsa-user");
    expect(ssh.keyType).toBe("ecdsa-sha2-nistp256");
    expect(ssh.authorizedKeysLine).toMatch(/^ecdsa-sha2-nistp256 [A-Za-z0-9+/=]+ ecdsa-user$/);

    // JWK
    const jwk = spkiToJwk(key.spkiBytes, "ecdsa-p256") as EcJwk;
    expect(jwk.kty).toBe("EC");
    expect(jwk.crv).toBe("P-256");
    expect(jwk.alg).toBe("ES256");
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();

    // JWKS Bundle
    const jwksJson = formatJwks([jwk]);
    const parsed = JSON.parse(jwksJson);
    expect(parsed.keys).toHaveLength(1);
    expect(parsed.keys[0].crv).toBe("P-256");
  });
});
