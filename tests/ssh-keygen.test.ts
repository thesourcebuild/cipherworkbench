import { describe, expect, it } from "vitest";
import {
  generateOpenSshSuite,
  calculateBubblebabble,
  generateDrunkenBishopRandomart,
  computeOpenSsh,
  createSpec,
  describeSpec,
  readSshKeyType,
  readSshComment,
  readSshPassphrase,
  readSshRounds,
  readSshFilename,
} from "@ocs/openssh";
import { loadTool, getManifest } from "@ocs/registry";

describe("OpenSSH tool suite (@ocs/openssh)", () => {
  it("registers ssh-keygen manifest with family openssh", () => {
    const manifest = getManifest("ssh-keygen");
    expect(manifest).toBeDefined();
    expect(manifest?.family).toBe("openssh");
    expect(manifest?.label).toBe("SSH Keygen");
    expect(manifest?.security).toBe("modern");
    expect(manifest?.readsInput).toBe(false);
    expect(manifest?.supportsFile).toBe(false);
  });

  it("loads tool definition via registry", async () => {
    const def = await loadTool("ssh-keygen");
    expect(def).toBeDefined();
    expect(def.id).toBe("ssh-keygen");
    expect(def.family).toBe("openssh");
    expect(def.groups).toHaveProperty("key");
    expect(def.groups).toHaveProperty("options");
    expect(def.groups).toHaveProperty("security");
  });

  it("creates valid default spec and describe summary", () => {
    const spec = createSpec();
    expect(spec.variant).toBe("ssh-keygen");
    expect(readSshKeyType(spec)).toBe("ed25519");
    expect(readSshComment(spec)).toBe("user@cipherworkbench");
    expect(readSshPassphrase(spec)).toBe("");
    expect(readSshRounds(spec)).toBe(16);
    expect(readSshFilename(spec)).toBe("id_ed25519");

    const desc = describeSpec(spec);
    expect(desc).toContain("Ed25519");
    expect(desc).toContain("user@cipherworkbench");
    expect(desc).toContain("unencrypted");
  });

  it("generates valid Ed25519 keypair suite (unencrypted)", async () => {
    const suite = await generateOpenSshSuite({
      keyType: "ed25519",
      comment: "alice@example.com",
    });

    expect(suite.keyType).toBe("ed25519");
    expect(suite.bits).toBe(256);
    expect(suite.comment).toBe("alice@example.com");
    expect(suite.isEncrypted).toBe(false);

    // Public key format
    expect(suite.authorizedKeysLine).toMatch(/^ssh-ed25519 AAAA[A-Za-z0-9+/=]+ alice@example\.com$/);

    // Private key format
    expect(suite.opensshPrivateKeyPem).toContain("-----BEGIN OPENSSH PRIVATE KEY-----");
    expect(suite.opensshPrivateKeyPem).toContain("-----END OPENSSH PRIVATE KEY-----");

    // PKCS#8 PEM format
    expect(suite.pkcs8PrivateKeyPem).toContain("-----BEGIN PRIVATE KEY-----");
    expect(suite.pkcs8PrivateKeyPem).toContain("-----END PRIVATE KEY-----");

    // RFC 4716 SECSH format
    expect(suite.rfc4716Format).toContain("---- BEGIN SSH2 PUBLIC KEY ----");
    expect(suite.rfc4716Format).toContain('Comment: "alice@example.com"');
    expect(suite.rfc4716Format).toContain("---- END SSH2 PUBLIC KEY ----");

    // Fingerprints
    expect(suite.sha256Fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
    expect(suite.md5Fingerprint).toMatch(/^MD5(:[0-9a-f]{2}){16}$/);

    // Bubblebabble
    expect(suite.bubblebabble).toMatch(/^x[a-z-]+x$/);

    // Randomart
    expect(suite.randomart).toContain("+--[ED25519 256]--+");
    expect(suite.randomart).toContain("+----[SHA256]-----+");
    expect(suite.randomart).toContain("S");
  });

  it("generates encrypted Ed25519 key with AES-256-CTR and bcrypt-PBKDF", async () => {
    const suite = await generateOpenSshSuite({
      keyType: "ed25519",
      comment: "bob@security.internal",
      passphrase: "super-secure-passphrase-2026",
      rounds: 32,
    });

    expect(suite.isEncrypted).toBe(true);
    expect(suite.kdfRounds).toBe(32);
    expect(suite.opensshPrivateKeyPem).toContain("-----BEGIN OPENSSH PRIVATE KEY-----");
    expect(suite.opensshPrivateKeyPem).toContain("-----END OPENSSH PRIVATE KEY-----");

    // Decoded wire header should indicate aes256-ctr and bcrypt
    const b64 = suite.opensshPrivateKeyPem
      .replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
      .replace("-----END OPENSSH PRIVATE KEY-----", "")
      .replace(/\s+/g, "");
    const decoded = Buffer.from(b64, "base64");
    const headerStr = decoded.toString("latin1");
    expect(headerStr).toContain("openssh-key-v1");
    expect(headerStr).toContain("aes256-ctr");
    expect(headerStr).toContain("bcrypt");
  });

  it("generates valid RSA 2048 keypair", async () => {
    const suite = await generateOpenSshSuite({
      keyType: "rsa-2048",
      comment: "infra@datacenter.net",
    });

    expect(suite.keyType).toBe("rsa-2048");
    expect(suite.bits).toBe(2048);
    expect(suite.authorizedKeysLine).toMatch(/^ssh-rsa AAAA[A-Za-z0-9+/=]+ infra@datacenter\.net$/);
    expect(suite.randomart).toContain("+---[RSA 2048]----+");
  });

  it("generates valid ECDSA P-256 keypair", async () => {
    const suite = await generateOpenSshSuite({
      keyType: "ecdsa-p256",
      comment: "cloud-dev@aws",
    });

    expect(suite.keyType).toBe("ecdsa-p256");
    expect(suite.bits).toBe(256);
    expect(suite.authorizedKeysLine).toMatch(/^ecdsa-sha2-nistp256 AAAA[A-Za-z0-9+/=]+ cloud-dev@aws$/);
    expect(suite.randomart).toContain("+---[ECDSA 256]---+");
  });

  it("computes Drunken Bishop randomart with exact 17x9 dimensions and boundaries", () => {
    const digest = new Uint8Array(32).fill(0x55);
    const art = generateDrunkenBishopRandomart(digest, "ED25519 256", "SHA256");
    const lines = art.split("\n");

    expect(lines.length).toBe(11); // top border + 9 rows + bottom border
    expect(lines[0]).toBe("+--[ED25519 256]--+");
    expect(lines[10]).toBe("+----[SHA256]-----+");

    for (let i = 1; i <= 9; i++) {
      expect(lines[i]?.startsWith("|")).toBe(true);
      expect(lines[i]?.endsWith("|")).toBe(true);
      expect(lines[i]?.length).toBe(19); // '|' + 17 chars + '|'
    }
  });

  it("computes Bubblebabble digest according to specification", () => {
    const bytes = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const bb = calculateBubblebabble(bytes);
    expect(bb.startsWith("x")).toBe(true);
    expect(bb.endsWith("x")).toBe(true);
    expect(bb).toContain("-");
  });

  it("computes complete ToolResult via computeOpenSsh", async () => {
    const spec = createSpec();
    const result = await computeOpenSsh(spec);

    expect(result.text).toMatch(/^ssh-ed25519 /);
    expect(result.fields).toBeDefined();
    expect(result.files).toBeDefined();
    expect(result.files?.length).toBe(8);

    const filenames = result.files?.map((f) => f.name);
    expect(filenames).toContain("id_ed25519.pub");
    expect(filenames).toContain("id_ed25519");
    expect(filenames).toContain("id_ed25519.pem");
    expect(filenames).toContain("id_ed25519_ssh2.pub");
    expect(filenames).toContain("config");
    expect(filenames).toContain("commands.sh");
    expect(filenames).toContain("commands.ps1");
    expect(filenames).toContain("commands.bat");

    expect(result.cliProviders).toBeDefined();
    expect(result.cliProviders?.length).toBe(3);
    expect(result.cliProviders?.[0]?.id).toBe("openssh");
  });

  it("switches primary result text based on output-format option", async () => {
    const spec = createSpec();
    spec.options["output-format"] = "private-openssh";
    const resPriv = await computeOpenSsh(spec);
    expect(resPriv.text).toContain("-----BEGIN OPENSSH PRIVATE KEY-----");

    spec.options["output-format"] = "config";
    const resConfig = await computeOpenSsh(spec);
    expect(resConfig.text).toContain("Host my-server");
    expect(resConfig.text).toContain("IdentityFile ~/.ssh/id_ed25519");

    spec.options["output-format"] = "randomart";
    const resArt = await computeOpenSsh(spec);
    expect(resArt.text).toContain("+--[ED25519 256]--+");

    spec.options["output-format"] = "bubblebabble";
    const resBb = await computeOpenSsh(spec);
    expect(resBb.text?.startsWith("x")).toBe(true);
    expect(resBb.text?.endsWith("x")).toBe(true);
  });

  it("evaluates OpenSSH lint diagnostics", async () => {
    const def = await loadTool("ssh-keygen");
    expect(def.lintRules.length).toBeGreaterThan(0);

    // Default spec has empty passphrase -> warning SSH001
    const spec = createSpec();
    const lints = def.lintRules.flatMap((r) => r.check(spec));
    const unencLint = lints.find((l) => l.code === "SSH001");
    expect(unencLint).toBeDefined();
    expect(unencLint?.level).toBe("warning");

    // RSA 2048 spec -> info SSH002
    spec.options["key-type"] = "rsa-2048";
    const rsaLints = def.lintRules.flatMap((r) => r.check(spec));
    const rsaLint = rsaLints.find((l) => l.code === "SSH002");
    expect(rsaLint).toBeDefined();
    expect(rsaLint?.level).toBe("info");
  });

  it("defaults to Modern Default preset and verifies group placements", async () => {
    const def = await loadTool("ssh-keygen");
    const spec = createSpec();
    expect(spec.options["preset"]).toBe("modern-ed25519");

    // Group placements: settings sidebar vs input canvas
    expect(def.groups["preset"]?.placement).toBeUndefined();
    expect(def.groups["output"]?.placement).toBeUndefined();
    expect(def.groups["key"]?.placement).toBe("input");
    expect(def.groups["options"]?.placement).toBe("input");
    expect(def.groups["security"]?.placement).toBe("input");
  });

  it("cascades preset changes through onOptionChange", async () => {
    const def = await loadTool("ssh-keygen");
    expect(def.onOptionChange).toBeDefined();

    const spec = createSpec();

    // Switch to enterprise RSA preset
    const rsaSpec = def.onOptionChange!(spec, "preset", "enterprise-rsa4096");
    expect(rsaSpec.options["preset"]).toBe("enterprise-rsa4096");
    expect(rsaSpec.options["key-type"]).toBe("rsa-4096");
    expect(rsaSpec.options["filename"]).toBe("id_rsa");
    expect(rsaSpec.options["rounds"]).toBe(16);

    // Switch to cloud ECDSA preset
    const ecdsaSpec = def.onOptionChange!(rsaSpec, "preset", "cloud-ecdsa256");
    expect(ecdsaSpec.options["preset"]).toBe("cloud-ecdsa256");
    expect(ecdsaSpec.options["key-type"]).toBe("ecdsa-p256");
    expect(ecdsaSpec.options["filename"]).toBe("id_ecdsa");

    // Switch to hardened preset
    const hardenedSpec = def.onOptionChange!(ecdsaSpec, "preset", "hardened-ed25519");
    expect(hardenedSpec.options["preset"]).toBe("hardened-ed25519");
    expect(hardenedSpec.options["key-type"]).toBe("ed25519");
    expect(hardenedSpec.options["filename"]).toBe("id_ed25519_hardened");
    expect(hardenedSpec.options["rounds"]).toBe(64);

    // Modify custom rounds -> preset updates to custom
    const customSpec = def.onOptionChange!(hardenedSpec, "rounds", 128);
    expect(customSpec.options["preset"]).toBe("custom");
    expect(customSpec.options["rounds"]).toBe(128);
  });
});
