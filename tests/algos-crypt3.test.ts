import { describe, expect, it } from "vitest";
import {
  apacheSha,
  apr1Crypt,
  crypt3,
  crypt3Verify,
  md5Crypt,
  sha256Crypt,
  sha512Crypt,
} from "@ocs/algos";

describe("MD5-Crypt ($1$)", () => {
  it("formats and hashes correctly with standard salt", () => {
    const hash = md5Crypt("password", "salt1234");
    expect(hash.startsWith("$1$salt1234$")).toBe(true);

    // Hash length: "$1$" (3) + salt (8) + "$" (1) + hash (22) = 34
    expect(hash.length).toBe(34);

    // Deterministic
    expect(md5Crypt("password", "salt1234")).toBe(hash);
    expect(md5Crypt("password2", "salt1234")).not.toBe(hash);
  });

  it("truncates salt longer than 8 characters", () => {
    const hash1 = md5Crypt("secret", "12345678");
    const hash2 = md5Crypt("secret", "12345678EXTRA_CHARACTERS");
    expect(hash1).toBe(hash2);
  });
});

describe("SHA-256-Crypt ($5$)", () => {
  it("computes standard SHA-256 shadow hash", () => {
    const hash = sha256Crypt("testpassword", "saltsalt", 1000);
    expect(hash.startsWith("$5$rounds=1000$saltsalt$")).toBe(true);
    // Hash suffix is 43 characters long
    const parts = hash.split("$");
    expect(parts[parts.length - 1]!.length).toBe(43);

    // Determinism
    expect(sha256Crypt("testpassword", "saltsalt", 1000)).toBe(hash);
    expect(sha256Crypt("otherpassword", "saltsalt", 1000)).not.toBe(hash);
  });

  it("handles salt parsing and default rounds", () => {
    const hash = sha256Crypt("pass", "$5$rounds=1234$customsalt$rest");
    expect(hash.startsWith("$5$rounds=1234$customsalt$")).toBe(true);
  });
});

describe("SHA-512-Crypt ($6$)", () => {
  it("computes standard SHA-512 shadow hash", () => {
    const hash = sha512Crypt("testpassword", "saltsalt", 1000);
    expect(hash.startsWith("$6$rounds=1000$saltsalt$")).toBe(true);
    // Hash suffix is 86 characters long
    const parts = hash.split("$");
    expect(parts[parts.length - 1]!.length).toBe(86);

    // Determinism
    expect(sha512Crypt("testpassword", "saltsalt", 1000)).toBe(hash);
    expect(sha512Crypt("diffpassword", "saltsalt", 1000)).not.toBe(hash);
  });
});

describe("Apache password formats", () => {
  it("matches Hashcat's APR1 fixture without relabeling MD5-Crypt", () => {
    expect(apr1Crypt("hashcat", "62722340")).toBe("$apr1$62722340$zGjeAwVP2KwY6MtumUI1N/");
    expect(apr1Crypt("hashcat", "62722340")).not.toBe(
      md5Crypt("hashcat", "62722340").replace("$1$", "$apr1$"),
    );
  });

  it("matches Apache's {SHA} fixture", () => {
    expect(apacheSha("hashcat")).toBe("{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=");
  });
});

describe("unified crypt(3)", () => {
  it("reuses the scheme implementations and verifies their stored forms", () => {
    const des = crypt3("hashcat", { scheme: "des-crypt", salt: "24" });
    const bsdi = crypt3("hashcat", { scheme: "bs-crypt", salt: "8147", rounds: 1163 });
    const md5 = crypt3("password", { scheme: "md5crypt", salt: "salt1234" });
    const sha256 = crypt3("password", {
      scheme: "sha256crypt",
      salt: "saltsalt",
      rounds: 1000,
    });
    const sha512 = crypt3("password", {
      scheme: "sha512crypt",
      salt: "saltsalt",
      rounds: 1000,
    });
    expect(des).toBe("24leDr0hHfb3A");
    expect(bsdi).toBe("_9G..8147mpcfKT8g0U.");
    expect(md5).toBe(md5Crypt("password", "salt1234"));
    expect(sha256).toBe(sha256Crypt("password", "saltsalt", 1000));
    expect(sha512).toBe(sha512Crypt("password", "saltsalt", 1000));
    expect(crypt3Verify("hashcat", des)).toBe(true);
    expect(crypt3Verify("hashcat", bsdi)).toBe(true);
    expect(crypt3Verify("password", md5)).toBe(true);
    expect(crypt3Verify("password", sha256)).toBe(true);
    expect(crypt3Verify("password", sha512)).toBe(true);
  });
});
