import { describe, expect, it } from "vitest";
import {
  bcryptPrehash,
  formatHtpasswdRecord,
  HTPASSWD_MAX_USERNAME_BYTES,
  parseHtpasswdRecord,
  validateHtpasswdUsername,
} from "@ocs/algos";

describe("bcrypt digest preprocessing", () => {
  it("uses lowercase hexadecimal text for all Hashcat constructions", () => {
    expect(bcryptPrehash("hashcat", "md5")).toBe("8743b52063cd84097a65d1633f5c74f5");
    expect(bcryptPrehash("hashcat", "sha1")).toBe("b89eaac7e61417341b710b727768294d0e6a277b");
    expect(bcryptPrehash("hashcat", "sha256")).toBe(
      "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935",
    );
    expect(bcryptPrehash("hashcat", "sha512")).toHaveLength(128);
    expect(bcryptPrehash("hashcat", "sha512")).toMatch(/^[0-9a-f]+$/);
  });
});

describe("htpasswd record serialization", () => {
  it("round-trips one username:hash record", () => {
    const line = formatHtpasswdRecord("alice", "{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=");
    expect(line).toBe("alice:{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=");
    expect(parseHtpasswdRecord(line)).toEqual({
      username: "alice",
      hash: "{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=",
    });
  });

  it("rejects field and record injection plus usernames over Apache's byte limit", () => {
    expect(validateHtpasswdUsername("a".repeat(HTPASSWD_MAX_USERNAME_BYTES))).toBeUndefined();
    expect(validateHtpasswdUsername("a:b")).toMatch(/colon/);
    expect(validateHtpasswdUsername("a\nb")).toMatch(/newline/);
    expect(validateHtpasswdUsername("a\rb")).toMatch(/newline/);
    expect(validateHtpasswdUsername("é".repeat(HTPASSWD_MAX_USERNAME_BYTES))).toMatch(
      /510 bytes/,
    );
    expect(() => formatHtpasswdRecord("a:b", "hash")).toThrow(/colon/);
  });
});
