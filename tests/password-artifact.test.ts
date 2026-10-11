import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { PASSWORD_ARTIFACT_MANIFESTS } from "@ocs/password-artifact";
import {
  convertGiteaToHashcat,
  convertGrafanaToHashcat,
  identifyHashArtifact,
  passwordArtifactToolDefinition,
} from "@ocs/password-artifact/definition";

const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/password-artifact/${name}`, import.meta.url), "utf8");

describe("password artifact family", () => {
  it("uses neutral analysis/extraction metadata instead of algorithm claims", () => {
    expect(PASSWORD_ARTIFACT_MANIFESTS.map((manifest) => manifest.id)).toEqual([
      "hash-identifier",
      "grafana2hashcat",
      "gitea2hashcat",
      "ssh2john",
      "truecrypt2john",
      "luks2john",
      "dmg2john",
      "bitlocker2john",
      "kdbx2john",
      "zip2john",
      "office2john",
      "pdf2john",
      "rar2john",
      "7z2john",
      "gpg2john",
    ]);
    expect(PASSWORD_ARTIFACT_MANIFESTS.map((manifest) => manifest.purpose)).toEqual([
      "analysis",
      "extraction",
      "extraction",
      "extraction",
      "extraction",
      "extraction",
      "extraction",
      "extraction",
      "extraction",
      "extraction",
      "extraction",
      "extraction",
      "extraction",
      "extraction",
      "extraction",
    ]);
    for (const manifest of PASSWORD_ARTIFACT_MANIFESTS) {
      expect(manifest.directions).toEqual([]);
      expect(manifest.security).toBeUndefined();
      if (["hash-identifier", "grafana2hashcat", "gitea2hashcat"].includes(manifest.id)) {
        expect(manifest.sourcePolicy).toMatchObject({
          semantics: "text-artifact",
          maxFileBytes: 4 * 1024 * 1024,
        });
      } else {
        expect(manifest.sourcePolicy?.semantics).toBe("file-artifact");
        expect(manifest.supportsFile).toBe(true);
      }
    }
  });

  it("ranks self-describing records from their structure", () => {
    expect(
      identifyHashArtifact("$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxZ9K1Cw1nQyXGz4h8eK0iF7m2O"),
    ).toEqual([
      expect.objectContaining({
        name: "bcrypt",
        confidence: "self-describing",
        hashcatMode: 3200,
      }),
    ]);

    expect(
      identifyHashArtifact(
        "pbkdf2_sha256$20000$H0dPx8NeajVu$GiC4k5kqbbR9qWBlsRgDywNqC2vd9kqfk7zdorEnNas=",
      )[0],
    ).toMatchObject({ name: "Django PBKDF2-SHA256", confidence: "self-describing" });
  });

  it("preserves ambiguity for a raw hash identified by length alone", () => {
    const candidates = identifyHashArtifact("8743b52063cd84097a65d1633f5c74f5");
    expect(candidates.map((candidate) => candidate.name)).toEqual(["MD4", "MD5", "NTLM"]);
    expect(new Set(candidates.map((candidate) => candidate.confidence))).toEqual(
      new Set(["length-only"]),
    );
    expect(
      candidates.every((candidate) => candidate.evidence.includes("cannot distinguish")),
    ).toBe(true);
  });

  it("converts the Grafana fixture to the exact mode 10900 record", () => {
    expect(convertGrafanaToHashcat(fixture("grafana.csv"))).toBe(
      "sha256:10000:WU9iU29MajU1Uw==:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n",
    );
  });

  it("converts either Gitea column order to exact canonical records", () => {
    const record =
      "sha256:50000:AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEE=";
    expect(convertGiteaToHashcat(fixture("gitea.txt"))).toBe(`${record}\n${record}\n`);
  });

  it("strictly rejects malformed or ambiguous converter input", () => {
    expect(() => convertGrafanaToHashcat("abcd,salt")).toThrow(/64 hex digest/i);
    expect(() => convertGrafanaToHashcat(`${"00".repeat(32)},salt,extra`)).toThrow(/64 hex/i);
    expect(() => convertGiteaToHashcat(`${"00".repeat(16)}:${"11".repeat(16)}`)).toThrow(
      /16-byte hex salt and a 50-byte hex digest/i,
    );
    expect(() => convertGiteaToHashcat(`${"zz".repeat(16)}:${"11".repeat(32)}`)).toThrow(
      /expected one hex salt/i,
    );
  });

  it("carries suggested export names and MIME types through definitions", async () => {
    const tool = passwordArtifactToolDefinition("grafana2hashcat");
    const result = await tool.compute(
      tool.createSpec(),
      new TextEncoder().encode(fixture("grafana.csv")),
    );
    expect(result.error).toBeUndefined();
    expect(result.suggestedFilename).toBe("grafana-hashcat.txt");
    expect(result.mimeType).toBe("text/plain;charset=utf-8");
  });
});
