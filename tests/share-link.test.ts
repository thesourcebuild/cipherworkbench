import { describe, expect, it } from "vitest";
import { createOptionCatalogue, type OptionDef } from "@ocs/engine";
import { EMPTY_INPUT } from "../apps/web/app/input-state";
import { buildShareLink, parseShareLink, stripSecrets } from "../apps/web/app/share-link";

/**
 * Share links are the one place this app can leak something, so the stripping is
 * tested directly rather than left to a browser pass. The failure mode is silent:
 * a link that carried a key would look exactly like one that did not.
 */

const OPTIONS: readonly OptionDef[] = [
  {
    id: "mode",
    label: "Mode",
    group: "core",
    kind: "enum",
    choices: [
      { value: "gcm", label: "GCM" },
      { value: "ecb", label: "ECB", insecure: true },
    ],
    summary: "s",
    detail: "d",
    order: 10,
  },
  {
    id: "key",
    label: "Key",
    group: "core",
    kind: "bytes",
    bytesLength: { exact: [16, 32], generate: 32 },
    secret: true,
    summary: "s",
    detail: "d",
    order: 20,
  },
  {
    id: "password",
    label: "Password",
    group: "core",
    kind: "password",
    arg: { placeholder: "" },
    secret: true,
    summary: "s",
    detail: "d",
    order: 30,
  },
  {
    // Public by design: an IV travels in the clear next to the ciphertext.
    id: "iv",
    label: "IV",
    group: "core",
    kind: "bytes",
    bytesLength: { exact: [12], generate: 12 },
    summary: "s",
    detail: "d",
    order: 40,
  },
];

const catalogue = createOptionCatalogue(OPTIONS);

const spec = {
  specVersion: 1,
  options: {
    mode: "gcm",
    key: "00112233445566778899aabbccddeeff",
    keyEncoding: "hex",
    password: "correct horse battery staple",
    iv: "0102030405060708090a0b0c",
    ivEncoding: "hex",
  },
};

describe("stripSecrets", () => {
  it("removes every option marked secret, and reports which", () => {
    const { options, omitted } = stripSecrets(catalogue, spec.options);
    expect(options.key).toBeUndefined();
    expect(options.password).toBeUndefined();
    expect(omitted.sort()).toEqual(["Key", "Password"]);
  });

  it("removes a secret's companion encoding selector too", () => {
    // A dangling `keyEncoding: "hex"` describing a key that is gone is confusing
    // rather than dangerous, but there is no reason to ship it.
    const { options } = stripSecrets(catalogue, spec.options);
    expect(options.keyEncoding).toBeUndefined();
  });

  it("keeps options that are not secret, including the IV and its encoding", () => {
    const { options } = stripSecrets(catalogue, spec.options);
    expect(options.mode).toBe("gcm");
    expect(options.iv).toBe("0102030405060708090a0b0c");
    expect(options.ivEncoding).toBe("hex");
  });

  it("does not mutate the input", () => {
    const before = JSON.stringify(spec.options);
    stripSecrets(catalogue, spec.options);
    expect(JSON.stringify(spec.options)).toBe(before);
  });

  it("reports nothing omitted when no secret was set", () => {
    const { omitted } = stripSecrets(catalogue, { mode: "gcm" });
    expect(omitted).toEqual([]);
  });
});

describe("buildShareLink", () => {
  const base = "https://example.test/app/";

  it("never puts a secret in the URL, in any encoding", () => {
    const { url, omittedSecrets } = buildShareLink(
      base,
      "aes",
      catalogue,
      spec,
      { ...EMPTY_INPUT, text: "hello" },
      "hex",
    );
    expect(omittedSecrets.sort()).toEqual(["Key", "Password"]);
    // The payload is base64url, so a substring search on the raw URL proves
    // nothing — decode it and look at the actual options.
    const parsed = parseShareLink(new URL(url).hash)!;
    expect(parsed.options.key).toBeUndefined();
    expect(parsed.options.password).toBeUndefined();
    expect(parsed.options.mode).toBe("gcm");
  });

  it("round-trips the tool, settings, input and output encoding", () => {
    const input = { ...EMPTY_INPUT, mode: "hex" as const, text: "deadbeef" };
    const { url } = buildShareLink(base, "sha256", catalogue, spec, input, "base64");
    const parsed = parseShareLink(new URL(url).hash)!;

    expect(parsed.toolId).toBe("sha256");
    expect(parsed.outputEncoding).toBe("base64");
    expect(parsed.input).toEqual({ mode: "hex", text: "deadbeef", textEncoding: "utf-8" });
  });

  it("carries extra spec fields that are not options", () => {
    // The hash family keeps its algorithm outside `options`; a link has to preserve it.
    const withAlgorithm = { ...spec, algorithm: "sha512" };
    const { url } = buildShareLink(
      base,
      "sha512",
      catalogue,
      withAlgorithm,
      EMPTY_INPUT,
      "hex",
    );
    expect(parseShareLink(new URL(url).hash)!.specFields.algorithm).toBe("sha512");
  });

  it("does not carry `options` twice — once stripped and once raw", () => {
    const { url } = buildShareLink(base, "aes", catalogue, spec, EMPTY_INPUT, "hex");
    const parsed = parseShareLink(new URL(url).hash)!;
    expect(parsed.specFields.options).toBeUndefined();
  });

  it("omits a file input rather than pretending to share it", () => {
    const withFile = { ...EMPTY_INPUT, mode: "file" as const, file: undefined };
    const { omittedInput } = buildShareLink(base, "sha256", catalogue, spec, withFile, "hex");
    expect(omittedInput).toBe(true);
  });

  it("drops oversized text instead of truncating it", () => {
    // Truncating would produce a link that computes a different, valid-looking
    // digest — strictly worse than a link that computes nothing.
    const huge = { ...EMPTY_INPUT, text: "a".repeat(5000) };
    const { url, omittedInput } = buildShareLink(base, "sha256", catalogue, spec, huge, "hex");
    expect(omittedInput).toBe(true);
    expect(parseShareLink(new URL(url).hash)!.input).toBeUndefined();
  });

  it("replaces an existing hash rather than appending to it", () => {
    const { url } = buildShareLink(
      `${base}#stale-payload`,
      "sha256",
      catalogue,
      spec,
      EMPTY_INPUT,
      "hex",
    );
    expect(url.match(/#/g)).toHaveLength(1);
  });

  it("survives a UTF-8 input that btoa alone could not encode", () => {
    const unicode = { ...EMPTY_INPUT, text: "héllo ☃ 日本語" };
    const { url } = buildShareLink(base, "sha256", catalogue, spec, unicode, "hex");
    expect(parseShareLink(new URL(url).hash)!.input!.text).toBe("héllo ☃ 日本語");
  });
});

describe("parseShareLink", () => {
  it("returns undefined for an empty or absent hash", () => {
    expect(parseShareLink("")).toBeUndefined();
    expect(parseShareLink("#")).toBeUndefined();
  });

  it("returns undefined rather than throwing on hostile input", () => {
    // A link is the one input to this app written by someone else. None of these
    // may produce an exception that takes the page down.
    for (const hostile of [
      "#not-base64!!!",
      "#" + Buffer.from("not json at all").toString("base64url"),
      "#" + Buffer.from('{"v":999,"t":"sha256"}').toString("base64url"),
      "#" + Buffer.from('{"v":1}').toString("base64url"),
      "#" + Buffer.from("null").toString("base64url"),
      "#" + Buffer.from("[]").toString("base64url"),
      "#" + Buffer.from('{"v":1,"t":123}').toString("base64url"),
    ]) {
      expect(() => parseShareLink(hostile)).not.toThrow();
      expect(parseShareLink(hostile)).toBeUndefined();
    }
  });

  it("coerces non-object spec and option fields to empty rather than passing them through", () => {
    const payload = Buffer.from(
      JSON.stringify({ v: 1, t: "sha256", s: "nope", o: 42, e: 7, i: "nope" }),
    ).toString("base64url");
    const parsed = parseShareLink(`#${payload}`)!;
    expect(parsed.specFields).toEqual({});
    expect(parsed.options).toEqual({});
    expect(parsed.outputEncoding).toBeUndefined();
    expect(parsed.input).toBeUndefined();
  });

  it("accepts a payload whose base64url padding was stripped", () => {
    const { url } = buildShareLink(
      "https://x.test/",
      "sha256",
      catalogue,
      spec,
      EMPTY_INPUT,
      "hex",
    );
    const hash = new URL(url).hash;
    expect(hash).not.toContain("=");
    expect(parseShareLink(hash)).toBeDefined();
  });
});
