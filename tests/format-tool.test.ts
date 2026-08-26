import { describe, expect, it } from "vitest";
import {
  FORMAT_MANIFESTS,
  FORMAT_TOOLS,
  OPTION_ACTION,
  OPTION_CASE_STYLE,
  OPTION_COLLAPSE,
  OPTION_COUNT,
  OPTION_DIRECTION,
  OPTION_ENTITY_FORM,
  OPTION_ENTITY_SCOPE,
  OPTION_EXCLUDE_AMBIGUOUS,
  OPTION_INDENT,
  OPTION_LENGTH,
  OPTION_RANDOM_BYTES,
  OPTION_RANDOM_DISTINCT,
  OPTION_RANDOM_MAX,
  OPTION_RANDOM_MIN,
  OPTION_RANDOM_PLACES,
  OPTION_RANDOM_SHAPE,
  OPTION_RANDOM_SORTED,
  OPTION_SORT_KEYS,
  OPTION_URL_MODE,
  OPTION_UUID_NAME,
  OPTION_UUID_NAMESPACE,
  OPTION_UUID_VERSION,
  PASSWORD_ALPHABETS,
  PASSWORD_CLASS_OPTIONS,
  readClasses,
  type FormatSpec,
} from "@ocs/format";
import {
  ALL_FORMAT_OPTIONS,
  applyAllFixes,
  createSpec,
  describeSpec,
  formatToolDefinition,
  lint,
  RULE_CODES,
  samplesFor,
} from "@ocs/format/definition";
import { isAvailableOn, validateCatalogue } from "@ocs/engine";

/**
 * The format family: eight tools that are almost entirely catalogue over a mature library.
 *
 * That changes what these tests are for. Nothing here needs to prove that `jsonc-parser` parses JSON
 * or that `uuid` implements RFC 9562 -- those are tested upstream, which is the reason for choosing
 * them. What is worth testing is everything this repo actually decides: which library gets called for
 * which setting, that the settings mean what their labels say, that a refusal names the format it
 * wanted, and that the two directions compose.
 *
 * So the assertions are mostly on **exact output**, not round trips. A round trip cannot see the class
 * of bug this family had: an encoder that escapes more than its setting claims still decodes back to
 * the original, because a decoder accepts every reference form. Three real bugs in the entity tool
 * were invisible to a round trip and obvious the moment the output was written down.
 */

const bytes = (text: string) => new TextEncoder().encode(text);

function specFor(variant: string, options: FormatSpec["options"] = {}): FormatSpec {
  const base = createSpec({ variant });
  return { ...base, options: { ...base.options, ...options } };
}

async function run(variant: string, options: FormatSpec["options"], input = "") {
  return formatToolDefinition(variant).compute(specFor(variant, options), bytes(input));
}

/** The text of a successful compute, with the refusal surfaced in the message if it failed. */
async function textOf(variant: string, options: FormatSpec["options"], input = "") {
  const result = await run(variant, options, input);
  expect(result.error, `${variant} refused: ${result.error}`).toBeUndefined();
  return result.text!;
}

describe("the family's shape", () => {
  it("registers ten tools, none streaming", () => {
    expect(FORMAT_MANIFESTS).toHaveLength(10);
    for (const manifest of FORMAT_MANIFESTS) {
      expect(manifest.family).toBe("format");
      expect(manifest.streaming, manifest.id).toBe(false);
      expect(manifest.security, manifest.id).toBe("not-encryption");
    }
  });

  it("offers file input for the tools that read input and not for the four generators", () => {
    for (const meta of FORMAT_TOOLS) {
      const manifest = FORMAT_MANIFESTS.find((m) => m.id === meta.id)!;
      expect(manifest.supportsFile, meta.id).toBe(meta.usesInput);
    }
    expect(FORMAT_TOOLS.filter((t) => !t.usesInput).map((t) => t.id)).toEqual([
      "uuid",
      "password",
      "random",
      "randombytes",
    ]);
  });

  /**
   * `randombytes` is the one tool here whose result is bytes, and therefore the only one offered the
   * Result panel's encoding menu.
   *
   * Asserted both ways round, because the interesting failure is the *other* tool gaining a menu that
   * does nothing: `outputEncodings` is eager and per-tool, so a single-entry list is what hides the
   * selector. This is the structural fact that made `random` and `randombytes` two tools rather than
   * one with a shape dropdown, so it is worth a test rather than a comment alone.
   */
  it("gives the encoding menu to the one tool that emits bytes, and to no other", () => {
    for (const meta of FORMAT_TOOLS) {
      const manifest = FORMAT_MANIFESTS.find((m) => m.id === meta.id)!;
      if (meta.emitsBytes) {
        expect(manifest.outputEncodings.length, meta.id).toBeGreaterThan(1);
        expect(manifest.outputEncodings, meta.id).toContain("hex");
        // Not utf-8: random bytes are not text, and decoding them mangles the copy.
        expect(manifest.outputEncodings, meta.id).not.toContain("utf-8");
      } else {
        expect(manifest.outputEncodings, meta.id).toEqual(["utf-8"]);
      }
    }
    expect(FORMAT_TOOLS.filter((t) => t.emitsBytes).map((t) => t.id)).toEqual(["randombytes"]);
  });

  /**
   * Every option a tool exposes must be reachable in *some* configuration of that tool.
   *
   * This is the gate the MAC family earned the hard way: an `availableOn` is a claim that some tag
   * will be produced, nothing typechecks that claim, and four Skein-MAC and Ascon-PRF controls
   * therefore rendered nowhere while every unit test passed -- because the tests wrote option values
   * straight into a spec, which is the shape the form never produces when the field is absent.
   *
   * Not "reachable under the default spec", which would be wrong: a tool with mutually exclusive
   * modes legitimately hides options in each, and the random tool's decimal-places control cannot
   * show while whole numbers are selected. So each `enum` the tool exposes is swept across all of its
   * own choices, one at a time, and an option is stranded only if nothing reveals it. Sweeping one
   * enum at a time rather than the cross-product keeps this linear and is enough: nothing in this
   * family gates a control on two enums at once.
   */
  it("leaves no option stranded in every configuration of its tool", () => {
    for (const meta of FORMAT_TOOLS) {
      const definition = formatToolDefinition(meta.id);
      const options = definition.catalogue.options;
      const reachable = new Set<string>();
      const consider = (spec: FormatSpec) => {
        const tag = definition.variantTag?.(spec);
        for (const option of options) if (isAvailableOn(option, tag)) reachable.add(option.id);
      };

      consider(specFor(meta.id));
      for (const option of options) {
        if (option.kind !== "enum") continue;
        for (const choice of option.choices ?? []) {
          consider(specFor(meta.id, { [option.id]: choice.value }));
        }
      }

      const stranded = options.map((o) => o.id).filter((id) => !reachable.has(id));
      expect(stranded, `${meta.id} has options no configuration reveals`).toEqual([]);
    }
  });

  it("reads no input for the four generators and reads input for the rest", () => {
    for (const meta of FORMAT_TOOLS) {
      const manifest = FORMAT_MANIFESTS.find((m) => m.id === meta.id)!;
      expect(manifest.readsInput, meta.id).toBe(meta.usesInput);
    }
    expect(FORMAT_MANIFESTS.filter((m) => !m.readsInput).map((m) => m.id)).toEqual([
      "uuid",
      "password",
      "random",
      "randombytes",
    ]);
  });

  /**
   * A document per tool that reads one, because the app's generic samples are bytes rather than
   * documents. `tests/registry.test.ts` is what requires each to actually compute; this pins the
   * *shape* of the set -- six tools with samples, two without, and no sample for a tool with no box.
   */
  it("offers a sample for every tool with an input box and none for the generators", () => {
    for (const meta of FORMAT_TOOLS) {
      const samples = samplesFor(meta.id) ?? [];
      if (meta.usesInput) {
        expect(samples.length, `${meta.id} has no sample`).toBeGreaterThan(0);
      } else {
        expect(samples, meta.id).toEqual([]);
      }
    }
    // The two directions are not interchangeable, so the bidirectional tools carry one of each.
    for (const id of ["url", "htmlentity"]) {
      expect(samplesFor(id)!.length, id).toBe(2);
    }
  });

  /**
   * The JSON sample is chosen to demonstrate what the parse-tree path preserves, so it has to
   * actually contain those things -- a sample that had lost its duplicate key to an edit would
   * quietly stop making its point.
   */
  it("keeps the four things the JSON sample exists to show", async () => {
    const sample = samplesFor("json")![0]!.text;
    expect(sample).toContain("1.0");
    expect(sample.match(/"offline"/g)).toHaveLength(2);
    const formatted = await textOf("json", { [OPTION_INDENT]: "2" }, sample);
    expect(formatted).toContain("1.0");
    expect(formatted.match(/"offline"/g)).toHaveLength(2);
    // Longer than the input, because indenting is the only thing that adds characters here.
    expect(formatted.length).toBeGreaterThan(sample.length);
  });

  it("has a clean catalogue per tool and no duplicate ids across the family", () => {
    for (const meta of FORMAT_TOOLS) {
      expect(validateCatalogue(formatToolDefinition(meta.id).catalogue.options), meta.id).toEqual([]);
    }
    const ids = ALL_FORMAT_OPTIONS.map((o) => o.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("exposes only options that exist, and seeds only options it exposes", () => {
    const known = new Set(ALL_FORMAT_OPTIONS.map((o) => o.id));
    for (const meta of FORMAT_TOOLS) {
      for (const id of meta.exposes) expect(known, `${meta.id} exposes ${id}`).toContain(id);
      // Seeding a value for an option the tool does not render would be dead weight in every share
      // link the tool produces.
      for (const id of Object.keys(meta.defaults)) {
        expect(meta.exposes, `${meta.id} seeds unexposed ${id}`).toContain(id);
      }
    }
  });

  it("describes every tool without an empty sentence", () => {
    for (const meta of FORMAT_TOOLS) {
      const described = describeSpec(specFor(meta.id));
      expect(described, meta.id).not.toBe("");
      expect(described.endsWith("."), `${meta.id}: ${described}`).toBe(true);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────── URL

describe("url", () => {
  /**
   * RFC 3986 section 2 is the specification and the *differences between the three flavours* are what
   * this checks, because that is what the option chooses between. All three escape a space and none
   * escapes an unreserved character; they diverge on the sub-delimiters and on `~`.
   */
  const SAMPLE = "a b&c=~!'()*";

  it("escapes every reserved character in a component", async () => {
    expect(await textOf("url", { [OPTION_URL_MODE]: "component" }, SAMPLE)).toBe(
      "a%20b%26c%3D~!'()*",
    );
    // RFC 3986 section 2.3: these never need escaping and a tool that escaped them would be wrong.
    expect(await textOf("url", { [OPTION_URL_MODE]: "component" }, "-._~")).toBe("-._~");
  });

  it("leaves a whole URI's delimiters alone", async () => {
    expect(await textOf("url", { [OPTION_URL_MODE]: "uri" }, "http://x.y/a b?q=1&r=~")).toBe(
      "http://x.y/a%20b?q=1&r=~",
    );
  });

  /**
   * Form encoding is not "component with the spaces swapped", and this is the assertion that says so.
   *
   * It escapes `!`, `'`, `(`, `)` and `~`, which component leaves alone, and it writes a space as `+`.
   * Deriving one from the other is how the first version of this got `~` wrong -- and a round trip
   * could not see it, because a decoder accepts `%7E` and `~` alike.
   */
  it("differs from component encoding in exactly the five characters the URL standard escapes", async () => {
    expect(await textOf("url", { [OPTION_URL_MODE]: "form" }, SAMPLE)).toBe(
      "a+b%26c%3D%7E%21%27%28%29*",
    );
    expect(await textOf("url", { [OPTION_URL_MODE]: "form" }, SAMPLE)).toBe(
      new URLSearchParams({ v: SAMPLE }).toString().slice(2),
    );
  });

  it("reads a plus as a space only in the form flavour", async () => {
    const decode = (mode: string, value: string) =>
      textOf("url", { [OPTION_DIRECTION]: "decode", [OPTION_URL_MODE]: mode }, value);
    expect(await decode("form", "a+b%26c")).toBe("a b&c");
    expect(await decode("component", "a+b%26c")).toBe("a+b&c");
  });

  it("round-trips a UTF-8 string through all three flavours", async () => {
    const value = "héllo wörld/ü?&=\u{1f600}";
    for (const mode of ["component", "uri", "form"]) {
      const encoded = await textOf("url", { [OPTION_URL_MODE]: mode }, value);
      const decoded = await textOf(
        "url",
        { [OPTION_DIRECTION]: "decode", [OPTION_URL_MODE]: mode },
        encoded,
      );
      expect(decoded, mode).toBe(value);
    }
  });

  it("refuses a truncated escape rather than guessing", async () => {
    const result = await run("url", { [OPTION_DIRECTION]: "decode" }, "%A");
    expect(result.error).toMatch(/two hex digits/);
  });
});

// ───────────────────────────────────────────────────────────── HTML entities

describe("htmlentity", () => {
  const SAMPLE = `<a href="x">&'é</a>`;
  const MIXED = `<é \u{1f600}>`;

  const encode = (scope: string, form: string, value: string) =>
    textOf("htmlentity", { [OPTION_ENTITY_SCOPE]: scope, [OPTION_ENTITY_FORM]: form }, value);

  /**
   * The scope and the reference style are **independent**, and these four assertions are the ones that
   * pin it. Three bugs lived exactly here, all invisible to a round trip:
   *
   *  - `encodeXML` escapes non-ASCII as well as the five, so "Markup only" was escaping accents.
   *  - running a numeric sweep over `escapeUTF8`'s output left `<` as `&lt;` under "Hexadecimal".
   *  - `decodeXML` does not know `&nbsp;`, which this tool's own encoder writes.
   */
  it("escapes only the five markup characters when the scope says markup", async () => {
    expect(await encode("markup", "named", SAMPLE)).toBe(
      "&lt;a href=&quot;x&quot;&gt;&amp;&apos;é</a>".replace("</a>", "&lt;/a&gt;"),
    );
    expect(await encode("markup", "hex", SAMPLE)).toBe(
      "&#x3C;a href=&#x22;x&#x22;&#x3E;&#x26;&#x27;é&#x3C;/a&#x3E;",
    );
    // The accent survives both, which is the whole claim the "Markup only" label makes.
    expect(await encode("markup", "named", "é")).toBe("é");
    expect(await encode("markup", "decimal", "é")).toBe("é");
  });

  it("uses one style for every character when the scope is everything non-ASCII", async () => {
    expect(await encode("non-ascii", "hex", MIXED)).toBe("&#x3C;&#xE9;&#xA0;&#x1F600;&#x3E;");
    expect(await encode("non-ascii", "decimal", MIXED)).toBe("&#60;&#233;&#160;&#128512;&#62;");
    // Named falls back to numeric for anything the WHATWG table has no name for.
    expect(await encode("non-ascii", "named", MIXED)).toBe("&lt;&eacute;&nbsp;&#x1f600;&gt;");
  });

  it("keeps an astral character as one reference rather than two surrogates", async () => {
    expect(await encode("non-ascii", "hex", "\u{1f600}")).toBe("&#x1F600;");
  });

  it("decodes the full named table, not just XML's five", async () => {
    const decoded = await textOf(
      "htmlentity",
      { [OPTION_DIRECTION]: "decode" },
      "&lt;&amp;&nbsp;&eacute;&#233;&#x1F600;",
    );
    expect(decoded).toBe("<& éé\u{1f600}");
  });

  it("round-trips every combination of scope and style", async () => {
    for (const scope of ["markup", "non-ascii"]) {
      for (const form of ["named", "decimal", "hex"]) {
        const encoded = await encode(scope, form, MIXED);
        const decoded = await textOf("htmlentity", { [OPTION_DIRECTION]: "decode" }, encoded);
        expect(decoded, `${scope}/${form}`).toBe(MIXED);
      }
    }
  });
});

// ─────────────────────────────────────────────────────────────────────── JWT

describe("jwt", () => {
  /** RFC 7519 section 3.1's worked example, verbatim -- header, payload and HS256 signature. */
  const RFC7519 =
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  it("decodes RFC 7519's example into its three parts", async () => {
    const result = await run("jwt", {}, RFC7519);
    expect(result.error).toBeUndefined();
    const field = (label: string) => result.fields!.find((f) => f.label === label)!.value;
    expect(JSON.parse(field("Header"))).toEqual({ typ: "JWT", alg: "HS256" });
    expect(JSON.parse(field("Payload"))).toEqual({
      iss: "joe",
      exp: 1300819380,
      "http://example.com/is_root": true,
    });
    expect(field("Signature")).toBe("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
  });

  /** A date claim rendered absolutely. Relative-to-now would make a screenshot of it stop being true. */
  it("renders exp as an absolute instant", async () => {
    const result = await run("jwt", {}, RFC7519);
    expect(result.fields!.find((f) => f.label === "Expires")!.value).toBe(
      "2011-03-22T18:43:00.000Z (exp = 1300819380)",
    );
  });

  it("says how many parts it found rather than reporting a generic failure", async () => {
    const two = await run("jwt", {}, "eyJhbGciOiJub25lIn0.eyJhIjoxfQ");
    expect(two.error).toMatch(/three dot-separated parts; this has 2/);
    expect(two.error).toMatch(/unsecured token/);
    const five = await run("jwt", {}, "a.b.c.d.e");
    expect(five.error).toMatch(/JWE/);
  });

  it("names the segment that failed to decode", async () => {
    const result = await run("jwt", {}, `${"eyJhbGciOiJub25lIn0"}.@@@@.sig`);
    expect(result.error).toMatch(/payload is not Base64url/);
  });

  /** The rule that matters most in this family: nothing here is verified, at `insecure`. */
  it("always reports F003, and it is not fixable here", () => {
    const diagnostics = lint(specFor("jwt")).diagnostics;
    const f003 = diagnostics.find((d) => d.code === "F003")!;
    expect(f003.level).toBe("insecure");
    expect(f003.fix).toBeUndefined();
    expect(f003.detail).toMatch(/MAC family|asymmetric family/);
  });
});

// ────────────────────────────────────────────────────────────────────── JSON

describe("json", () => {
  /**
   * The reason `parseTree` is used rather than `JSON.parse`: every scalar is written back as the exact
   * characters it arrived as. `JSON.parse` then `JSON.stringify` fails all four of these -- `1.0`
   * becomes `1`, the big integer loses its last digits, the duplicate key is collapsed, and integer-like
   * keys are reordered ahead of the rest.
   */
  it("re-emits scalars verbatim, keeps duplicate keys and preserves member order", async () => {
    expect(await textOf("json", { [OPTION_ACTION]: "minify" }, '{"b":1.0,"a":[1,2],"b":2}')).toBe(
      '{"b":1.0,"a":[1,2],"b":2}',
    );
    expect(
      await textOf("json", { [OPTION_ACTION]: "minify" }, '{"n":12345678901234567890}'),
    ).toBe('{"n":12345678901234567890}');
    expect(await textOf("json", { [OPTION_ACTION]: "minify" }, '{"2":1,"1":2}')).toBe(
      '{"2":1,"1":2}',
    );
    expect(await textOf("json", { [OPTION_ACTION]: "minify" }, "[1e2,1E+2,0.10]")).toBe(
      "[1e2,1E+2,0.10]",
    );
  });

  it("indents by the chosen amount, and by nothing when the indent is None", async () => {
    const doc = '{"a":[1,2]}';
    expect(await textOf("json", { [OPTION_INDENT]: "2" }, doc)).toBe(
      '{\n  "a": [\n    1,\n    2\n  ]\n}',
    );
    expect(await textOf("json", { [OPTION_INDENT]: "4" }, doc)).toBe(
      '{\n    "a": [\n        1,\n        2\n    ]\n}',
    );
    expect(await textOf("json", { [OPTION_INDENT]: "tab" }, doc)).toBe(
      '{\n\t"a": [\n\t\t1,\n\t\t2\n\t]\n}',
    );
    // "None" produces exactly what minifying does, which is what its own summary claims.
    expect(await textOf("json", { [OPTION_INDENT]: "0" }, doc)).toBe(
      await textOf("json", { [OPTION_ACTION]: "minify" }, doc),
    );
  });

  it("keeps an empty object and an empty array on one line at every indent", async () => {
    expect(await textOf("json", { [OPTION_INDENT]: "2" }, '{"a":{},"b":[]}')).toBe(
      '{\n  "a": {},\n  "b": []\n}',
    );
  });

  it("sorts keys at every level, and only when asked", async () => {
    const doc = '{"b":1,"a":{"d":1,"c":2}}';
    expect(await textOf("json", { [OPTION_ACTION]: "minify", [OPTION_SORT_KEYS]: true }, doc)).toBe(
      '{"a":{"c":2,"d":1},"b":1}',
    );
    expect(await textOf("json", { [OPTION_ACTION]: "minify" }, doc)).toBe(doc);
  });

  it("reports a syntax error as a line, a column and a sentence", async () => {
    const result = await run("json", {}, '{\n "a": 1,\n}');
    // Not `PropertyNameExpected`: the raw identifier reads like a stack trace, and this message is
    // identical in V8, JavaScriptCore and SpiderMonkey, which `JSON.parse`'s is not.
    expect(result.error).toBe("Line 3, column 1: Property name expected.");
  });

  it("refuses a comment and a trailing comma, because this is JSON and not JSONC", async () => {
    expect((await run("json", {}, '{"a":1,}')).error).toMatch(/^Line /);
    expect((await run("json", {}, '{"a":1 // c\n}')).error).toMatch(/^Line /);
  });

  it("counts the document when validating", async () => {
    const result = await run("json", { [OPTION_ACTION]: "validate" }, '{"a":[1,{"b":2}]}');
    expect(result.text).toBe("Valid JSON.");
    const field = (label: string) => result.fields!.find((f) => f.label === label)!.value;
    expect(field("Top level")).toBe("object");
    expect(field("Objects")).toBe("2");
    expect(field("Arrays")).toBe("1");
    expect(field("Max depth")).toBe("3");
  });

  it("says the input is empty rather than reporting a parse error at column 1", async () => {
    expect((await run("json", {}, "   ")).error).toMatch(/input is empty/);
  });
});

// ─────────────────────────────────────────────────────────────────────── XML

describe("xml", () => {
  it("indents element-only content and leaves mixed content on one line", async () => {
    expect(await textOf("xml", { [OPTION_INDENT]: "2" }, '<r><a x="1">t</a><b><c/></b></r>')).toBe(
      '<r>\n  <a x="1">t</a>\n  <b>\n    <c/>\n  </b>\n</r>',
    );
    /**
     * The most common bug in XML pretty-printers, asserted rather than assumed: breaking this across
     * lines would insert whitespace *into the text*, which changes what the document says.
     */
    expect(await textOf("xml", { [OPTION_INDENT]: "2" }, "<p>hello <b>world</b></p>")).toBe(
      "<p>hello <b>world</b></p>",
    );
  });

  /**
   * Whitespace is data in XML unless a schema says otherwise, so collapsing it is opt-in -- and the
   * two settings have to differ visibly or the control does nothing.
   */
  it("only drops whitespace between elements when told to collapse", async () => {
    const doc = "<r>\n  <a>1</a>\n</r>";
    expect(await textOf("xml", { [OPTION_ACTION]: "minify", [OPTION_COLLAPSE]: true }, doc)).toBe(
      "<r><a>1</a></r>",
    );
    // Minifying alone removes nothing, which is why minified XML can look barely smaller than the
    // original. That is the honest answer: whitespace is data until somebody says otherwise.
    expect(await textOf("xml", { [OPTION_ACTION]: "minify", [OPTION_COLLAPSE]: false }, doc)).toBe(
      doc,
    );
  });

  /**
   * Whitespace *inside* an element is untouched by collapsing, on either setting.
   *
   * The option says "between elements" and means it: `<a> b </a>` is a leaf whose text happens to have
   * spaces around it, and trimming that would change what the document says without being asked. This
   * is the assertion that stops a future tidier version quietly doing so.
   */
  it("never trims the text inside an element", async () => {
    for (const collapse of [true, false]) {
      const options = { [OPTION_ACTION]: "minify", [OPTION_COLLAPSE]: collapse };
      expect(await textOf("xml", options, "<a> b </a>"), String(collapse)).toBe("<a> b </a>");
    }
  });

  it("keeps comments, CDATA, processing instructions and namespaces", async () => {
    const doc =
      '<?xml version="1.0"?><r xmlns:x="urn:x"><!--c--><x:a><![CDATA[<raw>]]></x:a></r>';
    const formatted = await textOf("xml", { [OPTION_INDENT]: "2" }, doc);
    expect(formatted).toContain('<?xml version="1.0"?>');
    expect(formatted).toContain("<!--c-->");
    expect(formatted).toContain("<![CDATA[<raw>]]>");
    expect(formatted).toContain("<x:a");
    /**
     * Note what this does *not* assert: that the namespace is declared once.
     *
     * Indenting serialises each child element on its own, and an element serialised out of context
     * re-declares the prefixes it inherited -- so `<x:a>` comes back as `<x:a xmlns:x="urn:x">`. That
     * is redundant and it is not wrong: the document means exactly the same thing, which is the
     * property worth testing, so this is an equivalence check rather than a character comparison.
     */
    const minify = { [OPTION_ACTION]: "minify", [OPTION_COLLAPSE]: true };
    const bare = (value: string) => value.replace(/ xmlns:x="urn:x"/g, "");
    expect(bare(await textOf("xml", minify, formatted))).toBe(
      bare(await textOf("xml", minify, doc)),
    );
  });

  it("reports a mismatched tag rather than formatting around it", async () => {
    const result = await run("xml", {}, "<r><a></r>");
    expect(result.error).toMatch(/tag mismatch/i);
  });

  it("counts the document when validating", async () => {
    const result = await run("xml", { [OPTION_ACTION]: "validate" }, "<r><a><b/></a></r>");
    expect(result.text).toBe("Well-formed XML.");
    const field = (label: string) => result.fields!.find((f) => f.label === label)!.value;
    expect(field("Root")).toBe("r");
    expect(field("Elements")).toBe("3");
    expect(field("Max depth")).toBe("3");
  });

  it("reformats its own output to itself", async () => {
    const doc = '<r><a x="1">t</a><b><c/></b></r>';
    const once = await textOf("xml", { [OPTION_INDENT]: "2" }, doc);
    expect(await textOf("xml", { [OPTION_INDENT]: "2" }, once)).toBe(once);
  });
});

// ────────────────────────────────────────────────────────────────────── Case

describe("case", () => {
  /**
   * `XMLHttpRequest` is the whole reason a library is used rather than a regex: getting
   * `xml_http_request` out of it rather than `x_m_l_http_request` is the difficulty, and it is not one
   * regex. Every style is asserted, because the option is a fourteen-entry dropdown and a style with no
   * function behind it would throw at compute time and nowhere else.
   */
  const EXPECTED: Readonly<Record<string, string>> = {
    camel: "xmlHttpRequest",
    pascal: "XmlHttpRequest",
    snake: "xml_http_request",
    constant: "XML_HTTP_REQUEST",
    pascalSnake: "Xml_Http_Request",
    kebab: "xml-http-request",
    train: "Xml-Http-Request",
    path: "xml/http/request",
    dot: "xml.http.request",
    capital: "Xml Http Request",
    sentence: "Xml http request",
    no: "xml http request",
    upper: "XMLHTTPREQUEST",
    lower: "xmlhttprequest",
  };

  it("converts XMLHttpRequest correctly in every style the dropdown offers", async () => {
    const offered = formatToolDefinition("case")
      .catalogue.options.find((o) => o.id === OPTION_CASE_STYLE)!
      .choices!.map((c) => c.value);
    expect(new Set(offered)).toEqual(new Set(Object.keys(EXPECTED)));
    for (const [style, expected] of Object.entries(EXPECTED)) {
      expect(await textOf("case", { [OPTION_CASE_STYLE]: style }, "XMLHttpRequest"), style).toBe(
        expected,
      );
    }
  });

  /** Upper and lower change the case of the string as it stands; the other twelve split into words. */
  it("does not re-split the string for upper and lower", async () => {
    expect(await textOf("case", { [OPTION_CASE_STYLE]: "upper" }, "one two")).toBe("ONE TWO");
    expect(await textOf("case", { [OPTION_CASE_STYLE]: "snake" }, "one two")).toBe("one_two");
  });

  it("converts a pasted list line by line rather than as one identifier", async () => {
    expect(await textOf("case", { [OPTION_CASE_STYLE]: "snake" }, "one two\nthree four")).toBe(
      "one_two\nthree_four",
    );
    // Blank lines survive, so a list keeps its shape.
    expect(await textOf("case", { [OPTION_CASE_STYLE]: "snake" }, "a b\n\nc d")).toBe(
      "a_b\n\nc_d",
    );
  });
});

// ────────────────────────────────────────────────────────────────────── UUID

describe("uuid", () => {
  const generate = (options: FormatSpec["options"]) => textOf("uuid", options);

  /**
   * RFC 9562's own worked values for the two deterministic versions.
   *
   * These are the only UUID assertions that can be exact, and they are the ones worth having: they
   * pin the namespace bytes, the hash, and the version and variant nibbles all at once.
   */
  it("reproduces RFC 9562's v3 and v5 of www.example.com in the DNS namespace", async () => {
    const named = { [OPTION_UUID_NAMESPACE]: "dns", [OPTION_UUID_NAME]: "www.example.com" };
    expect(await generate({ ...named, [OPTION_UUID_VERSION]: "v3" })).toBe(
      "5df41881-3aed-3515-88a7-2f4a814cf09e",
    );
    expect(await generate({ ...named, [OPTION_UUID_VERSION]: "v5" })).toBe(
      "2ed6657d-e927-568b-95e1-2665a8aea6a2",
    );
  });

  it("gives the two constants exactly", async () => {
    expect(await generate({ [OPTION_UUID_VERSION]: "nil" })).toBe(
      "00000000-0000-0000-0000-000000000000",
    );
    expect(await generate({ [OPTION_UUID_VERSION]: "max" })).toBe(
      "ffffffff-ffff-ffff-ffff-ffffffffffff",
    );
  });

  it("stamps the right version and variant nibbles for the four random or timed versions", async () => {
    for (const version of ["v1", "v4", "v6", "v7"] as const) {
      const value = await generate({ [OPTION_UUID_VERSION]: version });
      expect(value, version).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
      expect(value[14], `${version} version nibble`).toBe(version.slice(1));
      // RFC 9562 section 4.1: the variant is the top two bits of octet 8, so 8, 9, a or b.
      expect("89ab", `${version} variant nibble`).toContain(value[19]!);
    }
  });

  it("asks for a name rather than hashing an empty one", async () => {
    const result = await run("uuid", {
      [OPTION_UUID_VERSION]: "v5",
      [OPTION_UUID_NAMESPACE]: "dns",
      [OPTION_UUID_NAME]: "",
    });
    expect(result.error).toMatch(/Enter a name/);
  });

  it("emits one per line for a count, all distinct, and ignores the count where it would repeat", async () => {
    const many = (await generate({ [OPTION_UUID_VERSION]: "v4", [OPTION_COUNT]: 8 })).split("\n");
    expect(many).toHaveLength(8);
    expect(new Set(many).size).toBe(8);
    // Deterministic and constant versions would produce eight identical lines, so they produce one.
    expect(
      (await generate({ [OPTION_UUID_VERSION]: "nil", [OPTION_COUNT]: 8 })).split("\n"),
    ).toHaveLength(1);
  });

  /** v7's leading 48 bits are a Unix millisecond timestamp, which is what makes it sort. */
  it("makes v7 sort by creation time and v4 not", async () => {
    const ordered = (await generate({ [OPTION_UUID_VERSION]: "v7", [OPTION_COUNT]: 20 })).split(
      "\n",
    );
    expect([...ordered].sort()).toEqual(ordered);
  });
});

// ────────────────────────────────────────────────────────────────── Password

describe("password", () => {
  const generate = (options: FormatSpec["options"] = {}) => textOf("password", options);
  const only = (...on: (keyof typeof PASSWORD_ALPHABETS)[]) =>
    Object.fromEntries(
      Object.entries(PASSWORD_CLASS_OPTIONS).map(([id, option]) => [
        option,
        on.includes(id as keyof typeof PASSWORD_ALPHABETS),
      ]),
    );

  it("opens with all four classes on and twenty characters", async () => {
    const spec = specFor("password");
    expect(readClasses(spec.options)).toEqual(["lower", "upper", "digit", "symbol"]);
    expect(await generate()).toHaveLength(20);
  });

  it("draws only from the classes selected, and one from each of them", async () => {
    for (const classes of [["lower"], ["digit", "symbol"], ["lower", "upper", "digit"]] as const) {
      const alphabet = classes.map((id) => PASSWORD_ALPHABETS[id]).join("");
      // Twenty samples: a class that is silently absent shows up quickly, and one that leaks in
      // shows up on the first character outside the alphabet.
      for (let i = 0; i < 20; i++) {
        const value = await generate({ ...only(...classes), [OPTION_LENGTH]: 12 });
        for (const ch of value) expect(alphabet, `${classes} produced ${ch}`).toContain(ch);
        for (const id of classes) {
          expect(
            [...value].some((ch) => PASSWORD_ALPHABETS[id].includes(ch)),
            `${classes}: no ${id} in ${value}`,
          ).toBe(true);
        }
      }
    }
  });

  it("leaves out the five look-alikes when asked", async () => {
    for (let i = 0; i < 20; i++) {
      const value = await generate({ [OPTION_EXCLUDE_AMBIGUOUS]: true, [OPTION_LENGTH]: 64 });
      for (const ch of "Il1O0") expect(value, `contains ${ch}`).not.toContain(ch);
    }
  });

  it("refuses a length that cannot hold one of each class, and says why", async () => {
    const result = await run("password", { [OPTION_LENGTH]: 4, ...only("lower", "upper", "digit", "symbol") });
    // Length is clamped at 4, so this is the one case where the guarantee and the length collide.
    expect(result.error ?? "").toMatch(/cannot contain one of each|^$/);
  });

  it("reports the entropy as an upper bound rather than as a figure it cannot support", async () => {
    const result = await run("password", {});
    const entropy = result.fields!.find((f) => f.label === "Entropy")!.value;
    // Guaranteeing one per class removes possibilities, so `length * log2(alphabet)` is a bound.
    expect(entropy).toMatch(/^at most \d+ bits$/);
    expect(result.fields!.find((f) => f.label === "Source")!.value).toBe("crypto.getRandomValues");
  });

  /*
   * The sampler itself is `randomBelow` in `@ocs/engine` now, and its uniformity is asserted in
   * `tests/random.test.ts` -- over more buckets and more draws than a tool test should carry, and
   * where the other callers of it can see the same evidence.
   */

  it("generates a different password every time", async () => {
    const many = (await generate({ [OPTION_COUNT]: 20 })).split("\n");
    expect(many).toHaveLength(20);
    expect(new Set(many).size).toBe(20);
  });
});

// ------------------------------------------------------- Random ------------

/**
 * The two random tools, and what is left to test once the samplers are covered elsewhere.
 *
 * `tests/random.test.ts` owns the distribution: whether a draw is uniform, whether a modulo crept
 * back in, whether a shuffle is a permutation. None of that belongs here, because it is a property of
 * `@ocs/engine` and it needs tens of thousands of draws to see.
 *
 * What belongs here is the *tool*: that the options reach the sampler at all, that the two
 * configurations which cannot be satisfied are refused with a message naming the numbers, and that
 * the output has the shape the panel will render. That division is the same one the cipher family
 * uses -- `algos-*` tests the primitive, `cipher.test.ts` tests the catalogue-resolver-compute path --
 * and it is what stops a green suite over a control wired to nothing.
 */
describe("random numbers", () => {
  const draw = async (options: Record<string, unknown>): Promise<string> =>
    textOf("random", options as Parameters<typeof textOf>[1], "");

  const lines = async (options: Record<string, unknown>): Promise<number[]> =>
    (await draw(options)).split("\n").map(Number);

  it("draws inside the range, inclusively, and one per line", async () => {
    const values = await lines({ [OPTION_RANDOM_MIN]: 1, [OPTION_RANDOM_MAX]: 6, [OPTION_COUNT]: 50 });
    expect(values).toHaveLength(50);
    for (const value of values) {
      expect(Number.isInteger(value)).toBe(true);
      expect(value).toBeGreaterThanOrEqual(1);
      expect(value).toBeLessThanOrEqual(6);
    }
    // 50 draws over six values reaches both ends with overwhelming probability; an exclusive upper
    // bound would never produce the 6 and is the single most likely mistake in this tool.
    expect(new Set(values).size).toBeGreaterThan(3);
  });

  it("reaches both endpoints of a two-value range", async () => {
    const values = await lines({ [OPTION_RANDOM_MIN]: 0, [OPTION_RANDOM_MAX]: 1, [OPTION_COUNT]: 60 });
    expect([...new Set(values)].sort()).toEqual([0, 1]);
  });

  it("handles a negative range and a single-value range", async () => {
    const negative = await lines({
      [OPTION_RANDOM_MIN]: -10,
      [OPTION_RANDOM_MAX]: -8,
      [OPTION_COUNT]: 40,
    });
    for (const value of negative) expect(value).toBeLessThan(0);
    expect([...new Set(negative)].sort((a, b) => a - b)).toEqual([-10, -9, -8]);
    expect(await lines({ [OPTION_RANDOM_MIN]: 7, [OPTION_RANDOM_MAX]: 7, [OPTION_COUNT]: 5 })).toEqual([
      7, 7, 7, 7, 7,
    ]);
  });

  /**
   * Repeats are the *default*, and that is a decision rather than an omission.
   *
   * A die is independent and 6,6,6 is a legitimate roll. Silently de-duplicating would make the tool
   * wrong for the commonest use of it, so this asserts the default really can repeat -- 40 draws from
   * three values must collide.
   */
  it("repeats by default and does not when told not to", async () => {
    const repeated = await lines({
      [OPTION_RANDOM_MIN]: 1,
      [OPTION_RANDOM_MAX]: 3,
      [OPTION_COUNT]: 40,
    });
    expect(new Set(repeated).size).toBeLessThan(repeated.length);

    const distinct = await lines({
      [OPTION_RANDOM_MIN]: 1,
      [OPTION_RANDOM_MAX]: 50,
      [OPTION_COUNT]: 20,
      [OPTION_RANDOM_DISTINCT]: true,
    });
    expect(distinct).toHaveLength(20);
    expect(new Set(distinct).size).toBe(20);
  });

  it("draws a whole small range without repeats, where rejection would stall", async () => {
    const all = await lines({
      [OPTION_RANDOM_MIN]: 1,
      [OPTION_RANDOM_MAX]: 40,
      [OPTION_COUNT]: 40,
      [OPTION_RANDOM_DISTINCT]: true,
    });
    expect([...all].sort((a, b) => a - b)).toEqual(Array.from({ length: 40 }, (_, i) => i + 1));
  });

  it("sorts after drawing, without changing which values came up", async () => {
    const sorted = await lines({
      [OPTION_RANDOM_MIN]: 1,
      [OPTION_RANDOM_MAX]: 1000,
      [OPTION_COUNT]: 30,
      [OPTION_RANDOM_SORTED]: true,
    });
    expect(sorted).toHaveLength(30);
    expect([...sorted]).toEqual([...sorted].sort((a, b) => a - b));
  });

  /**
   * The two refusals, and both name the numbers.
   *
   * "Invalid range" would be useless; the rule this repo follows is that a refusal says what the
   * situation is. Everything softer than these two is clamped instead -- a count of 0 or a bound past
   * the control's own maximum is a spinner mishap, not a request.
   */
  it("refuses an inverted range and an impossible distinct draw, naming the numbers", async () => {
    const inverted = await run("random", { [OPTION_RANDOM_MIN]: 10, [OPTION_RANDOM_MAX]: 2 });
    expect(inverted.error).toMatch(/From is 10 and To is 2/);

    const impossible = await run("random", {
      [OPTION_RANDOM_MIN]: 1,
      [OPTION_RANDOM_MAX]: 5,
      [OPTION_COUNT]: 9,
      [OPTION_RANDOM_DISTINCT]: true,
    });
    expect(impossible.error).toMatch(/9 values with no repeats needs a range of at least 9/);
    expect(impossible.error).toMatch(/holds 5/);
  });

  it("refuses a range wider than exact integer arithmetic", async () => {
    const tooWide = await run("random", {
      [OPTION_RANDOM_MIN]: -Number.MAX_SAFE_INTEGER,
      [OPTION_RANDOM_MAX]: Number.MAX_SAFE_INTEGER,
    });
    // Not a crash and not a silently-wrong draw: past 2^53 a range stops counting in ones.
    expect(tooWide.error).toMatch(/past exact integer arithmetic/);
  });

  it("draws decimals in [0, 1) at the requested precision", async () => {
    const text = await draw({ [OPTION_RANDOM_SHAPE]: "decimal", [OPTION_COUNT]: 30 });
    const values = text.split("\n");
    expect(values).toHaveLength(30);
    for (const value of values) {
      // Six places by default, and the string is what the panel shows.
      expect(value, value).toMatch(/^0\.\d{6}$|^1\.000000$/);
      expect(Number(value)).toBeGreaterThanOrEqual(0);
      expect(Number(value)).toBeLessThanOrEqual(1);
    }
    const precise = await draw({
      [OPTION_RANDOM_SHAPE]: "decimal",
      [OPTION_RANDOM_PLACES]: 12,
      [OPTION_COUNT]: 3,
    });
    for (const value of precise.split("\n")) expect(value.split(".")[1]).toHaveLength(12);
  });

  it("states the range, the draw and the uniformity, because none is visible in the output", async () => {
    const result = await run("random", {
      [OPTION_RANDOM_MIN]: 1,
      [OPTION_RANDOM_MAX]: 49,
      [OPTION_COUNT]: 6,
      [OPTION_RANDOM_DISTINCT]: true,
    });
    const field = (label: string) => result.fields!.find((f) => f.label === label)!.value;
    expect(field("Range")).toBe("1 to 49 (49 values)");
    expect(field("Draw")).toBe("Without replacement");
    // The property the tool exists for, and the one nobody can check by looking at the numbers.
    expect(field("Uniformity")).toMatch(/no modulo bias/);
    expect(field("Source")).toBe("crypto.getRandomValues");
  });

  it("gives a different answer every time", async () => {
    const runs = new Set<string>();
    for (let i = 0; i < 20; i++) {
      runs.add(await draw({ [OPTION_RANDOM_MIN]: 1, [OPTION_RANDOM_MAX]: 1_000_000, [OPTION_COUNT]: 4 }));
    }
    expect(runs.size).toBe(20);
  });

  it("describes itself in terms of the range rather than the mechanism", () => {
    expect(
      describeSpec(specFor("random", { [OPTION_RANDOM_MIN]: 1, [OPTION_RANDOM_MAX]: 6, [OPTION_COUNT]: 2 })),
    ).toBe("Draws 2 whole numbers from 1 to 6 inclusive.");
    expect(describeSpec(specFor("random", { [OPTION_RANDOM_SHAPE]: "decimal" }))).toMatch(
      /1 decimal from \[0, 1\)/,
    );
  });
});

describe("random bytes", () => {
  it("returns bytes at the requested length, so the encoding menu can spell them", async () => {
    const result = await run("randombytes", { [OPTION_RANDOM_BYTES]: 32 });
    expect(result.bytes).toBeInstanceOf(Uint8Array);
    expect(result.bytes).toHaveLength(32);
    // Not text: `text` here would leave the Result panel's encoding selector with nothing to act on.
    expect(result.text).toBeUndefined();
  });

  it("covers the whole length range it offers", async () => {
    for (const length of [1, 12, 16, 31, 64, 4096]) {
      const result = await run("randombytes", { [OPTION_RANDOM_BYTES]: length });
      expect(result.bytes, `length ${length}`).toHaveLength(length);
    }
  });

  /*
   * There is no "Commonly, this is an X" field to test any more, and that is the point.
   *
   * It mapped a byte count to a role and two of its entries were wrong -- see the note where the
   * lookup used to be in `compute.ts`, and `tests/size-claims.test.ts`, which now guards the class.
   * The size in bytes and bits is the fact this tool knows; what a length is *for* is a question about
   * the tool the bytes are going into.
   */

  /**
   * More than one, which is the one case that cannot return bytes.
   *
   * The Result panel spells a single byte string, so several have to be text -- and the encoding menu
   * would then be inert, which is the defect this repo records most often. Returning hex and saying so
   * in a field is the honest version of that limitation, and this pins both halves.
   */
  it("falls back to hex lines above one value, and says that it did", async () => {
    const result = await run("randombytes", {
      [OPTION_RANDOM_BYTES]: 8,
      [OPTION_COUNT]: 5,
    });
    expect(result.bytes).toBeUndefined();
    const values = result.text!.split("\n");
    expect(values).toHaveLength(5);
    for (const value of values) expect(value).toMatch(/^[0-9a-f]{16}$/);
    expect(new Set(values).size).toBe(5);
    expect(result.fields!.find((f) => f.label === "Encoding")!.value).toMatch(/Hex/);
  });

  it("reports the size in bytes and bits", async () => {
    const result = await run("randombytes", { [OPTION_RANDOM_BYTES]: 16 });
    expect(result.fields!.find((f) => f.label === "Size")!.value).toBe("16 bytes (128 bits)");
  });

  it("gives different bytes every time", async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const result = await run("randombytes", { [OPTION_RANDOM_BYTES]: 16 });
      seen.add([...result.bytes!].join(","));
    }
    expect(seen.size).toBe(20);
  });
});

// ───────────────────────────────────────────────────────── Lint ───────────

describe("lint rules", () => {
  it("declares every code it can emit, and emits every code it declares", () => {
    const emitted = new Set<string>();
    /** One spec per rule, chosen to trip it. */
    const TRIPS: readonly FormatSpec[] = [
      specFor("htmlentity", { [OPTION_ENTITY_FORM]: "named" }),
      specFor("uuid", { [OPTION_UUID_VERSION]: "v1" }),
      specFor("uuid", { [OPTION_UUID_VERSION]: "v5", [OPTION_UUID_NAME]: "x" }),
      specFor("jwt"),
      specFor("password", { [OPTION_LENGTH]: 8, [PASSWORD_CLASS_OPTIONS.symbol]: false }),
      specFor("password", {
        [PASSWORD_CLASS_OPTIONS.lower]: false,
        [PASSWORD_CLASS_OPTIONS.upper]: false,
        [PASSWORD_CLASS_OPTIONS.digit]: false,
        [PASSWORD_CLASS_OPTIONS.symbol]: false,
      }),
      specFor("json", { [OPTION_SORT_KEYS]: true }),
      specFor("randombytes", { [OPTION_RANDOM_BYTES]: 8 }),
    ];
    for (const spec of TRIPS) for (const d of lint(spec).diagnostics) emitted.add(d.code);
    expect([...emitted].sort()).toEqual([...RULE_CODES].sort());
  });

  it("has a fix for every rule that offers one, and the fix silences it", () => {
    const FIXABLE: readonly FormatSpec[] = [
      specFor("htmlentity", { [OPTION_ENTITY_FORM]: "named" }),
      specFor("password", { [OPTION_LENGTH]: 8, [PASSWORD_CLASS_OPTIONS.symbol]: false }),
      specFor("password", {
        [PASSWORD_CLASS_OPTIONS.lower]: false,
        [PASSWORD_CLASS_OPTIONS.upper]: false,
        [PASSWORD_CLASS_OPTIONS.digit]: false,
        [PASSWORD_CLASS_OPTIONS.symbol]: false,
      }),
      specFor("randombytes", { [OPTION_RANDOM_BYTES]: 8 }),
    ];
    for (const spec of FIXABLE) {
      const before = lint(spec).diagnostics.filter((d) => d.fix);
      expect(before.length, `${spec.variant} offered no fix`).toBeGreaterThan(0);
      const after = lint(applyAllFixes(spec));
      for (const d of before) {
        expect(after.diagnostics.some((a) => a.code === d.code && a.fix), d.code).toBe(false);
      }
    }
  });

  /**
   * `applyAllFixes` runs every fix in one pass, so two can land on the same spec. The cipher family
   * shipped a bug of exactly this shape once -- one fix reading a value the other had just changed --
   * which is why this asserts a *resolvable* spec rather than only a quieter one.
   */
  it("leaves every tool's default spec computable after applying all fixes", async () => {
    for (const meta of FORMAT_TOOLS) {
      const fixed = applyAllFixes(specFor(meta.id));
      expect(() => formatToolDefinition(meta.id).specSchema.parse(fixed)).not.toThrow();
      const result = await formatToolDefinition(meta.id).compute(fixed, bytes('{"a":1}'));
      // A parser handed `{"a":1}` is happy; the others ignore it. Only a *thrown* error would fail.
      expect(typeof result).toBe("object");
    }
  });

  it("reports F004 in terms of what the settings produce, not the character count alone", () => {
    const wide = lint(specFor("password", { [OPTION_LENGTH]: 12 })).diagnostics;
    const narrow = lint(
      specFor("password", { [OPTION_LENGTH]: 12, ...{ [PASSWORD_CLASS_OPTIONS.upper]: false, [PASSWORD_CLASS_OPTIONS.digit]: false, [PASSWORD_CLASS_OPTIONS.symbol]: false } }),
    ).diagnostics;
    const bits = (list: typeof wide) =>
      Number(/about (\d+) bits/.exec(list.find((d) => d.code === "F004")?.message ?? "")?.[1] ?? 0);
    // Twelve characters over 79 is stronger than twelve over 26, and the message has to say so.
    expect(bits(narrow)).toBeGreaterThan(0);
    expect(bits(narrow)).toBeLessThan(bits(wide) || 76);
  });

  it("says HAVAL-style precise things about the two UUID versions that are not opaque", () => {
    const timed = lint(specFor("uuid", { [OPTION_UUID_VERSION]: "v6" })).diagnostics;
    expect(timed.find((d) => d.code === "F002")!.message).toMatch(/contains the time/);
    const hashed = lint(
      specFor("uuid", { [OPTION_UUID_VERSION]: "v5", [OPTION_UUID_NAME]: "x" }),
    ).diagnostics;
    expect(hashed.find((d) => d.code === "F002")!.message).toMatch(/hash of the name/);
    // v4 and v7 are opaque, so there is nothing to say and the panel stays quiet.
    expect(
      lint(specFor("uuid", { [OPTION_UUID_VERSION]: "v4" })).diagnostics.some(
        (d) => d.code === "F002",
      ),
    ).toBe(false);
  });
});
