/**
 * Every tool's computation, and almost none of it is an implementation.
 *
 * This family is the one place in the repo where the rule cuts the other way. Everywhere else the
 * question is "does a library meet the constraints", and the answer has usually been no -- there is no
 * audited Streebog, no browser-safe FSB, no library with XTS over a generic block cipher. Here a
 * mature library exists for every job, so writing a second JSON parser or a second entity table would
 * add a way to be wrong rather than a way to be right. What is left is the catalogue: which options
 * exist, what they are called, and what the errors say.
 *
 * The libraries, and why each:
 *
 *  - **`jsonc-parser`** -- Microsoft's, and the parser VS Code reads its own settings with. Chosen over
 *    `JSON.parse` for two reasons that both matter here. Its errors carry an *offset*, so the tool can
 *    report a line and column identically in V8, JavaScriptCore and SpiderMonkey, where `JSON.parse`'s
 *    message is engine-specific. And its `parseTree` keeps each node's offset into the source, which is
 *    what lets scalars be re-emitted **verbatim** -- a `parse`/`stringify` round trip reorders
 *    integer-like keys, collapses duplicates, turns `1.0` into `1`, and silently rewrites an integer
 *    too large for a double. A formatter must not change what a document says.
 *  - **`@xmldom/xmldom`** -- a standards-compliant DOM in pure JavaScript, so namespaces, comments,
 *    CDATA and processing instructions are handled by something that has seen real XML. `DOMParser` is
 *    not available: `window` and `document` are eslint-restricted in these packages and absent from the
 *    compute worker and from Node.
 *  - **`entities`** -- the encoder and decoder htmlparser2 and cheerio use, carrying the full WHATWG
 *    named-reference table. Writing that table out here would be two thousand lines of data to mistype.
 *  - **`uuid`** -- the reference JavaScript implementation, tested upstream against RFC 9562. It also
 *    takes injectable `random` and `msecs`, which is what makes the time-based versions checkable.
 *  - **`change-case`** -- the standard splitter, and the reason to use it rather than a regex is
 *    `XMLHttpRequest`: getting `xml_http_request` out of that rather than `x_m_l_http_request` is the
 *    whole difficulty, and it is not one regex.
 *  - **The platform** for percent-encoding. `encodeURIComponent`, `encodeURI` and `URLSearchParams`
 *    *are* the three flavours; wrapping them in hand-written character sets was the first attempt here
 *    and it got form encoding's treatment of `~` wrong.
 *
 * The one exception is `password`, which has no library because none met the constraints -- see its
 * section below.
 */
import {
  randomBelow,
  randomBytes,
  randomFloat,
  randomInt,
  randomIntSample,
  shuffled,
  type ToolResult,
  type ToolResultField,
} from "@ocs/engine";
import { decodeHTML, encodeHTML, escapeUTF8 } from "entities";
import { getNodeValue, parseTree, printParseErrorCode, type Node } from "jsonc-parser";
/**
 * `xmldom` declares its own `Document`, `Element` and `Node`, and they are deliberately *not* the
 * `lib.dom` ones -- they are a pure-JavaScript DOM that happens to implement the same interfaces.
 * The global names are in scope here (`library.json` includes DOM, because `@ocs/asymmetric` needs
 * `CryptoKey`), so leaving these unaliased typechecks against the wrong declarations: the two are
 * structurally different, and lib.dom's `NodeListOf` is not iterable where xmldom's `NodeList` is.
 */
import {
  DOMParser,
  XMLSerializer,
  type Document as XmlDocument,
  type Element as XmlElement,
  type Node as XmlNode,
} from "@xmldom/xmldom";
import * as changeCase from "change-case";
import { NIL as UUID_NIL, MAX as UUID_MAX, v1, v3, v4, v5, v6, v7 } from "uuid";
import { requireFormatTool } from "./catalogue/tool-meta";
import {
  indentText,
  readAction,
  readCaseStyle,
  readClasses,
  readCount,
  readDirection,
  readEntityForm,
  readEntityScope,
  readIndent,
  readLength,
  readUrlMode,
  readUuidNamespace,
  readUuidVersion,
  OPTION_EXCLUDE_AMBIGUOUS,
  OPTION_SORT_KEYS,
  OPTION_COLLAPSE,
  OPTION_UUID_NAME,
  PASSWORD_ALPHABETS,
  type Action,
  type CaseStyle,
  readRandomShape,
  OPTION_RANDOM_BYTES,
  OPTION_RANDOM_DISTINCT,
  OPTION_RANDOM_MAX,
  OPTION_RANDOM_MIN,
  OPTION_RANDOM_PLACES,
  OPTION_RANDOM_SORTED,
  type PasswordClass,
} from "./pure";
import type { FormatSpec } from "./spec";
import { optBool, optNumber, optString } from "@ocs/contracts/pure";

const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

export async function computeFormat(spec: FormatSpec, input: Uint8Array): Promise<ToolResult> {
  const tool = requireFormatTool(spec.variant);
  try {
    switch (tool.kind) {
      case "url":
        return urlResult(spec, text(input));
      case "htmlentity":
        return entityResult(spec, text(input));
      case "jwt":
        return jwtResult(text(input));
      case "json":
        return jsonResult(spec, text(input));
      case "xml":
        return xmlResult(spec, text(input));
      case "case":
        return { text: applyCase(readCaseStyle(spec.options), text(input)) };
      case "uuid":
        return uuidResult(spec);
      case "password":
        return passwordResult(spec);
      case "random":
        return randomResult(spec);
      case "randombytes":
        return randomBytesResult(spec);
    }
  } catch (thrown) {
    /**
     * A library throwing is a *result*, not a crash.
     *
     * Same reasoning as the cipher family wrapping its bindings: a half-typed document is a normal
     * state of a text box, and the panel has to render the problem rather than the workbench catching
     * an exception. This wrapper is also what covers a future library that throws where the current
     * one returns.
     */
    return { error: thrown instanceof Error ? thrown.message : String(thrown) };
  }
}

// ─────────────────────────────────────────────────────────────────── URL

function urlResult(spec: FormatSpec, value: string): ToolResult {
  const mode = readUrlMode(spec.options);
  if (readDirection(spec.options) === "encode") {
    if (mode === "uri") return { text: encodeURI(value) };
    if (mode === "component") return { text: encodeURIComponent(value) };
    /**
     * The platform's own form serialiser, rather than `encodeURIComponent` with the spaces swapped.
     *
     * They differ in five characters: form escapes `!`, `'`, `(`, `)` and `~`, and `encodeURIComponent`
     * does not. Deriving one from the other is how the first version of this got `~` wrong -- and a
     * round-trip test cannot see that, because it cannot see *which* characters were escaped.
     */
    return { text: new URLSearchParams({ v: value }).toString().slice(2) };
  }

  try {
    // `decodeURIComponent` throws on a malformed escape, which is the right behaviour: a truncated
    // `%A` is a copy-paste error far more often than a literal percent sign.
    if (mode === "form") {
      const params = new URLSearchParams(`v=${value}`);
      return { text: params.get("v") ?? "" };
    }
    return { text: decodeURIComponent(value) };
  } catch {
    return {
      error:
        "That is not valid percent-encoded text. A '%' must be followed by two hex digits, and the escaped bytes must be valid UTF-8.",
    };
  }
}

// ────────────────────────────────────────────────────────── HTML entities

/** The five that change how a document parses. */
const MARKUP = /[&<>"']/g;
/** The same five, plus every code point above ASCII. `u` so a surrogate pair stays one reference. */
const MARKUP_OR_NON_ASCII = /[&<>"']|[^\x00-\x7F]/gu;

function entityResult(spec: FormatSpec, value: string): ToolResult {
  if (readDirection(spec.options) === "decode") {
    /**
     * `decodeHTML`, not `decodeXML`, and not the strict variant either.
     *
     * `decodeXML` knows the five XML references and every numeric one and *nothing else* -- so it
     * leaves `&nbsp;` and `&eacute;` untouched, which are precisely the references somebody arrives
     * with. Worse, this tool's own encoder writes them, so the pair would not have round-tripped.
     *
     * `decodeHTMLStrict` would require a semicolon on every reference; `decodeHTML` accepts the legacy
     * unterminated forms, which is what a browser does. That is deliberate even where it looks wrong:
     * `&notreal;` decodes to a not-sign followed by `real;`, because `&not` is a legacy reference the
     * HTML parser recognises without its semicolon. Reproducing what the destination will actually do
     * is the whole job -- the same reason the direction is one tool with an arrow rather than two.
     */
    return { text: decodeHTML(value) };
  }

  const scope = readEntityScope(spec.options);
  const form = readEntityForm(spec.options);

  /**
   * Which characters, then how each is written -- and the two are kept independent on purpose.
   *
   * The first version derived the numeric cases from the named ones (`escapeUTF8`, then a sweep for
   * non-ASCII) and that made *both* settings lie. `encodeXML` escapes non-ASCII as well as the five,
   * so "Markup only" was escaping accents; and running a numeric sweep over `escapeUTF8`'s output left
   * `<` as `&lt;` while the reference style said hexadecimal. Neither is visible in a round trip,
   * because a decoder accepts every form -- which is why the tests below assert the exact output.
   */
  const pattern = scope === "markup" ? MARKUP : MARKUP_OR_NON_ASCII;
  if (form !== "named") return { text: numeric(value, form, pattern) };
  // `escapeUTF8` is the five, named, with non-ASCII left as itself -- which is exactly "markup only".
  // `encodeHTML` is the full WHATWG named table, falling back to numeric for anything unnamed.
  return { text: scope === "markup" ? escapeUTF8(value) : encodeHTML(value) };
}

function numeric(value: string, form: "decimal" | "hex", pattern: RegExp): string {
  return value.replace(pattern, (ch) => {
    const point = ch.codePointAt(0) ?? 0;
    return form === "hex" ? `&#x${point.toString(16).toUpperCase()};` : `&#${point};`;
  });
}

// ─────────────────────────────────────────────────────────────────── JWT

function jwtResult(value: string): ToolResult {
  const parts = value.trim().split(".");
  if (parts.length !== 3) {
    return {
      error: `A JWT has three dot-separated parts; this has ${parts.length}. A two-part value is an unsecured token (alg "none") and a five-part one is JWE, which this does not read.`,
    };
  }
  const [rawHeader, rawPayload, signature] = parts as [string, string, string];

  const header = segment(rawHeader, "header");
  if ("error" in header) return { error: header.error };
  const payload = segment(rawPayload, "payload");
  if ("error" in payload) return { error: payload.error };

  const fields: ToolResultField[] = [
    { label: "Header", value: header.json },
    { label: "Payload", value: payload.json },
    /**
     * The signature is shown and *not* checked, which is the whole point of `F003`.
     *
     * Decoding a JWT is trivial and verifying one needs the key, so a tool that displayed claims
     * without saying so would invite exactly the mistake the RFC warns about: trusting a payload
     * anybody can rewrite. The MAC and asymmetric families are where the check belongs.
     */
    { label: "Signature", value: signature === "" ? "(none)" : signature },
  ];

  for (const [claim, label] of [
    ["iat", "Issued at"],
    ["nbf", "Not before"],
    ["exp", "Expires"],
  ] as const) {
    const seconds = timeClaim(payload.value, claim);
    if (seconds !== undefined) fields.push({ label, value: seconds });
  }

  return { text: `${header.json}\n${payload.json}`, fields };
}

function segment(
  raw: string,
  which: string,
): { json: string; value: unknown } | { error: string } {
  try {
    // Base64url, and a JWT's segments are unpadded. `atob` needs standard alphabet and padding.
    const standard = raw.replace(/-/g, "+").replace(/_/g, "/");
    const padded = standard + "=".repeat((4 - (standard.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value: unknown = JSON.parse(decoded);
    return { json: JSON.stringify(value, null, 2), value };
  } catch {
    return {
      error: `The ${which} is not Base64url-encoded JSON. JWT segments use '-' and '_' in place of '+' and '/', and carry no '=' padding.`,
    };
  }
}

/** A numeric date claim, rendered as an absolute time. Relative-to-now is deliberately absent. */
function timeClaim(payload: unknown, claim: string): string | undefined {
  if (typeof payload !== "object" || payload === null) return undefined;
  const value = (payload as Record<string, unknown>)[claim];
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  /**
   * Absolute only. "Expired 3 days ago" would be a nicer sentence and a worse one to compute here: it
   * depends on the reading clock, so a screenshot of it stops being true, and it would make the whole
   * tool's output nondeterministic for no gain over the timestamp beside it.
   */
  return `${new Date(value * 1000).toISOString()} (${claim} = ${value})`;
}

// ────────────────────────────────────────────────────────────────── JSON

function jsonResult(spec: FormatSpec, value: string): ToolResult {
  if (value.trim() === "") return { error: "Nothing to parse — the input is empty." };

  const errors: { error: number; offset: number; length: number }[] = [];
  const tree = parseTree(value, errors, { allowTrailingComma: false, disallowComments: true });

  if (errors.length > 0 || tree === undefined) {
    const first = errors[0];
    if (!first) return { error: "Could not parse that as JSON." };
    const { line, column } = lineColumn(value, first.offset);
    return { error: `Line ${line}, column ${column}: ${readableParseError(first.error)}.` };
  }

  const action = readAction(spec.options, "format");
  if (action === "validate") {
    return {
      text: "Valid JSON.",
      fields: describeJson(value, tree),
    };
  }

  const indent = action === "minify" ? "" : indentText(readIndent(spec.options));
  const sortKeys = optBool(spec.options, OPTION_SORT_KEYS);
  return { text: writeJson(value, tree, indent, sortKeys) };
}

/**
 * Re-emit from the parse tree, slicing scalars out of the *source*.
 *
 * This is why `parseTree` is used rather than `JSON.parse`: every scalar is written back as the exact
 * characters it was written with, so `1.0` stays `1.0`, a 20-digit integer survives, `A` is not
 * silently turned into `A`, and duplicate keys are both kept. Members stay in source order unless
 * sorting is asked for, which is the one setting that deliberately changes the document.
 */
function writeJson(source: string, node: Node, indent: string, sortKeys: boolean): string {
  const nl = indent === "" ? "" : "\n";
  const gap = indent === "" ? "" : " ";

  const raw = (n: Node): string => source.slice(n.offset, n.offset + n.length);

  const emit = (n: Node, depth: number): string => {
    const pad = indent === "" ? "" : indent.repeat(depth + 1);
    const closePad = indent === "" ? "" : indent.repeat(depth);

    if (n.type === "array") {
      const items = n.children ?? [];
      if (items.length === 0) return "[]";
      const body = items.map((item) => pad + emit(item, depth + 1)).join("," + nl);
      return `[${nl}${body}${nl}${closePad}]`;
    }
    if (n.type === "object") {
      const members = [...(n.children ?? [])];
      if (members.length === 0) return "{}";
      if (sortKeys) {
        members.sort((a, b) => {
          const ka = a.children?.[0] ? raw(a.children[0]) : "";
          const kb = b.children?.[0] ? raw(b.children[0]) : "";
          return ka < kb ? -1 : ka > kb ? 1 : 0;
        });
      }
      const body = members
        .map((member) => {
          const key = member.children?.[0];
          const val = member.children?.[1];
          if (!key || !val) return "";
          return `${pad}${raw(key)}:${gap}${emit(val, depth + 1)}`;
        })
        .join("," + nl);
      return `{${nl}${body}${nl}${closePad}}`;
    }
    // Scalars, verbatim. The whole reason this walks the tree rather than stringifying a value.
    return raw(n);
  };

  return emit(node, 0);
}

function describeJson(source: string, tree: Node): ToolResultField[] {
  const counts = { objects: 0, arrays: 0, scalars: 0 };
  let depth = 0;
  const walk = (n: Node, level: number) => {
    depth = Math.max(depth, level);
    if (n.type === "object") counts.objects++;
    else if (n.type === "array") counts.arrays++;
    else if (n.type !== "property") counts.scalars++;
    for (const child of n.children ?? []) walk(child, n.type === "property" ? level : level + 1);
  };
  walk(tree, 0);
  const value = getNodeValue(tree) as unknown;
  return [
    { label: "Top level", value: Array.isArray(value) ? "array" : typeof value },
    { label: "Objects", value: String(counts.objects) },
    { label: "Arrays", value: String(counts.arrays) },
    { label: "Values", value: String(counts.scalars) },
    { label: "Max depth", value: String(depth) },
    { label: "Size", value: `${source.length} characters` },
  ];
}

/**
 * `jsonc-parser`'s code as a sentence.
 *
 * It returns identifiers -- `PropertyNameExpected`, `CloseBraceExpected` -- which are precise and read
 * like a stack trace. Splitting on the capitals rather than looking the code up in a table is
 * deliberate: a table falls through to the raw identifier for anything added upstream, and a new code
 * is exactly the case where the message matters.
 */
function readableParseError(code: number): string {
  const words = printParseErrorCode(code).replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function lineColumn(source: string, offset: number): { line: number; column: number } {
  let line = 1;
  let start = 0;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source[i] === "\n") {
      line++;
      start = i + 1;
    }
  }
  return { line, column: offset - start + 1 };
}

// ─────────────────────────────────────────────────────────────────── XML

function xmlResult(spec: FormatSpec, value: string): ToolResult {
  if (value.trim() === "") return { error: "Nothing to parse — the input is empty." };

  /**
   * `xmldom` reports through a handler rather than throwing, and it distinguishes a *warning* from a
   * fatal error. Only the fatal ones are refused: it warns about things like an unbound namespace
   * prefix, which is a real observation and not a reason to decline to format a document somebody
   * pasted out of a larger file.
   */
  const problems: string[] = [];
  const parser = new DOMParser({
    onError: (level, message) => {
      if (level === "error" || level === "fatalError") problems.push(message);
    },
  });
  const doc = parser.parseFromString(value, "text/xml");
  if (problems.length > 0) return { error: problems[0]! };

  const action = readAction(spec.options, "format");
  const collapse = optBool(spec.options, OPTION_COLLAPSE);

  if (action === "validate") {
    return { text: "Well-formed XML.", fields: describeXml(doc, value) };
  }
  const indent = action === "minify" ? "" : indentText(readIndent(spec.options));
  return { text: writeXml(doc, indent, collapse) };
}

/**
 * The indentation walk, and the only part of XML handling written here.
 *
 * Parsing is `xmldom`'s and serialising a *node* is `XMLSerializer`'s; what is left is deciding where
 * a line break may go, which is presentation rather than parsing. One rule in it is worth stating:
 * **mixed content stays on one line.** An element holding both text and children --
 * `<p>hello <b>world</b></p>` -- cannot be broken across lines without inserting whitespace into the
 * text, so it is serialised whole. Indenting it anyway is the most common bug in XML pretty-printers.
 */
function writeXml(doc: XmlDocument, indent: string, collapse: boolean): string {
  const serializer = new XMLSerializer();
  const lines: string[] = [];

  const isText = (node: XmlNode) => node.nodeType === 3 || node.nodeType === 4;
  const blank = (node: XmlNode) => node.nodeType === 3 && (node.nodeValue ?? "").trim() === "";

  const emit = (node: XmlNode, depth: number): void => {
    if (blank(node)) {
      // Whitespace between elements. Dropped when laying out, because the layout replaces it.
      if (indent !== "" || collapse) return;
      lines.push(serializer.serializeToString(node));
      return;
    }
    const pad = indent === "" ? "" : indent.repeat(depth);

    if (node.nodeType !== 1) {
      const raw = serializer.serializeToString(node);
      lines.push(pad + (collapse && node.nodeType === 3 ? raw.trim() : raw));
      return;
    }

    const element = node as XmlElement;
    const children = [...element.childNodes];
    const meaningful = children.filter((child) => !blank(child));

    if (meaningful.length === 0 || meaningful.some(isText) || indent === "") {
      // Empty, mixed content, or minifying: one line, straight from the serialiser.
      const raw = serializer.serializeToString(element);
      lines.push(pad + (collapse ? raw.replace(/>\s+</g, "><") : raw));
      return;
    }

    // Element-only content: open tag, children indented, close tag. The open tag is reconstructed
    // from a shallow clone so its attributes are serialised by the library rather than by hand.
    const shallow = element.cloneNode(false) as XmlElement;
    const empty = serializer.serializeToString(shallow);
    const open = empty.endsWith("/>")
      ? `${empty.slice(0, -2).trimEnd()}>`
      : empty.slice(0, empty.lastIndexOf("</"));
    lines.push(pad + open);
    for (const child of meaningful) emit(child, depth + 1);
    lines.push(`${pad}</${element.nodeName}>`);
  };

  for (const node of [...doc.childNodes]) emit(node, 0);
  return indent === "" ? lines.join("") : lines.join("\n");
}

function describeXml(doc: XmlDocument, source: string): ToolResultField[] {
  let elements = 0;
  let depth = 0;
  const walk = (node: XmlNode, level: number) => {
    if (node.nodeType === 1) {
      elements++;
      depth = Math.max(depth, level);
    }
    for (const child of [...node.childNodes]) walk(child, level + 1);
  };
  for (const node of [...doc.childNodes]) walk(node, 1);
  return [
    { label: "Root", value: doc.documentElement?.nodeName ?? "(none)" },
    { label: "Elements", value: String(elements) },
    { label: "Max depth", value: String(depth) },
    { label: "Size", value: `${source.length} characters` },
  ];
}

// ────────────────────────────────────────────────────────────────── Case

/**
 * `change-case`'s own functions, by the name the option carries.
 *
 * A `Record` rather than a switch with a default, for the reason the other four in this repo record: a
 * style added to `CASE_STYLES` without an entry here should fail by name rather than silently become
 * camelCase.
 *
 * `upper` and `lower` are the two that do *not* split into words -- they change the case of the string
 * as it stands, which is what text needs and identifiers do not. `toUpperCase` rather than
 * `toLocaleUpperCase`: a locale-dependent result would make the same input give different output on
 * different machines, which is exactly what `navigator` is banned from these packages to prevent. It
 * does mean Turkish dotless i is not special-cased, and that is the correct trade for a tool whose
 * output people compare.
 */
const CASE_FUNCTIONS: Record<CaseStyle, (value: string) => string> = {
  camel: changeCase.camelCase,
  capital: changeCase.capitalCase,
  constant: changeCase.constantCase,
  dot: changeCase.dotCase,
  kebab: changeCase.kebabCase,
  no: changeCase.noCase,
  pascal: changeCase.pascalCase,
  pascalSnake: changeCase.pascalSnakeCase,
  path: changeCase.pathCase,
  sentence: changeCase.sentenceCase,
  snake: changeCase.snakeCase,
  train: changeCase.trainCase,
  upper: (value) => value.toUpperCase(),
  lower: (value) => value.toLowerCase(),
};

function applyCase(style: CaseStyle, value: string): string {
  const fn = CASE_FUNCTIONS[style];
  if (!fn) throw new Error(`No case function for style "${style}".`);
  /**
   * Line by line, so a list survives.
   *
   * `change-case` treats its input as one identifier, which is right for one and wrong for the twenty
   * somebody pasted out of a column. Splitting on newlines is what makes the tool usable on a list
   * without turning it into a single camelCased run.
   */
  return value.split("\n").map((line) => (line.trim() === "" ? line : fn(line))).join("\n");
}

// ────────────────────────────────────────────────────────────────── UUID

const NAMESPACES: Record<string, string> = {
  dns: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  url: "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
  oid: "6ba7b812-9dad-11d1-80b4-00c04fd430c8",
  x500: "6ba7b814-9dad-11d1-80b4-00c04fd430c8",
};

function uuidResult(spec: FormatSpec): ToolResult {
  const version = readUuidVersion(spec.options);
  const count = readCount(spec.options);

  if (version === "nil" || version === "max") {
    // Constants, so a count of ten would be ten identical lines. One, and the count is ignored.
    return {
      text: version === "nil" ? UUID_NIL : UUID_MAX,
      fields: [{ label: "Version", value: version === "nil" ? "Nil (all zeroes)" : "Max (all ones)" }],
    };
  }

  if (version === "v3" || version === "v5") {
    const named = readNamed(spec);
    if ("error" in named) return { error: named.error };
    const value = version === "v3" ? v3(named.name, named.namespace) : v5(named.name, named.namespace);
    return {
      // Deterministic, so a count above one would repeat the same value. Stated rather than silent.
      text: value,
      fields: [
        { label: "Version", value: version === "v3" ? "v3 (MD5)" : "v5 (SHA-1)" },
        { label: "Namespace", value: named.namespace },
        { label: "Name", value: named.name },
        {
          label: "Deterministic",
          value: "The same namespace and name always give this identifier.",
        },
      ],
    };
  }

  /**
   * Annotated, because each of these is overloaded (a buffer-writing form as well as a string one) and
   * TypeScript will not call a union of overloaded signatures. Narrowing to the arity actually used
   * here is the whole fix; nothing about the call changes.
   */
  const make: () => string = version === "v1" ? v1 : version === "v6" ? v6 : version === "v7" ? v7 : v4;
  const values: string[] = [];
  for (let i = 0; i < count; i++) values.push(make());
  return {
    text: values.join("\n"),
    fields: [
      { label: "Version", value: VERSION_NOTE[version] ?? version },
      { label: "Count", value: String(count) },
    ],
  };
}

const VERSION_NOTE: Record<string, string> = {
  v1: "v1 — 60-bit timestamp and a random node. Does not sort chronologically.",
  v4: "v4 — 122 random bits.",
  v6: "v6 — v1's timestamp with the fields reordered, so it sorts.",
  v7: "v7 — 48-bit Unix millisecond timestamp, then 74 random bits. Sorts chronologically.",
};

function readNamed(spec: FormatSpec): { namespace: string; name: string } | { error: string } {
  const selected = readUuidNamespace(spec.options);
  const raw = (optString(spec.options, OPTION_UUID_NAME) ?? "").trim();

  if (selected !== "custom") {
    if (raw === "") {
      return { error: "Enter a name to hash. v3 and v5 derive the identifier from it." };
    }
    return { namespace: NAMESPACES[selected]!, name: raw };
  }

  /**
   * Custom namespace: the UUID on the first line, the name on the second.
   *
   * Two values in one field rather than a second text control, because a namespace is only ever
   * entered alongside a name -- and a control that appears for one value out of five choices is more
   * form than it saves.
   */
  const [first, ...rest] = raw.split("\n");
  const namespace = (first ?? "").trim();
  const name = rest.join("\n").trim();
  if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(namespace)) {
    return {
      error:
        "With a custom namespace, put the namespace UUID on the first line and the name on the second.",
    };
  }
  if (name === "") return { error: "Put the name on the second line, after the namespace UUID." };
  return { namespace, name };
}

// ────────────────────────────────────────────────────────────── Password

/** The five that get misread aloud or mistyped on a phone keyboard. */
const AMBIGUOUS = "Il1O0";

function passwordResult(spec: FormatSpec): ToolResult {
  const length = readLength(spec.options);
  const count = readCount(spec.options);
  const selected = readClasses(spec.options);
  /**
   * The fallback, and `F005` is what makes it honest.
   *
   * Refusing outright would be defensible and is the wrong trade: somebody who has just unticked the
   * last box wants to see what happens, not an error where the output was. So it generates over
   * lower, upper and digits and the checks panel says in so many words that it did.
   */
  const classes: readonly PasswordClass[] = selected.length > 0 ? selected : ["lower", "upper", "digit"];
  const avoid = optBool(spec.options, OPTION_EXCLUDE_AMBIGUOUS);

  const pools = classes.map((id) => {
    const pool = PASSWORD_ALPHABETS[id];
    return avoid ? [...pool].filter((ch) => !AMBIGUOUS.includes(ch)).join("") : pool;
  });

  if (length < pools.length) {
    return {
      error: `A ${length}-character password cannot contain one of each of ${pools.length} classes. Raise the length or pick fewer classes.`,
    };
  }

  const alphabet = pools.join("");
  const values: string[] = [];
  for (let i = 0; i < count; i++) values.push(generate(length, pools, alphabet));

  /**
   * Entropy in bits, and reported honestly.
   *
   * `length * log2(alphabet)` is the figure everyone quotes and it is an *upper* bound here, because
   * guaranteeing one character from each class removes possibilities. The gap is small at these
   * lengths and stating the bound as a bound costs nothing, where quoting it as the exact figure
   * would be a number this tool cannot back up.
   */
  const bits = Math.floor(length * Math.log2(alphabet.length));
  return {
    text: values.join("\n"),
    fields: [
      { label: "Entropy", value: `at most ${bits} bits` },
      { label: "Alphabet", value: `${alphabet.length} characters` },
      { label: "Guaranteed", value: `one from each of ${pools.length} class${pools.length === 1 ? "" : "es"}` },
      { label: "Source", value: "crypto.getRandomValues" },
    ],
  };
}

/**
 * One password: one character from each class, then the rest from the union, then shuffled.
 *
 * Both halves draw through `randomBelow` from `@ocs/engine`, which rejects rather than taking a
 * modulo, and that is the point of writing this by hand at all. `randomBytes(1)[0] % alphabet.length`
 * is biased whenever 256 is not a multiple of the length -- for a 70-character alphabet the first 46
 * characters come up about 1.4% more often than the rest -- and the bias would make the entropy figure
 * above a claim this tool could not support. The shuffle is `shuffled`, Fisher-Yates over the same
 * unbiased draw, because placing the guaranteed characters at fixed positions would leak the class
 * layout.
 *
 * Both used to be local to this file. They moved to the engine when the random-number tools needed
 * them: two implementations of an unbiased draw is exactly the drift this repo keeps recording, and
 * the engine's version additionally works past a single byte, which this one did not.
 */
function generate(length: number, pools: readonly string[], alphabet: string): string {
  const pick = (from: string): string => from[randomBelow(from.length)]!;
  const chars = pools.map(pick);
  while (chars.length < length) chars.push(pick(alphabet));
  return shuffled(chars).join("");
}

// ----------------------------------------------------------------- Random ---

/**
 * Random integers or decimals.
 *
 * All the arithmetic that could be wrong is in `@ocs/engine` -- `randomInt` for the inclusive range,
 * `randomIntSample` for the no-repeats case, `randomFloat` for the 53-bit double -- so what is left
 * here is reading the options and refusing the two configurations that cannot be satisfied. That
 * split is deliberate: the samplers are checked by *distribution* in `tests/random.test.ts`, where a
 * bias can actually be seen, and this function is checked by its refusals and its shape.
 */
function randomResult(spec: FormatSpec): ToolResult {
  const count = readCount(spec.options);
  if (readRandomShape(spec.options) === "decimal") {
    const places = clampNumber(spec.options, OPTION_RANDOM_PLACES, 6, 1, 17);
    const values = Array.from({ length: count }, () => randomFloat().toFixed(places));
    return {
      text: values.join("\n"),
      fields: [
        { label: "Range", value: "[0, 1)", hint: "Zero is possible; one is not." },
        {
          label: "Precision",
          value: `${places} of 53 bits shown`,
          hint: "Every draw uses the full mantissa; this setting only rounds what is printed.",
        },
        { label: "Source", value: "crypto.getRandomValues" },
      ],
    };
  }

  const min = clampNumber(spec.options, OPTION_RANDOM_MIN, 1, -MAX_BOUND, MAX_BOUND);
  const max = clampNumber(spec.options, OPTION_RANDOM_MAX, 100, -MAX_BOUND, MAX_BOUND);
  if (max < min) {
    return { error: `From is ${min} and To is ${max}. Swap them, or raise To.` };
  }
  /**
   * The span, checked before it is used rather than after.
   *
   * `max - min + 1` past 2^53 is not an error JavaScript reports -- it is a number that has stopped
   * counting in ones, so a draw from it would silently skip values. Refusing what the algorithm
   * genuinely cannot do is the rule here; everything softer is a diagnostic.
   */
  const span = max - min + 1;
  if (!Number.isSafeInteger(span)) {
    return {
      error: `The range ${min} to ${max} holds more than ${Number.MAX_SAFE_INTEGER} values, which is past exact integer arithmetic. Narrow it.`,
    };
  }

  const distinct = optBool(spec.options, OPTION_RANDOM_DISTINCT);
  if (distinct && count > span) {
    return {
      error: `${count} values with no repeats needs a range of at least ${count}; ${min} to ${max} holds ${span}.`,
    };
  }

  const drawn = distinct
    ? randomIntSample(min, max, count)
    : Array.from({ length: count }, () => randomInt(min, max));
  const values = optBool(spec.options, OPTION_RANDOM_SORTED)
    ? [...drawn].sort((a, b) => a - b)
    : drawn;

  return {
    text: values.join("\n"),
    fields: [
      {
        label: "Range",
        value: `${min} to ${max} (${span} values)`,
        hint: "Inclusive at both ends.",
      },
      {
        label: "Draw",
        value: distinct ? "Without replacement" : "Independent",
        hint: distinct
          ? "Each value appears at most once, like a lottery draw."
          : "Every value is independent, like a die: repeats are a legitimate answer.",
      },
      /**
       * Stated because it is the property this tool exists for and the one nobody can check by
       * looking: any output of a biased sampler looks exactly like an output of an unbiased one.
       */
      {
        label: "Uniformity",
        value: "Rejection sampling, no modulo bias",
        hint: "Every value in the range is equally likely. A modulo would favour the lower part of it.",
      },
      { label: "Source", value: "crypto.getRandomValues" },
    ],
  };
}

/**
 * Random bytes, and the one tool in this family that returns `bytes` rather than `text`.
 *
 * Which is what puts the Result panel's encoding menu on screen -- hex for a key, Base64 for a token,
 * decimal for a byte array being pasted into source. Nothing here spells them: `ResultPanel` owns
 * that, so this tool gains every encoding the app grows, for free.
 *
 * A count above one is the exception, and it is a real trade rather than an oversight. The panel
 * spells one byte string, so several have to be text -- and then the encoding menu would be inert. So
 * a count above one returns hex lines and says so in a field, which is the honest version of a
 * limitation.
 */
function randomBytesResult(spec: FormatSpec): ToolResult {
  const length = clampNumber(spec.options, OPTION_RANDOM_BYTES, 32, 1, 4096);
  const count = readCount(spec.options);
  const bits = length * 8;

  if (count === 1) {
    return {
      bytes: randomBytes(length),
      fields: [
        { label: "Size", value: `${length} bytes (${bits} bits)` },
        { label: "Source", value: "crypto.getRandomValues" },
      ],
    };
  }

  const lines = Array.from({ length: count }, () =>
    [...randomBytes(length)].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
  );
  return {
    text: lines.join("\n"),
    fields: [
      { label: "Size", value: `${count} x ${length} bytes (${bits} bits each)` },
      {
        label: "Encoding",
        value: "Hex, fixed",
        hint: "The output menu spells one byte string; several have to be text, so these are hex. Ask for one to reach the other encodings.",
      },
      { label: "Source", value: "crypto.getRandomValues" },
    ],
  };
}

/*
 * There is no "Commonly, this length is an X" field, and there was one.
 *
 * It mapped byte counts to roles -- 12 to "a GCM nonce", 24 to "an XChaCha20 nonce", 64 to "a
 * block-sized HMAC-SHA512 key" -- and it was removed on a bug report against exactly the defect
 * `## There is no securityNote` records, one family over. Three separate things were wrong with it and
 * they are worth listing, because each is a different way for this shape to fail:
 *
 *  - **Two entries were factually false.** SHA-512's block is 128 bytes, not 64; 64 is its output. And
 *    "an Ed25519 keypair" at 64 bytes is libsodium's concatenated format, not the 32-byte private key
 *    the asymmetric family here actually takes.
 *  - **One was dangerous rather than merely wrong.** Telling somebody 12 random bytes is "a GCM nonce"
 *    recommends the precise mistake `C003` exists to warn about: random 96-bit nonces collide at the
 *    birthday bound, which is why GCM nonces are counters in every serious deployment.
 *  - **All of them were unverifiable from here.** This is the format family making claims about the
 *    cipher, hash and asymmetric families' parameters, in prose, with nothing to check them against --
 *    so they were free to drift the moment any of those changed.
 *
 * The size is already on screen in bytes and bits, which is the fact this tool actually knows. What a
 * length is *for* is a question about the tool you are going to paste it into, and that tool's own
 * Checks panel is handed a spec and can be right about it. If a size hint is ever wanted here, it has
 * to be derived from the other families' metadata with a test asserting it, not written by hand.
 */

/** The widest range the integer draw accepts, and the reason is exact integer arithmetic. */
const MAX_BOUND = Number.MAX_SAFE_INTEGER;

/**
 * A number option, clamped rather than validated.
 *
 * The same treatment `readCount` and `readLength` already give: a value outside the control's own min
 * and max is a typo or a spinner mishap rather than a request, and clamping keeps a half-typed minus
 * sign from turning the panel into an error. The two things that genuinely cannot be satisfied -- an
 * inverted range, and more distinct values than the range holds -- are refused in `randomResult`
 * instead, where the message can name both numbers.
 */
function clampNumber(
  options: FormatSpec["options"],
  id: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = optNumber(options, id);
  if (raw === undefined || !Number.isFinite(raw)) return fallback;
  return Math.min(Math.max(Math.trunc(raw), min), max);
}

/** What these settings *are*, for the Info panel: true before anything is typed. */
export function formatInfo(spec: FormatSpec): ToolResultField[] {
  const tool = requireFormatTool(spec.variant);
  const fields: ToolResultField[] = [{ label: "Implemented with", value: tool.library }];
  if (!tool.usesInput) {
    fields.push({
      label: "Input",
      value: "None — this tool generates. Everything it needs is in these settings.",
    });
  }
  return fields;
}

/** Re-exported for the tests, which check the sampler's uniformity rather than trusting it. */
export const __testing = { applyCase, actionOf: (spec: FormatSpec): Action => readAction(spec.options, "format") };
