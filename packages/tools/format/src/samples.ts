import type { ToolSample } from "@ocs/engine";

/**
 * A document per tool, because this is the family where the app's two generic samples do not work.
 *
 * `123456789` is *the* check string -- every CRC in the RevEng catalogue publishes its check value
 * over those nine bytes -- and it is not JSON, not XML and not a JWT. A format tool opening on it
 * shows a parse error where an answer should be, which reads as the tool being broken rather than as
 * the input being the wrong shape. The two generic samples are still offered in the menu beside
 * these; only what a fresh box is *seeded* with changes.
 *
 * Three rules these follow, and they are why the set is small.
 *
 * **Every one has to compute cleanly under its tool's default spec**, which a test asserts over all
 * of them. A sample that produced a diagnostic would be worse than none.
 *
 * **Each shows the thing the tool is for, and nothing else.** The JSON document has a nested object,
 * an array, a float written `1.0` and a duplicate key, because those are exactly the four cases the
 * parse-tree path exists to preserve -- format it and you can see they survived. The XML one carries
 * an attribute, a comment, CDATA and whitespace between elements, which is what the Collapse setting
 * acts on. A longer document would demonstrate less.
 *
 * **The decode direction gets its own entry where the two are not interchangeable.** Handing the URL
 * tool a plain URL while it is set to Decode does nothing visible, so there is an escaped sample
 * beside the plain one; the reader picks the one matching the direction they are in. There is no
 * `direction`-aware seeding, deliberately: the seed happens once per tool, before any setting has
 * been touched, and a box that swapped its contents when you flipped a dropdown would be the input
 * rewriting itself under you.
 *
 * These are the *whole* menu for the tools that have them -- the app's two generic samples are not
 * shown beside them, because `123456789` and a wall of Lorem are not things you hand a JSON
 * formatter, and offering them under a group heading was just labelling the noise. So the count is
 * one entry per thing worth trying rather than one per tool: a document and its opposite where a
 * setting has two interesting sides, an escaped sample where there are two directions.
 */

const JSON_DOCUMENT = `{"name":"Cipher Workbench","version":1.0,"tools":[{"id":"json","family":"format"},{"id":"crc32","family":"crc"}],"offline":true,"offline":"yes"}`;

const XML_DOCUMENT = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<catalogue xmlns:x="urn:example:workbench">',
  "  <!-- Whitespace between elements is data until you say otherwise. -->",
  '  <tool id="json" family="format"><x:note><![CDATA[<parse> & serialise]]></x:note></tool>',
  '  <tool id="crc32" family="crc"/>',
  "</catalogue>",
].join("\n");

const JSON_INDENTED = [
  "{",
  '  "page": 2,',
  '  "total": 137,',
  '  "results": [',
  '    { "id": 41, "name": "SHA-256", "family": "hash", "bits": 256 },',
  '    { "id": 42, "name": "CRC-32/ISO-HDLC", "family": "crc", "bits": 32 }',
  "  ],",
  '  "next": null',
  "}",
].join("\n");

const XML_MINIFIED =
  '<order id="4021"><customer>Ada Lovelace</customer>' +
  "<lines><line sku=\"AA-1\" qty=\"2\"/><line sku=\"BB-7\" qty=\"1\"/></lines>" +
  "<note>Deliver <em>before</em> Friday.</note></order>";

/** RFC 7519 section 3.1's worked example: the same token the tests pin. */
const RFC7519_TOKEN =
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
  ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
  ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

const BY_TOOL: Record<string, readonly ToolSample[]> = {
  url: [
    {
      id: "url",
      label: "A URL with a space and an accent",
      note: "Encode it under each of the three flavours to see where they differ: Component escapes the delimiters, Whole URI leaves them, Form turns the space into a plus.",
      text: "https://example.com/search?q=cafe crème&tag=c++#résumé",
    },
    {
      id: "encoded",
      label: "An encoded query string",
      note: "For the Decode direction. Note the plus signs: read as Form they are spaces, read as Component they are literal pluses.",
      text: "q=cafe+cr%C3%A8me&tag=c%2B%2B&note=100%25%20done",
    },
  ],
  htmlentity: [
    {
      id: "markup",
      label: "Markup with the five characters that matter",
      note: "Encode with Markup only and the accents survive; switch to Everything non-ASCII and they do not. That is the whole difference between the two scopes.",
      text: `<p class="note">Fish & chips — 5 € for "two" — it's café weather</p>`,
    },
    {
      id: "references",
      label: "Named, decimal and hexadecimal references",
      note: "For the Decode direction, and one of each form. All three decode whatever the encode settings say.",
      text: "&lt;p&gt;Caf&eacute; &amp; cr&#232;me &#x2014; 5&nbsp;&euro;&lt;/p&gt;",
    },
  ],
  jwt: [
    {
      id: "rfc7519",
      label: "RFC 7519's example token",
      note: "The specification's own worked example, HS256. Its claims decode; its signature is shown and not checked, which is what the Checks panel is about.",
      text: RFC7519_TOKEN,
    },
    {
      id: "unsigned",
      label: "An unsigned token (alg: none)",
      note: "Three parts with an empty third, which is what alg:none produces. The Signature row reads (none) -- and the claims in it are exactly as trustworthy as the signed token's, which is to say not at all.",
      text: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.",
    },
  ],
  json: [
    {
      id: "document",
      label: "A minified document with four things worth preserving",
      note: "Format it: the nesting appears, 1.0 stays 1.0 rather than becoming 1, and the duplicate key is still there twice. A parse-and-restringify round trip loses the last two.",
      text: JSON_DOCUMENT,
    },
    {
      id: "indented",
      label: "An already-indented API response",
      note: "The other direction: minify it, or turn Sort keys on and watch the members reorder at every level. Deliberately laid out, so there is something for Minify to remove.",
      text: JSON_INDENTED,
    },
  ],
  xml: [
    {
      id: "document",
      label: "A document with an attribute, a comment and CDATA",
      note: "Minify it twice, once with Collapse whitespace on: with it off almost nothing is removed, because in XML whitespace is data until a schema says otherwise.",
      text: XML_DOCUMENT,
    },
    {
      id: "minified",
      label: "A minified order",
      note: "For the Format direction. It contains mixed content -- an element holding both text and a child -- which stays on one line, because breaking it would insert whitespace into the text.",
      text: XML_MINIFIED,
    },
  ],
  case: [
    {
      id: "identifiers",
      label: "Names that split badly",
      note: "One per line, converted line by line. XMLHttpRequest is the interesting one: a regex gives x_m_l_http_request and the answer is xml_http_request.",
      text: ["XMLHttpRequest", "user ID", "HTTP response code", "parse-JSON-body"].join("\n"),
    },
    {
      id: "prose",
      label: "A sentence",
      note: "For the styles meant for text rather than identifiers -- Sentence case and Capital Case. Running camelCase over it is how you see that the two halves of that dropdown are different jobs.",
      text: "the quick brown fox jumps over the lazy dog",
    },
  ],
};

/**
 * `uuid` and `password` have none, and that is the point rather than an omission: they read no input,
 * so there is no box for a sample to go in and `ToolManifest.readsInput` says so.
 */
export function samplesFor(toolId: string): readonly ToolSample[] | undefined {
  return BY_TOOL[toolId];
}

/** Every sample in the family, for the test that requires each one to compute cleanly. */
export const ALL_FORMAT_SAMPLES: readonly (ToolSample & { toolId: string })[] = Object.entries(
  BY_TOOL,
).flatMap(([toolId, samples]) => samples.map((sample) => ({ ...sample, toolId })));
