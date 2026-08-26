import type { ToolManifest } from "@ocs/engine";
import { TOOL_MANIFESTS } from "@ocs/registry";

/**
 * Everything the search engines are told, in one place.
 *
 * This file exists because the same handful of strings is needed by four different consumers -- the
 * root layout's `metadata`, each tool page's `generateMetadata`, `robots.ts` and `sitemap.ts` -- and a
 * description that drifts between the page title and the sitemap is worse than no description.
 *
 * **The base URL is a build-time input, not a constant.** `NEXT_PUBLIC_SITE_URL` overrides it; the
 * default is the GitHub Pages address this repository's name implies, which matches where the sibling
 * command generator is published. It is only used for *absolute* URLs -- canonical links, Open Graph,
 * the sitemap -- and never for asset paths, because changing those would need a `basePath` and a
 * `basePath` would break the Electron build: the desktop shell loads the same `out/` directory over
 * `app://bundle/` and has no prefix. That is the one thing in here that must not become configurable.
 */
export const SITE_URL = (
  process.env.NEXT_PUBLIC_SITE_URL ?? "https://thesourcebuild.github.io/CipherWorkbench"
).replace(/\/$/, "");

export const SITE_NAME = "Cipher Workbench";

/**
 * The one-sentence description, and it leads with the differentiator rather than the feature list.
 *
 * Every online hash tool says "compute hashes online". The thing that is actually true here and mostly
 * false elsewhere is that nothing is uploaded -- there is no server to upload to -- so that goes first.
 * It is also under 160 characters, which is roughly where a search result stops showing it.
 */
export const SITE_DESCRIPTION =
  "Compute and verify hashes, CRCs, MACs, key derivations and ciphers in your browser. Nothing is uploaded — there is no server to upload to.";

/** Short form for Open Graph and Twitter, where the space is tighter than a meta description's. */
export const SITE_TAGLINE = "Hashes, checksums, MACs and ciphers — computed and verified offline";

/**
 * Search terms worth carrying, chosen rather than scraped.
 *
 * `keywords` is close to worthless to Google and is still read by some other engines and by the
 * social-card scrapers, so the cost of getting it right is one array. What is *not* here is a dump of
 * all 213 tool names: each tool has its own page whose title and heading name it, which is where a
 * name actually earns a ranking. Repeating them here would be the keyword stuffing that gets a site
 * demoted rather than found.
 */
export const SITE_KEYWORDS: readonly string[] = [
  "hash calculator",
  "checksum calculator",
  "crc calculator",
  "hmac generator",
  "online hash tool",
  "offline hash tool",
  "sha256",
  "md5",
  "crc32",
  "file checksum",
  "verify checksum",
  "key derivation",
  "encryption tool",
  "cryptography workbench",
];

/**
 * Which families get a human name in prose, for the tool pages' descriptions.
 *
 * Read from a map rather than the manifest's `family` id because "kdf" is not a word. The sidebar has
 * its own labels for the same reason, and these are deliberately *not* shared with it: a sidebar label
 * is a column heading and has to be short, while this one goes into a sentence a stranger reads first.
 */
const FAMILY_PROSE: Record<string, string> = {
  hash: "cryptographic hash",
  crc: "cyclic redundancy check",
  checksum: "checksum",
  parity: "parity and error-detection",
  mac: "message authentication code",
  kdf: "key derivation function",
  cipher: "cipher",
  asymmetric: "public-key",
  encoding: "encoding",
  format: "text format",
};

/** `/tools/sha256/` — one indexable URL per tool. Trailing slash, matching `trailingSlash: true`. */
export function toolPath(id: string): string {
  return `/tools/${id}/`;
}

export function toolUrl(id: string): string {
  return `${SITE_URL}${toolPath(id)}`;
}

/**
 * The `<title>` for a tool page.
 *
 * `"SHA-256 · Cipher Workbench"` rather than `"Cipher Workbench — SHA-256"`, because a search result
 * truncates from the right and the tool name is the part somebody searched for. The suffix earns its
 * place by making the result recognisable once it has been seen before, which is the only job a site
 * name has in a title.
 */
export function toolTitle(manifest: ToolManifest): string {
  return `${manifest.label} — calculate and verify online`;
}

/**
 * The meta description for a tool page, assembled from the manifest.
 *
 * Generated rather than written per tool, and that is a judgement worth recording. 213 hand-written
 * descriptions would be better copy and would rot: the summary, the family and the file support are
 * already stated once in the manifest, and a second copy of them in prose is a second thing to keep
 * true. What the template adds is the part a searcher is deciding on -- that it runs locally, and
 * whether it takes a file -- which is uniform across the app and so belongs in the template.
 */
export function toolDescription(manifest: ToolManifest): string {
  const family = FAMILY_PROSE[manifest.family] ?? manifest.family;
  const file = manifest.supportsFile
    ? " Works on typed text or a local file of any size."
    : "";
  return `${manifest.label}: ${manifest.summary} A ${family} tool that runs entirely in your browser — nothing is uploaded.${file}`;
}

/** Every tool, in the order the sidebar lists them, for the sitemap and the link index. */
export const ALL_TOOLS: readonly ToolManifest[] = TOOL_MANIFESTS;
