import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { getManifest, TOOL_MANIFESTS } from "@ocs/registry";
import { AppShell } from "../../app-shell";
import { SITE_NAME, toolDescription, toolTitle, toolUrl } from "../../site";

/**
 * One statically exported page per tool -- 213 of them -- and this is the whole point of the SEO work.
 *
 * The app is a single-page workbench: a sidebar picks a tool and nothing navigates. That is right for
 * using it and fatal for being found, because a crawler sees exactly one page. Somebody searching for
 * "CRC-16/MODBUS calculator" is not going to land on a page whose title is "Cipher Workbench" and whose
 * body, before JavaScript runs, is empty. Metadata, Open Graph tags and structured data on that one
 * page cannot fix it; a URL per tool can.
 *
 * `output: "export"` plus `generateStaticParams` gives that for free at build time: each tool becomes
 * `out/tools/<id>/index.html` with its own `<title>`, its own description and its own `<h1>`, and the
 * client bundle is shared. The registry's manifests are the *eager* half of the manifest/definition
 * split -- strings only, no `@noble` import, no compute path -- which is exactly why 213 pages can be
 * generated without pulling every algorithm into the build graph.
 *
 * **What these pages deliberately do not do is change the app's behaviour.** Landing on one opens the
 * workbench with that tool selected, which is the same thing a share link does and is consistent with
 * the rule that a session otherwise opens on `DEFAULT_TOOL_ID`: a named URL is an explicit request. But
 * switching tools afterwards does *not* rewrite the address bar. Doing so would make the URL a piece of
 * mutable state, and the app already has a better answer for "send someone this" -- the share link,
 * which carries the settings too. So the URL says where you arrived, and the share panel says what you
 * are looking at.
 */

export const dynamicParams = false;

export function generateStaticParams(): { tool: string }[] {
  return TOOL_MANIFESTS.map((manifest) => ({ tool: manifest.id }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ tool: string }>;
}): Promise<Metadata> {
  const { tool } = await params;
  const manifest = getManifest(tool);
  if (!manifest) return {};

  const title = toolTitle(manifest);
  const description = toolDescription(manifest);
  return {
    title,
    description,
    /**
     * The canonical URL, and it is per page rather than inherited.
     *
     * Without it every tool page would inherit the root layout's canonical and tell every engine that
     * all 213 are duplicates of the home page -- which is the one metadata mistake that actively
     * removes pages from an index rather than merely failing to add them.
     *
     * **Absolute, not relative, and that is because of GitHub Pages.** A project site is served from
     * `/CipherWorkbench/`, so `metadataBase` carries that subpath -- and a relative canonical starting
     * with `/` resolves against the *origin*, silently dropping it. Every canonical would point at a
     * URL that 404s. `toolUrl` builds the whole thing, which cannot go wrong that way.
     */
    alternates: { canonical: toolUrl(manifest.id) },
    /**
     * The tool's own search terms, from the manifest's `tags`.
     *
     * These are the strings the sidebar's search already matches -- every alias, every alternative
     * spelling, `crc-32/castagnoli` alongside `crc32c` -- so they are exactly the queries this page
     * should answer. Kept to the tool's own rather than merged with the site list, because a page that
     * claims every keyword claims none.
     */
    keywords: [...manifest.tags, manifest.label],
    openGraph: {
      type: "website",
      url: toolUrl(manifest.id),
      siteName: SITE_NAME,
      title,
      description,
    },
    twitter: { card: "summary", title, description },
  };
}

export default async function ToolPage({ params }: { params: Promise<{ tool: string }> }) {
  const { tool } = await params;
  const manifest = getManifest(tool);
  if (!manifest) notFound();

  return (
    <>
      {/*
        Prose a crawler can read before any JavaScript runs, and a reader never sees.

        `sr-only` rather than `display: none`: hidden text is what a search engine treats as an attempt
        to deceive it, and it is also invisible to a screen reader, which is the one audience that
        genuinely benefits from a heading naming the page. So this is off-screen but present in the
        accessibility tree -- the same content, served to both, which is the only version of this that
        is honest.

        It is an `<h1>` because the workbench has none: the tool's name is rendered in a panel header
        by `ToolHeader`, styled rather than structural. A page with no h1 and a title that says
        "SHA-256" is a page an engine is unsure about.
      */}
      <div className="sr-only">
        <h1>{toolTitle(manifest)}</h1>
        <p>{toolDescription(manifest)}</p>
        <p>
          {manifest.label} is one of {TOOL_MANIFESTS.length} tools in {SITE_NAME}. Every computation
          runs locally in this page; no input is sent anywhere.
        </p>
      </div>

      {/*
        Structured data for this specific tool.

        `SoftwareApplication` with the tool's name is what lets a result carry the tool rather than the
        site, and `isPartOf` is what ties the 213 together as one work instead of 213 unrelated pages.
        Inline, so the desktop CSP hashes it automatically -- see the note in `layout.tsx`.
      */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "SoftwareApplication",
            name: `${manifest.label} calculator`,
            url: toolUrl(manifest.id),
            description: toolDescription(manifest),
            applicationCategory: "DeveloperApplication",
            operatingSystem: "Any",
            isAccessibleForFree: true,
            offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
            isPartOf: { "@type": "WebApplication", name: SITE_NAME, url: toolUrl(manifest.id) },
          }),
        }}
      />

      <AppShell initialToolId={manifest.id} />
    </>
  );
}
