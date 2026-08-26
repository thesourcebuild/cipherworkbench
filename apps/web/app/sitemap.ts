import type { MetadataRoute } from "next";
import { ALL_TOOLS, SITE_URL, toolUrl } from "./site";

/**
 * Required under `output: "export"`.
 *
 * `robots.ts` and `sitemap.ts` compile to route handlers, and a route handler is dynamic by default --
 * a static export refuses to build with one, by name, which is how this was found rather than shipped.
 * Both are pure functions of the manifest list, so forcing them static is a statement of fact.
 */
export const dynamic = "force-static";

/**
 * The home page and one entry per tool: 214 URLs, generated from the manifest list.
 *
 * Generated rather than written, for the reason every derived list in this repo is: a tool added to
 * `TOOL_MANIFESTS` is in the sitemap the same build, and a tool removed is out of it. A hand-kept
 * sitemap is a list of 404s waiting to happen, and the failure is silent -- a crawler simply reports
 * errors somewhere nobody looks.
 *
 * `priority` and `changeFrequency` are set but should not be taken seriously: Google has said for years
 * that it ignores both. They are here because other engines still read them and they cost nothing. The
 * home page is 1.0 and the tools 0.8, which is the only ordering claim worth making.
 *
 * `lastModified` is deliberately *absent*. The honest value would be the last time each tool changed,
 * which nothing in the build knows; using the build time instead would tell every crawler that all 214
 * pages changed on every deploy, which is how a site teaches an engine to stop believing it.
 */
export default function sitemap(): MetadataRoute.Sitemap {
  return [
    { url: `${SITE_URL}/`, changeFrequency: "weekly", priority: 1 },
    ...ALL_TOOLS.map((manifest) => ({
      url: toolUrl(manifest.id),
      changeFrequency: "monthly" as const,
      priority: 0.8,
    })),
  ];
}
