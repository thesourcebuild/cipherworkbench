import type { MetadataRoute } from "next";
import { SITE_URL } from "./site";

/**
 * Required under `output: "export"`.
 *
 * `robots.ts` and `sitemap.ts` compile to route handlers, and a route handler is dynamic by default --
 * a static export refuses to build with one, by name, which is how this was found rather than shipped.
 * Both are pure functions of the manifest list, so forcing them static is a statement of fact.
 */
export const dynamic = "force-static";

/**
 * Everything is crawlable, which is worth stating explicitly rather than leaving to the default.
 *
 * There is nothing here to keep out: no accounts, no user content, no server. `/_next/` is excluded
 * anyway because there is no reason for a crawler to spend its budget on hashed chunk filenames that
 * change every build -- it cannot index them and following them costs the site nothing but crawl rate.
 *
 * Static-export compatible: Next writes this to `out/robots.txt` at build time. It is *also* served by
 * the Electron shell, harmlessly -- a robots.txt inside a desktop app is inert, and excluding it from
 * the bundle would mean diverging the two builds for no gain.
 */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: "*", allow: "/", disallow: "/_next/" }],
    sitemap: `${SITE_URL}/sitemap.xml`,
    host: SITE_URL,
  };
}
