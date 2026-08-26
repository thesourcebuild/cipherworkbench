import { describe, expect, it } from "vitest";
import { TOOL_MANIFESTS } from "@ocs/registry";
import robots from "../apps/web/app/robots";
import sitemap from "../apps/web/app/sitemap";
import {
  ALL_TOOLS,
  SITE_DESCRIPTION,
  SITE_KEYWORDS,
  SITE_NAME,
  SITE_URL,
  toolDescription,
  toolPath,
  toolTitle,
  toolUrl,
} from "../apps/web/app/site";

/**
 * The metadata surface, which is mostly strings and is therefore mostly untestable -- so this asserts
 * the parts that are *derived*, where a mistake is silent and permanent.
 *
 * The app is one page with a sidebar, and a crawler sees one page. So the whole SEO story rests on 213
 * statically exported `/tools/<id>/` routes, each with its own title, description and canonical URL, and
 * on a sitemap that lists them. Every one of those is generated from `TOOL_MANIFESTS`, which is what
 * makes this testable at all -- and what makes it worth testing, because the failure modes are the kind
 * nobody notices for months:
 *
 *  - A sitemap that lists a tool that no longer exists is a page of 404s reported somewhere nobody
 *    looks. A sitemap that *omits* a tool is a page that never gets found.
 *  - Two pages sharing a title or a description is how a search engine decides they are duplicates and
 *    keeps one.
 *  - A canonical URL that drops the GitHub Pages subpath points every page at a 404, which removes them
 *    from the index rather than merely failing to add them. That one is a real hazard here rather than
 *    a hypothetical: `metadataBase` carries `/CipherWorkbench`, and a relative canonical beginning with
 *    a slash resolves against the origin and silently discards it.
 *
 * `tests/share-link.test.ts` already reaches into `apps/web/app` this way, which is the precedent.
 */

describe("the sitemap", () => {
  const entries = sitemap();

  it("lists the home page and every tool, and nothing else", () => {
    const urls = entries.map((e) => e.url);
    expect(urls[0]).toBe(`${SITE_URL}/`);
    expect(urls.slice(1)).toEqual(TOOL_MANIFESTS.map((m) => toolUrl(m.id)));
    // One per tool plus the home page: derived, so adding a tool cannot leave it unlisted.
    expect(entries).toHaveLength(TOOL_MANIFESTS.length + 1);
  });

  it("has no duplicate URLs", () => {
    const urls = entries.map((e) => e.url);
    expect(new Set(urls).size).toBe(urls.length);
  });

  it("uses absolute URLs on the deployed origin, with a trailing slash", () => {
    for (const entry of entries) {
      expect(entry.url.startsWith(`${SITE_URL}/`), entry.url).toBe(true);
      expect(entry.url.endsWith("/"), `${entry.url} has no trailing slash`).toBe(true);
      // `trailingSlash: true` makes the export write directories, so a URL without one would 404 on a
      // static host -- there is no rewrite layer to forgive it.
      expect(entry.url).not.toContain(".html");
    }
  });

  /**
   * `lastModified` is deliberately absent, and this pins that decision.
   *
   * The honest value would be when each tool last changed, which nothing in the build knows. Using the
   * build time instead would tell every crawler that all 214 pages changed on every deploy, which is
   * how a site teaches an engine to stop believing its own sitemap.
   */
  it("claims no modification date it cannot support", () => {
    for (const entry of entries) expect(entry.lastModified, entry.url).toBeUndefined();
  });
});

describe("robots.txt", () => {
  const rules = robots();

  it("allows everything and points at the sitemap on the deployed origin", () => {
    expect(rules.sitemap).toBe(`${SITE_URL}/sitemap.xml`);
    const rule = Array.isArray(rules.rules) ? rules.rules[0]! : rules.rules;
    expect(rule.userAgent).toBe("*");
    expect(rule.allow).toBe("/");
  });

  /**
   * `/_next/` is excluded, and it is the only thing that is.
   *
   * Not for secrecy -- the bundle is public and inspectable -- but because a crawler cannot index a
   * hashed chunk filename that changes every build, so following them spends crawl budget on nothing.
   * Note this is the *robots* exclusion and has nothing to do with `.nojekyll`, which solves the
   * opposite problem: GitHub Pages refusing to *serve* `_next/` at all unless Jekyll is disabled.
   */
  it("keeps crawlers out of the build output and nowhere else", () => {
    const rule = Array.isArray(rules.rules) ? rules.rules[0]! : rules.rules;
    expect(rule.disallow).toBe("/_next/");
  });
});

describe("per-tool metadata", () => {
  /**
   * Two pages with the same title are two pages an engine may treat as one.
   *
   * The titles come from `manifest.label`, which the sidebar already requires to be unique-looking --
   * but "already" is not "asserted", and a merged tool or a copied entry is exactly how two labels end
   * up identical.
   */
  it("gives every tool a distinct title and description", () => {
    const titles = ALL_TOOLS.map((m) => toolTitle(m));
    const descriptions = ALL_TOOLS.map((m) => toolDescription(m));
    expect(new Set(titles).size, "duplicate titles").toBe(titles.length);
    expect(new Set(descriptions).size, "duplicate descriptions").toBe(descriptions.length);
  });

  /**
   * The tool name leads the title, because a search result truncates from the right.
   *
   * The site name is appended by the layout's `title.template`, so what is asserted here is the part
   * this function owns: that it starts with what somebody searched for rather than with the brand.
   */
  it("leads with the tool name rather than the site name", () => {
    for (const manifest of ALL_TOOLS) {
      const title = toolTitle(manifest);
      expect(title.startsWith(manifest.label), title).toBe(true);
      expect(title).not.toContain(SITE_NAME);
    }
  });

  /**
   * Descriptions stay in the range a search result will actually show.
   *
   * Roughly 160 characters is where Google truncates; under about 70 and the snippet looks unfinished.
   * The upper bound is generous because a truncated description is a cosmetic loss rather than a
   * ranking one -- what matters is that the first clause carries the point, which the template does by
   * putting the tool's own summary first.
   */
  it("keeps descriptions long enough to be useful and short enough to be shown", () => {
    for (const manifest of ALL_TOOLS) {
      const description = toolDescription(manifest);
      expect(description.length, `${manifest.id} description too short`).toBeGreaterThan(70);
      expect(description.length, `${manifest.id} description too long`).toBeLessThan(320);
      expect(description.startsWith(manifest.label), description).toBe(true);
      // The claim the whole site rests on, in every description.
      expect(description).toContain("nothing is uploaded");
    }
  });

  it("builds a path and an absolute URL that agree", () => {
    for (const manifest of ALL_TOOLS) {
      expect(toolPath(manifest.id)).toBe(`/tools/${manifest.id}/`);
      expect(toolUrl(manifest.id)).toBe(`${SITE_URL}${toolPath(manifest.id)}`);
    }
  });

  /**
   * A tool id has to survive being a directory name on a static host.
   *
   * These become `out/tools/<id>/index.html`, so an id with a slash, a space or an uppercase letter
   * would produce a path that either collides on a case-insensitive filesystem or 404s on a
   * case-sensitive host. Every id today is lower-case alphanumeric with hyphens; this is what stops the
   * first one that is not.
   */
  it("uses ids that are safe as URL path segments", () => {
    for (const manifest of ALL_TOOLS) {
      expect(manifest.id, `${manifest.id} is not URL-safe`).toMatch(/^[a-z0-9][a-z0-9-]*$/);
      expect(encodeURIComponent(manifest.id)).toBe(manifest.id);
    }
  });
});

describe("the site constants", () => {
  it("has no trailing slash on the base URL, so joining cannot double it", () => {
    expect(SITE_URL.endsWith("/")).toBe(false);
    expect(SITE_URL.startsWith("https://")).toBe(true);
  });

  it("keeps the site description within a search result's width", () => {
    expect(SITE_DESCRIPTION.length).toBeGreaterThan(70);
    expect(SITE_DESCRIPTION.length).toBeLessThan(170);
  });

  /**
   * The keyword list stays short and does not restate the tool names.
   *
   * Each tool's own page carries its own `tags` as keywords, which is where a name earns a ranking. A
   * site-wide list that also named all 213 would be the keyword stuffing that gets a site demoted, so
   * the bound here is deliberate rather than arbitrary.
   */
  it("keeps the site keyword list short and free of per-tool names", () => {
    expect(SITE_KEYWORDS.length).toBeLessThanOrEqual(20);
    expect(new Set(SITE_KEYWORDS).size).toBe(SITE_KEYWORDS.length);
    /**
     * A *few* names may appear, and the bound is what matters rather than the absence.
     *
     * The first version of this asserted no overlap at all, on the theory that the keywords are query
     * phrases (`sha256`) while the labels are display names (`SHA-256`). That is true of most of them
     * and false of `md5`, whose label is exactly what people type -- and `md5`, `sha256` and `crc32`
     * are the three highest-volume queries in this domain, so excluding them site-wide would be
     * pedantry rather than hygiene. What the list must not become is the catalogue, which is what the
     * bound below actually prevents.
     */
    const labels = new Set(ALL_TOOLS.map((m) => m.label.toLowerCase()));
    const restated = SITE_KEYWORDS.filter((k) => labels.has(k.toLowerCase()));
    expect(restated.length, `site keywords restating tool labels: ${restated.join(", ")}`)
      .toBeLessThanOrEqual(3);
  });
});
