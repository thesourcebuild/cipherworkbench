import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";
import { THEME_STORAGE_KEY } from "./theme-constants";
import {
  SITE_DESCRIPTION,
  SITE_KEYWORDS,
  SITE_NAME,
  SITE_TAGLINE,
  SITE_URL,
} from "./site";

/**
 * The site-wide metadata.
 *
 * `metadataBase` is what makes every relative URL below resolve to an absolute one, which Open Graph
 * and canonical links require -- a relative `og:image` is ignored by every scraper. It comes from
 * `SITE_URL`, which is a build-time input; see the note there on why it must not become a `basePath`.
 *
 * `title.template` gives each page `"<its title> · Cipher Workbench"` without every page repeating the
 * suffix, and `title.default` is what the home page gets. The order matters: a search result truncates
 * from the right, so the specific part goes first.
 */
export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: `${SITE_NAME} v${process.env.NEXT_PUBLIC_APP_VERSION ?? "0.1.0"} — hash, checksum, MAC and cipher calculator`,
    template: `%s · ${SITE_NAME} v${process.env.NEXT_PUBLIC_APP_VERSION ?? "0.1.0"}`,
  },
  description: SITE_DESCRIPTION,
  applicationName: SITE_NAME,
  keywords: [...SITE_KEYWORDS],
  authors: [{ name: SITE_NAME }],
  category: "developer tools",
  /**
   * Absolute, because of GitHub Pages: a project site lives at `/CipherWorkbench/`, and a relative
   * canonical beginning with `/` resolves against the origin and drops the subpath. See the longer note
   * on the tool pages, where the same mistake would have cost 213 canonicals rather than one.
   */
  alternates: { canonical: `${SITE_URL}/` },
  /**
   * Explicit rather than omitted, and `max-image-preview: large` is the one that earns its place: a
   * social card is only useful if the engine is allowed to show it at a useful size.
   */
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true, "max-image-preview": "large", "max-snippet": -1 },
  },
  openGraph: {
    type: "website",
    url: `${SITE_URL}/`,
    siteName: SITE_NAME,
    title: `${SITE_NAME} — ${SITE_TAGLINE}`,
    description: SITE_DESCRIPTION,
    locale: "en",
  },
  twitter: { card: "summary", title: SITE_NAME, description: SITE_DESCRIPTION },
  icons: {
    icon: [
      { url: "/icon.svg", type: "image/svg+xml" },
      { url: "/favicon.ico", sizes: "any" },
      { url: "/icon.png", type: "image/png", sizes: "512x512" },
    ],
    apple: [
      { url: "/icon.png", sizes: "180x180", type: "image/png" },
    ],
  },
  /**
   * `format-detection` off, and this is not cosmetic for this app.
   *
   * Safari on iOS turns anything that looks like a phone number into a tel: link, and a hex digest is
   * full of digit runs that qualify. The result is a result panel with tappable blue fragments in the
   * middle of it, which changes what a copy selects.
   */
  formatDetection: { telephone: false, date: false, address: false, email: false },
};

/**
 * Runs before hydration so the page never flashes the wrong theme — sets the same
 * `.dark` class `useTheme` manages, from the same storage key, before any CSS paints.
 */
const THEME_INIT_SCRIPT = `(function(){try{var k=${JSON.stringify(THEME_STORAGE_KEY)};var v=localStorage.getItem(k);var d=v==="dark"||(v!=="light"&&window.matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.classList.toggle("dark",d);}catch(e){}})();`;

/**
 * Structured data: a `WebApplication`, which is what this actually is.
 *
 * Worth having rather than skipping, because it is the one place the two facts a searcher cares about
 * can be stated in a form a machine reads: that it costs nothing, and that it needs no account or
 * upload. `offers` with a zero price is how "free" is expressed in schema.org -- there is no boolean --
 * and `browserRequirements` is where the "runs locally" claim goes.
 *
 * It is an inline `<script>`, which under the desktop CSP means its body has to be hashed. That
 * happens automatically: `inlineScriptHashes` in `protocol.ts` matches every `<script>` without a
 * `src` and adds its hash, so this needs no CSP edit and cannot silently break the packaged app. A
 * `type` of `application/ld+json` never executes, but Chromium applies `script-src` to the element
 * regardless, which is why that machinery matters here.
 */
const STRUCTURED_DATA = JSON.stringify({
  "@context": "https://schema.org",
  "@type": "WebApplication",
  name: SITE_NAME,
  url: SITE_URL,
  description: SITE_DESCRIPTION,
  applicationCategory: "DeveloperApplication",
  operatingSystem: "Any",
  browserRequirements: "Requires JavaScript. Runs entirely client-side; no data is uploaded.",
  isAccessibleForFree: true,
  offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
});

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
        <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: STRUCTURED_DATA }} />
      </head>
      <body className="min-h-screen">{children}</body>
    </html>
  );
}
