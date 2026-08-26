import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { protocol } from "electron";

/**
 * The renderer is served over a custom `app://` scheme rather than `file://`.
 *
 * Reasons this matters:
 *  - a real origin means localStorage, `crypto.subtle` and a meaningful CSP all
 *    behave normally, where file:// gives an opaque origin, inconsistent storage,
 *    and — critically for this app — no WebCrypto at all, since SubtleCrypto is
 *    gated on a secure context;
 *  - absolute asset paths like /_next/static/... resolve correctly, so the desktop
 *    app can load the exact same static export the web app deploys, with no
 *    assetPrefix divergence and no second build of the UI;
 *  - the compute worker is fetched as a same-origin script, which a file:// page
 *    cannot do.
 */
export const SCHEME = "app";
export const APP_ORIGIN = `${SCHEME}://bundle`;

/** Must be called before `app.whenReady()`. */
export function registerScheme(): void {
  protocol.registerSchemesAsPrivileged([
    {
      scheme: SCHEME,
      privileges: {
        standard: true,
        secure: true,
        supportFetchAPI: true,
        corsEnabled: true,
        stream: true,
      },
    },
  ]);
}

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".map": "application/json; charset=utf-8",
};

/** Inline <script> blocks — those without a src attribute. */
const INLINE_SCRIPT = /<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;

/**
 * Next's static export carries React's hydration payload in inline <script> tags,
 * and this app adds one more of its own: the pre-hydration theme setter in
 * `layout.tsx`. A bare `script-src 'self'` blocks every one of them, so the
 * prerendered markup renders and then nothing works — the page looks fine and is
 * completely dead to input.
 *
 * Rather than reach for 'unsafe-inline', each inline script is hashed and its
 * digest added to the directive. That permits exactly the scripts in our own
 * bundle and nothing else, so an injected inline script is still refused.
 */
function inlineScriptHashes(html: string): string[] {
  const hashes = new Set<string>();
  for (const match of html.matchAll(INLINE_SCRIPT)) {
    const body = match[1];
    if (!body) continue;
    hashes.add(`'sha256-${createHash("sha256").update(body, "utf8").digest("base64")}'`);
  }
  return [...hashes];
}

function buildCsp(scriptHashes: readonly string[] = []): string {
  return [
    "default-src 'self'",
    ["script-src 'self'", ...scriptHashes].join(" "),
    // The compute worker is a same-origin script under /_next/static/chunks.
    // Without this directive Chromium refuses to construct it and the app
    // silently falls back to main-thread hashing.
    "worker-src 'self'",
    // Next inlines critical CSS, and hashing that is not worth the coupling.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    // 'self' only — this app has no server to talk to, and nothing in it should
    // ever open a socket. A CSP violation here would be a genuine finding.
    "connect-src 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
}

/** Register the handler. Call after `app.whenReady()`. */
export function serveRenderer(rendererRoot: string): void {
  const root = path.resolve(rendererRoot);

  protocol.handle(SCHEME, async (request) => {
    let pathname: string;
    try {
      pathname = decodeURIComponent(new URL(request.url).pathname);
    } catch {
      return new Response("Bad request", { status: 400 });
    }

    // The static export uses trailingSlash, so directories map to index.html.
    const relative =
      pathname === "/" || pathname.endsWith("/") ? path.join(pathname, "index.html") : pathname;

    const resolved = path.resolve(root, `.${path.sep}${relative.replace(/^[/\\]+/, "")}`);

    // Refuse anything that escaped the bundle directory.
    if (resolved !== root && !resolved.startsWith(root + path.sep)) {
      return new Response("Forbidden", { status: 403 });
    }

    try {
      const body = await readFile(resolved);
      const isHtml = path.extname(resolved).toLowerCase() === ".html";
      return new Response(body, {
        status: 200,
        headers: {
          "Content-Type": MIME[path.extname(resolved).toLowerCase()] ?? "application/octet-stream",
          "Content-Security-Policy": isHtml
            ? buildCsp(inlineScriptHashes(body.toString("utf8")))
            : buildCsp(),
          "X-Content-Type-Options": "nosniff",
        },
      });
    } catch {
      // Fall back to the exported 404 page so client routing still looks right.
      try {
        const notFound = await readFile(path.join(root, "404.html"));
        return new Response(notFound, {
          status: 404,
          headers: {
            "Content-Type": MIME[".html"]!,
            "Content-Security-Policy": buildCsp(inlineScriptHashes(notFound.toString("utf8"))),
          },
        });
      } catch {
        return new Response("Not found", { status: 404 });
      }
    }
  });
}
