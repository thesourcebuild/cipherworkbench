import type { SecurityPosture, ToolManifest } from "@ocs/engine";
import { TOOL_MANIFESTS } from "@ocs/registry";
import { cn } from "@ocs/ui";
import { FAMILY_LABEL, toolPath } from "./site";

const POSTURE_STYLE: Record<SecurityPosture, string> = {
  modern: "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-300",
  legacy: "border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-300",
  broken: "border-red-300 bg-red-50 text-red-800 dark:border-red-800 dark:bg-red-950/30 dark:text-red-300",
  "not-a-mac": "border-sky-300 bg-sky-50 text-sky-800 dark:border-sky-800 dark:bg-sky-950/30 dark:text-sky-300",
  "not-encryption": "border-slate-300 bg-slate-100 text-slate-800 dark:border-slate-700 dark:bg-slate-800/40 dark:text-slate-300",
};

const POSTURE_LABEL: Record<SecurityPosture, string> = {
  modern: "Modern",
  legacy: "Legacy",
  broken: "Broken",
  "not-a-mac": "Not a MAC",
  "not-encryption": "Not encryption",
};

const POSTURE_EXPLANATION: Record<SecurityPosture, { title: string; description: string }> = {
  modern: {
    title: "Modern Cryptographic Standard",
    description:
      "Considered secure for current production applications. Resists known cryptanalytic attacks and is suitable for new designs, digital signatures, integrity checks, and secure communications.",
  },
  legacy: {
    title: "Legacy Algorithm (Interoperability Only)",
    description:
      "Retained for backward compatibility, historical protocol verification, or existing format parsing. Not recommended for new security-sensitive system architectures.",
  },
  broken: {
    title: "Cryptographically Insecure / Broken",
    description:
      "Practical collision, pre-image, or forgery attacks are known against this algorithm. It must NOT be used for security-bearing purposes, digital signatures, certificates, or password protection.",
  },
  "not-a-mac": {
    title: "Unauthenticated Error Detection",
    description:
      "Designed strictly for detecting accidental bit errors from transmission noise or hardware faults. Because it is unkeyed, it provides zero protection against deliberate manipulation or malicious forgery.",
  },
  "not-encryption": {
    title: "Reversible Encoding / Format",
    description:
      "A deterministic data representation or encoding scheme. It provides structural transformation rather than cryptographic confidentiality.",
  },
};

const ENCODING_LABEL: Record<string, string> = {
  "hex-upper": "Hex (Uppercase)",
  "hex-lower": "Hex (Lowercase)",
  base64: "Base64 (RFC 4648)",
  base64url: "Base64URL",
  binary: "Raw Binary Bytes",
  decimal: "Decimal Integer",
  utf8: "UTF-8 Text",
};

export interface ToolDetailsProps {
  manifest: ToolManifest;
  onSelect?: (id: string) => void;
  className?: string;
}

/**
 * Rich, statically pre-rendered reference specifications and technical details for a tool.
 *
 * Emitted at build time on every statically exported `/tools/<id>/` page so search engine crawlers
 * (Googlebot, Bingbot) see an authoritative, 500+ word technical reference rather than 3 generic
 * sr-only sentences and empty skeleton divs.
 *
 * Uses the HTML5 `<details>` and `<summary>` pattern: collapsed by default for a clean, non-intrusive
 * workbench interface, while remaining 100% indexed by search engines and expandable on demand.
 */
export function ToolDetails({ manifest, onSelect, className }: ToolDetailsProps) {
  const familyName = FAMILY_LABEL[manifest.family] ?? manifest.family;
  const posture = POSTURE_EXPLANATION[manifest.security];

  // Find related algorithms: same category first, then same family (max 8)
  const categorySiblings = TOOL_MANIFESTS.filter(
    (m) => m.family === manifest.family && m.category === manifest.category && m.id !== manifest.id,
  );
  const otherFamilySiblings = TOOL_MANIFESTS.filter(
    (m) => m.family === manifest.family && m.category !== manifest.category && m.id !== manifest.id,
  );
  const siblings = [...categorySiblings, ...otherFamilySiblings].slice(0, 8);

  return (
    <details
      data-ocs-tool-details={manifest.id}
      className={cn(
        "group mt-8 rounded-lg border border-slate-200 bg-white p-4 sm:p-5 text-slate-800 transition-colors hover:border-slate-300 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200 dark:hover:border-slate-700",
        className,
      )}
    >
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 select-none">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-sm sm:text-base font-semibold text-slate-900 dark:text-slate-100">
            About {manifest.label}
          </h2>
          <span
            className={cn(
              "rounded border px-1.5 py-px text-[10px] font-medium",
              POSTURE_STYLE[manifest.security],
            )}
          >
            {POSTURE_LABEL[manifest.security]}
          </span>
          <span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-px text-[10px] font-medium text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
            {familyName}
          </span>
          <span className="hidden sm:inline-block rounded border border-slate-200 bg-slate-50 px-1.5 py-px text-[10px] font-medium text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
            {manifest.category}
          </span>
          <span className="hidden md:inline-block text-[11px] text-slate-400 dark:text-slate-500">
            — Specifications, security &amp; details
          </span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0 text-xs font-medium text-slate-500 transition-colors group-hover:text-slate-800 dark:text-slate-400 dark:group-hover:text-slate-200">
          <span className="group-open:hidden">Expand</span>
          <span className="hidden group-open:inline">Collapse</span>
          <ChevronIcon className="h-3.5 w-3.5 transition-transform duration-200 group-open:rotate-180" />
        </div>
      </summary>

      <div className="mt-4 space-y-6 border-t border-slate-200 pt-4 dark:border-slate-800">
        {/* Overview text */}
        <div>
          <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-300">
            {manifest.summary}
          </p>
        </div>

        {/* Security Posture Notice */}
        <section className={cn("rounded-md border p-3 text-xs leading-relaxed", POSTURE_STYLE[manifest.security])}>
          <h3 className="font-semibold">{posture.title}</h3>
          <p className="mt-1 opacity-90">{posture.description}</p>
        </section>

        {/* Technical Specifications */}
        <section className="space-y-3">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Algorithm Specifications & Capabilities
          </h3>
          <div className="overflow-x-auto rounded-md border border-slate-200 dark:border-slate-800">
            <table className="w-full text-left text-xs">
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                <tr className="bg-slate-50/60 dark:bg-slate-950/30">
                  <th scope="row" className="w-1/3 px-3 py-2 font-medium text-slate-600 dark:text-slate-400">
                    Algorithm Family
                  </th>
                  <td className="px-3 py-2 text-slate-900 dark:text-slate-100">
                    {familyName} ({manifest.category})
                  </td>
                </tr>
                <tr>
                  <th scope="row" className="w-1/3 px-3 py-2 font-medium text-slate-600 dark:text-slate-400">
                    Operation Direction
                  </th>
                  <td className="px-3 py-2 text-slate-900 dark:text-slate-100">
                    {manifest.directions.length === 1 && manifest.directions[0] === "forward"
                      ? "One-way transform (irreversible — no inverse function exists)"
                      : "Bidirectional (reversible forward and inverse transformations)"}
                  </td>
                </tr>
                <tr className="bg-slate-50/60 dark:bg-slate-950/30">
                  <th scope="row" className="w-1/3 px-3 py-2 font-medium text-slate-600 dark:text-slate-400">
                    Streaming Execution
                  </th>
                  <td className="px-3 py-2 text-slate-900 dark:text-slate-100">
                    {manifest.streaming
                      ? "Supported — processes arbitrary-length files in streaming chunks without memory bloat"
                      : "In-memory block processing"}
                  </td>
                </tr>
                <tr>
                  <th scope="row" className="w-1/3 px-3 py-2 font-medium text-slate-600 dark:text-slate-400">
                    Input Modes
                  </th>
                  <td className="px-3 py-2 text-slate-900 dark:text-slate-100">
                    {manifest.supportsFile
                      ? "Direct text, hex/base64 byte strings, and local file drag-and-drop"
                      : manifest.readsInput
                        ? "Direct text input and byte strings"
                        : "Parameter and configuration generation"}
                  </td>
                </tr>
                <tr className="bg-slate-50/60 dark:bg-slate-950/30">
                  <th scope="row" className="w-1/3 px-3 py-2 font-medium text-slate-600 dark:text-slate-400">
                    Expected Output Verification
                  </th>
                  <td className="px-3 py-2 text-slate-900 dark:text-slate-100">
                    {manifest.supportsVerify
                      ? "Supported — real-time byte matching against expected test vectors or published checksums"
                      : "Not applicable for this output format"}
                  </td>
                </tr>
                <tr>
                  <th scope="row" className="w-1/3 px-3 py-2 font-medium text-slate-600 dark:text-slate-400">
                    Supported Output Encodings
                  </th>
                  <td className="px-3 py-2 text-slate-900 dark:text-slate-100">
                    {manifest.outputEncodings
                      .map((enc) => ENCODING_LABEL[enc] ?? enc)
                      .join(", ")}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        {/* Aliases / Tags */}
        {manifest.tags.length > 0 && (
          <section className="space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Cryptographic Aliases & Standards
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {manifest.tags.map((tag) => (
                <span
                  key={tag}
                  className="rounded border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-mono text-slate-600 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400"
                >
                  {tag}
                </span>
              ))}
            </div>
          </section>
        )}

        {/* Related Algorithms (Internal Link Equity) */}
        {siblings.length > 0 && (
          <section className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Related Algorithms in {manifest.category} & {familyName}
            </h3>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
              {siblings.map((sibling) => (
                <a
                  key={sibling.id}
                  href={toolPath(sibling.id)}
                  onClick={(e) => {
                    if (onSelect && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey && e.button === 0) {
                      e.preventDefault();
                      onSelect(sibling.id);
                      if (typeof window !== "undefined") {
                        window.history.pushState(null, "", toolPath(sibling.id));
                      }
                    }
                  }}
                  className="group block rounded-md border border-slate-200 p-2.5 transition-colors hover:border-blue-400 hover:bg-slate-50 dark:border-slate-800 dark:hover:border-blue-700 dark:hover:bg-slate-800/60"
                >
                  <div className="flex items-center justify-between gap-1">
                    <span className="text-xs font-medium text-slate-900 group-hover:text-blue-600 dark:text-slate-100 dark:group-hover:text-blue-400">
                      {sibling.label}
                    </span>
                    <span className="text-[10px] text-slate-400 dark:text-slate-500">
                      {sibling.category}
                    </span>
                  </div>
                  <p className="mt-1 line-clamp-2 text-[11px] text-slate-500 dark:text-slate-400">
                    {sibling.summary}
                  </p>
                </a>
              ))}
            </div>
          </section>
        )}

        {/* Client-Side Privacy Guarantee */}
        <footer className="rounded-md border border-slate-200 bg-slate-50/80 p-3 text-[11px] text-slate-500 dark:border-slate-800 dark:bg-slate-950/40 dark:text-slate-400">
          <strong>Privacy & Execution Guarantee:</strong> All computations for {manifest.label} execute
          strictly within your browser using local JavaScript and Web Workers. No files, passwords,
          keys, or plaintext data are ever transmitted to any remote server or third-party service.
        </footer>
      </div>
    </details>
  );
}

function ChevronIcon({ className }: { className?: string }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}
