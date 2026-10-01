import tls from "node:tls";
import type { CtLogEntry, OcspQueryResult, TlsProbeOptions, TlsProbeResult } from "@ocs/contracts";

function derToPem(label: string, der: Buffer | Uint8Array): string {
  const b64 = Buffer.from(der).toString("base64");
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

/**
 * Connects to a remote TLS endpoint, executes the TLS handshake, and extracts
 * the full peer certificate chain, negotiated cipher suite, protocol, and any
 * stapled OCSP response.
 *
 * Runs strictly in the Electron main process via node:tls with no external binaries
 * or child processes.
 */
export function probeTlsEndpoint(opts: TlsProbeOptions): Promise<TlsProbeResult> {
  return new Promise((resolve, reject) => {
    const port = opts.port ?? 443;
    const host = opts.host.trim();
    const servername = opts.servername?.trim() || host;
    const timeoutMs = opts.timeoutMs ?? 20000;

    const startTime = Date.now();
    let connectTime = 0;
    let ocspResponseBase64: string | null = null;
    let settled = false;

    const connectOptions: tls.ConnectionOptions & {
      requestOCSP?: boolean;
      autoSelectFamily?: boolean;
      autoSelectFamilyAttemptTimeout?: number;
    } = {
      host,
      port,
      servername,
      rejectUnauthorized: false, // Allows inspecting expired/self-signed certs
      requestOCSP: true, // Requests OCSP staple from server
      ALPNProtocols: ["h2", "http/1.1"], // Advertise HTTP/2 and HTTP/1.1 support
      autoSelectFamily: true, // RFC 8305 Happy Eyeballs: eliminates IPv6 routing stalls on Windows
      autoSelectFamilyAttemptTimeout: 500,
      timeout: timeoutMs,
    };
    const socket = tls.connect(connectOptions);

    const cleanup = () => {
      if (!socket.destroyed) {
        socket.destroy();
      }
    };

    socket.on("connect", () => {
      connectTime = Date.now() - startTime;
    });

    socket.on("OCSPResponse", (response: Buffer) => {
      if (response && response.length > 0) {
        ocspResponseBase64 = response.toString("base64");
      }
    });

    socket.on("secureConnect", () => {
      if (settled) return;
      settled = true;
      socket.setTimeout(0); // clear timeout once connected

      const totalMs = Date.now() - startTime;
      const handshakeMs = Math.max(0, totalMs - connectTime);

      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();
      const alpnProtocol = socket.alpnProtocol;
      const authorized = socket.authorized;
      const authorizationError = socket.authorizationError
        ? String(socket.authorizationError)
        : null;
      const ip = socket.remoteAddress;

      const chainPems: string[] = [];
      let current: tls.DetailedPeerCertificate | null = socket.getPeerCertificate(true);
      const seen = new Set<string>();

      while (current && current.raw && current.raw.length > 0) {
        const pem = derToPem("CERTIFICATE", current.raw);
        if (seen.has(pem)) break;
        seen.add(pem);
        chainPems.push(pem);
        if (current.issuerCertificate && current.issuerCertificate !== current) {
          current = current.issuerCertificate;
        } else {
          break;
        }
      }

      cleanup();

      resolve({
        host,
        port,
        ip,
        protocol: protocol ?? null,
        cipher: cipher
          ? {
              name: cipher.name,
              standardName: cipher.standardName,
              version: cipher.version,
            }
          : null,
        alpnProtocol: alpnProtocol ?? null,
        authorized,
        authorizationError,
        peerCertificatePem: chainPems[0] ?? null,
        certificateChainPems: chainPems,
        ocspStapled: Boolean(ocspResponseBase64),
        ocspResponseBase64,
        timing: {
          connectMs: connectTime,
          handshakeMs,
          totalMs,
        },
      });
    });

    socket.on("timeout", () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error(`Connection to ${host}:${port} timed out after ${timeoutMs}ms`));
    });

    socket.on("error", (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    });
  });
}

/**
 * Queries an AIA OCSP responder URL over HTTP with a binary DER OCSPRequest body,
 * returning the binary DER OCSPResponse.
 */
export async function queryOcspResponder(
  responderUrl: string,
  requestBase64: string,
): Promise<OcspQueryResult> {
  const reqBytes = Buffer.from(requestBase64, "base64");
  const startTime = Date.now();
  const res = await fetch(responderUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/ocsp-request",
      Accept: "application/ocsp-response",
    },
    body: reqBytes,
    signal: AbortSignal.timeout(10000),
  });

  const arrayBuffer = await res.arrayBuffer();
  const responseBase64 = Buffer.from(arrayBuffer).toString("base64");
  return {
    status: res.status,
    responseBase64,
    latencyMs: Date.now() - startTime,
  };
}

/**
 * Queries Certificate Transparency logs for a domain, using Certspotter with fallback
 * to crt.sh.
 */
export async function queryCtLogs(domain: string): Promise<CtLogEntry[]> {
  const cleanDomain = domain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "");

  // 1. Try Certspotter first: fast (2-3s) and structured
  try {
    const certspotterUrl = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(
      cleanDomain,
    )}&include_subdomains=false&expand=dns_names&expand=issuer`;
    const res = await fetch(certspotterUrl, {
      headers: { "User-Agent": "CipherWorkbench/0.15.2" },
      signal: AbortSignal.timeout(6000),
    });
    if (res.ok) {
      const data = (await res.json()) as Array<{
        id: string;
        dns_names?: string[];
        issuer?: { name?: string; friendly_name?: string };
        not_before?: string;
        not_after?: string;
        cert_sha256?: string;
      }>;
      if (Array.isArray(data) && data.length > 0) {
        return data.slice(0, 50).map((item, idx) => ({
          issuerCaId: 0,
          issuerName: item.issuer?.friendly_name || item.issuer?.name || "Unknown Issuer",
          commonName: item.dns_names?.[0] || cleanDomain,
          nameValue: item.dns_names?.join(", ") || cleanDomain,
          id: parseInt(item.id, 10) || idx,
          entryTimestamp: item.not_before || "",
          notBefore: item.not_before || "",
          notAfter: item.not_after || "",
          serialNumber: item.cert_sha256 ? item.cert_sha256.slice(0, 16) : "",
        }));
      }
    }
  } catch {
    // Fall through to crt.sh
  }

  // 2. Fallback to crt.sh with exclude=expired and 12s timeout
  try {
    const crtUrl = `https://crt.sh/?q=${encodeURIComponent(cleanDomain)}&output=json&exclude=expired`;
    const res = await fetch(crtUrl, {
      headers: { "User-Agent": "CipherWorkbench/0.15.2" },
      signal: AbortSignal.timeout(12000),
    });

    if (res.ok) {
      const raw = (await res.json()) as Array<Record<string, unknown>>;
      if (Array.isArray(raw)) {
        return raw.slice(0, 50).map((item) => ({
          issuerCaId: typeof item.issuer_ca_id === "number" ? item.issuer_ca_id : 0,
          issuerName: typeof item.issuer_name === "string" ? item.issuer_name : "",
          commonName: typeof item.common_name === "string" ? item.common_name : "",
          nameValue: typeof item.name_value === "string" ? item.name_value : "",
          id: typeof item.id === "number" ? item.id : 0,
          entryTimestamp: typeof item.entry_timestamp === "string" ? item.entry_timestamp : "",
          notBefore: typeof item.not_before === "string" ? item.not_before : "",
          notAfter: typeof item.not_after === "string" ? item.not_after : "",
          serialNumber: typeof item.serial_number === "string" ? item.serial_number : "",
        }));
      }
    }
  } catch {
    // Both providers failed
  }

  throw new Error(
    `Certificate Transparency servers timed out for "${cleanDomain}". Public CT log databases may be temporarily throttled.`,
  );
}
