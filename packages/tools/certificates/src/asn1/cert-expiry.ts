import { parseX509Certificate } from "./x509";

export interface CertExpiryItem {
  index: number;
  subjectCn: string;
  issuerCn: string;
  notBefore: string;
  notAfter: string;
  daysRemaining: number;
  totalDays: number;
  percentElapsed: number;
  visualProgressBar: string;
  isExpired: boolean;
  status: "OK" | "EXPIRING_SOON" | "CRITICAL" | "EXPIRED" | "NOT_YET_VALID";
  statusLabel: string;
  sans: string[];
  serialNumber: string;
}

export interface CertExpiryReport {
  items: CertExpiryItem[];
  totalCount: number;
  healthyCount: number;
  expiringSoonCount: number;
  criticalCount: number;
  expiredCount: number;
  asciiTable: string;
  jsonExport: string;
  csvExport: string;
  prometheusSnippet: string;
  sslxCommand: string;
}

/**
 * Extract all PEM certificates from a combined string or bundle.
 */
export function extractCertPems(input: string): string[] {
  const matches = input.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return matches ? matches.map((m) => m.trim()) : [];
}

/**
 * Audit expiration schedules across one or many certificates.
 */
export function auditCertificateExpiry(input: string | Uint8Array): CertExpiryReport {
  const text = typeof input === "string" ? input : new TextDecoder().decode(input);
  const pems = extractCertPems(text);

  // If no standard PEM blocks matched, try parsing the whole input as one certificate
  const certStrings = pems.length > 0 ? pems : [text.trim()];

  const items: CertExpiryItem[] = [];
  let healthyCount = 0;
  let expiringSoonCount = 0;
  let criticalCount = 0;
  let expiredCount = 0;

  for (let idx = 0; idx < certStrings.length; idx++) {
    const raw = certStrings[idx];
    if (!raw) continue;
    try {
      const cert = parseX509Certificate(new TextEncoder().encode(raw));
      const val = cert.validity;
      const days = val.daysRemaining;

      let itemStatus: CertExpiryItem["status"] = "OK";
      if (val.status === "expired") {
        itemStatus = "EXPIRED";
        expiredCount++;
      } else if (val.status === "not-yet-valid") {
        itemStatus = "NOT_YET_VALID";
      } else if (days <= 7) {
        itemStatus = "CRITICAL";
        criticalCount++;
      } else if (days <= 30) {
        itemStatus = "EXPIRING_SOON";
        expiringSoonCount++;
      } else {
        itemStatus = "OK";
        healthyCount++;
      }

      const subjectCn =
        cert.subject.commonName ||
        cert.extensions.sans[0]?.replace(/^DNS:/, "") ||
        `Certificate #${idx + 1}`;
      const issuerCn = cert.issuer.commonName || cert.issuer.organization || "Unknown Issuer";

      items.push({
        index: idx + 1,
        subjectCn,
        issuerCn,
        notBefore: val.notBefore.toISOString().split("T")[0]!,
        notAfter: val.notAfter.toISOString().split("T")[0]!,
        daysRemaining: days,
        totalDays: val.totalDays,
        percentElapsed: val.percentElapsed,
        visualProgressBar: val.visualProgressBar,
        isExpired: itemStatus === "EXPIRED",
        status: itemStatus,
        statusLabel: val.statusLabel,
        sans: cert.extensions.sans,
        serialNumber: cert.serialNumber,
      });
    } catch {
      // Skip unparseable blocks in bulk inputs
    }
  }

  // Format ASCII Table (sslx style)
  const header = "Host / Subject CN          Expires      Days Left  Lifespan Gauge   Status";
  const divider = "─────────────────────────────────────────────────────────────────────────────";
  const rows = items.map((item) => {
    const mark =
      item.status === "OK" ? "✓" : item.status === "EXPIRING_SOON" ? "!" : item.status === "CRITICAL" ? "⚠" : "✗";
    const name = `${mark} ${item.subjectCn}`.padEnd(26);
    const expires = item.notAfter.padEnd(12);
    const days = String(item.daysRemaining).padEnd(10);
    const gauge = item.visualProgressBar.padEnd(16);
    const status = item.status;
    return `${name} ${expires} ${days} ${gauge} ${status}`;
  });

  const asciiTable = [header, divider, ...rows].join("\n");

  // Format JSON export
  const jsonExport = JSON.stringify(
    {
      summary: {
        total: items.length,
        healthy: healthyCount,
        expiringSoon: expiringSoonCount,
        critical: criticalCount,
        expired: expiredCount,
      },
      certificates: items,
    },
    null,
    2,
  );

  // Format CSV export
  const csvHeaders = "Index,Subject,Issuer,Expires,DaysRemaining,Progress,Status";
  const csvRows = items.map(
    (i) => `"${i.index}","${i.subjectCn}","${i.issuerCn}","${i.notAfter}",${i.daysRemaining},"${i.visualProgressBar}","${i.status}"`,
  );
  const csvExport = [csvHeaders, ...csvRows].join("\n");

  // Format Prometheus alerting rules snippet
  const prometheusSnippet = [
    "# Prometheus Alertmanager rule for certificate expiry (Blackbox Exporter)",
    "- alert: CertificateExpiringSoon",
    "  expr: (probe_ssl_earliest_cert_expiry - time()) / 86400 < 30",
    "  for: 12h",
    "  labels:",
    "    severity: warning",
    "  annotations:",
    "    summary: 'SSL certificate for {{ $labels.instance }} is expiring in {{ $value | printf \"%.0f\" }} days'",
    "",
    "- alert: CertificateCriticalExpiry",
    "  expr: (probe_ssl_earliest_cert_expiry - time()) / 86400 < 7",
    "  for: 1h",
    "  labels:",
    "    severity: critical",
    "  annotations:",
    "    summary: 'CRITICAL: SSL certificate for {{ $labels.instance }} expires in {{ $value | printf \"%.0f\" }} days!'",
  ].join("\n");

  // Extract only genuine hostnames/FQDNs (omitting CA names and organizational strings with spaces)
  const targetHosts: string[] = [];
  const seenHosts = new Set<string>();

  for (const item of items) {
    const cleanCn = item.subjectCn.trim().replace(/^\*\./, "");
    const isDomainCn =
      !/[\s"'`\\/()<>,;]/.test(cleanCn) &&
      (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(cleanCn) ||
        /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanCn) ||
        /^localhost$/i.test(cleanCn));

    if (isDomainCn) {
      const lower = cleanCn.toLowerCase();
      if (!seenHosts.has(lower)) {
        seenHosts.add(lower);
        targetHosts.push(cleanCn);
        continue;
      }
    }

    for (const san of item.sans || []) {
      const cleanSan = san.replace(/^(DNS|IP Address):/i, "").trim().replace(/^\*\./, "");
      const isDomainSan =
        !/[\s"'`\\/()<>,;]/.test(cleanSan) &&
        (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(cleanSan) ||
          /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanSan) ||
          /^localhost$/i.test(cleanSan));

      if (isDomainSan) {
        const lower = cleanSan.toLowerCase();
        if (!seenHosts.has(lower)) {
          seenHosts.add(lower);
          targetHosts.push(cleanSan);
          break;
        }
      }
    }
  }

  const hostsStr = targetHosts.slice(0, 4).join(" ");
  const sslxCommand = hostsStr ? `sslx expiry ${hostsStr}` : "sslx expiry cert.pem";

  return {
    items,
    totalCount: items.length,
    healthyCount,
    expiringSoonCount,
    criticalCount,
    expiredCount,
    asciiTable,
    jsonExport,
    csvExport,
    prometheusSnippet,
    sslxCommand,
  };
}
