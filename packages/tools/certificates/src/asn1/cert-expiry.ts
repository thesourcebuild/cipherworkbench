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
    "# Prometheus alert rule for certificate expiry",
    "- alert: CertificateExpiringSoon",
    "  expr: x509_cert_expiry_days < 30",
    "  for: 12h",
    "  labels:",
    "    severity: warning",
    "  annotations:",
    "    summary: 'SSL certificate for {{ $labels.subject }} is expiring in {{ $value }} days'",
    "",
    "- alert: CertificateCriticalExpiry",
    "  expr: x509_cert_expiry_days < 7",
    "  for: 1h",
    "  labels:",
    "    severity: critical",
    "  annotations:",
    "    summary: 'CRITICAL: SSL certificate for {{ $labels.subject }} expires in {{ $value }} days!'",
  ].join("\n");

  const hosts = items.map((i) => i.subjectCn.replace(/^\*\./, "")).slice(0, 4).join(" ");
  const sslxCommand = `sslx expiry ${hosts || "example.com"}`;

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
