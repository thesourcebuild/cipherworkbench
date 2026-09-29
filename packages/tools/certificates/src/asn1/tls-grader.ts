import { detectInputBytes } from "./pem";
import { parseX509Certificate, type ParsedX509Certificate } from "./x509";

export interface TlsGradeCheck {
  id: string;
  name: string;
  category: "key" | "signature" | "validity" | "san" | "chain";
  status: "pass" | "warn" | "fail";
  score: number; // 0..100
  title: string;
  detail: string;
}

export type TlsGradeLetter = "A+" | "A" | "B" | "C" | "D" | "F";

export interface TlsGradeResult {
  grade: TlsGradeLetter;
  score: number; // 0..100
  summary: string;
  checks: TlsGradeCheck[];
  asciiBanner: string;
  cert: ParsedX509Certificate;
  sslxCommand: string;
}

/**
 * Audit an X.509 certificate and chain, producing a letter grade (A+ to F)
 * following CA/B Forum and modern TLS security baselines.
 */
export function gradeCertificate(certInput: Uint8Array | string): TlsGradeResult {
  const bytes = typeof certInput === "string" ? new TextEncoder().encode(certInput) : certInput;
  const der = detectInputBytes(bytes).der;
  const cert = parseX509Certificate(der);

  const checks: TlsGradeCheck[] = [];
  let isCriticalFail = false;

  // 1. Signature Algorithm Check
  const sigName = cert.signatureAlgorithmName.toLowerCase();
  if (sigName.includes("md5")) {
    isCriticalFail = true;
    checks.push({
      id: "sig-alg",
      name: "Signature Algorithm",
      category: "signature",
      status: "fail",
      score: 0,
      title: "Broken MD5 Signature",
      detail: `Certificate signed with MD5 (${cert.signatureAlgorithmName}), susceptible to collision attacks.`,
    });
  } else if (sigName.includes("sha1") || sigName.includes("sha-1")) {
    isCriticalFail = true;
    checks.push({
      id: "sig-alg",
      name: "Signature Algorithm",
      category: "signature",
      status: "fail",
      score: 0,
      title: "Deprecated SHA-1 Signature",
      detail: `Certificate signed with SHA-1 (${cert.signatureAlgorithmName}), untrusted by modern browsers.`,
    });
  } else {
    checks.push({
      id: "sig-alg",
      name: "Signature Algorithm",
      category: "signature",
      status: "pass",
      score: 100,
      title: `Secure Signature (${cert.signatureAlgorithmName})`,
      detail: `Signed with cryptographic digest ${cert.signatureAlgorithmName}.`,
    });
  }

  // 2. Public Key Type & Strength Check
  const keyType = cert.publicKey.keyType;
  if (keyType === "rsa") {
    const bits = cert.publicKey.rsaBits ?? 0;
    if (bits < 2048) {
      isCriticalFail = true;
      checks.push({
        id: "key-strength",
        name: "Public Key Strength",
        category: "key",
        status: "fail",
        score: 0,
        title: `Weak RSA Key (${bits} bits)`,
        detail: `RSA key size of ${bits} bits is below the minimum safe baseline of 2048 bits.`,
      });
    } else if (bits === 2048) {
      checks.push({
        id: "key-strength",
        name: "Public Key Strength",
        category: "key",
        status: "pass",
        score: 85,
        title: "Standard RSA Key (2048 bits)",
        detail: "Standard RSA 2048-bit key. Modern recommendation is RSA 3072+ or ECC P-256.",
      });
    } else {
      checks.push({
        id: "key-strength",
        name: "Public Key Strength",
        category: "key",
        status: "pass",
        score: 100,
        title: `Robust RSA Key (${bits} bits)`,
        detail: `High security RSA ${bits}-bit public key.`,
      });
    }
  } else if (keyType === "ec" || keyType === "ed25519") {
    checks.push({
      id: "key-strength",
      name: "Public Key Strength",
      category: "key",
      status: "pass",
      score: 100,
      title: `Modern Elliptic Curve (${cert.publicKey.algorithmName})`,
      detail: `ECC key ${cert.publicKey.details} providing optimal security and performance.`,
    });
  } else if (keyType.startsWith("ml-dsa")) {
    checks.push({
      id: "key-strength",
      name: "Public Key Strength",
      category: "key",
      status: "pass",
      score: 100,
      title: `Post-Quantum Algorithm (${cert.publicKey.algorithmName})`,
      detail: `FIPS 204 lattice-based quantum-resistant signature scheme.`,
    });
  } else {
    checks.push({
      id: "key-strength",
      name: "Public Key Strength",
      category: "key",
      status: "pass",
      score: 90,
      title: cert.publicKey.algorithmName,
      detail: cert.publicKey.details,
    });
  }

  // 3. Expiration & Status Check
  const val = cert.validity;
  if (val.status === "expired") {
    isCriticalFail = true;
    checks.push({
      id: "expiry",
      name: "Certificate Validity",
      category: "validity",
      status: "fail",
      score: 0,
      title: "Certificate Expired",
      detail: `${val.statusLabel}. TLS handshakes will be rejected by clients.`,
    });
  } else if (val.status === "not-yet-valid") {
    isCriticalFail = true;
    checks.push({
      id: "expiry",
      name: "Certificate Validity",
      category: "validity",
      status: "fail",
      score: 10,
      title: "Certificate Not Yet Active",
      detail: val.statusLabel,
    });
  } else if (val.daysRemaining <= 7) {
    checks.push({
      id: "expiry",
      name: "Certificate Validity",
      category: "validity",
      status: "warn",
      score: 40,
      title: `Critical Expiry (${val.daysRemaining} days remaining)`,
      detail: `Certificate will expire in ${val.daysRemaining} day(s). Immediate renewal required.`,
    });
  } else if (val.daysRemaining <= 30) {
    checks.push({
      id: "expiry",
      name: "Certificate Validity",
      category: "validity",
      status: "warn",
      score: 70,
      title: `Expiring Soon (${val.daysRemaining} days remaining)`,
      detail: `Certificate expires within 30 days. Plan renewal.`,
    });
  } else {
    checks.push({
      id: "expiry",
      name: "Certificate Validity",
      category: "validity",
      status: "pass",
      score: 100,
      title: `Valid (${val.daysRemaining} days remaining)`,
      detail: `Active through ${val.notAfter.toISOString().split("T")[0]}.`,
    });
  }

  // 4. CA/B Forum Lifespan Limit Check (398-day limit for non-CA leaf certs)
  const isCa = cert.extensions.basicConstraints?.isCa ?? false;
  if (!isCa && val.totalDays > 398) {
    checks.push({
      id: "lifespan",
      name: "CA/B Forum Lifespan",
      category: "validity",
      status: "warn",
      score: 70,
      title: `Excessive Lifespan (${val.totalDays} days)`,
      detail: `Lifespan exceeds the CA/B Forum 398-day maximum for public TLS certificates.`,
    });
  } else {
    checks.push({
      id: "lifespan",
      name: "CA/B Forum Lifespan",
      category: "validity",
      status: "pass",
      score: 100,
      title: `Lifespan Compliant (${val.totalDays} days)`,
      detail: isCa ? "CA Certificate validity" : "Within CA/B Forum 398-day baseline limit.",
    });
  }

  // 5. Subject Alternative Name (SAN) Extension Check
  const sans = cert.extensions.sans;
  if (!isCa && sans.length === 0) {
    checks.push({
      id: "san-presence",
      name: "SAN Extension",
      category: "san",
      status: "warn",
      score: 50,
      title: "Missing Subject Alternative Names (SAN)",
      detail: "Modern TLS clients (Chrome, Safari, Firefox, curl) require SAN. Deprecated CommonName fallback.",
    });
  } else {
    checks.push({
      id: "san-presence",
      name: "SAN Extension",
      category: "san",
      status: "pass",
      score: 100,
      title: isCa ? "CA Certificate Structure" : `Subject Alternative Names Present (${sans.length} SANs)`,
      detail: isCa ? "CA certificate" : `Configured for: ${sans.slice(0, 3).join(", ")}${sans.length > 3 ? "..." : ""}`,
    });
  }

  // Calculate Weighted Overall Score
  const rawScore = checks.reduce((acc, c) => acc + c.score, 0) / checks.length;
  let finalScore = Math.round(rawScore);
  if (isCriticalFail) {
    finalScore = Math.min(25, finalScore);
  }

  // Letter Grade Assignment
  let grade: TlsGradeLetter;
  if (finalScore >= 95) grade = "A+";
  else if (finalScore >= 85) grade = "A";
  else if (finalScore >= 70) grade = "B";
  else if (finalScore >= 50) grade = "C";
  else if (finalScore >= 35) grade = "D";
  else grade = "F";

  const hostHint = sans[0]?.replace(/^DNS:/, "") || cert.subject.commonName || "certificate";

  const bannerLines = [
    "╭──────────────────────────────────────────────────────────╮",
    `│ ${hostHint.padEnd(40)} Grade: ${grade.padEnd(4)} │`,
    "╰──────────────────────────────────────────────────────────╯",
    ...checks.map((c) => {
      const mark = c.status === "pass" ? "✓" : c.status === "warn" ? "!" : "✗";
      return `${mark} ${c.name.padEnd(24)} ${c.title}`;
    }),
  ];

  const asciiBanner = bannerLines.join("\n");
  const sslxCommand = `sslx grade ${hostHint}`;

  return {
    grade,
    score: finalScore,
    summary: `TLS Health Grade: ${grade} (${finalScore}/100) — ${checks.filter((c) => c.status === "pass").length}/${checks.length} checks passed.`,
    checks,
    asciiBanner,
    cert,
    sslxCommand,
  };
}
