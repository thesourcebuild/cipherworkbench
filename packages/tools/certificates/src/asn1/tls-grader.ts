import { detectInputBytes, type PemBlock } from "./pem";
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
  chainCerts?: ParsedX509Certificate[];
  sslxCommand: string;
}

/**
 * Audit an X.509 certificate and chain, producing a letter grade (A+ to F)
 * following CA/B Forum and modern TLS security baselines.
 */
export function gradeCertificate(certInput: Uint8Array | string): TlsGradeResult {
  const bytes = typeof certInput === "string" ? new TextEncoder().encode(certInput) : certInput;
  const detected = detectInputBytes(bytes);
  const der = detected.der;
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

  // 6. Chain Completeness & Intermediate CA Trust Path Check
  const certBlocks = (detected.blocks || []).filter(
    (b: PemBlock) => b.label.includes("CERTIFICATE") && !b.label.includes("REQUEST"),
  );
  let parsedChainCerts: ParsedX509Certificate[] = [];
  if (certBlocks.length > 1) {
    const chainCerts = certBlocks
      .map((b: PemBlock) => {
        try {
          return parseX509Certificate(b.bytes);
        } catch {
          return null;
        }
      })
      .filter((c: ParsedX509Certificate | null): c is ParsedX509Certificate => c !== null);
    parsedChainCerts = chainCerts;

    const hasWeakCa = chainCerts.some((c: ParsedX509Certificate) => {
      const alg = c.signatureAlgorithmName.toLowerCase();
      return alg.includes("md5") || alg.includes("sha1") || alg.includes("sha-1");
    });

    const isLinked = chainCerts.every((c: ParsedX509Certificate, idx: number) => {
      if (idx === 0) return true;
      const prev = chainCerts[idx - 1];
      if (!prev) return true;
      return prev.issuer.dn === c.subject.dn || prev.issuer.commonName === c.subject.commonName;
    });

    if (hasWeakCa) {
      isCriticalFail = true;
      checks.push({
        id: "chain-completeness",
        name: "Chain Health",
        category: "chain",
        status: "fail",
        score: 0,
        title: "Weak/Deprecated Intermediate CA Signature",
        detail: "One or more intermediate CAs in the certificate chain use SHA-1 or MD5 signatures.",
      });
    } else if (!isLinked) {
      checks.push({
        id: "chain-completeness",
        name: "Chain Health",
        category: "chain",
        status: "warn",
        score: 75,
        title: `Chain Linkage Gap (${chainCerts.length} certificates)`,
        detail: "The intermediate CA certificates provided do not cleanly match the leaf issuer DN.",
      });
    } else {
      checks.push({
        id: "chain-completeness",
        name: "Chain Health",
        category: "chain",
        status: "pass",
        score: 100,
        title: `Complete Chain Provided (${chainCerts.length} certificates)`,
        detail: `Valid validation path supplied from leaf (${cert.subject.commonName || "Leaf"}) to intermediate/root CA.`,
      });
    }
  } else if (!isCa) {
    checks.push({
      id: "chain-completeness",
      name: "Chain Health",
      category: "chain",
      status: "warn",
      score: 85,
      title: "Standalone Leaf Certificate (No Intermediates Provided)",
      detail: "Modern TLS servers must serve intermediate CA certificates alongside the leaf certificate to prevent validation failures on clients without cached intermediates.",
    });
  } else {
    checks.push({
      id: "chain-completeness",
      name: "Chain Health",
      category: "chain",
      status: "pass",
      score: 100,
      title: "CA Certificate Architecture",
      detail: "Self-contained Certificate Authority structure.",
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

  const rawCandidate = sans[0]?.replace(/^DNS:/, "") || cert.subject.commonName || "";
  const cleanCandidate = rawCandidate.replace(/^\*\./, "").trim();
  const isHost =
    Boolean(cleanCandidate) &&
    !/[\s"'`\\/()<>,;]/.test(cleanCandidate) &&
    (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(cleanCandidate) ||
      /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanCandidate) ||
      /^localhost$/i.test(cleanCandidate));

  const hostDisplay = isHost ? cleanCandidate : (cert.subject.commonName || "certificate");
  const bannerName = hostDisplay.length > 38 ? `${hostDisplay.slice(0, 35)}...` : hostDisplay;

  const bannerLines = [
    "╭──────────────────────────────────────────────────────────╮",
    `│ ${bannerName.padEnd(40)} Grade: ${grade.padEnd(4)} │`,
    "╰──────────────────────────────────────────────────────────╯",
    ...checks.map((c) => {
      const mark = c.status === "pass" ? "✓" : c.status === "warn" ? "!" : "✗";
      return `${mark} ${c.name.padEnd(24)} ${c.title}`;
    }),
  ];

  const asciiBanner = bannerLines.join("\n");
  const sslxCommand = isHost ? `sslx grade ${cleanCandidate}` : "sslx inspect cert.pem";

  return {
    grade,
    score: finalScore,
    summary: `TLS Health Grade: ${grade} (${finalScore}/100) — ${checks.filter((c) => c.status === "pass").length}/${checks.length} checks passed.`,
    checks,
    asciiBanner,
    cert,
    chainCerts: parsedChainCerts.length > 1 ? parsedChainCerts : undefined,
    sslxCommand,
  };
}
