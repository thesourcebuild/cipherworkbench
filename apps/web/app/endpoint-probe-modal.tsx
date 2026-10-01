"use client";

import { useEffect, useMemo, useState } from "react";
import {
  detectInputBytes,
  parseX509Certificate,
  parseOcspResponse,
  buildOcspRequest,
  type ParsedX509Certificate,
  type ParsedOcspResponse,
} from "@ocs/certificates";
import type { CtLogEntry, TlsProbeResult } from "@ocs/contracts";
import { platform } from "@ocs/platform";
import { Button, CopyButton, Dialog } from "@ocs/ui";

export interface ProbeApplyPayload {
  inputText?: string;
  options?: Record<string, unknown>;
  targetSlot?: "primary" | "secondary";
}

export interface EndpointProbeModalProps {
  open: boolean;
  onClose: () => void;
  onApplyCertificate: (pem: string) => void;
  onApplyPayload?: (payload: ProbeApplyPayload) => void;
  currentToolId?: string;
  currentSpec?: unknown;
}

export interface SslxGradeCheck {
  id: string;
  label: string;
  value: string;
  status: "pass" | "warn" | "fail" | "info";
  detail?: string;
}

export interface SslxGradeAssessment {
  hostPort: string;
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  score: number;
  checks: SslxGradeCheck[];
  asciiBox: string;
  sslxCommand: string;
  cert: ParsedX509Certificate | null;
}

function matchesHost(targetHost: string, san: string): boolean {
  const h = targetHost.toLowerCase().trim();
  const s = san.toLowerCase().replace(/^(dns|ip):/i, "").trim();
  if (h === s) return true;
  if (s.startsWith("*.")) {
    const domain = s.slice(2);
    const hostParts = h.split(".");
    const domainParts = domain.split(".");
    if (hostParts.length === domainParts.length + 1) {
      const hostDomain = hostParts.slice(1).join(".");
      if (hostDomain === domain) return true;
    }
  }
  return false;
}

function generateSslxGradeAscii(
  hostPort: string,
  grade: string,
  checks: SslxGradeCheck[]
): string {
  const innerWidth = 42;
  const gradeStr = `Grade: ${grade}`;
  const padSpaces = Math.max(1, innerWidth - hostPort.length - gradeStr.length);
  const topBorder = `  ╭${"─".repeat(innerWidth + 4)}╮`;
  const headerLine = `  │  ${hostPort}${" ".repeat(padSpaces)}${gradeStr}  │`;
  const botBorder = `  ╰${"─".repeat(innerWidth + 4)}╯`;

  const rows = checks.map((c) => {
    const mark =
      c.status === "pass" ? "✓" : c.status === "warn" ? "!" : c.status === "fail" ? "✗" : "•";
    const labelPadded = c.label.padEnd(13);
    return `  ${mark} ${labelPadded} ${c.value}`;
  });

  return [topBorder, headerLine, botBorder, "", ...rows].join("\n");
}

function evaluateEndpointGrade(
  result: TlsProbeResult,
  cert: ParsedX509Certificate | null
): SslxGradeAssessment {
  const checks: SslxGradeCheck[] = [];

  // 1. Protocol Check (e.g. TLS 1.3)
  const protoRaw = result.protocol || "";
  let protoLabel = "Unknown";
  let protoStatus: "pass" | "warn" | "fail" = "warn";
  if (/1\.3/i.test(protoRaw)) {
    protoLabel = "TLS 1.3";
    protoStatus = "pass";
  } else if (/1\.2/i.test(protoRaw)) {
    protoLabel = "TLS 1.2";
    protoStatus = "pass";
  } else if (/1\.[01]/i.test(protoRaw)) {
    protoLabel = protoRaw.replace(/^TLSv?/i, "TLS ");
    protoStatus = "fail";
  } else if (protoRaw) {
    protoLabel = protoRaw;
  }
  checks.push({
    id: "protocol",
    label: "Protocol",
    value: protoLabel,
    status: protoStatus,
    detail: protoStatus === "pass" ? "Modern TLS protocol negotiated" : "Deprecated TLS protocol",
  });

  // 2. Cipher Check (e.g. TLS13_AES_128_GCM_SHA256 (AEAD))
  const cipherName = result.cipher?.name || "Unknown";
  const isAead = /(GCM|POLY1305|CCM)/i.test(cipherName);
  const isCbc = /CBC/i.test(cipherName);
  const isBroken = /(RC4|DES|3DES|MD5|NULL|EXPORT)/i.test(cipherName);
  const cipherValue = `${cipherName}${isAead ? " (AEAD)" : isCbc ? " (CBC)" : ""}`;
  const cipherStatus: "pass" | "warn" | "fail" = isBroken
    ? "fail"
    : isAead
    ? "pass"
    : isCbc
    ? "warn"
    : "pass";
  checks.push({
    id: "cipher",
    label: "Cipher",
    value: cipherValue,
    status: cipherStatus,
    detail: isAead
      ? "Authenticated Encryption with Associated Data"
      : isCbc
      ? "Legacy CBC mode"
      : undefined,
  });

  // 3. Certificate Validity Check (e.g. Valid, 49 days remaining)
  let certStatus: "pass" | "warn" | "fail" = "warn";
  let certValue = "Unavailable";
  if (cert) {
    const val = cert.validity;
    if (val.status === "valid") {
      if (val.daysRemaining > 30) {
        certStatus = "pass";
        certValue = `Valid, ${val.daysRemaining} days remaining`;
      } else {
        certStatus = "warn";
        certValue = `Expiring soon (${val.daysRemaining} days remaining)`;
      }
    } else if (val.status === "expired") {
      certStatus = "fail";
      certValue = `Expired (${Math.abs(val.daysRemaining)} days ago)`;
    } else {
      certStatus = "fail";
      certValue = "Not yet active";
    }
  }
  checks.push({
    id: "certificate",
    label: "Certificate",
    value: certValue,
    status: certStatus,
    detail: cert ? `Expires ${cert.validity.notAfter.toISOString().split("T")[0]}` : undefined,
  });

  // 4. Public Key Check (e.g. ECDSA P-256 (256 bit))
  let keyStatus: "pass" | "warn" | "fail" = "warn";
  let keyValue = "Unavailable";
  if (cert) {
    const pk = cert.publicKey;
    if (pk.keyType === "ec") {
      const curve = pk.curveName || pk.details.split(" ")[0] || "P-256";
      const bits = pk.details.match(/\d+ bit/)?.[0] || "256 bit";
      keyValue = `ECDSA ${curve} (${bits})`;
      keyStatus = "pass";
    } else if (pk.keyType === "ed25519") {
      keyValue = "Ed25519 (256 bit)";
      keyStatus = "pass";
    } else if (pk.keyType.startsWith("ml-dsa")) {
      keyValue = `${pk.algorithmName} (Post-Quantum)`;
      keyStatus = "pass";
    } else if (pk.keyType === "rsa") {
      const bits = pk.rsaBits ?? 0;
      keyValue = `RSA ${bits} (${bits} bit)`;
      keyStatus = bits >= 2048 ? "pass" : "fail";
    } else {
      keyValue = `${pk.algorithmName} (${pk.details})`;
      keyStatus = "pass";
    }
  }
  checks.push({
    id: "key",
    label: "Key",
    value: keyValue,
    status: keyStatus,
  });

  // 5. Hostname SAN Check (e.g. github.com in SANs)
  let hostStatus: "pass" | "warn" | "fail" = "warn";
  let hostValue = "Unavailable";
  if (cert) {
    const sans = cert.extensions.sans;
    const commonName = cert.subject.commonName;
    const targetHost = result.host;
    const isMatched =
      sans.some((s) => matchesHost(targetHost, s)) ||
      (commonName ? matchesHost(targetHost, commonName) : false);

    if (isMatched) {
      hostStatus = "pass";
      hostValue = `${targetHost} in SANs`;
    } else {
      hostStatus = "fail";
      hostValue = `Mismatch (${targetHost} not in SANs)`;
    }
  }
  checks.push({
    id: "hostname",
    label: "Hostname",
    value: hostValue,
    status: hostStatus,
    detail: cert?.extensions.sans?.length
      ? `${cert.extensions.sans.length} SANs configured`
      : undefined,
  });

  // 6. Chain Completeness Check (e.g. Complete (3 certs))
  const chainCount = result.certificateChainPems.length || 1;
  let chainStatus: "pass" | "warn" | "fail" = "warn";
  let chainValue = `${chainCount} certs`;
  if (result.authorized) {
    chainStatus = chainCount > 1 ? "pass" : "warn";
    chainValue = `Complete (${chainCount} ${chainCount === 1 ? "cert" : "certs"})`;
  } else {
    chainStatus = "fail";
    chainValue = `Untrusted (${result.authorizationError || "CA verification failed"})`;
  }
  checks.push({
    id: "chain",
    label: "Chain",
    value: chainValue,
    status: chainStatus,
    detail: result.authorized
      ? "Trusted root certificate verified"
      : result.authorizationError || "Untrusted",
  });

  // 7. ALPN Check (e.g. HTTP/2 supported)
  const alpn = result.alpnProtocol;
  let alpnStatus: "pass" | "warn" | "fail" | "info" = "info";
  let alpnValue = "None";
  if (alpn === "h2") {
    alpnValue = "HTTP/2 supported";
    alpnStatus = "pass";
  } else if (alpn === "h3") {
    alpnValue = "HTTP/3 supported";
    alpnStatus = "pass";
  } else if (alpn === "http/1.1") {
    alpnValue = "HTTP/1.1 supported";
    alpnStatus = "pass";
  } else if (alpn) {
    alpnValue = `${alpn} supported`;
    alpnStatus = "pass";
  } else {
    alpnValue = "None negotiated";
    alpnStatus = "info";
  }
  checks.push({
    id: "alpn",
    label: "ALPN",
    value: alpnValue,
    status: alpnStatus,
  });

  // 8. OCSP Staple Check (Bonus)
  checks.push({
    id: "ocsp",
    label: "OCSP Staple",
    value: result.ocspStapled ? "Stapled (Present)" : "Not stapled",
    status: result.ocspStapled ? "pass" : "info",
  });

  // Calculate Overall Grade
  const hasFail = checks.some((c) => c.status === "fail");
  const warnCount = checks.filter((c) => c.status === "warn").length;

  let grade: "A+" | "A" | "B" | "C" | "D" | "F" = "A+";
  let score = 100;

  if (hasFail) {
    grade = "F";
    score = 25;
  } else if (warnCount >= 2) {
    grade = "B";
    score = 75;
  } else if (warnCount === 1) {
    grade = "A";
    score = 88;
  } else {
    const isTls13 = /1\.3/.test(protoLabel);
    const isAead = cipherStatus === "pass";
    const days = cert?.validity.daysRemaining ?? 0;
    if (isTls13 && isAead && result.authorized && days > 30) {
      grade = "A+";
      score = 100;
    } else if (result.authorized && days > 30) {
      grade = "A";
      score = 92;
    } else {
      grade = "B";
      score = 80;
    }
  }

  const hostPort = `${result.host}:${result.port}`;
  const asciiBox = generateSslxGradeAscii(hostPort, grade, checks);
  const sslxCommand = `sslx grade ${result.host}`;

  return {
    hostPort,
    grade,
    score,
    checks,
    asciiBox,
    sslxCommand,
    cert,
  };
}

export function EndpointProbeModal({
  open,
  onClose,
  onApplyCertificate,
  onApplyPayload,
  currentToolId,
  currentSpec: _currentSpec,
}: EndpointProbeModalProps) {
  const [isDesktop, setIsDesktop] = useState<boolean>(false);
  const [host, setHost] = useState<string>("github.com");
  const [port, setPort] = useState<string>("443");
  const [servername, setServername] = useState<string>("");
  const [showSni, setShowSni] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<TlsProbeResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Context-aware starting tab based on which tool opened the modal
  const defaultTab = useMemo<"grade" | "ocsp" | "diff" | "chain" | "crl" | "ct">(() => {
    if (currentToolId === "ocsp") return "ocsp";
    if (currentToolId === "cert-diff") return "diff";
    if (currentToolId === "cert-verifier") return "chain";
    if (currentToolId === "crl") return "crl";
    return "grade";
  }, [currentToolId]);

  const [activeTab, setActiveTab] = useState<"grade" | "ocsp" | "diff" | "chain" | "crl" | "ct">(
    defaultTab
  );
  const [showRawAscii, setShowRawAscii] = useState<boolean>(false);

  // Live AIA OCSP query state
  const [liveOcspLoading, setLiveOcspLoading] = useState<boolean>(false);
  const [liveOcspResponse, setLiveOcspResponse] = useState<ParsedOcspResponse | null>(null);
  const [liveOcspRawB64, setLiveOcspRawB64] = useState<string | null>(null);
  const [liveOcspError, setLiveOcspError] = useState<string | null>(null);

  const [ctLoading, setCtLoading] = useState<boolean>(false);
  const [ctLogs, setCtLogs] = useState<CtLogEntry[] | null>(null);
  const [ctError, setCtError] = useState<string | null>(null);

  const [webPastedInput, setWebPastedInput] = useState<string>("");

  useEffect(() => {
    void platform()
      .environment()
      .then((env) => {
        setIsDesktop(env.isDesktop);
      });
  }, []);

  useEffect(() => {
    if (open) {
      setActiveTab(defaultTab);
    }
  }, [open, defaultTab]);

  const handleProbe = async () => {
    if (!host.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setLiveOcspResponse(null);
    setLiveOcspRawB64(null);
    setLiveOcspError(null);
    setCtLogs(null);
    setCtError(null);
    setActiveTab(defaultTab);

    try {
      if (!platform().probeTls) {
        throw new Error("Live TLS probing requires the Cipher Workbench Desktop App.");
      }
      const probeRes = await platform().probeTls!({
        host: host.trim(),
        port: parseInt(port.trim(), 10) || 443,
        servername: servername.trim() || undefined,
      });
      setResult(probeRes);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleFetchCtLogs = async () => {
    if (!host.trim()) return;
    setCtLoading(true);
    setCtError(null);
    setActiveTab("ct");
    try {
      if (!platform().queryCtLogs) {
        throw new Error("CT Log query requires the Desktop App.");
      }
      const logs = await platform().queryCtLogs!(host.trim());
      setCtLogs(logs);
    } catch (err) {
      setCtError(err instanceof Error ? err.message : String(err));
    } finally {
      setCtLoading(false);
    }
  };

  // Parse leaf cert
  const parsedCert = useMemo<ParsedX509Certificate | null>(() => {
    if (!result) return null;
    const targetPem = result.peerCertificatePem || result.certificateChainPems[0];
    if (!targetPem) return null;
    try {
      const bytes = new TextEncoder().encode(targetPem);
      const der = detectInputBytes(bytes).der;
      return parseX509Certificate(der);
    } catch {
      return null;
    }
  }, [result]);

  // Parse stapled OCSP response if present in TLS handshake
  const stapledOcsp = useMemo<ParsedOcspResponse | null>(() => {
    if (!result?.ocspStapled || !result.ocspResponseBase64) return null;
    try {
      return parseOcspResponse(result.ocspResponseBase64);
    } catch {
      return null;
    }
  }, [result]);

  // Live query AIA OCSP responder
  const handleQueryAiaOcsp = async () => {
    if (!result || !result.peerCertificatePem || !result.certificateChainPems[1]) return;
    const aiaUrl = parsedCert?.extensions.ocspUrls[0];
    if (!aiaUrl) return;

    setLiveOcspLoading(true);
    setLiveOcspError(null);
    try {
      if (!platform().queryOcsp) {
        throw new Error("Live AIA OCSP query requires the Desktop App.");
      }
      const req = buildOcspRequest({
        certInput: result.peerCertificatePem,
        issuerCertInput: result.certificateChainPems[1],
        hashAlgorithm: "sha256",
      });
      const queryRes = await platform().queryOcsp!({
        responderUrl: aiaUrl,
        requestBase64: req.requestB64,
      });
      const parsedResp = parseOcspResponse(queryRes.responseBase64);
      setLiveOcspResponse(parsedResp);
      setLiveOcspRawB64(queryRes.responseBase64);
    } catch (err) {
      setLiveOcspError(err instanceof Error ? err.message : String(err));
    } finally {
      setLiveOcspLoading(false);
    }
  };

  // Evaluate general TLS grade
  const gradeAssessment = useMemo<SslxGradeAssessment | null>(() => {
    if (!result) return null;
    return evaluateEndpointGrade(result, parsedCert);
  }, [result, parsedCert]);

  // Smart Context-Aware Apply handlers
  const handleApplyChain = () => {
    if (!result) return;
    const pems =
      result.certificateChainPems.length > 0
        ? result.certificateChainPems.join("\n\n")
        : result.peerCertificatePem || "";
    if (onApplyPayload) {
      onApplyPayload({ inputText: pems });
    } else {
      onApplyCertificate(pems);
    }
    onClose();
  };

  const handleApplyLeafOnly = (targetSlot: "primary" | "secondary" = "primary") => {
    if (!result?.peerCertificatePem) return;
    if (onApplyPayload) {
      onApplyPayload({ inputText: result.peerCertificatePem, targetSlot });
    } else {
      onApplyCertificate(result.peerCertificatePem);
    }
    onClose();
  };

  const handleApplyStapleResponse = (rawB64: string) => {
    if (onApplyPayload) {
      onApplyPayload({
        inputText: rawB64,
        options: { ocspOp: "inspect-response" },
      });
    } else {
      onApplyCertificate(rawB64);
    }
    onClose();
  };

  const handleApplyOcspBuilder = () => {
    if (!result) return;
    const leaf = result.peerCertificatePem || result.certificateChainPems[0] || "";
    const issuer = result.certificateChainPems[1] || "";
    if (onApplyPayload) {
      onApplyPayload({
        inputText: leaf,
        options: {
          caCert: issuer,
          ocspOp: "build-request",
        },
      });
    } else {
      onApplyCertificate(leaf);
    }
    onClose();
  };

  const cleanHost = host.trim() || "example.com";
  const cleanPort = port.trim() || "443";
  const sslxGradeCmd = `sslx grade ${cleanHost}`;
  const sslxCheckCmd = `sslx check ${cleanHost}:${cleanPort}`;
  const openSslCmd = `openssl s_client -connect ${cleanHost}:${cleanPort} -servername ${cleanHost} -showcerts </dev/null`;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      className="max-w-2xl max-h-[92vh] overflow-y-auto overflow-x-hidden p-0 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl"
    >
      {/* Sleek Modal Header */}
      <div className="p-5 border-b border-slate-100 dark:border-slate-800/80 bg-gradient-to-b from-slate-50/70 to-white dark:from-slate-900 dark:to-slate-900/60">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-blue-600/10 text-blue-600 dark:bg-blue-500/20 dark:text-blue-400 font-bold text-base">
            🌐
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
              Live TLS Endpoint Prober
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Inspect active TLS certificates, negotiated ciphers, OCSP stapling, and CA/B Forum
              compliance.
            </p>
          </div>
        </div>
      </div>

      <div className="p-5 space-y-4 text-xs overflow-x-hidden">
        {/* Omnibox Target Bar */}
        <div className="rounded-xl border border-slate-200/80 bg-slate-50/70 p-2.5 dark:border-slate-800 dark:bg-slate-950/40">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
            <div className="relative flex-1">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-xs">
                🌐
              </span>
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="Target host (e.g. github.com)"
                className="w-full rounded-lg border border-slate-200 bg-white pl-8 pr-3 py-2 text-xs font-mono text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <div className="flex items-center gap-2">
              <div className="relative w-24">
                <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 text-[11px] font-mono">
                  :
                </span>
                <input
                  type="text"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  placeholder="443"
                  className="w-full rounded-lg border border-slate-200 bg-white pl-5 pr-2 py-2 text-xs font-mono text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-center"
                />
              </div>
              <Button
                variant="primary"
                size="sm"
                onClick={handleProbe}
                disabled={loading || !host.trim() || !isDesktop}
                className="px-4 py-2 font-semibold text-xs whitespace-nowrap shadow-xs justify-center"
              >
                {loading ? "Probing..." : isDesktop ? "⚡ Probe Host" : "Desktop Only"}
              </Button>
            </div>
          </div>

          {/* Collapsible SNI Header */}
          <div className="mt-2 flex items-center justify-between text-[11px] text-slate-500 px-1">
            <button
              type="button"
              onClick={() => setShowSni(!showSni)}
              className="hover:text-slate-800 dark:hover:text-slate-200 flex items-center gap-1 font-medium cursor-pointer"
            >
              <span>{showSni ? "▼" : "▶"}</span>
              <span>Advanced SNI options</span>
            </button>
            {isDesktop && (
              <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-medium">
                ✓ Native node:tls ready
              </span>
            )}
          </div>
          {showSni && (
            <div className="mt-2 pt-2 border-t border-slate-200/60 dark:border-slate-800/80">
              <input
                type="text"
                value={servername}
                onChange={(e) => setServername(e.target.value)}
                placeholder={host ? `SNI override (defaults to ${host})` : "SNI Servername override"}
                className="w-full rounded border border-slate-200 bg-white px-2.5 py-1 text-xs font-mono text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
              />
            </div>
          )}
        </div>

        {/* WEB MODE NOTICE */}
        {!isDesktop && (
          <div className="rounded-xl border border-amber-300/60 bg-amber-50/80 p-3.5 dark:border-amber-900/50 dark:bg-amber-950/20">
            <div className="flex items-start gap-2.5">
              <span className="text-base leading-none">⚡</span>
              <div className="space-y-2">
                <div className="font-semibold text-amber-900 dark:text-amber-200">
                  Live TCP Socket Probing is Desktop-Exclusive
                </div>
                <p className="text-amber-800 dark:text-amber-300/90 leading-relaxed text-xs">
                  Web browser security sandboxes block outbound raw TCP sockets. In the{" "}
                  <strong>Cipher Workbench Desktop App</strong>, this uses native{" "}
                  <code>node:tls</code> with zero external dependencies.
                </p>
                <div className="space-y-1.5 pt-1">
                  <div className="flex items-center justify-between text-[11px] font-medium text-slate-700 dark:text-slate-300">
                    <span>Rate host with sslx CLI:</span>
                    <CopyButton value={sslxGradeCmd} label="Copy sslx grade" size="sm" />
                  </div>
                  <pre className="overflow-x-auto rounded bg-slate-900 p-2 font-mono text-[11px] text-amber-300">
                    {sslxGradeCmd}
                  </pre>
                  <div className="flex items-center justify-between text-[11px] font-medium text-slate-700 dark:text-slate-300 pt-1">
                    <span>Fetch certificate chain via CLI:</span>
                    <CopyButton value={openSslCmd} label="Copy OpenSSL" size="sm" />
                  </div>
                  <pre className="overflow-x-auto rounded bg-slate-900 p-2 font-mono text-[11px] text-emerald-400">
                    {openSslCmd}
                  </pre>
                  <div className="flex items-center justify-between text-[11px] font-medium text-slate-700 dark:text-slate-300 pt-1">
                    <span>Or with sslx check:</span>
                    <CopyButton value={sslxCheckCmd} label="Copy sslx check" size="sm" />
                  </div>
                  <pre className="overflow-x-auto rounded bg-slate-900 p-2 font-mono text-[11px] text-sky-400">
                    {sslxCheckCmd}
                  </pre>
                </div>
                <div className="pt-2">
                  <label className="mb-1 block font-medium text-slate-700 dark:text-slate-300">
                    Paste Certificate Output Here to Audit & Import:
                  </label>
                  <textarea
                    rows={3}
                    value={webPastedInput}
                    onChange={(e) => setWebPastedInput(e.target.value)}
                    placeholder="Paste -----BEGIN CERTIFICATE----- output here..."
                    className="w-full rounded border border-slate-300 bg-white p-2 font-mono text-[11px] dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                  />
                  {webPastedInput.trim() && (
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => {
                        onApplyCertificate(webPastedInput.trim());
                        onClose();
                      }}
                      className="mt-2"
                    >
                      Import Pasted Certificate
                    </Button>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ERROR STATE */}
        {error && (
          <div className="rounded-xl border border-red-300 bg-red-50 p-3 text-red-900 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200">
            <div className="font-semibold">Probe Failed:</div>
            <div className="mt-1 font-mono text-xs">{error}</div>
          </div>
        )}

        {/* DESKTOP PROBE RESULT */}
        {result && (
          <div className="space-y-3">
            {/* Connected Host Status Bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 px-3.5 py-2 rounded-xl bg-slate-900 text-slate-100 dark:bg-slate-950 border border-slate-800 shadow-xs">
              <div className="flex items-center gap-2">
                <span className="flex h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse" />
                <span className="font-mono font-bold text-xs text-white">
                  {result.host}:{result.port}
                </span>
                {result.ip && (
                  <span className="text-[11px] font-mono text-slate-400">
                    ({result.ip})
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 text-[11px] font-mono text-slate-300">
                <span className="rounded bg-slate-800 px-2 py-0.5 text-emerald-400 font-semibold">
                  ⚡ {result.timing.handshakeMs} ms handshake
                </span>
                <span className="text-slate-500">•</span>
                <span className="text-slate-400">
                  {result.timing.totalMs} ms total
                </span>
              </div>
            </div>

            {/* Segmented Pill Navigation Tabs */}
            <div className="flex p-1 rounded-xl bg-slate-100 dark:bg-slate-800/80 text-xs font-medium gap-1 overflow-x-auto">
              <button
                type="button"
                onClick={() => setActiveTab("grade")}
                className={`rounded-lg px-3 py-1.5 transition-all text-xs font-medium whitespace-nowrap cursor-pointer ${
                  activeTab === "grade"
                    ? "bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs font-semibold"
                    : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
                }`}
              >
                ⚡ sslx grade ({gradeAssessment?.grade ?? "—"})
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("ocsp")}
                className={`rounded-lg px-3 py-1.5 transition-all text-xs font-medium whitespace-nowrap cursor-pointer ${
                  activeTab === "ocsp"
                    ? "bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs font-semibold"
                    : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
                }`}
              >
                🛡️ OCSP Staple {result.ocspStapled ? "✓" : ""}
              </button>

              {currentToolId === "cert-diff" && (
                <button
                  type="button"
                  onClick={() => setActiveTab("diff")}
                  className={`rounded-lg px-3 py-1.5 transition-all text-xs font-medium whitespace-nowrap cursor-pointer ${
                    activeTab === "diff"
                      ? "bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs font-semibold"
                      : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
                  }`}
                >
                  🔄 Live Diff
                </button>
              )}

              <button
                type="button"
                onClick={() => setActiveTab("chain")}
                className={`rounded-lg px-3 py-1.5 transition-all text-xs font-medium whitespace-nowrap cursor-pointer ${
                  activeTab === "chain"
                    ? "bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs font-semibold"
                    : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
                }`}
              >
                🔗 Chain ({result.certificateChainPems.length})
              </button>

              {currentToolId === "crl" && (
                <button
                  type="button"
                  onClick={() => setActiveTab("crl")}
                  className={`rounded-lg px-3 py-1.5 transition-all text-xs font-medium whitespace-nowrap cursor-pointer ${
                    activeTab === "crl"
                      ? "bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs font-semibold"
                    : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
                  }`}
                >
                  📜 CRL Points
                </button>
              )}

              <button
                type="button"
                onClick={() => setActiveTab("ct")}
                className={`rounded-lg px-3 py-1.5 transition-all text-xs font-medium whitespace-nowrap cursor-pointer ${
                  activeTab === "ct"
                    ? "bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs font-semibold"
                    : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
                }`}
              >
                🌐 CT Logs {ctLogs ? `(${ctLogs.length})` : ""}
              </button>
            </div>

            {/* TAB: SSLX GRADE ASSESSMENT */}
            {activeTab === "grade" && gradeAssessment && (
              <div className="space-y-3">
                <div className="flex items-center justify-between px-1">
                  <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                    CA/B Forum & Modern TLS Baseline Rating
                  </span>
                  <button
                    type="button"
                    onClick={() => setShowRawAscii(!showRawAscii)}
                    className="text-[11px] text-blue-600 hover:text-blue-700 dark:text-blue-400 cursor-pointer font-medium"
                  >
                    {showRawAscii ? "View Graphical Card" : "View Terminal Box"}
                  </button>
                </div>

                {showRawAscii ? (
                  /* Authentic Terminal ASCII View */
                  <div className="relative rounded-xl bg-slate-950 p-4 font-mono text-[11px] text-slate-200 border border-slate-800 shadow-md">
                    <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80 text-[10px] text-slate-500">
                      <div className="flex items-center gap-1.5">
                        <span className="h-2 w-2 rounded-full bg-red-500/80 inline-block" />
                        <span className="h-2 w-2 rounded-full bg-amber-500/80 inline-block" />
                        <span className="h-2 w-2 rounded-full bg-emerald-500/80 inline-block" />
                        <span className="ml-1 text-slate-400 font-medium">
                          $ {gradeAssessment.sslxCommand}
                        </span>
                      </div>
                      <CopyButton value={gradeAssessment.asciiBox} label="Copy ASCII" size="sm" />
                    </div>
                    <pre className="overflow-x-auto text-emerald-400 whitespace-pre leading-relaxed select-all">
                      {gradeAssessment.asciiBox}
                    </pre>
                  </div>
                ) : (
                  /* Graphical sslx grade Card */
                  <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-slate-200 shadow-md">
                    <div className="rounded-lg border border-slate-700 bg-slate-900/80 p-3 mb-3 flex items-center justify-between">
                      <div className="font-semibold text-slate-100 text-sm">
                        {gradeAssessment.hostPort}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-400">Grade:</span>
                        <span
                          className={`rounded px-2.5 py-0.5 text-xs font-bold tracking-wide ${
                            gradeAssessment.grade === "A+" || gradeAssessment.grade === "A"
                              ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                              : gradeAssessment.grade === "B"
                              ? "bg-blue-500/20 text-blue-300 border border-blue-500/40"
                              : gradeAssessment.grade === "C"
                              ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                              : "bg-red-500/20 text-red-300 border border-red-500/40"
                          }`}
                        >
                          {gradeAssessment.grade}
                        </span>
                      </div>
                    </div>

                    <div className="space-y-1.5 divide-y divide-slate-800/60 text-xs">
                      {gradeAssessment.checks.map((check) => (
                        <div
                          key={check.id}
                          className="flex items-center justify-between pt-1.5 first:pt-0"
                        >
                          <div className="flex items-center gap-2">
                            <span
                              className={`w-4 font-bold text-center ${
                                check.status === "pass"
                                  ? "text-emerald-400"
                                  : check.status === "warn"
                                  ? "text-amber-400"
                                  : check.status === "fail"
                                  ? "text-red-400"
                                  : "text-slate-500"
                              }`}
                            >
                              {check.status === "pass"
                                ? "✓"
                                : check.status === "warn"
                                ? "!"
                                : check.status === "fail"
                                ? "✗"
                                : "•"}
                            </span>
                            <span className="font-medium text-slate-400 w-24">
                              {check.label}
                            </span>
                          </div>
                          <span
                            className={`text-right font-medium truncate max-w-[280px] sm:max-w-md ${
                              check.status === "pass"
                                ? "text-slate-100"
                                : check.status === "warn"
                                ? "text-amber-300"
                                : check.status === "fail"
                                ? "text-red-300"
                                : "text-slate-400"
                            }`}
                            title={check.detail || check.value}
                          >
                            {check.value}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 px-1">
                  <span>
                    Security Score: <strong>{gradeAssessment.score}/100</strong> (
                    {gradeAssessment.checks.filter((c) => c.status === "pass").length} of{" "}
                    {gradeAssessment.checks.length} checks satisfied)
                  </span>
                  <div className="flex items-center gap-2">
                    <CopyButton
                      value={gradeAssessment.sslxCommand}
                      label="Copy CLI command"
                      size="sm"
                    />
                    <CopyButton
                      value={gradeAssessment.asciiBox}
                      label="Copy sslx grade"
                      size="sm"
                    />
                  </div>
                </div>
              </div>
            )}

            {/* TAB: OCSP STAPLE & REVOCATION AUDIT */}
            {activeTab === "ocsp" && (
              <div className="space-y-3">
                {result.ocspStapled && stapledOcsp ? (
                  <div className="rounded-xl border border-emerald-300 bg-emerald-50/60 p-4 dark:border-emerald-900/60 dark:bg-emerald-950/20 space-y-3 shadow-xs">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="flex h-3 w-3 rounded-full bg-emerald-500" />
                        <span className="font-semibold text-emerald-900 dark:text-emerald-200 text-sm">
                          OCSP Staple Received in TLS Handshake
                        </span>
                      </div>
                      <span className="rounded bg-emerald-200/80 px-2 py-0.5 font-mono text-[11px] font-bold text-emerald-900 dark:bg-emerald-900 dark:text-emerald-200">
                        {stapledOcsp.responses[0]?.certStatus === "good"
                          ? "✓ STATUS: GOOD"
                          : `⚠ STATUS: ${stapledOcsp.responses[0]?.certStatus?.toUpperCase()}`}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 rounded-lg border border-emerald-200 bg-white p-2.5 font-mono text-xs dark:border-slate-800 dark:bg-slate-900">
                      <div>
                        <div className="text-[10px] text-slate-500 uppercase">Revocation Status</div>
                        <div className="font-semibold text-emerald-600 dark:text-emerald-400">
                          {stapledOcsp.responses[0]?.certStatus === "good"
                            ? "✓ GOOD (Not Revoked)"
                            : stapledOcsp.responses[0]?.certStatus?.toUpperCase()}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-slate-500 uppercase">Produced At</div>
                        <div className="text-slate-800 dark:text-slate-200">
                          {stapledOcsp.producedAt
                            ? stapledOcsp.producedAt
                                .toISOString()
                                .replace("T", " ")
                                .replace(/\..+/, "Z")
                            : "—"}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-slate-500 uppercase">This Update</div>
                        <div className="text-slate-800 dark:text-slate-200">
                          {stapledOcsp.responses[0]?.thisUpdate
                            ? stapledOcsp.responses[0].thisUpdate.toISOString().split("T")[0]
                            : "—"}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-slate-500 uppercase">Next Update</div>
                        <div className="text-slate-800 dark:text-slate-200">
                          {stapledOcsp.responses[0]?.nextUpdate
                            ? stapledOcsp.responses[0].nextUpdate.toISOString().split("T")[0]
                            : "No expiry specified"}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 pt-1">
                      <Button
                        variant="primary"
                        size="sm"
                        onClick={() => handleApplyStapleResponse(result.ocspResponseBase64!)}
                      >
                        📥 Import Staple Response into Inspector
                      </Button>
                      <CopyButton
                        value={result.ocspResponseBase64!}
                        label="Copy Base64 Response"
                        size="sm"
                      />
                    </div>
                  </div>
                ) : (
                  <div className="rounded-xl border border-amber-300 bg-amber-50/70 p-4 dark:border-amber-900/60 dark:bg-amber-950/20 space-y-3 shadow-xs">
                    <div className="flex items-center gap-2">
                      <span className="text-amber-600 dark:text-amber-400 font-bold text-sm">⚠</span>
                      <span className="font-semibold text-amber-900 dark:text-amber-200 text-sm">
                        No OCSP Staple in TLS Handshake
                      </span>
                    </div>
                    <p className="text-amber-800 dark:text-amber-300/90 leading-relaxed text-xs">
                      The server did not send an RFC 6066 <code>status_request</code> staple during
                      negotiation. You can query the CA&apos;s out-of-band AIA OCSP responder URL
                      directly over HTTP:
                    </p>

                    {parsedCert?.extensions.ocspUrls[0] ? (
                      <div className="space-y-2 rounded-lg border border-amber-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-medium text-slate-600 dark:text-slate-400">
                            AIA Responder:
                          </span>
                          <span className="font-mono text-blue-600 dark:text-blue-400 break-all">
                            {parsedCert.extensions.ocspUrls[0]}
                          </span>
                        </div>
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={handleQueryAiaOcsp}
                          disabled={liveOcspLoading}
                        >
                          {liveOcspLoading
                            ? "Querying AIA Responder..."
                            : `⚡ Live Query AIA Responder`}
                        </Button>
                      </div>
                    ) : (
                      <div className="text-xs text-slate-500">
                        Leaf certificate does not contain an Authority Information Access (AIA) OCSP URL.
                      </div>
                    )}

                    {liveOcspError && (
                      <div className="rounded border border-red-300 bg-red-50 p-2 text-red-900 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200 text-xs">
                        AIA Query Failed: {liveOcspError}
                      </div>
                    )}

                    {liveOcspResponse && (
                      <div className="rounded-lg border border-emerald-300 bg-emerald-50 p-3 font-mono text-xs dark:border-emerald-900 dark:bg-emerald-950/30 space-y-2">
                        <div className="font-semibold text-emerald-900 dark:text-emerald-200">
                          Live AIA Query Result:{" "}
                          <span className="uppercase font-bold">
                            {liveOcspResponse.responses[0]?.certStatus || "Received"}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-700 dark:text-slate-300">
                          Produced At: {liveOcspResponse.producedAt?.toISOString() || "—"} • Next
                          Update: {liveOcspResponse.responses[0]?.nextUpdate?.toISOString() || "—"}
                        </div>
                        {liveOcspRawB64 && (
                          <Button
                            variant="primary"
                            size="sm"
                            onClick={() => handleApplyStapleResponse(liveOcspRawB64)}
                          >
                            📥 Import Queried Response into Inspector
                          </Button>
                        )}
                      </div>
                    )}
                  </div>
                )}

                <div className="rounded-xl border border-slate-200 bg-slate-50 p-3.5 dark:border-slate-800 dark:bg-slate-950 flex flex-col sm:flex-row sm:items-center justify-between gap-2 shadow-xs">
                  <div>
                    <div className="font-semibold text-slate-800 dark:text-slate-200">
                      Build OCSP Request for this Target
                    </div>
                    <div className="text-[11px] text-slate-500">
                      Loads leaf certificate and issuer intermediate CA into OCSP Request Builder.
                    </div>
                  </div>
                  <Button variant="secondary" size="sm" onClick={handleApplyOcspBuilder}>
                    📥 Setup Request Builder
                  </Button>
                </div>
              </div>
            )}

            {/* TAB: LIVE DIFF (Polished & Non-Overflowing for cert-diff) */}
            {activeTab === "diff" && parsedCert && (
              <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-950 shadow-xs space-y-4">
                <div className="flex items-start justify-between border-b border-slate-100 dark:border-slate-800/80 pb-3">
                  <div className="min-w-0 pr-2">
                    <div className="text-[11px] uppercase tracking-wider font-semibold text-slate-400">
                      Target Server Certificate
                    </div>
                    <div className="text-base font-bold text-slate-900 dark:text-white font-mono mt-0.5 truncate">
                      {parsedCert.subject.commonName || parsedCert.subject.dn}
                    </div>
                  </div>
                  <span className="shrink-0 rounded-full bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/50 px-2.5 py-1 text-[11px] font-semibold">
                    ✓ {parsedCert.validity.daysRemaining} days left
                  </span>
                </div>

                {/* Structured Metadata Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
                  <div className="rounded-lg bg-slate-50 dark:bg-slate-900/60 p-2.5 border border-slate-200/60 dark:border-slate-800">
                    <div className="text-[10px] uppercase font-semibold text-slate-400">
                      Issuer CA
                    </div>
                    <div
                      className="font-medium text-slate-800 dark:text-slate-200 truncate mt-0.5"
                      title={parsedCert.issuer.commonName || parsedCert.issuer.dn}
                    >
                      {parsedCert.issuer.commonName || parsedCert.issuer.dn}
                    </div>
                  </div>

                  <div className="rounded-lg bg-slate-50 dark:bg-slate-900/60 p-2.5 border border-slate-200/60 dark:border-slate-800">
                    <div className="text-[10px] uppercase font-semibold text-slate-400">
                      Public Key
                    </div>
                    <div className="font-mono text-slate-800 dark:text-slate-200 mt-0.5 truncate">
                      {parsedCert.publicKey.algorithmName} ({parsedCert.publicKey.details})
                    </div>
                  </div>

                  <div className="rounded-lg bg-slate-50 dark:bg-slate-900/60 p-2.5 border border-slate-200/60 dark:border-slate-800 sm:col-span-2">
                    <div className="flex items-center justify-between text-[10px] uppercase font-semibold text-slate-400 mb-0.5">
                      <span>Serial Number</span>
                      <CopyButton value={parsedCert.serialNumber} label="Copy Serial" size="sm" />
                    </div>
                    <div className="font-mono text-[11px] text-slate-700 dark:text-slate-300 break-all select-all">
                      0x{parsedCert.serialNumber}
                    </div>
                  </div>

                  <div className="rounded-lg bg-slate-50 dark:bg-slate-900/60 p-2.5 border border-slate-200/60 dark:border-slate-800 sm:col-span-2">
                    <div className="text-[10px] uppercase font-semibold text-slate-400">
                      Subject Alternative Names ({parsedCert.extensions.sans.length})
                    </div>
                    <div className="font-mono text-[11px] text-blue-600 dark:text-blue-400 mt-0.5 break-all">
                      {parsedCert.extensions.sans.join(", ")}
                    </div>
                  </div>
                </div>

                {/* Clear & Distinct Dual Action Cards */}
                <div className="pt-2 border-t border-slate-100 dark:border-slate-800 grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  <button
                    type="button"
                    onClick={() => handleApplyLeafOnly("secondary")}
                    className="flex flex-col text-left p-3 rounded-xl border border-blue-500/40 bg-blue-50/60 dark:bg-blue-950/30 dark:border-blue-700/50 hover:border-blue-500 transition-all cursor-pointer group shadow-xs"
                  >
                    <span className="flex items-center gap-1.5 font-semibold text-xs text-blue-700 dark:text-blue-300">
                      <span>🎯</span> Set as Second Cert (Diff Live)
                    </span>
                    <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 leading-snug">
                      Compare your local certificate against what is currently live on {result.host}.
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleApplyLeafOnly("primary")}
                    className="flex flex-col text-left p-3 rounded-xl border border-slate-200 bg-slate-50 hover:bg-white dark:border-slate-800 dark:bg-slate-900/50 dark:hover:bg-slate-900 transition-all cursor-pointer group shadow-xs"
                  >
                    <span className="flex items-center gap-1.5 font-semibold text-xs text-slate-800 dark:text-slate-200">
                      <span>📄</span> Set as First Cert (Local)
                    </span>
                    <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 leading-snug">
                      Use this live certificate as the primary baseline to inspect and compare.
                    </span>
                  </button>
                </div>
              </div>
            )}

            {/* TAB: CERTIFICATE CHAIN DETAILS */}
            {activeTab === "chain" && (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 rounded-xl border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-950 shadow-xs">
                  <div>
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">Protocol</div>
                    <div className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                      {result.protocol || "Unknown"}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">Cipher Suite</div>
                    <div
                      className="font-mono font-semibold text-[11px] leading-tight text-slate-800 dark:text-slate-200 break-all"
                      title={result.cipher?.name}
                    >
                      {result.cipher?.name || "Unknown"}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">
                      ALPN (App Protocol)
                    </div>
                    <div className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                      {result.alpnProtocol === "h2"
                        ? "HTTP/2 (h2)"
                        : result.alpnProtocol === "h3"
                        ? "HTTP/3 (h3)"
                        : result.alpnProtocol === "http/1.1"
                        ? "HTTP/1.1"
                        : result.alpnProtocol || "None"}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">OCSP Staple</div>
                    <div
                      className={`font-semibold ${
                        result.ocspStapled ? "text-emerald-600 dark:text-emerald-400" : "text-slate-500"
                      }`}
                    >
                      {result.ocspStapled ? "✓ Stapled" : "Not Stapled"}
                    </div>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between font-medium text-slate-700 dark:text-slate-300">
                    <span>
                      Certificate Chain ({result.certificateChainPems.length}{" "}
                      {result.certificateChainPems.length === 1 ? "cert" : "certs"} received)
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono">
                      {result.authorized
                        ? "✓ Trusted Root"
                        : `⚠ ${result.authorizationError || "Untrusted CA"}`}
                    </span>
                  </div>
                  <textarea
                    readOnly
                    rows={6}
                    value={result.certificateChainPems.join("\n\n")}
                    className="w-full rounded-xl border border-slate-300 bg-slate-900 p-2.5 font-mono text-[10px] text-emerald-300 dark:border-slate-700 shadow-inner"
                  />
                </div>
              </div>
            )}

            {/* TAB: CRL DISTRIBUTION POINTS */}
            {activeTab === "crl" && (
              <div className="space-y-3">
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950 space-y-3 shadow-xs">
                  <div className="font-semibold text-slate-800 dark:text-slate-200 text-sm">
                    CRL Distribution Points for {result.host}
                  </div>
                  {parsedCert?.extensions.crlUrls && parsedCert.extensions.crlUrls.length > 0 ? (
                    <div className="space-y-2">
                      {parsedCert.extensions.crlUrls.map((url, idx) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between p-2.5 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 font-mono text-xs gap-2"
                        >
                          <span className="truncate text-blue-600 dark:text-blue-400 break-all">
                            {url}
                          </span>
                          <CopyButton value={url} label="Copy URL" size="sm" />
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-500 text-xs">
                      This certificate does not declare a CRL Distribution Point (CDP) extension. It
                      relies on OCSP revocation checking.
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* TAB: CERTIFICATE TRANSPARENCY RESULTS */}
            {activeTab === "ct" && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-800 dark:text-slate-200">
                    Certificate Transparency Records for {host}{" "}
                    {ctLogs ? `(${ctLogs.length} found)` : ""}
                  </span>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={handleFetchCtLogs}
                    disabled={ctLoading}
                  >
                    {ctLoading ? "Querying..." : "🔄 Refresh CT Logs"}
                  </Button>
                </div>

                {ctError && (
                  <div className="rounded-lg border border-red-300 bg-red-50 p-2.5 text-red-900 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200 text-xs">
                    CT Log Query: {ctError}
                  </div>
                )}

                {ctLogs && (
                  <div className="max-h-56 overflow-y-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-950 shadow-xs">
                    <table className="w-full text-left font-mono text-[10px]">
                      <thead className="bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 sticky top-0">
                        <tr>
                          <th className="p-2">Logged Date</th>
                          <th className="p-2">Issuer</th>
                          <th className="p-2">Common Name</th>
                          <th className="p-2">Expires</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                        {ctLogs.map((entry, idx) => (
                          <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                            <td className="p-2 text-slate-500 whitespace-nowrap">
                              {entry.entryTimestamp ? entry.entryTimestamp.split("T")[0] : "—"}
                            </td>
                            <td
                              className="p-2 font-sans truncate max-w-[150px]"
                              title={entry.issuerName}
                            >
                              {entry.issuerName || "Unknown"}
                            </td>
                            <td className="p-2 text-blue-600 dark:text-blue-400 truncate max-w-[150px]">
                              {entry.commonName}
                            </td>
                            <td className="p-2 text-slate-500 whitespace-nowrap">
                              {entry.notAfter ? entry.notAfter.split("T")[0] : "—"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {!ctLogs && !ctLoading && !ctError && (
                  <div className="rounded-xl border border-dashed border-slate-200 p-6 text-center text-slate-500 dark:border-slate-800">
                    Click &quot;Refresh CT Logs&quot; to fetch public append-only transparency log
                    records for {host}.
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Clean Modal Footer (No Redundant Duplicate Buttons!) */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-slate-100 dark:border-slate-800">
          <div className="flex items-center gap-2">
            {result && currentToolId !== "cert-diff" && (
              <Button variant="primary" size="sm" onClick={handleApplyChain}>
                📥 Import Chain into Workbench
              </Button>
            )}

            {result && (
              <CopyButton
                value={result.certificateChainPems.join("\n\n")}
                label="Copy PEM Chain"
                size="sm"
              />
            )}
          </div>

          <Button variant="secondary" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
