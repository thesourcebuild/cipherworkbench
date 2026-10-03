"use client";

import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { OptionValue } from "@ocs/contracts";
import type { ToolDefinition, ToolSpecBase } from "@ocs/engine";
import { Button, CopyButton, CopyIconButton, cn } from "@ocs/ui";
import {
  shamirSplit,
  shamirCombine,
  formatShamirShare,
  parseShamirShare,
  detectTamperedShares,
  type ShamirShare,
} from "@ocs/algos";
import type { ComputeState } from "./use-compute";

export interface CustomWorkbenchProps {
  tool: ToolDefinition<ToolSpecBase>;
  spec: ToolSpecBase;
  setOptionValue: (id: string, value: OptionValue | undefined) => void;
  recompute: () => void;
  canRecompute: boolean;
  state: ComputeState;
  tag?: string | readonly string[];
  inputStep?: ReactNode;
  generateLength?: (optionId: string) => number | undefined;
  acceptedByteLengths?: (optionId: string) => readonly number[] | undefined;
}

type TabMode = "split" | "combine" | "explorer";

const PRESETS = [
  { label: "Bank Vault Key", text: "VAULT-ALPHA-9821-SECURE-MASTER-KEY" },
  { label: "Crypto Seed Phrase", text: "abandon ability able about above absent absorb abstract absurd abuse access accident" },
  { label: "API Root Secret", text: "api_root_sec_94f8a02b1c4e7d56e890123456789abc" },
  { label: "Disk Encryption Passphrase", text: "Correct-Horse-Battery-Staple-2026!#" },
];

const cryptoRng = (len: number): Uint8Array => {
  const buf = new Uint8Array(len);
  globalThis.crypto.getRandomValues(buf);
  return buf;
};

export function SecretSharingWorkbench({ tool: _tool }: CustomWorkbenchProps) {
  const [activeTab, setActiveTab] = useState<TabMode>("split");

  // --- Split State ---
  const [secretText, setSecretText] = useState("TopSecret-Vault-Master-Key-2026");
  const [isHexSecret, setIsHexSecret] = useState(false);
  const [thresholdK, setThresholdK] = useState(3);
  const [totalSharesN, setTotalSharesN] = useState(5);
  const [generatedShares, setGeneratedShares] = useState<ShamirShare[]>(() => {
    try {
      const bytes = new TextEncoder().encode("TopSecret-Vault-Master-Key-2026");
      return shamirSplit(bytes, 5, 3, cryptoRng);
    } catch {
      return [];
    }
  });

  // --- Combine State ---
  const [combineInput, setCombineInput] = useState("");
  const [combineThreshold, setCombineThreshold] = useState(3);

  // Convert secret input to bytes
  const getSecretBytes = (): Uint8Array => {
    if (isHexSecret) {
      const clean = secretText.replace(/[^0-9a-fA-F]/g, "");
      if (clean.length % 2 !== 0) return new TextEncoder().encode(secretText);
      const bytes = new Uint8Array(clean.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
      }
      return bytes;
    }
    return new TextEncoder().encode(secretText);
  };

  // Handle Split
  const handleSplit = () => {
    try {
      const bytes = getSecretBytes();
      if (bytes.length === 0) return;
      const shares = shamirSplit(bytes, totalSharesN, thresholdK, cryptoRng);
      setGeneratedShares(shares);
    } catch (e) {
      console.error("Shamir split failed:", e);
    }
  };

  // Quick Send to Reconstructor
  const handleSendToReconstructor = (subsetCount?: number) => {
    const count = subsetCount ?? thresholdK;
    const subset = generatedShares.slice(0, count);
    const text = subset.map((s) => formatShamirShare(s)).join("\n");
    setCombineInput(text);
    setCombineThreshold(thresholdK);
    setActiveTab("combine");
  };

  // Parse combine input shares
  const parsedShares = useMemo(() => {
    const lines = combineInput.split(/[\r\n,;]+/).map((l) => l.trim()).filter(Boolean);
    const shares: ShamirShare[] = [];
    const seen = new Set<number>();
    for (const line of lines) {
      const parsed = parseShamirShare(line);
      if (parsed && !seen.has(parsed.x)) {
        seen.add(parsed.x);
        shares.push(parsed);
      }
    }
    return shares;
  }, [combineInput]);

  // Combine computation and tamper detection
  const combineResult = useMemo(() => {
    if (parsedShares.length < 2) {
      return {
        status: "waiting",
        message: `Paste at least ${combineThreshold} shares to reconstruct the secret.`,
      };
    }

    if (parsedShares.length < combineThreshold) {
      return {
        status: "insufficient",
        message: `Have ${parsedShares.length} of ${combineThreshold} required shares. Need ${combineThreshold - parsedShares.length} more.`,
      };
    }

    try {
      // Check for tamper if we have >= threshold
      const tamperCheck = detectTamperedShares(parsedShares, combineThreshold);
      if (tamperCheck.tampered) {
        return {
          status: "tampered",
          message: `Tamper Detected! Corrupted share indices: ${tamperCheck.tamperedShareIndices?.join(", ") || "Unknown"}. Mathematical inconsistency in polynomial interpolation.`,
          recoveredSecret: tamperCheck.recoveredSecret,
        };
      }

      const secretBytes = tamperCheck.recoveredSecret ?? shamirCombine(parsedShares.slice(0, combineThreshold));
      const utf8 = new TextDecoder("utf-8", { fatal: false }).decode(secretBytes);
      let hex = "";
      for (let i = 0; i < secretBytes.length; i++) {
        hex += secretBytes[i]!.toString(16).padStart(2, "0");
      }

      return {
        status: "success",
        utf8,
        hex,
        sharesUsed: parsedShares.length,
      };
    } catch (err) {
      return {
        status: "error",
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }, [parsedShares, combineThreshold]);

  return (
    <div className="flex flex-col gap-6 w-full max-w-6xl mx-auto py-2">
      {/* Workbench Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-2xl bg-gradient-to-r from-emerald-500/10 via-cyan-500/10 to-blue-500/10 border border-emerald-500/20 backdrop-blur-md">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-2xl">🗝️</span>
            <h1 className="text-xl font-bold tracking-tight text-neutral-100">
              Shamir's Secret Sharing (SSSS)
            </h1>
            <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              GF(256) Threshold Cryptosystem
            </span>
          </div>
          <p className="text-sm text-neutral-400 mt-1 max-w-2xl">
            Split sensitive secrets into $N$ mathematically distributed shares. Any threshold of $K$ shares recovers the original secret perfectly via Lagrange interpolation, while $K-1$ shares reveal zero information.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-neutral-900/80 border border-neutral-800">
          <button
            type="button"
            onClick={() => setActiveTab("split")}
            className={cn(
              "px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all duration-200",
              activeTab === "split"
                ? "bg-emerald-500 text-neutral-950 font-semibold shadow-md"
                : "text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/50"
            )}
          >
            ✂️ Split Secret
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("combine")}
            className={cn(
              "px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all duration-200",
              activeTab === "combine"
                ? "bg-emerald-500 text-neutral-950 font-semibold shadow-md"
                : "text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/50"
            )}
          >
            🧩 Reconstruct & Verify
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("explorer")}
            className={cn(
              "px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all duration-200",
              activeTab === "explorer"
                ? "bg-emerald-500 text-neutral-950 font-semibold shadow-md"
                : "text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/50"
            )}
          >
            📐 Math & Polynomials
          </button>
        </div>
      </div>

      {/* TAB 1: SPLIT SECRET */}
      {activeTab === "split" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Controls Column */}
          <div className="lg:col-span-5 flex flex-col gap-5 p-5 rounded-2xl bg-neutral-900/60 border border-neutral-800 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-neutral-300">
                1. Secret Input
              </h2>
              <button
                type="button"
                onClick={() => setIsHexSecret(!isHexSecret)}
                className="text-xs text-neutral-400 hover:text-emerald-400 transition-colors"
              >
                Format: <span className="font-mono text-neutral-200">{isHexSecret ? "HEX" : "UTF-8 TEXT"}</span>
              </button>
            </div>

            {/* Secret Textarea */}
            <div className="flex flex-col gap-1.5">
              <textarea
                value={secretText}
                onChange={(e) => setSecretText(e.target.value)}
                placeholder={isHexSecret ? "Enter hex bytes e.g. 48656c6c6f..." : "Enter secret password, recovery phrase, or token..."}
                rows={4}
                className="w-full px-3.5 py-2.5 rounded-xl bg-neutral-950 border border-neutral-800 focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 font-mono text-xs text-neutral-200 resize-none transition-all placeholder:text-neutral-600"
              />
              <div className="flex items-center justify-between text-[11px] text-neutral-500 px-1">
                <span>{secretText.length} characters ({getSecretBytes().length} bytes)</span>
                <span className="text-emerald-400/80">Information-theoretic security</span>
              </div>
            </div>

            {/* Presets */}
            <div className="flex flex-col gap-2">
              <span className="text-xs text-neutral-400 font-medium">Quick Presets:</span>
              <div className="flex flex-wrap gap-1.5">
                {PRESETS.map((p) => (
                  <button
                    key={p.label}
                    type="button"
                    onClick={() => {
                      setSecretText(p.text);
                      setIsHexSecret(false);
                    }}
                    className="px-2.5 py-1 text-[11px] rounded-lg bg-neutral-800/80 hover:bg-neutral-800 text-neutral-300 hover:text-white border border-neutral-700/60 transition-colors"
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Threshold & Shares Sliders */}
            <div className="flex flex-col gap-4 pt-2 border-t border-neutral-800/80">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-neutral-300">
                2. Threshold Parameters
              </h2>

              {/* Threshold (k) */}
              <div className="flex flex-col gap-1.5">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-neutral-300 font-medium">
                    Threshold (<span className="text-emerald-400 font-mono">k</span>)
                  </span>
                  <span className="font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    {thresholdK} shares required
                  </span>
                </div>
                <input
                  type="range"
                  min={2}
                  max={totalSharesN}
                  value={thresholdK}
                  onChange={(e) => setThresholdK(parseInt(e.target.value, 10))}
                  className="w-full accent-emerald-500 cursor-pointer h-1.5 bg-neutral-800 rounded-lg appearance-none"
                />
                <span className="text-[11px] text-neutral-500">
                  Any {thresholdK} shares can reconstruct. {thresholdK - 1} or fewer reveal nothing.
                </span>
              </div>

              {/* Total Shares (n) */}
              <div className="flex flex-col gap-1.5">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-neutral-300 font-medium">
                    Total Shares (<span className="text-cyan-400 font-mono">n</span>)
                  </span>
                  <span className="font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                    {totalSharesN} shares total
                  </span>
                </div>
                <input
                  type="range"
                  min={thresholdK}
                  max={12}
                  value={totalSharesN}
                  onChange={(e) => setTotalSharesN(parseInt(e.target.value, 10))}
                  className="w-full accent-cyan-500 cursor-pointer h-1.5 bg-neutral-800 rounded-lg appearance-none"
                />
                <span className="text-[11px] text-neutral-500">
                  Total participants receiving shares (coordinates x = 1 .. {totalSharesN}).
                </span>
              </div>
            </div>

            {/* Split Action Button */}
            <Button
              variant="primary"
              onClick={handleSplit}
              className="mt-2 w-full py-2.5 bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-neutral-950 font-bold shadow-lg shadow-emerald-500/10"
            >
              🎲 Split Secret into {totalSharesN} Shares
            </Button>
          </div>

          {/* Generated Shares Output Column */}
          <div className="lg:col-span-7 flex flex-col gap-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 rounded-2xl bg-neutral-900/60 border border-neutral-800">
              <div>
                <h3 className="text-sm font-semibold text-neutral-200">
                  Generated Shares ({thresholdK}-of-{totalSharesN} Threshold)
                </h3>
                <p className="text-xs text-neutral-400">
                  Distribute these tokens to key custodians. Any {thresholdK} can combine to recover the secret.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    const allText = generatedShares.map((s) => formatShamirShare(s)).join("\n");
                    navigator.clipboard.writeText(allText);
                  }}
                  className="text-xs"
                >
                  📋 Copy All
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => handleSendToReconstructor(thresholdK)}
                  className="text-xs bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30"
                >
                  🚀 Test Reconstruct
                </Button>
              </div>
            </div>

            {/* Shares Grid */}
            <div className="grid grid-cols-1 gap-3 overflow-y-auto max-h-[560px] pr-1">
              {generatedShares.map((share) => {
                const token = formatShamirShare(share);
                return (
                  <div
                    key={share.x}
                    className="flex flex-col gap-2 p-3.5 rounded-xl bg-neutral-900/80 border border-neutral-800/80 hover:border-emerald-500/30 transition-all group"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="flex items-center justify-center w-6 h-6 rounded-md bg-emerald-500/10 text-emerald-400 font-mono text-xs font-bold border border-emerald-500/20">
                          #{share.x}
                        </span>
                        <span className="text-xs font-medium text-neutral-300">
                          Share Coordinate <span className="font-mono text-neutral-400">(x = {share.x})</span>
                        </span>
                      </div>
                      <CopyIconButton value={token} aria-label={`Copy Share #${share.x}`} />
                    </div>

                    <div className="p-2.5 rounded-lg bg-neutral-950 border border-neutral-800/80 font-mono text-xs text-emerald-300/90 break-all select-all">
                      {token}
                    </div>

                    <div className="flex justify-between items-center text-[11px] text-neutral-500 px-1">
                      <span>Evaluated bytes: {share.y.length} B</span>
                      <span className="text-neutral-400">P({share.x}) in GF(256)</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: COMBINE & VERIFY */}
      {activeTab === "combine" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Input Shares Column */}
          <div className="lg:col-span-6 flex flex-col gap-5 p-5 rounded-2xl bg-neutral-900/60 border border-neutral-800 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold uppercase tracking-wider text-neutral-300">
                  Input Shares
                </h2>
                <p className="text-xs text-neutral-400 mt-0.5">
                  Paste any {combineThreshold} or more shares (one per line, format: SSSS-x-hex).
                </p>
              </div>

              {/* Threshold control */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-neutral-400">Threshold:</span>
                <select
                  value={combineThreshold}
                  onChange={(e) => setCombineThreshold(parseInt(e.target.value, 10))}
                  className="px-2 py-1 rounded bg-neutral-950 border border-neutral-800 text-xs font-mono text-neutral-200"
                >
                  {[2, 3, 4, 5, 6, 7, 8].map((k) => (
                    <option key={k} value={k}>
                      k = {k}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Combine Input Area */}
            <textarea
              value={combineInput}
              onChange={(e) => setCombineInput(e.target.value)}
              placeholder="Paste shares here, for example:&#10;SSSS-1-a1b2c3d4...&#10;SSSS-3-e5f60718...&#10;SSSS-5-9a8b7c6d..."
              rows={9}
              className="w-full px-3.5 py-3 rounded-xl bg-neutral-950 border border-neutral-800 focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 font-mono text-xs text-neutral-200 resize-none transition-all placeholder:text-neutral-600"
            />

            {/* Live Share Counter Badge */}
            <div className="flex items-center justify-between p-3 rounded-xl bg-neutral-950 border border-neutral-800/80 text-xs">
              <span className="text-neutral-400">
                Shares parsed:{" "}
                <span className="font-mono font-bold text-neutral-200">
                  {parsedShares.length}
                </span>{" "}
                ({parsedShares.map((s) => `#${s.x}`).join(", ") || "None"})
              </span>

              <span
                className={cn(
                  "px-2.5 py-0.5 rounded-full text-xs font-medium border",
                  parsedShares.length >= combineThreshold
                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                    : "bg-amber-500/10 text-amber-400 border-amber-500/30"
                )}
              >
                {parsedShares.length >= combineThreshold
                  ? `Threshold Reached (${parsedShares.length}/${combineThreshold})`
                  : `Need ${combineThreshold - parsedShares.length} more shares`}
              </span>
            </div>

            {/* Quick Actions */}
            <div className="flex items-center gap-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setCombineInput("")}
                className="w-1/2 text-xs"
              >
                Clear Input
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => handleSendToReconstructor(combineThreshold)}
                className="w-1/2 text-xs"
              >
                Load From Split Tab
              </Button>
            </div>
          </div>

          {/* Reconstruction & Tamper Status Column */}
          <div className="lg:col-span-6 flex flex-col gap-5 p-5 rounded-2xl bg-neutral-900/60 border border-neutral-800 backdrop-blur-sm">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-neutral-300">
              Reconstruction & Tamper Analysis
            </h2>

            {/* Status Card */}
            {combineResult.status === "tampered" && (
              <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex flex-col gap-2">
                <div className="flex items-center gap-2 text-red-400 font-semibold text-sm">
                  <span>⚠️</span>
                  <span>Tamper Detected in Shares!</span>
                </div>
                <p className="text-xs text-red-300/90 leading-relaxed">
                  {combineResult.message}
                </p>
                <p className="text-[11px] text-red-400/80">
                  Subsets of {combineThreshold} shares yielded conflicting polynomials. The corrupt share has been mathematically isolated.
                </p>
              </div>
            )}

            {combineResult.status === "success" && (
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex flex-col gap-2">
                <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
                  <span>✅</span>
                  <span>Lagrange Interpolation Successful</span>
                </div>
                <p className="text-xs text-emerald-300/90">
                  Reconstructed perfectly from {combineResult.sharesUsed} shares using polynomial evaluation at x = 0 (P(0) = Secret).
                </p>
                {parsedShares.length > combineThreshold && (
                  <div className="flex items-center gap-1.5 text-[11px] text-emerald-400/80 mt-1">
                    <span>🛡️</span>
                    <span>Cross-subset redundancy verified: 0 tampered shares detected.</span>
                  </div>
                )}
              </div>
            )}

            {combineResult.status === "insufficient" && (
              <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 flex flex-col gap-2">
                <div className="flex items-center gap-2 text-amber-400 font-semibold text-sm">
                  <span>⏳</span>
                  <span>Awaiting Sufficient Shares</span>
                </div>
                <p className="text-xs text-amber-300/90">
                  {combineResult.message}
                </p>
              </div>
            )}

            {combineResult.status === "waiting" && (
              <div className="p-4 rounded-xl bg-neutral-800/40 border border-neutral-700/60 text-xs text-neutral-400">
                {combineResult.message}
              </div>
            )}

            {/* Reconstructed Secret Result */}
            {combineResult.status === "success" && (
              <div className="flex flex-col gap-3 mt-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">
                    Reconstructed Secret (UTF-8)
                  </span>
                  <CopyButton value={combineResult.utf8 || ""} label="Copy Secret" />
                </div>
                <div className="p-4 rounded-xl bg-neutral-950 border border-neutral-800 font-mono text-sm text-neutral-100 break-all select-all">
                  {combineResult.utf8}
                </div>

                <div className="flex items-center justify-between mt-2">
                  <span className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">
                    Hex Bytes
                  </span>
                  <CopyIconButton value={combineResult.hex || ""} aria-label="Copy Hex" />
                </div>
                <div className="p-3 rounded-xl bg-neutral-950 border border-neutral-800/80 font-mono text-xs text-neutral-400 break-all select-all">
                  {combineResult.hex}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: MATHEMATICAL EXPLORER */}
      {activeTab === "explorer" && (
        <div className="flex flex-col gap-6 p-6 rounded-2xl bg-neutral-900/60 border border-neutral-800 backdrop-blur-sm">
          <div>
            <h2 className="text-base font-bold text-neutral-100">
              The Mathematics of Shamir's Secret Sharing over GF(256)
            </h2>
            <p className="text-xs text-neutral-400 mt-1">
              Adi Shamir published this scheme in 1979 ("How to Share a Secret", Communications of the ACM).
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-neutral-950 border border-neutral-800/80 flex flex-col gap-2">
              <span className="text-xs font-bold text-emerald-400 uppercase">1. Polynomial Construction</span>
              <p className="text-xs text-neutral-300 leading-relaxed">
                For a threshold <span className="font-mono text-emerald-400">k</span>, a random polynomial of degree <span className="font-mono">k - 1</span> is generated for each secret byte:
              </p>
              <div className="p-2.5 rounded bg-neutral-900 font-mono text-xs text-neutral-200 text-center">
                P(x) = S + a₁x + a₂x² + ... + aₖ₋₁xᵏ⁻¹
              </div>
              <p className="text-[11px] text-neutral-500">
                The secret byte <span className="font-mono">S</span> is embedded at <span className="font-mono">x = 0</span>, so <span className="font-mono">P(0) = S</span>.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-neutral-950 border border-neutral-800/80 flex flex-col gap-2">
              <span className="text-xs font-bold text-cyan-400 uppercase">2. Lagrange Basis Interpolation</span>
              <p className="text-xs text-neutral-300 leading-relaxed">
                Any <span className="font-mono text-cyan-400">k</span> points <span className="font-mono">(xᵢ, yᵢ)</span> uniquely determine the degree <span className="font-mono">k - 1</span> polynomial:
              </p>
              <div className="p-2.5 rounded bg-neutral-900 font-mono text-xs text-neutral-200 text-center">
                P(0) = Σ yᵢ · ∏ (-xⱼ / (xᵢ - xⱼ))
              </div>
              <p className="text-[11px] text-neutral-500">
                In Galois Field GF(256), addition/subtraction is XOR (<span className="font-mono">^</span>), eliminating carry propagation.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-neutral-950 border border-neutral-800/80 flex flex-col gap-2">
              <span className="text-xs font-bold text-amber-400 uppercase">3. Perfect Secrecy (k - 1)</span>
              <p className="text-xs text-neutral-300 leading-relaxed">
                With only <span className="font-mono text-amber-400">k - 1</span> shares, for every candidate secret <span className="font-mono">S' ∈ GF(256)</span>, there exists a unique polynomial passing through all <span className="font-mono">k - 1</span> points and <span className="font-mono">(0, S')</span>.
              </p>
              <p className="text-[11px] text-neutral-400">
                Every candidate is equally likely—providing information-theoretic security that quantum computers cannot crack.
              </p>
            </div>
          </div>

          {/* Interactive Visual Tamper Demo */}
          <div className="p-5 rounded-xl bg-neutral-950 border border-neutral-800 flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-neutral-200">
                  Interactive Tamper Simulation
                </h3>
                <p className="text-xs text-neutral-400">
                  See how corrupting even a single bit in one share prevents secret recovery.
                </p>
              </div>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  if (generatedShares.length >= 3) {
                    const sharesCopy = generatedShares.slice(0, 3).map((s) => ({
                      x: s.x,
                      y: new Uint8Array(s.y),
                    }));
                    // Corrupt share 2
                    sharesCopy[1]!.y[0]! ^= 0x55;
                    const text = sharesCopy.map((s) => formatShamirShare(s)).join("\n");
                    setCombineInput(text);
                    setCombineThreshold(3);
                    setActiveTab("combine");
                  }
                }}
                className="text-xs text-red-400 border-red-500/30 hover:bg-red-500/10"
              >
                🧪 Simulate Corrupted Share #2
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
