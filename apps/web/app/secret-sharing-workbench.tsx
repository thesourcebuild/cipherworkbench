"use client";

import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { OptionValue } from "@ocs/contracts";
import type { ToolDefinition, ToolResult, ToolSpecBase } from "@ocs/engine";
import { Button, CopyButton, CopyIconButton, Panel, cn } from "@ocs/ui";
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
  onResultChange: (result: ToolResult) => void;
}

type TabMode = "split" | "combine" | "explorer";

const PRESETS = [
  { label: "Bank Vault Master Key", text: "VAULT-ALPHA-9821-SECURE-MASTER-KEY" },
  { label: "BIP-39 Recovery Mnemonic", text: "abandon ability able about above absent absorb abstract absurd abuse access accident" },
  { label: "Cloud API Root Secret", text: "api_root_sec_94f8a02b1c4e7d56e890123456789abc" },
  { label: "Disk Encryption Passphrase", text: "Correct-Horse-Battery-Staple-2026!#" },
];

const cryptoRng = (len: number): Uint8Array => {
  const buf = new Uint8Array(len);
  globalThis.crypto.getRandomValues(buf);
  return buf;
};

function SplitIcon({ className }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className={className} aria-hidden="true">
      <path d="M12.232 4.232a2.5 2.5 0 0 1 3.536 3.536l-1.225 1.224a.75.75 0 0 0 1.061 1.06l1.224-1.224a4 4 0 0 0-5.656-5.656l-3 3a4 4 0 0 0 .225 5.865.75.75 0 0 0 .977-1.138 2.5 2.5 0 0 1-.142-3.667l3-3Z" />
      <path d="M11.603 7.963a.75.75 0 0 0-.977 1.138 2.5 2.5 0 0 1 .142 3.667l-3 3a2.5 2.5 0 0 1-3.536-3.536l1.225-1.224a.75.75 0 0 0-1.061-1.06l-1.224 1.224a4 4 0 1 0 5.656 5.656l3-3a4 4 0 0 0-.225-5.865Z" />
    </svg>
  );
}

function MergeIcon({ className }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className={className} aria-hidden="true">
      <path d="M14.75 4a.75.75 0 0 0-.75.75v5.5a.75.75 0 0 1-.75.75H6.56l1.72-1.72a.75.75 0 0 0-1.06-1.06l-3 3a.75.75 0 0 0 0 1.06l3 3a.75.75 0 1 0 1.06-1.06L6.56 12.5h6.69a2.25 2.25 0 0 0 2.25-2.25v-5.5a.75.75 0 0 0-.75-.75Z" />
    </svg>
  );
}

function MathIcon({ className }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className={className} aria-hidden="true">
      <path d="M4.75 3a.75.75 0 0 0 0 1.5h1.272l1.986 7.447a1.75 1.75 0 0 0 1.487 1.3l.235.006c.64 0 1.218-.344 1.534-.897l2.842-4.974h2.144a.75.75 0 0 0 0-1.5h-2.735a.75.75 0 0 0-.651.378L10.36 10.51 8.784 4.6A1.75 1.75 0 0 0 7.094 3.25H4.75Z" />
    </svg>
  );
}

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className={className} aria-hidden="true">
      <path fillRule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm3.857-9.809a.75.75 0 0 0-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 1 0-1.06 1.061l2.5 2.5a.75.75 0 0 0 1.137-.089l4-5.5Z" clipRule="evenodd" />
    </svg>
  );
}

function AlertIcon({ className }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className={className} aria-hidden="true">
      <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495ZM10 5a.75.75 0 0 1 .75.75v3.5a.75.75 0 0 1-1.5 0v-3.5A.75.75 0 0 1 10 5Zm0 9a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z" clipRule="evenodd" />
    </svg>
  );
}

function InfoIcon({ className }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className={className} aria-hidden="true">
      <path fillRule="evenodd" d="M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0Zm-7-4a1 1 0 1 1-2 0 1 1 0 0 1 2 0ZM9 9a.75.75 0 0 0 0 1.5h.253a.25.25 0 0 1 .247.25v3.5a.25.25 0 0 1-.247.25H9a.75.75 0 0 0 0 1.5h2a.75.75 0 0 0 0-1.5h-.253a.25.25 0 0 1-.247-.25v-4.5A.75.75 0 0 0 9.75 9H9Z" clipRule="evenodd" />
    </svg>
  );
}

export function SecretSharingWorkbench({
  tool: _tool,
  onResultChange,
}: CustomWorkbenchProps) {
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

  // Generate cryptographically secure random bytes as hex
  const handleGenerateRandom = (bytes: number) => {
    const randomBuf = cryptoRng(bytes);
    let hex = "";
    for (let i = 0; i < randomBuf.length; i++) {
      hex += randomBuf[i]!.toString(16).padStart(2, "0");
    }
    setSecretText(hex);
    setIsHexSecret(true);
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
    if (parsedShares.length === 0) {
      return {
        status: "empty",
        message: `Paste at least ${combineThreshold} share tokens below to reconstruct the secret.`,
      };
    }

    if (parsedShares.length < combineThreshold) {
      return {
        status: "insufficient",
        message: `Parsed ${parsedShares.length} of ${combineThreshold} required shares. You need ${combineThreshold - parsedShares.length} more valid share(s).`,
      };
    }

    try {
      const tamperCheck = detectTamperedShares(parsedShares, combineThreshold);
      if (tamperCheck.tampered) {
        return {
          status: "tampered",
          message: `Inconsistent polynomial evaluations detected. Corrupted coordinate(s): ${
            tamperCheck.tamperedShareIndices?.map((i) => `Share #${i}`).join(", ") || "Unknown"
          }.`,
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
        bytes: secretBytes,
        sharesUsed: parsedShares.length,
      };
    } catch (err) {
      return {
        status: "error",
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }, [parsedShares, combineThreshold]);

  const publishedResult = useMemo<ToolResult>(() => {
    if (activeTab === "combine" && combineResult.status === "success") {
      const reconstructed = combineResult.utf8 ?? "";
      return {
        text: reconstructed,
        bytes: combineResult.bytes,
        fields: [
          { label: "Shares supplied", value: String(combineResult.sharesUsed) },
          { label: "Reconstructed secret", value: reconstructed, secret: true },
        ],
      };
    }

    const formatted = generatedShares.map((share) => formatShamirShare(share));
    return {
      text: formatted.join("\n"),
      bytes: generatedShares[0]?.y,
      fields: [
        { label: "Threshold (k)", value: `${thresholdK} shares needed to reconstruct` },
        { label: "Total shares (n)", value: `${totalSharesN} shares generated` },
        ...formatted.map((share, index) => ({
          label: `Share #${index + 1}`,
          value: share,
          secret: true,
        })),
      ],
    };
  }, [activeTab, combineResult, generatedShares, thresholdK, totalSharesN]);

  useEffect(() => {
    onResultChange(publishedResult);
  }, [onResultChange, publishedResult]);

  return (
    <div className="space-y-6">
      {/* Studio Header Navigation Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-3 dark:border-slate-800">
        <nav
          className="inline-flex max-w-full flex-wrap rounded-lg border border-slate-200 bg-slate-100 p-1 dark:border-slate-800 dark:bg-slate-950"
          aria-label="Tabs"
        >
          <button
            type="button"
            onClick={() => setActiveTab("split")}
            className={cn(
              "relative flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors cursor-pointer",
              activeTab === "split"
                ? "bg-white text-slate-900 shadow-xs after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-indigo-600 dark:bg-slate-800 dark:text-slate-100 dark:after:bg-indigo-400"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            <SplitIcon className="h-4 w-4" />
            <span>Split Secret</span>
            <span className="rounded-full bg-indigo-100 px-2 py-0.5 text-[10px] font-semibold text-indigo-800 dark:bg-indigo-950 dark:text-indigo-300">
              {totalSharesN} Shares
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("combine")}
            className={cn(
              "relative flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors cursor-pointer",
              activeTab === "combine"
                ? "bg-white text-slate-900 shadow-xs after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-indigo-600 dark:bg-slate-800 dark:text-slate-100 dark:after:bg-indigo-400"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            <MergeIcon className="h-4 w-4" />
            <span>Reconstruct & Verify</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("explorer")}
            className={cn(
              "relative flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors cursor-pointer",
              activeTab === "explorer"
                ? "bg-white text-slate-900 shadow-xs after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-indigo-600 dark:bg-slate-800 dark:text-slate-100 dark:after:bg-indigo-400"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            <MathIcon className="h-4 w-4" />
            <span>Lagrange Math & GF(256)</span>
          </button>
        </nav>

        <div className="hidden items-center gap-2 text-xs text-slate-500 dark:text-slate-400 sm:flex">
          <span className="inline-flex items-center gap-1 rounded-md bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/50">
            Information-Theoretic Security
          </span>
          <span>•</span>
          <span className="font-mono text-[11px]">k-of-n Threshold</span>
        </div>
      </div>

      {/* TAB 1: SPLIT SECRET */}
      {activeTab === "split" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Controls Column */}
          <div className="lg:col-span-5 space-y-4">
            <Panel
              title="1. Secret Payload"
              description="Provide the sensitive master key, passphrase, or binary token to partition."
              actions={
                <div className="inline-flex rounded-md border border-slate-200 bg-slate-50 p-0.5 dark:border-slate-800 dark:bg-slate-950">
                  <button
                    type="button"
                    onClick={() => setIsHexSecret(false)}
                    className={cn(
                      "px-2 py-0.5 text-[11px] font-medium rounded transition-colors cursor-pointer",
                      !isHexSecret
                        ? "bg-white text-slate-900 shadow-2xs dark:bg-slate-800 dark:text-slate-100"
                        : "text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200"
                    )}
                  >
                    UTF-8
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsHexSecret(true)}
                    className={cn(
                      "px-2 py-0.5 text-[11px] font-medium rounded transition-colors cursor-pointer",
                      isHexSecret
                        ? "bg-white text-slate-900 shadow-2xs dark:bg-slate-800 dark:text-slate-100"
                        : "text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200"
                    )}
                  >
                    Hex
                  </button>
                </div>
              }
            >
              <div className="space-y-3">
                <textarea
                  value={secretText}
                  onChange={(e) => setSecretText(e.target.value)}
                  placeholder={
                    isHexSecret
                      ? "Enter hexadecimal byte string (e.g. 48656c6c6f20576f726c64)..."
                      : "Enter secret string to share among custodians..."
                  }
                  rows={4}
                  className="w-full resize-y rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus-visible:outline-2 focus-visible:outline-blue-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-600"
                />

                <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
                  <span>
                    Payload: <strong className="text-slate-700 dark:text-slate-300">{getSecretBytes().length} bytes</strong> ({secretText.length} characters)
                  </span>
                  <span>Evaluated in GF(256)</span>
                </div>

                {/* Presets and Random Entropy */}
                <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-slate-800">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-[11px] font-medium text-slate-600 dark:text-slate-400">
                      Sample Presets:
                    </span>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => handleGenerateRandom(16)}
                        title="Generate 128-bit (16 bytes) random entropy"
                      >
                        128-bit Random Seed
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => handleGenerateRandom(32)}
                        title="Generate 256-bit (32 bytes) random entropy"
                      >
                        256-bit Random Seed
                      </Button>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {PRESETS.map((p) => (
                      <button
                        key={p.label}
                        type="button"
                        onClick={() => {
                          setSecretText(p.text);
                          setIsHexSecret(false);
                        }}
                        className="rounded border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:border-slate-800 dark:bg-slate-800/60 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-slate-100 transition-colors cursor-pointer"
                      >
                        {p.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </Panel>

            <Panel
              title="2. Threshold Configuration"
              description="Configure minimum threshold k required to reconstruct out of total n shares."
            >
              <div className="space-y-4">
                {/* Visual Representation Bar */}
                <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 dark:border-slate-800 dark:bg-slate-950/60">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                      Distribution Scheme: {thresholdK}-of-{totalSharesN}
                    </span>
                    <span className="text-[11px] text-slate-500 dark:text-slate-400">
                      {thresholdK} required • {totalSharesN - thresholdK} redundant
                    </span>
                  </div>

                  {/* Visual dots */}
                  <div className="flex items-center gap-1.5">
                    {Array.from({ length: totalSharesN }).map((_, i) => {
                      const isRequired = i < thresholdK;
                      return (
                        <div
                          key={i}
                          className={cn(
                            "flex-1 h-3 rounded transition-all",
                            isRequired
                              ? "bg-emerald-500 dark:bg-emerald-400 shadow-2xs"
                              : "bg-slate-300 dark:bg-slate-700"
                          )}
                          title={`Share #${i + 1}: ${isRequired ? "Required for threshold" : "Redundant backup"}`}
                        />
                      );
                    })}
                  </div>

                  <p className="mt-2 text-[11px] text-slate-500 dark:text-slate-400 leading-tight">
                    Any subset of <strong className="text-slate-700 dark:text-slate-300">{thresholdK} shares</strong> will reconstruct the secret. Possessing {thresholdK - 1} or fewer shares yields <strong className="text-slate-700 dark:text-slate-300">zero information</strong>.
                  </p>
                </div>

                {/* Slider: Threshold k */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <label htmlFor="range-k" className="font-medium text-slate-700 dark:text-slate-300">
                      Threshold (<span className="font-mono font-bold text-emerald-600 dark:text-emerald-400">k</span>)
                    </label>
                    <span className="font-mono text-xs font-semibold text-emerald-600 dark:text-emerald-400">
                      {thresholdK} shares
                    </span>
                  </div>
                  <input
                    id="range-k"
                    type="range"
                    min={2}
                    max={totalSharesN}
                    value={thresholdK}
                    onChange={(e) => setThresholdK(parseInt(e.target.value, 10))}
                    className="w-full h-1.5 bg-slate-200 dark:bg-slate-700 rounded-lg appearance-none cursor-pointer accent-emerald-600 dark:accent-emerald-400"
                  />
                  <div className="flex justify-between text-[10px] text-slate-400">
                    <span>Min: 2</span>
                    <span>Max: {totalSharesN} (n)</span>
                  </div>
                </div>

                {/* Slider: Total Shares n */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <label htmlFor="range-n" className="font-medium text-slate-700 dark:text-slate-300">
                      Total Shares (<span className="font-mono font-bold text-indigo-600 dark:text-indigo-400">n</span>)
                    </label>
                    <span className="font-mono text-xs font-semibold text-indigo-600 dark:text-indigo-400">
                      {totalSharesN} custodians
                    </span>
                  </div>
                  <input
                    id="range-n"
                    type="range"
                    min={thresholdK}
                    max={12}
                    value={totalSharesN}
                    onChange={(e) => setTotalSharesN(parseInt(e.target.value, 10))}
                    className="w-full h-1.5 bg-slate-200 dark:bg-slate-700 rounded-lg appearance-none cursor-pointer accent-indigo-600 dark:accent-indigo-400"
                  />
                  <div className="flex justify-between text-[10px] text-slate-400">
                    <span>Min: {thresholdK} (k)</span>
                    <span>Max: 12</span>
                  </div>
                </div>

                {/* Generate / Split Button */}
                <Button
                  variant="primary"
                  onClick={handleSplit}
                  className="w-full mt-1 flex items-center justify-center gap-2 py-2.5"
                >
                  <SplitIcon className="h-4 w-4" />
                  <span>Split Secret into {totalSharesN} Shares</span>
                </Button>
              </div>
            </Panel>
          </div>

          {/* Generated Shares Output Column */}
          <div className="lg:col-span-7 space-y-4">
            <Panel
              title={`Generated Shares (${thresholdK}-of-${totalSharesN} Scheme)`}
              description="Each token represents an evaluated coordinate (x, P(x)) on a random Galois polynomial."
              actions={
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
                    Copy All Shares
                  </Button>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => handleSendToReconstructor(thresholdK)}
                    className="text-xs font-semibold text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/80 hover:bg-emerald-50 dark:hover:bg-emerald-950/30"
                  >
                    Send {thresholdK} to Reconstructor
                  </Button>
                </div>
              }
            >
              <div className="space-y-3">
                {generatedShares.map((share) => {
                  const token = formatShamirShare(share);
                  return (
                    <div
                      key={share.x}
                      className="rounded-lg border border-slate-200 bg-white p-3 shadow-2xs dark:border-slate-800 dark:bg-slate-900 transition-all hover:border-slate-300 dark:hover:border-slate-700"
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <div className="flex items-center gap-2">
                          <span className="flex h-5 w-5 items-center justify-center rounded bg-slate-100 font-mono text-[11px] font-bold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                            #{share.x}
                          </span>
                          <span className="text-xs font-medium text-slate-700 dark:text-slate-300">
                            Share Coordinate: <span className="font-mono text-slate-500 dark:text-slate-400">x = {share.x}</span>
                          </span>
                        </div>
                        <CopyIconButton value={token} aria-label={`Copy Share #${share.x}`} />
                      </div>

                      <div className="rounded border border-slate-200 bg-slate-50 px-2.5 py-1.5 font-mono text-xs text-slate-900 break-all select-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100">
                        {token}
                      </div>

                      <div className="mt-1.5 flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
                        <span>Payload: {share.y.length} bytes</span>
                        <span>Evaluation: P({share.x}) in GF(256)</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </Panel>
          </div>
        </div>
      )}

      {/* TAB 2: COMBINE & VERIFY */}
      {activeTab === "combine" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Input Shares Column */}
          <div className="lg:col-span-6 space-y-4">
            <Panel
              title="Input Shares"
              description={`Paste at least ${combineThreshold} share tokens (one per line, format: SSSS-x-hex).`}
              actions={
                <div className="flex items-center gap-2">
                  <label htmlFor="combine-k-select" className="text-xs text-slate-500 dark:text-slate-400">
                    Threshold:
                  </label>
                  <select
                    id="combine-k-select"
                    value={combineThreshold}
                    onChange={(e) => setCombineThreshold(parseInt(e.target.value, 10))}
                    className="rounded-md border border-slate-300 bg-white px-2 py-1 text-xs font-mono text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                  >
                    {[2, 3, 4, 5, 6, 7, 8].map((k) => (
                      <option key={k} value={k}>
                        k = {k}
                      </option>
                    ))}
                  </select>
                </div>
              }
            >
              <div className="space-y-3">
                <textarea
                  value={combineInput}
                  onChange={(e) => setCombineInput(e.target.value)}
                  placeholder={"Paste SSSS tokens here, for example:\nSSSS-1-808641434b47...\nSSSS-2-5a9f8e7cf791...\nSSSS-3-8e76bf6cd9b5..."}
                  rows={8}
                  className="w-full resize-y rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus-visible:outline-2 focus-visible:outline-blue-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-600"
                />

                {/* Parsed Shares Status Badge */}
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs dark:border-slate-800 dark:bg-slate-950">
                  <div className="flex items-center gap-2 text-slate-600 dark:text-slate-300">
                    <span>Parsed shares:</span>
                    <strong className="font-mono text-slate-900 dark:text-slate-100">{parsedShares.length}</strong>
                    {parsedShares.length > 0 && (
                      <span className="text-[11px] text-slate-500 dark:text-slate-400">
                        ({parsedShares.map((s) => `#${s.x}`).join(", ")})
                      </span>
                    )}
                  </div>

                  <span
                    className={cn(
                      "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold border",
                      parsedShares.length >= combineThreshold
                        ? "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/60"
                        : "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800/60"
                    )}
                  >
                    {parsedShares.length >= combineThreshold ? (
                      <>
                        <CheckIcon className="h-3.5 w-3.5" />
                        <span>Threshold Reached ({parsedShares.length}/{combineThreshold})</span>
                      </>
                    ) : (
                      <>
                        <AlertIcon className="h-3.5 w-3.5" />
                        <span>Need {combineThreshold - parsedShares.length} More Share(s)</span>
                      </>
                    )}
                  </span>
                </div>

                {/* Action Buttons */}
                <div className="flex items-center gap-2 pt-1">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => setCombineInput("")}
                    className="flex-1 text-xs"
                  >
                    Clear Input
                  </Button>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => handleSendToReconstructor(combineThreshold)}
                    className="flex-1 text-xs"
                  >
                    Load From Split Tab
                  </Button>
                </div>
              </div>
            </Panel>
          </div>

          {/* Reconstruction & Tamper Status Column */}
          <div className="lg:col-span-6 space-y-4">
            <Panel
              title="Reconstruction & Tamper Analysis"
              description="Lagrange basis interpolation at x = 0 with cross-subset tamper detection."
            >
              <div className="space-y-4">
                {/* Result Status Cards */}
                {combineResult.status === "tampered" && (
                  <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-xs dark:border-red-900/60 dark:bg-red-950/40">
                    <div className="flex items-center gap-2 font-bold text-red-700 dark:text-red-300">
                      <AlertIcon className="h-4 w-4 shrink-0 text-red-600 dark:text-red-400" />
                      <span>Tamper Detected in Key Shares</span>
                    </div>
                    <p className="mt-1 text-red-600 dark:text-red-300/90 leading-relaxed">
                      {combineResult.message}
                    </p>
                    <p className="mt-2 text-[11px] text-red-500 dark:text-red-400">
                      Subsets of {combineThreshold} shares yielded mathematically conflicting polynomials in GF(256).
                    </p>
                  </div>
                )}

                {combineResult.status === "success" && (
                  <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-xs dark:border-emerald-900/60 dark:bg-emerald-950/40">
                    <div className="flex items-center gap-2 font-bold text-emerald-700 dark:text-emerald-300">
                      <CheckIcon className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                      <span>Secret Reconstructed Successfully</span>
                    </div>
                    <p className="mt-1 text-emerald-600 dark:text-emerald-300/90 leading-relaxed">
                      Recovered original secret from {combineResult.sharesUsed} shares using Lagrange interpolation at P(0).
                    </p>
                    {parsedShares.length > combineThreshold && (
                      <p className="mt-1.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-400">
                        Cross-subset integrity check passed: 0 tampered shares detected across all combinations.
                      </p>
                    )}
                  </div>
                )}

                {combineResult.status === "insufficient" && (
                  <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-xs dark:border-amber-900/60 dark:bg-amber-950/40">
                    <div className="flex items-center gap-2 font-bold text-amber-700 dark:text-amber-300">
                      <InfoIcon className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
                      <span>Awaiting Sufficient Shares</span>
                    </div>
                    <p className="mt-1 text-amber-600 dark:text-amber-300/90">
                      {combineResult.message}
                    </p>
                  </div>
                )}

                {combineResult.status === "empty" && (
                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 text-xs text-slate-500 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400">
                    {combineResult.message}
                  </div>
                )}

                {/* Reconstructed Secret Result */}
                {combineResult.status === "success" && (
                  <div className="space-y-3 pt-2 border-t border-slate-100 dark:border-slate-800">
                    <div>
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                          Reconstructed Secret (UTF-8)
                        </span>
                        <CopyButton value={combineResult.utf8 || ""} label="Copy Secret" />
                      </div>
                      <div className="rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-xs text-slate-900 break-all select-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100">
                        {combineResult.utf8}
                      </div>
                    </div>

                    <div>
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">
                          Hexadecimal Representation
                        </span>
                        <CopyIconButton value={combineResult.hex || ""} aria-label="Copy Hex Secret" />
                      </div>
                      <div className="rounded-md border border-slate-200 bg-slate-50 p-2.5 font-mono text-[11px] text-slate-600 break-all select-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400">
                        {combineResult.hex}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </Panel>
          </div>
        </div>
      )}

      {/* TAB 3: MATHEMATICAL EXPLORER */}
      {activeTab === "explorer" && (
        <div className="space-y-4">
          <Panel
            title="The Mathematics of Shamir's Secret Sharing (SSSS)"
            description="Published by Adi Shamir in 1979 ('How to Share a Secret', Communications of the ACM 22 (11): 612–613)."
          >
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950 space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
                    1. Polynomial Construction
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    For a threshold <span className="font-mono font-bold text-emerald-600 dark:text-emerald-400">k</span>, a random polynomial of degree <span className="font-mono">k - 1</span> is sampled for each byte:
                  </p>
                  <div className="rounded bg-white p-2.5 font-mono text-xs text-slate-900 text-center border border-slate-200 dark:bg-slate-900 dark:text-slate-100 dark:border-slate-800">
                    P(x) = S + a₁x + a₂x² + ... + aₖ₋₁xᵏ⁻¹
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    The secret byte <span className="font-mono font-semibold">S</span> is embedded as constant term <span className="font-mono">P(0) = S</span>.
                  </p>
                </div>

                <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950 space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400">
                    2. Lagrange Interpolation
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Any <span className="font-mono font-bold text-indigo-600 dark:text-indigo-400">k</span> distinct points <span className="font-mono">(xᵢ, yᵢ)</span> uniquely reconstruct the degree <span className="font-mono">k - 1</span> polynomial:
                  </p>
                  <div className="rounded bg-white p-2.5 font-mono text-xs text-slate-900 text-center border border-slate-200 dark:bg-slate-900 dark:text-slate-100 dark:border-slate-800">
                    P(0) = Σ yᵢ · ∏ (-xⱼ / (xᵢ - xⱼ))
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    In Galois field GF(256), addition is XOR (<span className="font-mono">^</span>), eliminating precision loss or carry spill.
                  </p>
                </div>

                <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950 space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-amber-600 dark:text-amber-400">
                    3. Information-Theoretic Secrecy
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    With only <span className="font-mono font-bold text-amber-600 dark:text-amber-400">k - 1</span> shares, for every candidate secret <span className="font-mono">S' ∈ GF(256)</span>, there exists an identical number of polynomials passing through all <span className="font-mono">k - 1</span> points.
                  </p>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Every possible secret is equally probable. Unbreakable even by an adversary with infinite compute power.
                  </p>
                </div>
              </div>

              {/* Interactive Tamper Simulation Box */}
              <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                  <div>
                    <h4 className="text-xs font-bold text-slate-900 dark:text-slate-100">
                      Interactive Tamper Detection Demonstration
                    </h4>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      Corrupting even a single bit in one custodian share causes mathematical inconsistency across polynomial subsets.
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
                    className="text-xs font-semibold text-rose-600 border-rose-200 hover:bg-rose-50 dark:text-rose-400 dark:border-rose-900/60 dark:hover:bg-rose-950/40"
                  >
                    Simulate Corrupting Share #2
                  </Button>
                </div>
              </div>
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}
