"use client";

import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { OptionValue } from "@ocs/contracts";
import type { ToolDefinition, ToolResult, ToolSpecBase } from "@ocs/engine";
import { Button, CopyButton, Panel, cn, useToast } from "@ocs/ui";
import {
  slip39Generate,
  slip39ParsePhrase,
  slip39Combine,
  type Slip39Share,
} from "@ocs/algos";
import { downloadTextFile } from "./export-json";
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

type TabMode = "split" | "combine" | "spec";

const PRESETS = [
  { label: "Trezor Cold Vault (128-bit)", text: "vault-master-sec-alpha-9821-cold" },
  { label: "Hardware Wallet Root (256-bit)", text: "trezor-recovery-seed-master-vault-2026-secure-key" },
  { label: "Corporate Multisig Secret", text: "CORP-TREASURY-MULTI-SIGNATURE-ROOT-SECRET-KEY" },
  { label: "Air-Gapped Signer Passphrase", text: "Correct-Horse-Battery-Staple-SLIP39!#" },
];

const cryptoRng = (len: number): Uint8Array => {
  const buf = new Uint8Array(len);
  globalThis.crypto.getRandomValues(buf);
  return buf;
};

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/i, "").replace(/[\s\r\n:]+/g, "");
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    return new Uint8Array(0);
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// Clean SVG Icons
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

function BookIcon({ className }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className={className} aria-hidden="true">
      <path d="M10.75 16.82A7.462 7.462 0 0 1 15 15.5c.71 0 1.396.098 2.046.282A.75.75 0 0 0 18 15.06v-11a.75.75 0 0 0-.546-.721A9.006 9.006 0 0 0 15 3a8.963 8.963 0 0 0-4.25 1.065V16.82ZM9.25 4.065A8.963 8.963 0 0 0 5 3c-.85 0-1.673.118-2.454.339A.75.75 0 0 0 2 4.06v11a.75.75 0 0 0 .954.721A7.506 7.506 0 0 1 5 15.5c1.579 0 3.042.487 4.25 1.32V4.065Z" />
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

export function Slip39Workbench({
  state: _state,
  onResultChange,
}: CustomWorkbenchProps) {
  const { showToast } = useToast();
  const [tab, setTab] = useState<TabMode>("split");

  // Generator State
  const [secretText, setSecretText] = useState("vault-master-sec-alpha-9821-cold");
  const [secretFormat, setSecretFormat] = useState<"utf8" | "hex">("utf8");
  const [k, setK] = useState(3);
  const [n, setN] = useState(5);
  const [identifier, setIdentifier] = useState(0x1337);

  // Recovery State
  const [combineInput, setCombineInput] = useState("");

  // Convert input text to bytes
  const secretBytes = useMemo(() => {
    if (secretFormat === "hex") {
      const b = hexToBytes(secretText);
      return b.length > 0 ? b : new TextEncoder().encode(secretText);
    }
    return new TextEncoder().encode(secretText);
  }, [secretText, secretFormat]);

  // Generate SLIP-0039 shares
  const shares: Slip39Share[] = useMemo(() => {
    if (secretBytes.length === 0) return [];
    try {
      return slip39Generate(secretBytes, n, k, cryptoRng, identifier);
    } catch {
      return [];
    }
  }, [secretBytes, n, k, identifier]);

  // Handle total shares change (ensure n >= k)
  const handleNChange = (newN: number) => {
    setN(newN);
    if (k > newN) setK(newN);
  };

  // Handle threshold change (ensure k <= n)
  const handleKChange = (newK: number) => {
    setK(newK);
    if (n < newK) setN(newK);
  };

  // Generate fresh random 128-bit / 256-bit secret
  const handleGenerateRandom = (bytesCount: number) => {
    const randomBuf = cryptoRng(bytesCount);
    if (secretFormat === "hex") {
      setSecretText(bytesToHex(randomBuf));
    } else {
      setSecretText(bytesToHex(randomBuf).slice(0, bytesCount));
    }
    setIdentifier(Math.floor(Math.random() * 0xffff));
    showToast({
      title: `${n} SLIP-39 shares generated`,
      description: `${k} shares are required to recover the ${bytesCount}-byte secret`,
      tone: "success",
    });
  };

  // Export all shares to text file
  const handleExportAllPhrases = () => {
    if (shares.length === 0) return;
    const lines = [
      `# SLIP-0039 Shamir Mnemonic Backup`,
      `# Identifier: 0x${identifier.toString(16).toUpperCase()}`,
      `# Threshold: ${k} of ${n} shares required`,
      `# Generated: ${new Date().toISOString()}`,
      "",
      ...shares.map((s, idx) => `Share #${idx + 1} (${s.words.length} words):\n${s.phrase}\n`),
    ];
    downloadTextFile(`slip39-backup-0x${identifier.toString(16)}.txt`, lines.join("\n"));
  };

  // Parse lines in combine input
  const parsedShares = useMemo(() => {
    const rawLines = combineInput
      .split(/[\r\n]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && !s.startsWith("#"));

    return rawLines.map((line, idx) => {
      const res = slip39ParsePhrase(line, secretBytes.length || 32);
      return {
        lineIndex: idx + 1,
        raw: line,
        ok: res.ok,
        error: res.error,
        share: res.share,
      };
    });
  }, [combineInput, secretBytes.length]);

  // Combine result
  const combineResult = useMemo(() => {
    const validShares = parsedShares
      .filter((p) => p.ok && p.share)
      .map((p) => p.share!);

    if (validShares.length === 0) return null;
    return slip39Combine(validShares, secretBytes.length || undefined);
  }, [parsedShares, secretBytes.length]);

  const publishedResult = useMemo<ToolResult>(() => {
    if (tab === "combine" && combineResult?.ok && combineResult.secret) {
      const reconstructed = new TextDecoder().decode(combineResult.secret);
      return {
        text: reconstructed,
        bytes: combineResult.secret,
        fields: [
          {
            label: "Shares supplied",
            value: `${parsedShares.filter((entry) => entry.ok).length} valid share phrases`,
          },
          { label: "Recovered secret", value: reconstructed, secret: true },
        ],
      };
    }

    const phrases = shares.map((share) => share.phrase);
    return {
      text: phrases.join("\n\n"),
      bytes: secretBytes,
      fields: [
        { label: "Standard", value: "SLIP-0039 Shamir Mnemonic (SatoshiLabs)" },
        { label: "Backup set ID", value: `0x${identifier.toString(16).toUpperCase()}` },
        { label: "Threshold (k)", value: `${k} shares needed to recover secret` },
        { label: "Total shares (n)", value: `${n} shares generated` },
        ...phrases.map((phrase, index) => ({
          label: `Share #${index + 1}`,
          value: phrase,
          secret: true,
        })),
      ],
    };
  }, [combineResult, identifier, k, n, parsedShares, secretBytes, shares, tab]);

  useEffect(() => {
    onResultChange(publishedResult);
  }, [onResultChange, publishedResult]);

  return (
    <div className="space-y-6">
      {/* Studio Header Navigation Tabs */}
      <div className="border-b border-slate-200 pb-3 dark:border-slate-800">
        <nav
          className="inline-flex max-w-full flex-wrap rounded-lg border border-slate-200 bg-slate-100 p-1 dark:border-slate-800 dark:bg-slate-950"
          aria-label="Tabs"
        >
          <button
            type="button"
            onClick={() => setTab("split")}
            className={cn(
              "relative flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors cursor-pointer",
              tab === "split"
                ? "bg-white text-slate-900 shadow-xs after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-indigo-600 dark:bg-slate-800 dark:text-slate-100 dark:after:bg-indigo-400"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            <SplitIcon className="h-4 w-4" />
            <span>Generate SLIP-39 Phrases</span>
            <span className="rounded-full bg-indigo-100 px-2 py-0.5 text-[10px] font-semibold text-indigo-800 dark:bg-indigo-950 dark:text-indigo-300">
              {n} Shares
            </span>
          </button>

          <button
            type="button"
            onClick={() => setTab("combine")}
            className={cn(
              "relative flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors cursor-pointer",
              tab === "combine"
                ? "bg-white text-slate-900 shadow-xs after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-indigo-600 dark:bg-slate-800 dark:text-slate-100 dark:after:bg-indigo-400"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            <MergeIcon className="h-4 w-4" />
            <span>Combine & Recover Secret</span>
          </button>

          <button
            type="button"
            onClick={() => setTab("spec")}
            className={cn(
              "relative flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors cursor-pointer",
              tab === "spec"
                ? "bg-white text-slate-900 shadow-xs after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-indigo-600 dark:bg-slate-800 dark:text-slate-100 dark:after:bg-indigo-400"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            <BookIcon className="h-4 w-4" />
            <span>SLIP-0039 Architecture & Math</span>
          </button>
        </nav>
      </div>

      {/* TAB 1: GENERATE SLIP-39 PHRASES */}
      {tab === "split" && (
        <div className="space-y-6">
          {/* Master Secret & Parameters */}
          <Panel
            title="Master Secret & Backup Parameters"
            description="SLIP-0039 splits your master recovery secret into N mnemonic phrases such that any K phrases reconstruct it."
          >
            <div className="space-y-4">
              {/* Presets Row */}
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400">Presets:</span>
                {PRESETS.map((p) => (
                  <button
                    key={p.label}
                    type="button"
                    onClick={() => {
                      setSecretText(p.text);
                      setSecretFormat("utf8");
                    }}
                    className="rounded border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-slate-700 hover:bg-slate-100 hover:border-slate-300 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
                  >
                    {p.label}
                  </button>
                ))}
                <div className="ml-auto flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => handleGenerateRandom(16)}
                    title="Generate 128-bit random seed (20 words per share)"
                  >
                    128-bit Random Seed
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => handleGenerateRandom(32)}
                    title="Generate 256-bit random seed (33 words per share)"
                  >
                    256-bit Random Seed
                  </Button>
                </div>
              </div>

              {/* Secret Input Box */}
              <div>
                <div className="flex items-center justify-between pb-1.5">
                  <label htmlFor="slip39-secret" className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Master Secret Payload ({secretBytes.length} bytes / {secretBytes.length * 8} bits)
                  </label>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-slate-500 dark:text-slate-400">Format:</span>
                    <button
                      type="button"
                      onClick={() => setSecretFormat("utf8")}
                      className={cn(
                        "px-2 py-0.5 text-[11px] rounded font-medium",
                        secretFormat === "utf8"
                          ? "bg-indigo-600 text-white"
                          : "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400",
                      )}
                    >
                      UTF-8 Text
                    </button>
                    <button
                      type="button"
                      onClick={() => setSecretFormat("hex")}
                      className={cn(
                        "px-2 py-0.5 text-[11px] rounded font-medium",
                        secretFormat === "hex"
                          ? "bg-indigo-600 text-white"
                          : "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400",
                      )}
                    >
                      Hex Bytes
                    </button>
                  </div>
                </div>
                <textarea
                  id="slip39-secret"
                  value={secretText}
                  onChange={(e) => setSecretText(e.target.value)}
                  rows={2}
                  className="w-full rounded-md border border-slate-300 bg-white p-2.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                  placeholder="Enter secret text, seed phrase, or hex string to backup..."
                />
              </div>

              {/* Sliders Grid: K and N and Identifier */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                {/* Threshold Slider (K) */}
                <div className="rounded-lg border border-slate-200 bg-slate-50/60 p-3.5 dark:border-slate-800 dark:bg-slate-900/40">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                      Required Threshold (k)
                    </span>
                    <span className="rounded bg-indigo-100 px-2 py-0.5 text-xs font-bold text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300">
                      {k} shares
                    </span>
                  </div>
                  <input
                    type="range"
                    min={2}
                    max={n}
                    value={k}
                    onChange={(e) => handleKChange(Number(e.target.value))}
                    className="mt-2.5 w-full accent-indigo-600"
                  />
                  <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                    Minimum number of share phrases needed to restore.
                  </p>
                </div>

                {/* Total Shares Slider (N) */}
                <div className="rounded-lg border border-slate-200 bg-slate-50/60 p-3.5 dark:border-slate-800 dark:bg-slate-900/40">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                      Total Shares to Issue (n)
                    </span>
                    <span className="rounded bg-indigo-100 px-2 py-0.5 text-xs font-bold text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300">
                      {n} shares
                    </span>
                  </div>
                  <input
                    type="range"
                    min={k}
                    max={16}
                    value={n}
                    onChange={(e) => handleNChange(Number(e.target.value))}
                    className="mt-2.5 w-full accent-indigo-600"
                  />
                  <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                    Total distributed mnemonic shares generated.
                  </p>
                </div>

                {/* Backup Identifier */}
                <div className="rounded-lg border border-slate-200 bg-slate-50/60 p-3.5 dark:border-slate-800 dark:bg-slate-900/40">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                      Backup Set ID
                    </span>
                    <span className="font-mono text-xs font-bold text-slate-800 dark:text-slate-200">
                      0x{identifier.toString(16).toUpperCase()}
                    </span>
                  </div>
                  <div className="mt-2.5 flex items-center gap-2">
                    <input
                      type="number"
                      min={0}
                      max={65535}
                      value={identifier}
                      onChange={(e) => setIdentifier(Number(e.target.value) & 0xffff)}
                      className="w-full rounded border border-slate-300 bg-white px-2 py-1 font-mono text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
                    />
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => setIdentifier(Math.floor(Math.random() * 0xffff))}
                    >
                      Roll
                    </Button>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                    16-bit random identifier tagged in each phrase header.
                  </p>
                </div>
              </div>
            </div>
          </Panel>

          {/* Generated Share Cards */}
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  Generated SLIP-0039 Share Phrases ({shares.length} Total)
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Distribute these phrases to different physical locations. Any {k} of them will reconstruct your secret.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={handleExportAllPhrases}
                  className="flex items-center gap-1.5"
                >
                  <span>Export Backup Bundle (.txt)</span>
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => {
                    const text = shares.map((s) => s.phrase).join("\n");
                    setCombineInput(text);
                    setTab("combine");
                  }}
                  className="flex items-center gap-1.5 text-indigo-600 dark:text-indigo-400"
                >
                  <MergeIcon className="h-3.5 w-3.5" />
                  <span>Send to Combine Studio</span>
                </Button>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3">
              {shares.map((s, idx) => (
                <div
                  key={s.memberIndex}
                  className="rounded-lg border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b border-slate-100 dark:border-slate-800">
                    <div className="flex items-center gap-2">
                      <span className="flex h-5 w-5 items-center justify-center rounded-full bg-indigo-100 text-[11px] font-bold text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300">
                        {idx + 1}
                      </span>
                      <span className="font-semibold text-xs text-slate-900 dark:text-slate-100">
                        Share Phrase #{idx + 1}
                      </span>
                      <span className="rounded bg-slate-100 px-2 py-0.5 text-[10px] font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                        Threshold: {k} of {n}
                      </span>
                      <span className="rounded bg-slate-100 px-2 py-0.5 text-[10px] font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                        {s.words.length} Words
                      </span>
                      <span className="rounded bg-emerald-100 px-2 py-0.5 text-[10px] font-semibold text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300">
                        30-bit Checksum OK
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CopyButton value={s.phrase} label="Copy Phrase" />
                    </div>
                  </div>

                  {/* Words Grid */}
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {s.words.map((w, wIdx) => {
                      const isHeader = wIdx < 4;
                      const isChecksum = wIdx >= s.words.length - 3;
                      return (
                        <span
                          key={wIdx}
                          title={
                            isHeader
                              ? "Header word (ID / Group / Member)"
                              : isChecksum
                              ? "Polynomial Checksum word"
                              : "Polynomial Share Data word"
                          }
                          className={cn(
                            "inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-mono border",
                            isHeader
                              ? "border-sky-200 bg-sky-50 text-sky-900 dark:border-sky-800/40 dark:bg-sky-950/40 dark:text-sky-300"
                              : isChecksum
                              ? "border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-800/40 dark:bg-emerald-950/40 dark:text-emerald-300"
                              : "border-slate-200 bg-slate-50 text-slate-800 dark:border-slate-800 dark:bg-slate-800/60 dark:text-slate-200",
                          )}
                        >
                          <span className="text-[10px] text-slate-400 dark:text-slate-500">{wIdx + 1}</span>
                          <span className="font-semibold">{w}</span>
                        </span>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: COMBINE & RECOVER SECRET */}
      {tab === "combine" && (
        <div className="space-y-6">
          <Panel
            title="Combine & Recover Master Secret"
            description="Paste your SLIP-0039 mnemonic share phrases below (one phrase per line). Once K valid shares are detected, the master secret is reconstructed automatically."
          >
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label htmlFor="slip39-combine-input" className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                  SLIP-0039 Share Phrases Input
                </label>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => {
                      // Load demo shares (e.g. 3 of 5)
                      const demoShares = shares.slice(0, Math.max(k, 3));
                      setCombineInput(demoShares.map((s) => s.phrase).join("\n\n"));
                    }}
                  >
                    Load Current Generated Shares ({k} of {n})
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => setCombineInput("")}
                  >
                    Clear Input
                  </Button>
                </div>
              </div>

              <textarea
                id="slip39-combine-input"
                value={combineInput}
                onChange={(e) => setCombineInput(e.target.value)}
                rows={6}
                className="w-full rounded-md border border-slate-300 bg-white p-3 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                placeholder="Paste SLIP-0039 share phrases here, one per line..."
              />

              {/* Status and Parsed Shares Readout */}
              {parsedShares.length > 0 && (
                <div className="space-y-3 pt-2">
                  <h4 className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Inspected Share Phrases ({parsedShares.filter((p) => p.ok).length} Valid, {parsedShares.filter((p) => !p.ok).length} Invalid)
                  </h4>
                  <div className="space-y-2">
                    {parsedShares.map((p) => (
                      <div
                        key={p.lineIndex}
                        className={cn(
                          "flex flex-wrap items-center justify-between gap-2 rounded-lg border p-3 text-xs",
                          p.ok
                            ? "border-emerald-200 bg-emerald-50/50 dark:border-emerald-900/40 dark:bg-emerald-950/20"
                            : "border-red-200 bg-red-50/50 dark:border-red-900/40 dark:bg-red-950/20",
                        )}
                      >
                        <div className="flex items-center gap-2.5">
                          {p.ok ? (
                            <span className="flex h-5 w-5 items-center justify-center rounded-full bg-emerald-600 text-white text-[11px] font-bold">
                              ✓
                            </span>
                          ) : (
                            <span className="flex h-5 w-5 items-center justify-center rounded-full bg-red-600 text-white text-[11px] font-bold">
                              ✕
                            </span>
                          )}
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-semibold text-slate-900 dark:text-slate-100">
                                Line #{p.lineIndex}:
                              </span>
                              {p.ok && p.share && (
                                <>
                                  <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                                    Share #{p.share.memberIndex}
                                  </span>
                                  <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                                    Threshold: {p.share.memberThreshold}
                                  </span>
                                  <span className="font-mono text-[10px] text-slate-500">
                                    ID: 0x{p.share.identifier.toString(16).toUpperCase()}
                                  </span>
                                </>
                              )}
                            </div>
                            <p className="mt-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-400 truncate max-w-xl">
                              {p.raw}
                            </p>
                          </div>
                        </div>

                        <div>
                          {p.ok ? (
                            <span className="rounded bg-emerald-100 px-2 py-0.5 text-[11px] font-medium text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300">
                              Checksum Valid
                            </span>
                          ) : (
                            <span className="rounded bg-red-100 px-2 py-0.5 text-[11px] font-medium text-red-800 dark:bg-red-950 dark:text-red-300">
                              {p.error ?? "Invalid Phrase"}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Reconstructed Secret Result Panel */}
              {combineResult && (
                <div
                  className={cn(
                    "mt-4 rounded-xl border p-4.5 space-y-3",
                    combineResult.ok && combineResult.secret
                      ? "border-emerald-300 bg-emerald-50/70 dark:border-emerald-800 dark:bg-emerald-950/40"
                      : "border-amber-300 bg-amber-50/70 dark:border-amber-800 dark:bg-amber-950/40",
                  )}
                >
                  <div className="flex items-center gap-2">
                    {combineResult.ok ? (
                      <CheckIcon className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <AlertIcon className="h-5 w-5 text-amber-600 dark:text-amber-400" />
                    )}
                    <h4 className="font-semibold text-sm text-slate-900 dark:text-slate-100">
                      {combineResult.ok
                        ? "Master Secret Reconstructed Successfully!"
                        : "Threshold Not Yet Reached"}
                    </h4>
                  </div>

                  {combineResult.ok && combineResult.secret ? (
                    <div className="space-y-3">
                      <div>
                        <div className="flex items-center justify-between pb-1">
                          <span className="text-[11px] font-semibold text-slate-600 dark:text-slate-400">
                            UTF-8 Decoded Text
                          </span>
                          <CopyButton
                            value={new TextDecoder().decode(combineResult.secret)}
                            label="Copy UTF-8"
                          />
                        </div>
                        <div className="rounded-md border border-slate-200 bg-white p-2.5 font-mono text-xs text-slate-900 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100">
                          {new TextDecoder().decode(combineResult.secret)}
                        </div>
                      </div>

                      <div>
                        <div className="flex items-center justify-between pb-1">
                          <span className="text-[11px] font-semibold text-slate-600 dark:text-slate-400">
                            Hexadecimal Byte Stream (32 Bytes)
                          </span>
                          <CopyButton
                            value={bytesToHex(combineResult.secret)}
                            label="Copy Hex"
                          />
                        </div>
                        <div className="rounded-md border border-slate-200 bg-white p-2.5 font-mono text-xs text-slate-900 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100">
                          0x{bytesToHex(combineResult.secret)}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-amber-800 dark:text-amber-200">
                      {combineResult.error}
                    </p>
                  )}
                </div>
              )}
            </div>
          </Panel>
        </div>
      )}

      {/* TAB 3: SLIP-0039 ARCHITECTURE & MATH */}
      {tab === "spec" && (
        <div className="space-y-6">
          <Panel
            title="SLIP-0039 Specification & Math Breakdown"
            description="Understanding how SatoshiLabs SLIP-0039 combines Shamir's Secret Sharing with Reed-Solomon polynomial checksums."
          >
            <div className="space-y-6 text-xs text-slate-700 dark:text-slate-300">
              {/* Anatomy Diagram */}
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-900/60">
                <h4 className="font-semibold text-sm text-slate-900 dark:text-slate-100">
                  SLIP-0039 Share Phrase Anatomy (20 or 33 Words)
                </h4>
                <p className="mt-1 text-slate-600 dark:text-slate-400">
                  Every share phrase consists of a 4-word header, 13 or 26 data words, and a 3-word polynomial checksum:
                </p>

                <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="rounded-lg border border-sky-200 bg-sky-50/70 p-3 dark:border-sky-900/40 dark:bg-sky-950/40">
                    <span className="font-bold text-sky-800 dark:text-sky-300">1. Header (4 Words)</span>
                    <ul className="mt-2 space-y-1 text-[11px] text-slate-600 dark:text-slate-400">
                      <li>• <strong>Words 1–2:</strong> 16-bit random identifier + 4-bit iteration exp.</li>
                      <li>• <strong>Word 3:</strong> Group index & group threshold.</li>
                      <li>• <strong>Word 4:</strong> Member index ($x$) & member threshold ($k$).</li>
                    </ul>
                  </div>

                  <div className="rounded-lg border border-indigo-200 bg-indigo-50/70 p-3 dark:border-indigo-900/40 dark:bg-indigo-950/40">
                    <span className="font-bold text-indigo-800 dark:text-indigo-300">2. Share Data (13 or 26 Words)</span>
                    <ul className="mt-2 space-y-1 text-[11px] text-slate-600 dark:text-slate-400">
                      <li>• 128-bit secret = 13 words (130 bits, 2 bits pad).</li>
                      <li>• 256-bit secret = 26 words (260 bits, 4 bits pad).</li>
                      <li>• Encodes the polynomial evaluation y = f(x) over Galois Field GF(256).</li>
                    </ul>
                  </div>

                  <div className="rounded-lg border border-emerald-200 bg-emerald-50/70 p-3 dark:border-emerald-900/40 dark:bg-emerald-950/40">
                    <span className="font-bold text-emerald-800 dark:text-emerald-300">3. Checksum (3 Words)</span>
                    <ul className="mt-2 space-y-1 text-[11px] text-slate-600 dark:text-slate-400">
                      <li>• 30-bit polynomial checksum over 10-bit symbols.</li>
                      <li>• Catches up to 3 substituted words and all transpositions.</li>
                      <li>• Instant offline error detection before combining.</li>
                    </ul>
                  </div>
                </div>
              </div>

              {/* Comparison Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse border border-slate-200 dark:border-slate-800">
                  <thead>
                    <tr className="bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-200">
                      <th className="border border-slate-200 dark:border-slate-800 p-2.5">Feature</th>
                      <th className="border border-slate-200 dark:border-slate-800 p-2.5">BIP-39 Mnemonic</th>
                      <th className="border border-slate-200 dark:border-slate-800 p-2.5">Raw Shamir SSS</th>
                      <th className="border border-slate-200 dark:border-slate-800 p-2.5">SLIP-0039 (Shamir Mnemonic)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                    <tr>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5 font-semibold">Format</td>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5">Single 12/24 word phrase</td>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5">Raw hex or base64 strings</td>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5">Set of 20 or 33 word phrases</td>
                    </tr>
                    <tr>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5 font-semibold">Threshold Redundancy</td>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5 text-red-600 dark:text-red-400">No (Single Point of Failure)</td>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5 text-emerald-600 dark:text-emerald-400">Yes ($K$ of $N$)</td>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5 text-emerald-600 dark:text-emerald-400">Yes ($K$ of $N$ or multi-group)</td>
                    </tr>
                    <tr>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5 font-semibold">Human Readability</td>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5">High (English dictionary)</td>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5 text-red-600 dark:text-red-400">Low (Unpronounceable hex)</td>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5 text-emerald-600 dark:text-emerald-400">High (1024-word dictionary)</td>
                    </tr>
                    <tr>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5 font-semibold">Checksum Protection</td>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5">4–8 bit SHA-256 (Weak)</td>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5 text-red-600 dark:text-red-400">None</td>
                      <td className="border border-slate-200 dark:border-slate-800 p-2.5 text-emerald-600 dark:text-emerald-400">30-bit polynomial (Detects all single errors)</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}
