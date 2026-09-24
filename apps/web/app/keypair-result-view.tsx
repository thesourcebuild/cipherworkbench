"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ToolManifest, ToolResultField, ToolSpecBase } from "@ocs/engine";
import { Button, MonoBlock, cn, useCopy } from "@ocs/ui";
import { platform } from "@ocs/platform";
import { downloadBinaryFile, downloadTextFile } from "./export-json";
import type { ComputeStatus } from "./use-compute";
import {
  type KeypairFormat,
  resolveKeypairData,
  getKeypairView,
  downloadActiveKeypairFiles,
  downloadPemPairFiles,
  downloadRawBinaryPairFiles,
  downloadJwkPairFiles,
  downloadKeypairBundleFiles,
} from "./keypair-formats";

export interface KeypairResultViewProps {
  fields: readonly ToolResultField[];
  manifest?: ToolManifest;
  spec?: ToolSpecBase;
  status: ComputeStatus;
  stale: boolean;
  pending: boolean;
}

export function KeypairResultView({
  fields,
  manifest,
  spec: _spec,
  status,
  stale,
  pending,
}: KeypairResultViewProps) {
  const keyData = useMemo(() => resolveKeypairData(fields, manifest), [fields, manifest]);

  const [format, setFormat] = useState<KeypairFormat>(keyData.defaultFormat);
  const [revealedPrivate, setRevealedPrivate] = useState(false);
  const [downloadMenuOpen, setDownloadMenuOpen] = useState(false);
  const [menuAlign, setMenuAlign] = useState<"left" | "right">("right");
  const downloadMenuRef = useRef<HTMLDivElement>(null);

  // Sync format if switching tools makes current format invalid
  useEffect(() => {
    const isAvailable = keyData.availableFormats.some((f) => f.id === format);
    if (!isAvailable) {
      setFormat(keyData.defaultFormat);
    }
  }, [keyData, format]);

  const computeAlignment = useCallback(() => {
    if (!downloadMenuRef.current) return;
    const rect = downloadMenuRef.current.getBoundingClientRect();
    const parent = downloadMenuRef.current.parentElement;
    const containerLeft = parent ? parent.getBoundingClientRect().left : 0;
    const containerRight = parent ? parent.getBoundingClientRect().right : window.innerWidth;
    const spaceToContainerLeft = rect.right - containerLeft;
    const spaceToViewportLeft = rect.right;
    const spaceToViewportRight = window.innerWidth - rect.left;
    const menuWidth = 280;

    if (spaceToContainerLeft < menuWidth || spaceToViewportLeft < menuWidth) {
      setMenuAlign("left");
    } else if (spaceToViewportRight < menuWidth) {
      setMenuAlign("right");
    } else {
      const distFromLeft = rect.left - containerLeft;
      const distFromRight = containerRight - rect.right;
      setMenuAlign(distFromLeft < distFromRight ? "left" : "right");
    }
  }, []);

  useEffect(() => {
    if (!downloadMenuOpen) return;
    computeAlignment();
    const handleClickOutside = (e: MouseEvent) => {
      if (downloadMenuRef.current && !downloadMenuRef.current.contains(e.target as Node)) {
        setDownloadMenuOpen(false);
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setDownloadMenuOpen(false);
    };
    const handleResizeOrScroll = () => {
      computeAlignment();
    };

    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleKeyDown);
    window.addEventListener("resize", handleResizeOrScroll);
    window.addEventListener("scroll", handleResizeOrScroll, true);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("resize", handleResizeOrScroll);
      window.removeEventListener("scroll", handleResizeOrScroll, true);
    };
  }, [downloadMenuOpen, computeAlignment]);

  // Original raw fields for hints and labels
  const originalPrivateField = fields.find(
    (f) =>
      f.label.toLowerCase().includes("private") ||
      f.label.toLowerCase().includes("secret") ||
      f.secret,
  );
  const originalPublicField = fields.find(
    (f) =>
      f.label.toLowerCase().includes("public") &&
      !f.label.includes("JWK") &&
      !f.label.includes("PEM"),
  );

  const basePrivateLabel = originalPrivateField?.label ?? "Private key";
  const basePublicLabel = originalPublicField?.label ?? "Public key";

  const activeView = useMemo(
    () => getKeypairView(format, keyData, basePrivateLabel, basePublicLabel),
    [format, keyData, basePrivateLabel, basePublicLabel],
  );

  // Key metadata items (Key size, curve, parameter set, public exponent)
  const metaFields = useMemo(() => {
    return fields.filter(
      (f) =>
        f.label === "Key size" ||
        f.label === "Curve" ||
        f.label === "Parameter set" ||
        f.label === "Public exponent",
    );
  }, [fields]);

  const toolName = manifest?.id ?? "keypair";
  const keySizeLabel =
    metaFields.find((f) => f.label === "Key size")?.value.replace(/\s+/g, "-") ?? "";
  const baseFilename = `${toolName}${keySizeLabel ? `-${keySizeLabel}` : ""}`;

  const activeFormatOption = keyData.availableFormats.find((f) => f.id === format);
  const activeFormatLabel = activeFormatOption?.label ?? format.toUpperCase();

  const handleDownloadPrivate = () => {
    if (format === "raw") {
      if (keyData.rawPrivate) {
        downloadBinaryFile(`${baseFilename}-private.bin`, keyData.rawPrivate);
      }
    } else {
      downloadTextFile(
        `${baseFilename}-private.${activeView.fileExt}`,
        activeView.privateVal,
        activeView.mimeType,
      );
    }
  };

  const handleDownloadPublic = () => {
    if (format === "raw") {
      if (keyData.rawPublic) {
        downloadBinaryFile(`${baseFilename}-public.bin`, keyData.rawPublic);
      }
    } else {
      downloadTextFile(
        `${baseFilename}-public.${activeView.fileExt}`,
        activeView.publicVal,
        activeView.mimeType,
      );
    }
  };

  const privateHint =
    format === keyData.defaultFormat && originalPrivateField?.hint
      ? originalPrivateField.hint
      : activeView.privateHint ?? originalPrivateField?.hint;

  const publicHint =
    format === keyData.defaultFormat && originalPublicField?.hint
      ? originalPublicField.hint
      : activeView.publicHint ?? originalPublicField?.hint;

  return (
    <div className={cn("space-y-4", (stale || pending) && "opacity-60")}>
      {/* Format Switcher & Batch Actions Header */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 border-b border-slate-200 pb-3 dark:border-slate-800">
        <div className="flex items-center gap-2 flex-nowrap overflow-x-auto no-scrollbar py-0.5">
          {keyData.availableFormats.length > 1 && (
            <div className="flex shrink-0 items-center gap-1.5 whitespace-nowrap">
              <label
                htmlFor="keypair-format-select"
                className="text-[11px] font-medium text-slate-500 dark:text-slate-400"
              >
                Source:
              </label>
              <select
                id="keypair-format-select"
                data-ocs-keypair-format=""
                aria-label="Key source format"
                value={format}
                onChange={(e) => setFormat(e.target.value as KeypairFormat)}
                className="h-6 rounded-md border border-slate-300 bg-white px-2 py-0.5 text-[11px] font-medium text-slate-800 shadow-xs focus:border-indigo-500 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-200"
              >
                {keyData.availableFormats.map((opt) => (
                  <option key={opt.id} value={opt.id}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Quick info pills (Key size, Public exponent, Curve, Parameter set) */}
          {metaFields.map((field) => (
            <span
              key={field.label}
              className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 font-mono text-[11px] text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
            >
              <span className="text-slate-500">{field.label}:</span>
              <span className="font-semibold">{field.value}</span>
            </span>
          ))}
        </div>

        {/* Dropdown for Download Keypair */}
        <div className="relative inline-block shrink-0 text-left" ref={downloadMenuRef}>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              if (!downloadMenuOpen) {
                computeAlignment();
              }
              setDownloadMenuOpen((prev) => !prev);
            }}
            className="inline-flex items-center gap-1.5"
            aria-expanded={downloadMenuOpen}
            aria-haspopup="true"
            title="Download keypair options"
          >
            <span>Download Keypair</span>
            <span
              className="text-[9px] opacity-70 transition-transform duration-150"
              style={{ transform: downloadMenuOpen ? "rotate(180deg)" : undefined }}
            >
              ▼
            </span>
          </Button>

          {downloadMenuOpen && (
            <div
              className={cn(
                "absolute z-30 mt-1.5 w-72 max-w-[calc(100vw-2rem)] rounded-lg border border-slate-200 bg-white p-1 shadow-lg ring-1 ring-black/5 dark:border-slate-800 dark:bg-slate-900",
                menuAlign === "left" ? "left-0 origin-top-left" : "right-0 origin-top-right",
              )}
            >
              <div className="space-y-0.5">
                {/* 1. Download in currently selected source format */}
                <button
                  type="button"
                  onClick={() => {
                    setDownloadMenuOpen(false);
                    downloadActiveKeypairFiles(baseFilename, format, keyData);
                  }}
                  className="flex w-full flex-col items-start rounded-md px-3 py-2 text-left transition-colors hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                    Download Active Format ({activeFormatLabel}) (2 Files)
                  </span>
                  <span className="text-[11px] text-slate-500 dark:text-slate-400">
                    Separate private and public files in {activeFormatLabel}
                  </span>
                </button>

                {/* 2. Download PEM Pair */}
                {keyData.hasPem && (
                  <button
                    type="button"
                    onClick={() => {
                      setDownloadMenuOpen(false);
                      downloadPemPairFiles(baseFilename, keyData);
                    }}
                    className="flex w-full flex-col items-start rounded-md px-3 py-2 text-left transition-colors hover:bg-slate-100 dark:hover:bg-slate-800"
                  >
                    <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                      Download PEM Pair (2 Files)
                    </span>
                    <span className="text-[11px] text-slate-500 dark:text-slate-400">
                      Separate private and public .pem files (Base64 ASCII)
                    </span>
                  </button>
                )}

                {/* 3. Download Raw Binary Files */}
                {(keyData.rawPrivate || keyData.rawPublic) && (
                  <button
                    type="button"
                    onClick={() => {
                      setDownloadMenuOpen(false);
                      downloadRawBinaryPairFiles(baseFilename, keyData);
                    }}
                    className="flex w-full flex-col items-start rounded-md px-3 py-2 text-left transition-colors hover:bg-slate-100 dark:hover:bg-slate-800"
                  >
                    <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                      Download Raw Binary Files (2 Files)
                    </span>
                    <span className="text-[11px] text-slate-500 dark:text-slate-400">
                      Raw binary .bin key files (genuine bytes)
                    </span>
                  </button>
                )}

                {/* 4. Download JWK Pair */}
                {keyData.hasJwk && (
                  <button
                    type="button"
                    onClick={() => {
                      setDownloadMenuOpen(false);
                      downloadJwkPairFiles(baseFilename, keyData);
                    }}
                    className="flex w-full flex-col items-start rounded-md px-3 py-2 text-left transition-colors hover:bg-slate-100 dark:hover:bg-slate-800"
                  >
                    <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                      Download JWK Pair (2 Files)
                    </span>
                    <span className="text-[11px] text-slate-500 dark:text-slate-400">
                      Separate private and public .jwk.json files
                    </span>
                  </button>
                )}

                <div className="my-1 border-t border-slate-200 dark:border-slate-800" />

                {/* 5. Download Keypair Bundle */}
                <button
                  type="button"
                  onClick={() => {
                    setDownloadMenuOpen(false);
                    downloadKeypairBundleFiles(baseFilename, keyData);
                  }}
                  className="flex w-full flex-col items-start rounded-md px-3 py-2 text-left transition-colors hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  <span className="text-xs font-semibold text-indigo-600 dark:text-indigo-400">
                    Download Keypair Bundle (All Formats)
                  </span>
                  <span className="text-[11px] text-slate-500 dark:text-slate-400">
                    PEM, Raw Binary, Active Format, and JWK across separate files
                  </span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Private Key Card */}
      {activeView.privateVal && (
        <div className="rounded-lg border border-amber-200/80 bg-gradient-to-b from-amber-50/30 to-transparent p-3.5 dark:border-amber-900/40 dark:from-amber-950/20">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold tracking-tight text-slate-900 dark:text-slate-100">
                {activeView.privateLabel}
              </span>
              <span className="inline-flex items-center rounded-sm border border-amber-300/50 bg-amber-100/80 px-1.5 py-0.2 text-[10px] font-semibold text-amber-900 dark:border-amber-800/40 dark:bg-amber-950/60 dark:text-amber-300">
                SECRET
              </span>
            </div>

            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setRevealedPrivate((prev) => !prev)}
                className="mr-1 font-sans text-[11px] text-slate-500 underline decoration-dotted hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
              >
                {revealedPrivate ? "Hide" : "Show"}
              </button>
              <CardCopyIconButton
                value={() => activeView.privateVal}
                aria-label="Copy private key"
                title="Copy private key"
              />
              <Button
                size="sm"
                variant="secondary"
                onClick={handleDownloadPrivate}
                className="h-6 w-6 rounded-full p-0 flex items-center justify-center text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
                aria-label="Download private key"
                title={`Download private key (${activeView.fileExt})`}
              >
                <DownloadIcon />
              </Button>
            </div>
          </div>

          <MonoBlock
            data-ocs-private-result=""
            value={revealedPrivate ? activeView.privateVal : "•".repeat(64)}
            className="max-h-56 overflow-auto whitespace-pre font-mono text-[11px] leading-relaxed"
          />
          {privateHint && (
            <p className="mt-1.5 text-[11px] text-amber-800/80 dark:text-amber-400/80">
              {privateHint}
            </p>
          )}
        </div>
      )}

      {/* Public Key Card */}
      {activeView.publicVal && (
        <div className="rounded-lg border border-emerald-200/80 bg-gradient-to-b from-emerald-50/30 to-transparent p-3.5 dark:border-emerald-900/40 dark:from-emerald-950/20">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold tracking-tight text-slate-900 dark:text-slate-100">
                {activeView.publicLabel}
              </span>
              <span className="inline-flex items-center rounded-sm border border-emerald-300/50 bg-emerald-100/80 px-1.5 py-0.2 text-[10px] font-semibold text-emerald-900 dark:border-emerald-800/40 dark:bg-emerald-950/60 dark:text-emerald-300">
                PUBLIC · SHAREABLE
              </span>
            </div>

            <div className="flex items-center gap-1.5">
              <CardCopyIconButton
                value={() => activeView.publicVal}
                aria-label="Copy public key"
                title="Copy public key"
              />
              <Button
                size="sm"
                variant="secondary"
                onClick={handleDownloadPublic}
                className="h-6 w-6 rounded-full p-0 flex items-center justify-center text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
                aria-label="Download public key"
                title={`Download public key (${activeView.fileExt})`}
              >
                <DownloadIcon />
              </Button>
            </div>
          </div>

          <MonoBlock
            data-ocs-result=""
            data-ocs-status={status}
            value={activeView.publicVal}
            className="max-h-56 overflow-auto whitespace-pre font-mono text-[11px] leading-relaxed"
          />
          {publicHint && (
            <p className="mt-1.5 text-[11px] text-emerald-800/80 dark:text-emerald-400/80">
              {publicHint}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function CardCopyIconButton({
  value,
  "aria-label": ariaLabel,
  title,
}: {
  value: string | (() => string);
  "aria-label": string;
  title: string;
}) {
  const { copied, copy } = useCopy({
    value,
    writeClipboard: (text) => platform().copyToClipboard(text),
  });

  return (
    <Button
      size="sm"
      variant="secondary"
      onClick={() => void copy()}
      className="h-6 w-6 rounded-full p-0 flex items-center justify-center text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
      aria-label={ariaLabel}
      title={copied ? "Copied" : title}
    >
      {copied ? <TickIcon /> : <ClipboardIcon />}
    </Button>
  );
}

function ClipboardIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.9"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <rect x="9" y="9" width="12" height="12" rx="2" />
      <path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1" />
    </svg>
  );
}

function TickIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.4"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function DownloadIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.9"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  );
}
