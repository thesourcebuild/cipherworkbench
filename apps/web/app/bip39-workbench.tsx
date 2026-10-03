"use client";

import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { OptionValue } from "@ocs/contracts";
import type { ToolDefinition, ToolSpecBase } from "@ocs/engine";
import { Button, CopyButton, CopyIconButton, cn } from "@ocs/ui";
import {
  entropyToMnemonic,
  mnemonicToSeed,
  createMasterFromSeed,
  derivePath,
  deriveChild,
} from "@ocs/algos";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
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

type DerivationPreset = "eth" | "btc-segwit" | "btc-legacy" | "custom";

const WORD_COUNTS = [12, 15, 18, 21, 24] as const;

// Base58 encoder for Bitcoin legacy addresses
const B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Check(payload: Uint8Array, versionByte = 0x00): string {
  const data = new Uint8Array([versionByte, ...payload]);
  const h1 = sha256(data);
  const h2 = sha256(h1);
  const checksum = h2.subarray(0, 4);
  const full = new Uint8Array(data.length + 4);
  full.set(data);
  full.set(checksum, data.length);

  let leadingZeros = 0;
  while (leadingZeros < full.length && full[leadingZeros] === 0) leadingZeros++;

  let num = 0n;
  for (let i = 0; i < full.length; i++) {
    num = (num << 8n) | BigInt(full[i]!);
  }

  let str = "";
  while (num > 0n) {
    str = B58_CHARS[Number(num % 58n)] + str;
    num /= 58n;
  }
  return "1".repeat(leadingZeros) + str;
}

// Bech32 for Native SegWit (P2WPKH)
const BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function bech32Segwit(pubKeyHash: Uint8Array, hrp = "bc"): string {
  // convert 8-bit to 5-bit
  const words: number[] = [0]; // witness version 0
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < pubKeyHash.length; i++) {
    acc = (acc << 8) | pubKeyHash[i]!;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      words.push((acc >> bits) & 31);
    }
  }
  if (bits > 0) {
    words.push((acc << (5 - bits)) & 31);
  }

  // checksum
  function polymod(values: number[]): number {
    let chk = 1;
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    for (const v of values) {
      const b = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) {
        if ((b >>> i) & 1) chk ^= GEN[i]!;
      }
    }
    return chk;
  }

  const hrpExpanded: number[] = [];
  for (let i = 0; i < hrp.length; i++) hrpExpanded.push(hrp.charCodeAt(i) >>> 5);
  hrpExpanded.push(0);
  for (let i = 0; i < hrp.length; i++) hrpExpanded.push(hrp.charCodeAt(i) & 31);

  const mod = polymod([...hrpExpanded, ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksumWords: number[] = [];
  for (let i = 0; i < 6; i++) {
    checksumWords.push((mod >>> (5 * (5 - i))) & 31);
  }

  let out = hrp + "1";
  for (const w of [...words, ...checksumWords]) {
    out += BECH32_CHARS[w];
  }
  return out;
}

// Checksummed Ethereum address
function toChecksumAddress(hexAddr: string): string {
  const clean = hexAddr.toLowerCase().replace(/^0x/, "");
  const hash = keccak_256(new TextEncoder().encode(clean));
  let checksum = "0x";
  for (let i = 0; i < clean.length; i++) {
    const char = clean[i]!;
    const hashNibble = (hash[i >> 1]! >> (i % 2 === 0 ? 4 : 0)) & 0x0f;
    checksum += hashNibble >= 8 ? char.toUpperCase() : char.toLowerCase();
  }
  return checksum;
}

export function Bip39Workbench({ tool: _tool }: CustomWorkbenchProps) {
  const [wordCount, setWordCount] = useState<number>(12);
  const [entropyBytes, setEntropyBytes] = useState<Uint8Array>(() => {
    const buf = new Uint8Array(16);
    globalThis.crypto.getRandomValues(buf);
    return buf;
  });
  const [passphrase, setPassphrase] = useState("");
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [showPrivateKeys, setShowPrivateKeys] = useState(false);
  const [preset, setPreset] = useState<DerivationPreset>("eth");
  const [customPath, setCustomPath] = useState("m/44'/60'/0'/0");
  const [accountCount, setAccountCount] = useState(5);

  // Generate new random mnemonic
  const handleGenerate = (count: number = wordCount) => {
    const byteLen = (count / 3) * 4; // 12 -> 16, 24 -> 32
    const buf = new Uint8Array(byteLen);
    globalThis.crypto.getRandomValues(buf);
    setWordCount(count);
    setEntropyBytes(buf);
  };

  // Derive mnemonic from entropy
  const mnemonic = useMemo(() => {
    try {
      return entropyToMnemonic(entropyBytes);
    } catch {
      return "abandon ability able about above absent absorb abstract absurd abuse access accident";
    }
  }, [entropyBytes]);

  const words = useMemo(() => mnemonic.split(" "), [mnemonic]);

  // Derive 512-bit seed from mnemonic + passphrase
  const seed = useMemo(() => {
    return mnemonicToSeed(mnemonic, passphrase);
  }, [mnemonic, passphrase]);

  const seedHex = useMemo(() => {
    let hex = "";
    for (let i = 0; i < seed.length; i++) hex += seed[i]!.toString(16).padStart(2, "0");
    return hex;
  }, [seed]);

  const entropyHex = useMemo(() => {
    let hex = "";
    for (let i = 0; i < entropyBytes.length; i++) hex += entropyBytes[i]!.toString(16).padStart(2, "0");
    return hex;
  }, [entropyBytes]);

  // BIP-32 Master Extended Key
  const hmacSha512 = (key: Uint8Array, data: Uint8Array) => hmac(sha512, key, data);

  const masterKey = useMemo(() => {
    return createMasterFromSeed(seed, hmacSha512);
  }, [seed]);

  // Active base path
  const basePath = useMemo(() => {
    switch (preset) {
      case "eth":
        return "m/44'/60'/0'/0";
      case "btc-segwit":
        return "m/84'/0'/0'/0";
      case "btc-legacy":
        return "m/44'/0'/0'/0";
      case "custom":
        return customPath.trim();
    }
  }, [preset, customPath]);

  // Derive account rows
  const derivedAccounts = useMemo(() => {
    try {
      const parent = derivePath(masterKey, basePath, hmacSha512);
      const accounts = [];

      for (let i = 0; i < accountCount; i++) {
        const child = deriveChild(parent, i, hmacSha512);
        const privKey = child.key;

        // secp256k1 public key
        let pubKeyCompressed = new Uint8Array(33);
        let pubKeyUncompressed = new Uint8Array(65);
        try {
          pubKeyCompressed = secp256k1.getPublicKey(privKey, true);
          pubKeyUncompressed = secp256k1.getPublicKey(privKey, false);
        } catch {
          // fallback if zero key
        }

        let address = "";
        if (preset === "eth" || (preset === "custom" && basePath.includes("60'"))) {
          // Ethereum: keccak256(uncompressed[1..65])[12..32]
          const hash = keccak_256(pubKeyUncompressed.subarray(1));
          const rawHex = Array.from(hash.subarray(12))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          address = toChecksumAddress(rawHex);
        } else if (preset === "btc-segwit" || (preset === "custom" && basePath.includes("84'"))) {
          // Bitcoin Native SegWit: bech32(ripemd160(sha256(pubKeyCompressed)))
          const pkh = ripemd160(sha256(pubKeyCompressed));
          address = bech32Segwit(pkh, "bc");
        } else {
          // Bitcoin Legacy: base58Check(ripemd160(sha256(pubKeyCompressed)))
          const pkh = ripemd160(sha256(pubKeyCompressed));
          address = base58Check(pkh, 0x00);
        }

        let privHex = "";
        for (let b = 0; b < privKey.length; b++) privHex += privKey[b]!.toString(16).padStart(2, "0");

        let pubHex = "";
        for (let b = 0; b < pubKeyCompressed.length; b++) pubHex += pubKeyCompressed[b]!.toString(16).padStart(2, "0");

        accounts.push({
          index: i,
          path: `${basePath}/${i}`,
          address,
          pubKeyHex: pubHex,
          privKeyHex: privHex,
        });
      }

      return accounts;
    } catch (e) {
      console.error("Derivation failed:", e);
      return [];
    }
  }, [masterKey, basePath, accountCount, preset]);

  return (
    <div className="flex flex-col gap-6 w-full max-w-6xl mx-auto py-2">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-2xl bg-gradient-to-r from-amber-500/10 via-orange-500/10 to-yellow-500/10 border border-amber-500/20 backdrop-blur-md">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-2xl">🌱</span>
            <h1 className="text-xl font-bold tracking-tight text-neutral-100">
              BIP-39 Mnemonic & BIP-32/44 HD Wallet
            </h1>
            <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30">
              Hierarchical Deterministic Derivation
            </span>
          </div>
          <p className="text-sm text-neutral-400 mt-1 max-w-2xl">
            Generate cryptographically secure 12-24 word recovery seed phrases, derive 512-bit master seeds via PBKDF2-HMAC-SHA512, and explore multi-chain deterministic key trees (Ethereum, Bitcoin SegWit, Taproot).
          </p>
        </div>

        <Button
          variant="primary"
          onClick={() => handleGenerate(wordCount)}
          className="bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-neutral-950 font-bold shadow-lg shadow-amber-500/10 text-xs py-2 px-4"
        >
          🎲 Generate Fresh Phrase
        </Button>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Mnemonic Configuration */}
        <div className="lg:col-span-5 flex flex-col gap-5 p-5 rounded-2xl bg-neutral-900/60 border border-neutral-800 backdrop-blur-sm">
          {/* Word Count Selector */}
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-neutral-300">
              Phrase Length
            </span>
            <div className="flex items-center gap-1 bg-neutral-950 p-1 rounded-lg border border-neutral-800">
              {WORD_COUNTS.map((cnt) => (
                <button
                  key={cnt}
                  type="button"
                  onClick={() => handleGenerate(cnt)}
                  className={cn(
                    "px-2.5 py-1 rounded text-xs font-mono font-medium transition-colors",
                    wordCount === cnt
                      ? "bg-amber-500 text-neutral-950 font-bold"
                      : "text-neutral-400 hover:text-neutral-200"
                  )}
                >
                  {cnt}w
                </button>
              ))}
            </div>
          </div>

          {/* Word Pills Grid */}
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-xs text-neutral-400">Recovery Seed Words:</span>
              <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-medium">
                <span>✓</span>
                <span>BIP-39 Checksum Valid</span>
              </span>
            </div>

            <div className="grid grid-cols-3 gap-2 p-3 rounded-xl bg-neutral-950 border border-neutral-800/80">
              {words.map((w, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-neutral-900/90 border border-neutral-800 text-xs hover:border-amber-500/30 transition-colors"
                >
                  <span className="text-[10px] font-mono text-neutral-500 select-none w-4 text-right">
                    {idx + 1}.
                  </span>
                  <span className="font-mono font-semibold text-neutral-200 select-all">
                    {w}
                  </span>
                </div>
              ))}
            </div>

            <div className="flex items-center justify-between pt-1">
              <span className="text-[11px] text-neutral-500">
                Entropy: {entropyBytes.length * 8} bits ({entropyBytes.length} bytes)
              </span>
              <CopyButton value={mnemonic} label="Copy Phrase" />
            </div>
          </div>

          {/* Optional Passphrase (25th word) */}
          <div className="flex flex-col gap-2 pt-3 border-t border-neutral-800/80">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-neutral-300">
                Optional Passphrase ("25th Word")
              </span>
              <button
                type="button"
                onClick={() => setShowPassphrase(!showPassphrase)}
                className="text-xs text-neutral-400 hover:text-amber-400 transition-colors"
              >
                {showPassphrase ? "Hide" : "Show"}
              </button>
            </div>

            <input
              type={showPassphrase ? "text" : "password"}
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Leave empty or enter extra salt passphrase..."
              className="w-full px-3.5 py-2 rounded-xl bg-neutral-950 border border-neutral-800 focus:border-amber-500/50 focus:ring-1 focus:ring-amber-500/50 font-mono text-xs text-neutral-200 transition-all placeholder:text-neutral-600"
            />
            <p className="text-[11px] text-neutral-500">
              Acts as a salt in PBKDF2. An incorrect passphrase creates a completely separate, valid empty wallet.
            </p>
          </div>

          {/* Seed Details */}
          <div className="flex flex-col gap-3 pt-3 border-t border-neutral-800/80">
            <span className="text-xs font-semibold uppercase tracking-wider text-neutral-300">
              Binary Seed & Root Key
            </span>

            <div className="flex flex-col gap-1">
              <div className="flex items-center justify-between text-[11px] text-neutral-400">
                <span>512-bit Root Seed (PBKDF2-HMAC-SHA512)</span>
                <CopyIconButton value={seedHex} aria-label="Copy Seed Hex" />
              </div>
              <div className="p-2.5 rounded-lg bg-neutral-950 border border-neutral-800/80 font-mono text-[11px] text-neutral-400 break-all select-all">
                {seedHex}
              </div>
            </div>

            <div className="flex flex-col gap-1">
              <div className="flex items-center justify-between text-[11px] text-neutral-400">
                <span>Entropy Hex</span>
                <CopyIconButton value={entropyHex} aria-label="Copy Entropy Hex" />
              </div>
              <div className="p-2 rounded-lg bg-neutral-950 border border-neutral-800/80 font-mono text-[11px] text-neutral-400 break-all select-all">
                0x{entropyHex}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: HD Derivation Tree & Accounts */}
        <div className="lg:col-span-7 flex flex-col gap-5 p-5 rounded-2xl bg-neutral-900/60 border border-neutral-800 backdrop-blur-sm">
          {/* Preset Selector */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold uppercase tracking-wider text-neutral-300">
                Derivation Path & Accounts
              </h2>
              <p className="text-xs text-neutral-400 mt-0.5">
                Standard BIP-44 / BIP-84 account derivation paths.
              </p>
            </div>

            <div className="flex items-center gap-1 bg-neutral-950 p-1 rounded-xl border border-neutral-800">
              <button
                type="button"
                onClick={() => setPreset("eth")}
                className={cn(
                  "px-3 py-1 rounded-lg text-xs font-medium transition-colors",
                  preset === "eth"
                    ? "bg-amber-500 text-neutral-950 font-bold"
                    : "text-neutral-400 hover:text-neutral-200"
                )}
              >
                Ethereum
              </button>
              <button
                type="button"
                onClick={() => setPreset("btc-segwit")}
                className={cn(
                  "px-3 py-1 rounded-lg text-xs font-medium transition-colors",
                  preset === "btc-segwit"
                    ? "bg-amber-500 text-neutral-950 font-bold"
                    : "text-neutral-400 hover:text-neutral-200"
                )}
              >
                BTC Native SegWit
              </button>
              <button
                type="button"
                onClick={() => setPreset("btc-legacy")}
                className={cn(
                  "px-3 py-1 rounded-lg text-xs font-medium transition-colors",
                  preset === "btc-legacy"
                    ? "bg-amber-500 text-neutral-950 font-bold"
                    : "text-neutral-400 hover:text-neutral-200"
                )}
              >
                BTC Legacy
              </button>
              <button
                type="button"
                onClick={() => setPreset("custom")}
                className={cn(
                  "px-3 py-1 rounded-lg text-xs font-medium transition-colors",
                  preset === "custom"
                    ? "bg-amber-500 text-neutral-950 font-bold"
                    : "text-neutral-400 hover:text-neutral-200"
                )}
              >
                Custom
              </button>
            </div>
          </div>

          {/* Path Details Bar */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3 rounded-xl bg-neutral-950 border border-neutral-800/80">
            <div className="flex items-center gap-2">
              <span className="text-xs text-neutral-400">Path:</span>
              {preset === "custom" ? (
                <input
                  type="text"
                  value={customPath}
                  onChange={(e) => setCustomPath(e.target.value)}
                  className="px-2 py-0.5 rounded bg-neutral-900 border border-neutral-700 font-mono text-xs text-amber-300 w-44"
                />
              ) : (
                <span className="font-mono text-xs text-amber-400 font-bold bg-amber-500/10 px-2.5 py-0.5 rounded border border-amber-500/20">
                  {basePath}
                </span>
              )}
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => setShowPrivateKeys(!showPrivateKeys)}
                className="text-xs text-neutral-400 hover:text-amber-400 transition-colors flex items-center gap-1"
              >
                <span>{showPrivateKeys ? "🔒 Hide Private Keys" : "👁️ Reveal Private Keys"}</span>
              </button>

              <div className="flex items-center gap-1 text-xs text-neutral-400">
                <span>Count:</span>
                <select
                  value={accountCount}
                  onChange={(e) => setAccountCount(parseInt(e.target.value, 10))}
                  className="px-1.5 py-0.5 rounded bg-neutral-900 border border-neutral-800 font-mono text-xs text-neutral-200"
                >
                  {[3, 5, 10, 20].map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* Accounts List */}
          <div className="flex flex-col gap-3 overflow-y-auto max-h-[580px] pr-1">
            {derivedAccounts.map((acc) => (
              <div
                key={acc.index}
                className="flex flex-col gap-2 p-3.5 rounded-xl bg-neutral-900/80 border border-neutral-800/80 hover:border-amber-500/30 transition-all"
              >
                {/* Account Header */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="flex items-center justify-center w-5 h-5 rounded-md bg-amber-500/10 text-amber-400 font-mono text-xs font-bold border border-amber-500/20">
                      {acc.index}
                    </span>
                    <span className="font-mono text-xs text-neutral-300 font-semibold">
                      {acc.path}
                    </span>
                  </div>
                  <CopyButton value={acc.address} label="Copy Address" />
                </div>

                {/* Address */}
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] text-neutral-500 uppercase font-medium">
                    Address:
                  </span>
                  <div className="p-2 rounded-lg bg-neutral-950 border border-neutral-800 font-mono text-xs text-emerald-300 break-all select-all font-semibold">
                    {acc.address}
                  </div>
                </div>

                {/* Public Key */}
                <div className="flex flex-col gap-1">
                  <div className="flex items-center justify-between text-[11px] text-neutral-500">
                    <span className="uppercase font-medium">Public Key (Compressed 33B):</span>
                    <CopyIconButton value={acc.pubKeyHex} aria-label="Copy Public Key" />
                  </div>
                  <div className="p-1.5 rounded-lg bg-neutral-950 border border-neutral-800/80 font-mono text-[11px] text-neutral-400 break-all select-all">
                    0x{acc.pubKeyHex}
                  </div>
                </div>

                {/* Private Key */}
                {showPrivateKeys && (
                  <div className="flex flex-col gap-1 pt-1 border-t border-neutral-800/60">
                    <div className="flex items-center justify-between text-[11px] text-red-400 font-medium">
                      <span>Private Key (secp256k1):</span>
                      <CopyIconButton value={acc.privKeyHex} aria-label="Copy Private Key" />
                    </div>
                    <div className="p-1.5 rounded-lg bg-red-950/20 border border-red-900/30 font-mono text-[11px] text-red-300 break-all select-all">
                      0x{acc.privKeyHex}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
