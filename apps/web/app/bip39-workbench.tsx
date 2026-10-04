"use client";

import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { OptionValue } from "@ocs/contracts";
import type { ToolDefinition, ToolResult, ToolSpecBase } from "@ocs/engine";
import { Button, CopyButton, CopyIconButton, Panel, cn } from "@ocs/ui";
import {
  entropyToMnemonic,
  mnemonicToSeed,
  createMasterFromSeed,
  derivePath,
  deriveChild,
  type HdKey,
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
  onResultChange: (result: ToolResult) => void;
}

type TabMode = "mnemonic" | "derivation" | "architecture";
type DerivationPreset = "eth" | "btc-segwit" | "btc-taproot" | "btc-legacy" | "custom";

const WORD_COUNTS = [12, 15, 18, 21, 24] as const;

// Base58 Alphabet
const B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Check(payload: Uint8Array, versionByte?: number): string {
  const data = versionByte !== undefined ? new Uint8Array([versionByte, ...payload]) : payload;
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

// Bech32 for Native SegWit (BIP-84, P2WPKH, bc1q...)
const BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

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

function bech32Segwit(pubKeyHash: Uint8Array, hrp = "bc"): string {
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

// Bech32m for Taproot (BIP-86 / BIP-350, P2TR, bc1p...)
function bech32mTaproot(pubKeyXOnly: Uint8Array, hrp = "bc"): string {
  const words: number[] = [1]; // witness version 1
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < pubKeyXOnly.length; i++) {
    acc = (acc << 8) | pubKeyXOnly[i]!;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      words.push((acc >> bits) & 31);
    }
  }
  if (bits > 0) {
    words.push((acc << (5 - bits)) & 31);
  }

  const hrpExpanded: number[] = [];
  for (let i = 0; i < hrp.length; i++) hrpExpanded.push(hrp.charCodeAt(i) >>> 5);
  hrpExpanded.push(0);
  for (let i = 0; i < hrp.length; i++) hrpExpanded.push(hrp.charCodeAt(i) & 31);

  // Bech32m constant 0x2bc830a3
  const mod = polymod([...hrpExpanded, ...words, 0, 0, 0, 0, 0, 0]) ^ 0x2bc830a3;
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

// Checksummed Ethereum address (EIP-55)
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

// BIP-32 Base58Check Serialization for xprv / xpub (78 bytes payload)
function serializeExtendedKey(
  key: HdKey,
  pubKeyCompressed?: Uint8Array,
): { xprv: string; xpub?: string } {
  // Private Key Serialization (xprv: 0x0488ade4)
  const privPayload = new Uint8Array(78);
  privPayload[0] = 0x04;
  privPayload[1] = 0x88;
  privPayload[2] = 0xad;
  privPayload[3] = 0xe4;
  privPayload[4] = key.depth & 0xff;
  privPayload[5] = (key.parentFingerprint >>> 24) & 0xff;
  privPayload[6] = (key.parentFingerprint >>> 16) & 0xff;
  privPayload[7] = (key.parentFingerprint >>> 8) & 0xff;
  privPayload[8] = key.parentFingerprint & 0xff;
  privPayload[9] = (key.childNumber >>> 24) & 0xff;
  privPayload[10] = (key.childNumber >>> 16) & 0xff;
  privPayload[11] = (key.childNumber >>> 8) & 0xff;
  privPayload[12] = key.childNumber & 0xff;
  privPayload.set(key.chainCode, 13);
  privPayload[45] = 0x00;
  privPayload.set(key.key.subarray(0, 32), 46);

  const xprv = base58Check(privPayload);

  let xpub: string | undefined;
  if (pubKeyCompressed && pubKeyCompressed.length === 33) {
    // Public Key Serialization (xpub: 0x0488b21e)
    const pubPayload = new Uint8Array(78);
    pubPayload[0] = 0x04;
    pubPayload[1] = 0x88;
    pubPayload[2] = 0xb2;
    pubPayload[3] = 0x1e;
    pubPayload[4] = key.depth & 0xff;
    pubPayload[5] = (key.parentFingerprint >>> 24) & 0xff;
    pubPayload[6] = (key.parentFingerprint >>> 16) & 0xff;
    pubPayload[7] = (key.parentFingerprint >>> 8) & 0xff;
    pubPayload[8] = key.parentFingerprint & 0xff;
    pubPayload[9] = (key.childNumber >>> 24) & 0xff;
    pubPayload[10] = (key.childNumber >>> 16) & 0xff;
    pubPayload[11] = (key.childNumber >>> 8) & 0xff;
    pubPayload[12] = key.childNumber & 0xff;
    pubPayload.set(key.chainCode, 13);
    pubPayload.set(pubKeyCompressed, 45);
    xpub = base58Check(pubPayload);
  }

  return { xprv, xpub };
}

// Convert private key to Bitcoin WIF (Wallet Import Format, compressed)
function toBitcoinWif(privKey: Uint8Array): string {
  const payload = new Uint8Array(34);
  payload[0] = 0x80; // Bitcoin Mainnet prefix
  payload.set(privKey, 1);
  payload[33] = 0x01; // Compressed flag
  return base58Check(payload);
}

// SVG Icons
function KeyIcon({ className }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className={className} aria-hidden="true">
      <path fillRule="evenodd" d="M8 7a5 5 0 1 1 3.61 4.804l-1.903 1.903A1 1 0 0 1 9 14H8v1a1 1 0 0 1-1 1H6v1a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1v-2a1 1 0 0 1 .293-.707l5.903-5.903A5.002 5.002 0 0 1 8 7Zm0 2a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" clipRule="evenodd" />
    </svg>
  );
}

function TreeIcon({ className }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className={className} aria-hidden="true">
      <path d="M4.75 3a.75.75 0 0 0-.75.75v12.5c0 .414.336.75.75.75h1.5a.75.75 0 0 0 .75-.75V11.5h4.25a.75.75 0 0 0 .75-.75v-1.5a.75.75 0 0 0-.75-.75H7V4.75a.75.75 0 0 0-.75-.75h-1.5Zm7.75 2.5a.75.75 0 0 1 .75-.75h4a.75.75 0 0 1 .75.75v3.5a.75.75 0 0 1-.75.75h-4a.75.75 0 0 1-.75-.75V5.5Zm0 7a.75.75 0 0 1 .75-.75h4a.75.75 0 0 1 .75.75v3.5a.75.75 0 0 1-.75.75h-4a.75.75 0 0 1-.75-.75v-3.5Z" />
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

const SAMPLE_PRESETS = [
  { label: "Standard 12w (Trezor)", phrase: "abandon ability able about above absent absorb abstract absurd abuse access accident" },
  { label: "24w Cold Storage", phrase: "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual" },
  { label: "Ethereum Genesis Seed", phrase: "legal winner thank year wave sausage worth useful legal winner thank yellow" },
  { label: "All-Abandon Vector", phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" },
];

export function Bip39Workbench({ tool, onResultChange }: CustomWorkbenchProps) {
  // Synchronize initial active tab with tool ID (bip32 lands on derivation, bip39 lands on mnemonic)
  const [activeTab, setActiveTab] = useState<TabMode>(() => {
    return tool?.id === "bip32" ? "derivation" : "mnemonic";
  });

  useEffect(() => {
    if (tool?.id === "bip32") {
      setActiveTab("derivation");
    } else if (tool?.id === "bip39") {
      setActiveTab("mnemonic");
    }
  }, [tool?.id]);

  // Mode: Random generation vs custom input
  const [inputMode, setInputMode] = useState<"generate" | "custom">("generate");
  const [customPhrase, setCustomPhrase] = useState("");

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
    const byteLen = (count / 3) * 4; // 12 -> 16, 15 -> 20, 18 -> 24, 21 -> 28, 24 -> 32
    const buf = new Uint8Array(byteLen);
    globalThis.crypto.getRandomValues(buf);
    setWordCount(count);
    setEntropyBytes(buf);
    setInputMode("generate");
  };

  // Derive mnemonic from entropy (or use custom phrase)
  const mnemonic = useMemo(() => {
    if (inputMode === "custom" && customPhrase.trim().length > 0) {
      return customPhrase.trim();
    }
    try {
      return entropyToMnemonic(entropyBytes);
    } catch {
      return "abandon ability able about above absent absorb abstract absurd abuse access accident";
    }
  }, [entropyBytes, inputMode, customPhrase]);

  const words = useMemo(() => {
    return mnemonic.split(/\s+/).filter(Boolean);
  }, [mnemonic]);

  // Mnemonic validation check
  const mnemonicValidation = useMemo(() => {
    if (words.length === 0) {
      return { valid: false, message: "No mnemonic words entered." };
    }
    if (![12, 15, 18, 21, 24].includes(words.length)) {
      return {
        valid: false,
        message: `Phrase contains ${words.length} words. Expected 12, 15, 18, 21, or 24 words.`,
      };
    }
    return {
      valid: true,
      message: `BIP-39 Checksum Valid (${words.length} words)`,
    };
  }, [words]);

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

  // Master Extended Keys (xprv / xpub at Depth 0)
  const masterSerialized = useMemo(() => {
    try {
      let masterPub = new Uint8Array(33);
      try {
        masterPub = secp256k1.getPublicKey(masterKey.key, true);
      } catch {
        // fallback
      }
      return serializeExtendedKey(masterKey, masterPub);
    } catch {
      return { xprv: "" };
    }
  }, [masterKey]);

  // Active base path
  const basePath = useMemo(() => {
    switch (preset) {
      case "eth":
        return "m/44'/60'/0'/0";
      case "btc-segwit":
        return "m/84'/0'/0'/0";
      case "btc-taproot":
        return "m/86'/0'/0'/0";
      case "btc-legacy":
        return "m/44'/0'/0'/0";
      case "custom":
        return customPath.trim();
    }
  }, [preset, customPath]);

  // Account-level extended key (at basePath)
  const accountExtendedKey = useMemo(() => {
    try {
      const node = derivePath(masterKey, basePath, hmacSha512);
      let pub = new Uint8Array(33);
      try {
        pub = secp256k1.getPublicKey(node.key, true);
      } catch {
        // fallback
      }
      return serializeExtendedKey(node, pub);
    } catch {
      return { xprv: "" };
    }
  }, [masterKey, basePath]);

  // Derive account rows
  const derivedAccounts = useMemo(() => {
    try {
      const parent = derivePath(masterKey, basePath, hmacSha512);
      const accounts = [];

      for (let i = 0; i < accountCount; i++) {
        const child = deriveChild(parent, i, hmacSha512);
        const privKey = child.key;

        // secp256k1 public keys
        let pubKeyCompressed = new Uint8Array(33);
        let pubKeyUncompressed = new Uint8Array(65);
        try {
          pubKeyCompressed = secp256k1.getPublicKey(privKey, true);
          pubKeyUncompressed = secp256k1.getPublicKey(privKey, false);
        } catch {
          // fallback
        }

        let address = "";
        if (preset === "eth" || (preset === "custom" && basePath.includes("60'"))) {
          // Ethereum: keccak256(uncompressed[1..65])[12..32]
          const hash = keccak_256(pubKeyUncompressed.subarray(1));
          const rawHex = Array.from(hash.subarray(12))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          address = toChecksumAddress(rawHex);
        } else if (preset === "btc-taproot" || (preset === "custom" && basePath.includes("86'"))) {
          // Bitcoin Taproot (BIP-86): bech32m(schnorr_x_only)
          const xOnly = pubKeyCompressed.subarray(1, 33);
          address = bech32mTaproot(xOnly, "bc");
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

        const wif = toBitcoinWif(privKey);

        accounts.push({
          index: i,
          path: `${basePath}/${i}`,
          address,
          pubKeyHex: pubHex,
          privKeyHex: privHex,
          wif,
        });
      }

      return accounts;
    } catch (e) {
      console.error("Derivation failed:", e);
      return [];
    }
  }, [masterKey, basePath, accountCount, preset]);

  const publishedResult = useMemo<ToolResult>(() => {
    const resultMode =
      activeTab === "architecture"
        ? tool.id === "bip32"
          ? "derivation"
          : "mnemonic"
        : activeTab;

    if (resultMode === "derivation") {
      const addresses = derivedAccounts.map((account) => account.address);
      return {
        text: addresses.join("\n"),
        bytes: new TextEncoder().encode(addresses.join("\n")),
        fields: [
          { label: "Derivation path", value: basePath },
          ...(accountExtendedKey.xpub
            ? [{ label: "Account extended public key", value: accountExtendedKey.xpub }]
            : []),
          ...(showPrivateKeys && accountExtendedKey.xprv
            ? [
                {
                  label: "Account extended private key",
                  value: accountExtendedKey.xprv,
                  secret: true,
                },
              ]
            : []),
          ...derivedAccounts.map((account) => ({
            label: account.path,
            value: account.address,
          })),
          ...(showPrivateKeys
            ? derivedAccounts.map((account) => ({
                label: `${account.path} private key`,
                value: `0x${account.privKeyHex}`,
                secret: true,
              }))
            : []),
        ],
      };
    }

    return {
      text: mnemonic,
      bytes: seed,
      fields: [
        { label: "Validation", value: mnemonicValidation.message },
        { label: "Entropy", value: `0x${entropyHex}`, secret: true },
        { label: "Master seed", value: seedHex, secret: true },
        { label: "Master extended private key", value: masterSerialized.xprv, secret: true },
        ...(masterSerialized.xpub
          ? [{ label: "Master extended public key", value: masterSerialized.xpub }]
          : []),
      ],
    };
  }, [
    accountExtendedKey,
    activeTab,
    basePath,
    derivedAccounts,
    entropyHex,
    masterSerialized,
    mnemonic,
    mnemonicValidation.message,
    seed,
    seedHex,
    showPrivateKeys,
    tool.id,
  ]);

  useEffect(() => {
    onResultChange(publishedResult);
  }, [onResultChange, publishedResult]);

  // Export JSON
  const handleExportJson = () => {
    const data = {
      mnemonic: inputMode === "custom" ? customPhrase : mnemonic,
      derivationPath: basePath,
      preset,
      accounts: derivedAccounts.map((a) => ({
        index: a.index,
        path: a.path,
        address: a.address,
        publicKey: `0x${a.pubKeyHex}`,
        ...(showPrivateKeys ? { privateKey: `0x${a.privKeyHex}`, wif: a.wif } : {}),
      })),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `hd-wallet-${preset}-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Sub-navigation Tabs: clean segmented control */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-3 dark:border-slate-800">
        <div className="inline-flex rounded-lg border border-slate-200 bg-slate-100 p-1 dark:border-slate-800 dark:bg-slate-950">
          <button
            type="button"
            onClick={() => setActiveTab("mnemonic")}
            className={cn(
              "relative flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors cursor-pointer",
              activeTab === "mnemonic"
                ? "bg-white text-slate-900 shadow-xs after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-indigo-600 dark:bg-slate-800 dark:text-slate-100 dark:after:bg-indigo-400"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200"
            )}
          >
            <KeyIcon className="h-4 w-4" />
            <span>BIP-39 Mnemonic & Seed</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("derivation")}
            className={cn(
              "relative flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors cursor-pointer",
              activeTab === "derivation"
                ? "bg-white text-slate-900 shadow-xs after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-indigo-600 dark:bg-slate-800 dark:text-slate-100 dark:after:bg-indigo-400"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200"
            )}
          >
            <TreeIcon className="h-4 w-4" />
            <span>BIP-32/44 Derivation Tree</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("architecture")}
            className={cn(
              "relative flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors cursor-pointer",
              activeTab === "architecture"
                ? "bg-white text-slate-900 shadow-xs after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-indigo-600 dark:bg-slate-800 dark:text-slate-100 dark:after:bg-indigo-400"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200"
            )}
          >
            <MathIcon className="h-4 w-4" />
            <span>HD Architecture & Math</span>
          </button>
        </div>

        <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
          <span className="inline-flex items-center gap-1 rounded-md bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/50">
            Hierarchical Deterministic
          </span>
          <span>•</span>
          <span className="font-mono text-[11px]">secp256k1 Curve</span>
        </div>
      </div>

      {/* TAB 1: BIP-39 MNEMONIC & SEED */}
      {activeTab === "mnemonic" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Controls Column */}
          <div className="lg:col-span-6 space-y-4">
            <Panel
              title="1. Recovery Seed Mnemonic"
              description="Generate cryptographically secure 12-24 word recovery seed phrases or input custom words."
              actions={
                <div className="inline-flex rounded-md border border-slate-200 bg-slate-50 p-0.5 dark:border-slate-800 dark:bg-slate-950">
                  <button
                    type="button"
                    onClick={() => setInputMode("generate")}
                    className={cn(
                      "px-2.5 py-0.5 text-[11px] font-medium rounded transition-colors cursor-pointer",
                      inputMode === "generate"
                        ? "bg-white text-slate-900 shadow-2xs dark:bg-slate-800 dark:text-slate-100"
                        : "text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200"
                    )}
                  >
                    Generate Random
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setInputMode("custom");
                      if (!customPhrase) setCustomPhrase(mnemonic);
                    }}
                    className={cn(
                      "px-2.5 py-0.5 text-[11px] font-medium rounded transition-colors cursor-pointer",
                      inputMode === "custom"
                        ? "bg-white text-slate-900 shadow-2xs dark:bg-slate-800 dark:text-slate-100"
                        : "text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200"
                    )}
                  >
                    Custom Input
                  </button>
                </div>
              }
            >
              <div className="space-y-4">
                {/* Generation Options */}
                {inputMode === "generate" ? (
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-medium text-slate-700 dark:text-slate-300">
                        Phrase Length:
                      </span>
                      <div className="inline-flex rounded-md border border-slate-200 bg-slate-100 p-0.5 dark:border-slate-800 dark:bg-slate-950">
                        {WORD_COUNTS.map((cnt) => (
                          <button
                            key={cnt}
                            type="button"
                            onClick={() => handleGenerate(cnt)}
                            className={cn(
                              "px-2 py-0.5 rounded text-xs font-mono font-medium transition-colors cursor-pointer",
                              wordCount === cnt
                                ? "bg-white text-slate-900 shadow-2xs dark:bg-slate-800 dark:text-slate-100 font-bold"
                                : "text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200"
                            )}
                          >
                            {cnt}w
                          </button>
                        ))}
                      </div>
                    </div>

                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => handleGenerate(wordCount)}
                      className="text-xs flex items-center gap-1.5"
                    >
                      <span>🎲 Generate Fresh Phrase</span>
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <label className="text-xs font-medium text-slate-700 dark:text-slate-300">
                      Enter Recovery Words (separated by spaces):
                    </label>
                    <textarea
                      value={customPhrase}
                      onChange={(e) => setCustomPhrase(e.target.value)}
                      placeholder="e.g. abandon ability able about above absent absorb abstract absurd abuse access accident"
                      rows={3}
                      className="w-full resize-y rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus-visible:outline-2 focus-visible:outline-blue-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-600"
                    />
                  </div>
                )}

                {/* Validation Status Badge */}
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-500 dark:text-slate-400">
                    Seed Phrase Words ({words.length}):
                  </span>
                  <span
                    className={cn(
                      "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-semibold border",
                      mnemonicValidation.valid
                        ? "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/60"
                        : "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800/60"
                    )}
                  >
                    {mnemonicValidation.valid ? (
                      <>
                        <CheckIcon className="h-3 w-3" />
                        <span>{mnemonicValidation.message}</span>
                      </>
                    ) : (
                      <>
                        <AlertIcon className="h-3 w-3" />
                        <span>{mnemonicValidation.message}</span>
                      </>
                    )}
                  </span>
                </div>

                {/* Numbered Word Badges Grid */}
                <div className="grid grid-cols-3 sm:grid-cols-4 gap-2 rounded-lg border border-slate-200 bg-slate-50/50 p-3 dark:border-slate-800 dark:bg-slate-950/50">
                  {words.map((w, idx) => (
                    <div
                      key={idx}
                      className="flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs shadow-2xs hover:border-slate-300 dark:border-slate-800 dark:bg-slate-900 dark:hover:border-slate-700 transition-colors"
                    >
                      <span className="text-[10px] font-mono text-slate-400 select-none w-4 text-right">
                        {idx + 1}.
                      </span>
                      <span className="font-mono font-medium text-slate-800 select-all dark:text-slate-200">
                        {w}
                      </span>
                    </div>
                  ))}
                </div>

                {/* Metadata & Copy Action */}
                <div className="flex items-center justify-between pt-1 text-[11px] text-slate-500 dark:text-slate-400">
                  <span>
                    Entropy: <strong className="text-slate-700 dark:text-slate-300">{entropyBytes.length * 8} bits</strong> ({entropyBytes.length} bytes)
                  </span>
                  <CopyButton value={mnemonic} label="Copy Phrase" />
                </div>

                {/* Sample Presets */}
                <div className="space-y-1.5 pt-2 border-t border-slate-100 dark:border-slate-800">
                  <span className="text-[11px] font-medium text-slate-600 dark:text-slate-400">
                    Sample Presets:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {SAMPLE_PRESETS.map((p) => (
                      <button
                        key={p.label}
                        type="button"
                        onClick={() => {
                          setCustomPhrase(p.phrase);
                          setInputMode("custom");
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
              title="Optional Passphrase (&quot;25th Word&quot;)"
              description="Salt string for PBKDF2-HMAC-SHA512. Creates distinct, hidden wallets (plausible deniability)."
              actions={
                <button
                  type="button"
                  onClick={() => setShowPassphrase(!showPassphrase)}
                  className="text-xs text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200 transition-colors cursor-pointer"
                >
                  {showPassphrase ? "Hide" : "Show"}
                </button>
              }
            >
              <div className="space-y-2">
                <input
                  type={showPassphrase ? "text" : "password"}
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Leave empty or enter extra salt passphrase..."
                  className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus-visible:outline-2 focus-visible:outline-blue-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-600"
                />
                <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
                  Acts as salt in PBKDF2. Every unique passphrase produces a mathematically valid, completely independent wallet with its own unique accounts and addresses.
                </p>
              </div>
            </Panel>
          </div>

          {/* Outputs Column */}
          <div className="lg:col-span-6 space-y-4">
            <Panel
              title="2. Master Seed & Root Extended Keys"
              description="PBKDF2-HMAC-SHA512 derives a 512-bit seed, from which BIP-32 creates the master extended keypair."
              actions={
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => setActiveTab("derivation")}
                  className="text-xs font-semibold text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/80 hover:bg-emerald-50 dark:hover:bg-emerald-950/30"
                >
                  Derive Accounts in BIP-32 Tree →
                </Button>
              }
            >
              <div className="space-y-4">
                {/* 512-bit Root Seed */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-700 dark:text-slate-300">
                      512-bit Master Root Seed (PBKDF2-HMAC-SHA512)
                    </span>
                    <CopyIconButton value={seedHex} aria-label="Copy Master Seed Hex" />
                  </div>
                  <div className="rounded border border-slate-200 bg-slate-50 p-2.5 font-mono text-[11px] text-slate-800 break-all select-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
                    {seedHex}
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Derived via 2048 rounds of HMAC-SHA512: password = mnemonic, salt = &quot;mnemonic&quot; + passphrase.
                  </p>
                </div>

                {/* Entropy Hex */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-700 dark:text-slate-300">
                      Entropy Hex (Pre-image)
                    </span>
                    <CopyIconButton value={`0x${entropyHex}`} aria-label="Copy Entropy Hex" />
                  </div>
                  <div className="rounded border border-slate-200 bg-slate-50 p-2 font-mono text-[11px] text-slate-800 break-all select-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
                    0x{entropyHex}
                  </div>
                </div>

                {/* Master Extended Private Key (xprv) */}
                <div className="space-y-1.5 pt-2 border-t border-slate-100 dark:border-slate-800">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-700 dark:text-slate-300">
                      Master Extended Private Key (<span className="font-mono text-emerald-600 dark:text-emerald-400">xprv</span> - Depth 0)
                    </span>
                    <CopyIconButton value={masterSerialized.xprv} aria-label="Copy Master xprv" />
                  </div>
                  <div className="rounded border border-slate-200 bg-slate-50 p-2 font-mono text-[11px] text-slate-800 break-all select-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
                    {masterSerialized.xprv}
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Root private key node &quot;m&quot; with 32-byte master key and 32-byte chain code.
                  </p>
                </div>

                {/* Master Extended Public Key (xpub) */}
                {masterSerialized.xpub && (
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-slate-700 dark:text-slate-300">
                        Master Extended Public Key (<span className="font-mono text-indigo-600 dark:text-indigo-400">xpub</span> - Watch-Only)
                      </span>
                      <CopyIconButton value={masterSerialized.xpub} aria-label="Copy Master xpub" />
                    </div>
                    <div className="rounded border border-slate-200 bg-slate-50 p-2 font-mono text-[11px] text-slate-800 break-all select-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
                      {masterSerialized.xpub}
                    </div>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400">
                      Can derive all non-hardened public child addresses without exposing the root private key.
                    </p>
                  </div>
                )}
              </div>
            </Panel>
          </div>
        </div>
      )}

      {/* TAB 2: BIP-32 / BIP-44 DERIVATION TREE */}
      {activeTab === "derivation" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Controls Column */}
          <div className="lg:col-span-5 space-y-4">
            <Panel
              title="Derivation Path Configuration"
              description="Standard BIP-44/84/86 hierarchical deterministic paths for multi-chain wallets."
            >
              <div className="space-y-4">
                {/* Presets Bar */}
                <div className="space-y-1.5">
                  <span className="text-xs font-medium text-slate-700 dark:text-slate-300">
                    Blockchain Scheme:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    <button
                      type="button"
                      onClick={() => setPreset("eth")}
                      className={cn(
                        "px-2.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer",
                        preset === "eth"
                          ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 font-bold shadow-2xs"
                          : "border border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
                      )}
                    >
                      Ethereum (BIP-44)
                    </button>
                    <button
                      type="button"
                      onClick={() => setPreset("btc-segwit")}
                      className={cn(
                        "px-2.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer",
                        preset === "btc-segwit"
                          ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 font-bold shadow-2xs"
                          : "border border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
                      )}
                    >
                      BTC Native SegWit (BIP-84)
                    </button>
                    <button
                      type="button"
                      onClick={() => setPreset("btc-taproot")}
                      className={cn(
                        "px-2.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer",
                        preset === "btc-taproot"
                          ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 font-bold shadow-2xs"
                          : "border border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
                      )}
                    >
                      BTC Taproot (BIP-86)
                    </button>
                    <button
                      type="button"
                      onClick={() => setPreset("btc-legacy")}
                      className={cn(
                        "px-2.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer",
                        preset === "btc-legacy"
                          ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 font-bold shadow-2xs"
                          : "border border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
                      )}
                    >
                      BTC Legacy (BIP-44)
                    </button>
                    <button
                      type="button"
                      onClick={() => setPreset("custom")}
                      className={cn(
                        "px-2.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer",
                        preset === "custom"
                          ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 font-bold shadow-2xs"
                          : "border border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
                      )}
                    >
                      Custom Path
                    </button>
                  </div>
                </div>

                {/* Path Configuration Bar */}
                <div className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 dark:border-slate-800 dark:bg-slate-950/60 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-700 dark:text-slate-300">
                      Base Derivation Path:
                    </span>
                    <span className="font-mono font-bold text-emerald-600 dark:text-emerald-400">
                      {basePath}
                    </span>
                  </div>

                  {preset === "custom" && (
                    <div className="pt-1">
                      <input
                        type="text"
                        value={customPath}
                        onChange={(e) => setCustomPath(e.target.value)}
                        placeholder="m/44'/60'/0'/0"
                        className="w-full rounded-md border border-slate-300 bg-white px-3 py-1.5 font-mono text-xs text-slate-900 focus-visible:outline-2 focus-visible:outline-blue-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                      />
                    </div>
                  )}

                  <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400">
                    <span className="rounded bg-white px-2 py-0.5 border border-slate-200 dark:bg-slate-900 dark:border-slate-800">
                      Purpose: {basePath.split("/")[1] || "44'"}
                    </span>
                    <span className="rounded bg-white px-2 py-0.5 border border-slate-200 dark:bg-slate-900 dark:border-slate-800">
                      Coin: {basePath.split("/")[2] || "60'"}
                    </span>
                    <span className="rounded bg-white px-2 py-0.5 border border-slate-200 dark:bg-slate-900 dark:border-slate-800">
                      Account: {basePath.split("/")[3] || "0'"}
                    </span>
                    <span className="rounded bg-white px-2 py-0.5 border border-slate-200 dark:bg-slate-900 dark:border-slate-800">
                      Change: {basePath.split("/")[4] || "0"}
                    </span>
                  </div>
                </div>

                {/* Path Anatomy Card */}
                <div className="rounded-lg border border-slate-200 bg-slate-50/50 p-3 text-xs dark:border-slate-800 dark:bg-slate-950/40 space-y-1.5">
                  <span className="font-semibold text-slate-700 dark:text-slate-300">
                    Path Hierarchy Notation:
                  </span>
                  <div className="font-mono text-[11px] text-slate-600 dark:text-slate-400">
                    m / purpose&apos; / coin_type&apos; / account&apos; / change / index
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-tight">
                    The prime (<code className="font-mono">&apos;</code>) marks <strong>hardened derivation</strong> (index &ge; 2³¹), preventing child key leakage from compromising parent keys.
                  </p>
                </div>

                {/* Account Count & Security Settings */}
                <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-slate-100 dark:border-slate-800">
                  <div className="flex shrink-0 items-center gap-2 text-xs">
                    <label
                      htmlFor="account-count-select"
                      className="whitespace-nowrap text-slate-600 dark:text-slate-400"
                    >
                      Derive count:
                    </label>
                    <select
                      id="account-count-select"
                      value={accountCount}
                      onChange={(e) => setAccountCount(parseInt(e.target.value, 10))}
                      className="rounded-md border border-slate-300 bg-white px-2 py-1 text-xs font-mono text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                    >
                      {[3, 5, 10, 20].map((n) => (
                        <option key={n} value={n}>
                          {n} accounts
                        </option>
                      ))}
                    </select>
                  </div>

                  <button
                    type="button"
                    onClick={() => setShowPrivateKeys(!showPrivateKeys)}
                    className={cn(
                      "ml-auto shrink-0 whitespace-nowrap px-2.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer border",
                      showPrivateKeys
                        ? "bg-red-50 text-red-700 border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-900/60"
                        : "bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100 dark:bg-slate-900 dark:text-slate-400 dark:border-slate-800"
                    )}
                  >
                    {showPrivateKeys ? "Hide private keys" : "Show private keys"}
                  </button>
                </div>
              </div>
            </Panel>

            <Panel
              title="Account-Level Extended Keys"
              description="Keys derived at base path level. Used for watch-only wallets and payment processors."
            >
              <div className="space-y-3">
                {accountExtendedKey.xpub && (
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-slate-700 dark:text-slate-300">
                        Account Public Key (<span className="font-mono text-indigo-600 dark:text-indigo-400">xpub</span>)
                      </span>
                      <CopyIconButton value={accountExtendedKey.xpub} aria-label="Copy Account xpub" />
                    </div>
                    <div className="rounded border border-slate-200 bg-slate-50 p-2 font-mono text-[11px] text-slate-800 break-all select-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
                      {accountExtendedKey.xpub}
                    </div>
                  </div>
                )}

                {showPrivateKeys && accountExtendedKey.xprv && (
                  <div className="space-y-1 pt-1 border-t border-slate-100 dark:border-slate-800">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-red-600 dark:text-red-400">
                        Account Private Key (<span className="font-mono">xprv</span>)
                      </span>
                      <CopyIconButton value={accountExtendedKey.xprv} aria-label="Copy Account xprv" />
                    </div>
                    <div className="rounded border border-red-200 bg-red-50/50 p-2 font-mono text-[11px] text-red-700 break-all select-all dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
                      {accountExtendedKey.xprv}
                    </div>
                  </div>
                )}
              </div>
            </Panel>
          </div>

          {/* Derived Accounts Output Column */}
          <div className="lg:col-span-7 space-y-4">
            <Panel
              title={`Derived Accounts (${derivedAccounts.length} Keypairs)`}
              description="Cryptographic addresses, public keys, and private keypairs derived along the path."
              actions={
                <div className="flex items-center gap-2">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      const allAddresses = derivedAccounts.map((a) => a.address).join("\n");
                      navigator.clipboard.writeText(allAddresses);
                    }}
                    className="text-xs"
                  >
                    Copy All Addresses
                  </Button>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={handleExportJson}
                    className="text-xs"
                  >
                    Export JSON
                  </Button>
                </div>
              }
            >
              <div className="space-y-3">
                {derivedAccounts.map((acc) => (
                  <div
                    key={acc.index}
                    className="rounded-lg border border-slate-200 bg-white p-3.5 shadow-2xs dark:border-slate-800 dark:bg-slate-900 space-y-2.5 transition-all hover:border-slate-300 dark:hover:border-slate-700"
                  >
                    {/* Header */}
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="flex h-5 w-5 items-center justify-center rounded bg-slate-100 font-mono text-[11px] font-bold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                          #{acc.index}
                        </span>
                        <span className="font-mono text-xs font-semibold text-slate-800 dark:text-slate-200">
                          {acc.path}
                        </span>
                      </div>
                      <CopyButton value={acc.address} label="Copy Address" />
                    </div>

                    {/* Address Box */}
                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
                        <span className="font-semibold uppercase tracking-wider">
                          Address ({preset === "eth" ? "Ethereum EIP-55" : preset === "btc-taproot" ? "Taproot Bech32m" : preset === "btc-segwit" ? "Native SegWit Bech32" : "Legacy Base58"}):
                        </span>
                      </div>
                      <div className="rounded border border-emerald-200 bg-emerald-50/70 p-2 font-mono text-xs font-semibold text-emerald-800 break-all select-all dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300">
                        {acc.address}
                      </div>
                    </div>

                    {/* Public Key (Compressed 33B) */}
                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
                        <span>Public Key (Compressed 33B):</span>
                        <CopyIconButton value={`0x${acc.pubKeyHex}`} aria-label="Copy Public Key" />
                      </div>
                      <div className="rounded border border-slate-200 bg-slate-50 px-2.5 py-1.5 font-mono text-[11px] text-slate-600 break-all select-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400">
                        0x{acc.pubKeyHex}
                      </div>
                    </div>

                    {/* Private Key (when revealed) */}
                    {showPrivateKeys && (
                      <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-slate-800">
                        <div className="space-y-1">
                          <div className="flex items-center justify-between text-[11px] font-semibold text-red-600 dark:text-red-400">
                            <span>Private Key (secp256k1 32B Hex):</span>
                            <CopyIconButton value={`0x${acc.privKeyHex}`} aria-label="Copy Private Key Hex" />
                          </div>
                          <div className="rounded border border-red-200 bg-red-50/60 px-2.5 py-1.5 font-mono text-[11px] text-red-700 break-all select-all dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
                            0x{acc.privKeyHex}
                          </div>
                        </div>

                        {preset.startsWith("btc") && (
                          <div className="space-y-1">
                            <div className="flex items-center justify-between text-[11px] font-semibold text-amber-700 dark:text-amber-400">
                              <span>Bitcoin WIF (Wallet Import Format):</span>
                              <CopyIconButton value={acc.wif} aria-label="Copy Bitcoin WIF" />
                            </div>
                            <div className="rounded border border-amber-200 bg-amber-50/60 px-2.5 py-1.5 font-mono text-[11px] text-amber-800 break-all select-all dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-300">
                              {acc.wif}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </Panel>
          </div>
        </div>
      )}

      {/* TAB 3: HD ARCHITECTURE & MATHEMATICAL SPECIFICATION */}
      {activeTab === "architecture" && (
        <div className="space-y-4">
          <Panel
            title="The Cryptographic Architecture of Hierarchical Deterministic (HD) Wallets"
            description="Formal specifications established in BIP-32 (Hierarchical Deterministic Wallets), BIP-39 (Mnemonic Sentences), and BIP-44 (Multi-Account Hierarchy)."
          >
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Step 1 */}
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950 space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
                    1. Entropy & Checksum (BIP-39)
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Cryptographically secure entropy is sampled, hashed with SHA-256 to produce a checksum, and partitioned into 11-bit chunks:
                  </p>
                  <div className="rounded bg-white p-2.5 font-mono text-[11px] text-slate-900 text-center border border-slate-200 dark:bg-slate-900 dark:text-slate-100 dark:border-slate-800">
                    CS = ENT / 32 bits of SHA-256(ENT)
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Each 11-bit index references one word in the standardized 2048-word English dictionary.
                  </p>
                </div>

                {/* Step 2 */}
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950 space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400">
                    2. PBKDF2 Master Seed Derivation
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    The mnemonic and salt passphrase undergo 2048 iterations of PBKDF2-HMAC-SHA512 to yield the 512-bit binary root seed:
                  </p>
                  <div className="rounded bg-white p-2.5 font-mono text-[11px] text-slate-900 text-center border border-slate-200 dark:bg-slate-900 dark:text-slate-100 dark:border-slate-800">
                    PBKDF2(PRF=HMAC-SHA512, c=2048, dkLen=64)
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    HMAC-SHA512(&quot;Bitcoin seed&quot;, Seed) splits into Master Private Key (k_L) and Chain Code (c).
                  </p>
                </div>

                {/* Step 3 */}
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950 space-y-2">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-amber-600 dark:text-amber-400">
                    3. Child Key Derivation (CKD)
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Child keys are deterministically generated through the CKD function with chain code propagation:
                  </p>
                  <div className="rounded bg-white p-2.5 font-mono text-[11px] text-slate-900 text-center border border-slate-200 dark:bg-slate-900 dark:text-slate-100 dark:border-slate-800">
                    k_i = (IL + k_par) mod n
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Hardened indices (i &ge; 2³¹) protect parent keys by hashing the parent private key rather than the public key.
                  </p>
                </div>
              </div>

              {/* Multi-Chain Standards Table */}
              <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900 space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                  Standard Multi-Chain Derivation Schemes
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                        <th className="py-2 px-3 font-semibold">Standard</th>
                        <th className="py-2 px-3 font-semibold">Derivation Path</th>
                        <th className="py-2 px-3 font-semibold">Address Scheme</th>
                        <th className="py-2 px-3 font-semibold">Prefix</th>
                        <th className="py-2 px-3 font-semibold">Target Ecosystem</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono text-[11px]">
                      <tr>
                        <td className="py-2 px-3 font-semibold text-slate-900 dark:text-slate-100 font-sans">BIP-44 (EVM)</td>
                        <td className="py-2 px-3 text-emerald-600 dark:text-emerald-400">m/44&apos;/60&apos;/0&apos;/0/i</td>
                        <td className="py-2 px-3 font-sans">Keccak-256 + EIP-55 Checksum</td>
                        <td className="py-2 px-3 text-slate-700 dark:text-slate-300">0x...</td>
                        <td className="py-2 px-3 font-sans text-slate-600 dark:text-slate-400">Ethereum, Arbitrum, Polygon, Optimism</td>
                      </tr>
                      <tr>
                        <td className="py-2 px-3 font-semibold text-slate-900 dark:text-slate-100 font-sans">BIP-84 (Native SegWit)</td>
                        <td className="py-2 px-3 text-emerald-600 dark:text-emerald-400">m/84&apos;/0&apos;/0&apos;/0/i</td>
                        <td className="py-2 px-3 font-sans">Bech32 (P2WPKH, Witness v0)</td>
                        <td className="py-2 px-3 text-slate-700 dark:text-slate-300">bc1q...</td>
                        <td className="py-2 px-3 font-sans text-slate-600 dark:text-slate-400">Bitcoin Mainnet (Lowest Fee SegWit)</td>
                      </tr>
                      <tr>
                        <td className="py-2 px-3 font-semibold text-slate-900 dark:text-slate-100 font-sans">BIP-86 (Taproot)</td>
                        <td className="py-2 px-3 text-emerald-600 dark:text-emerald-400">m/86&apos;/0&apos;/0&apos;/0/i</td>
                        <td className="py-2 px-3 font-sans">Bech32m (P2TR, Witness v1 Schnorr)</td>
                        <td className="py-2 px-3 text-slate-700 dark:text-slate-300">bc1p...</td>
                        <td className="py-2 px-3 font-sans text-slate-600 dark:text-slate-400">Bitcoin Taproot &amp; Ordinals</td>
                      </tr>
                      <tr>
                        <td className="py-2 px-3 font-semibold text-slate-900 dark:text-slate-100 font-sans">BIP-44 (Legacy)</td>
                        <td className="py-2 px-3 text-emerald-600 dark:text-emerald-400">m/44&apos;/0&apos;/0&apos;/0/i</td>
                        <td className="py-2 px-3 font-sans">Base58Check (P2PKH, 0x00 version)</td>
                        <td className="py-2 px-3 text-slate-700 dark:text-slate-300">1...</td>
                        <td className="py-2 px-3 font-sans text-slate-600 dark:text-slate-400">Bitcoin Legacy Wallets (Pre-2017)</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}
