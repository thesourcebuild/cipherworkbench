import { encodeHex, timingSafeEqual, type ToolResult, type ToolResultField } from "@ocs/engine";
import {
  bcryptCostOf,
  deriveAnsiX963,
  deriveArgon2,
  deriveBalloon,
  deriveBcryptPbkdf,
  deriveCatena,
  deriveEvpKdf,
  deriveHkdf,
  deriveOpenPgpS2k,
  derivePbkdf2,
  deriveScrypt,
  deriveSp800108,
  deriveSshKdf,
  deriveTls12Prf,
  deriveYescrypt,
  hashBcrypt,
  verifyBcrypt,
} from "./bindings";
import { formatPhc, parsePhc, phcNumber, type PhcString } from "./phc";
import { OPENSSH_DEFAULT_ROUNDS } from "./pure";
import { resolveKdf, type ResolvedKdf } from "./resolve";
import type { KdfSpec } from "./spec";

/**
 * Every derivation here is synchronous and some deliberately take a long time — Argon2 at
 * 2 GiB, or scrypt at N=2^20, is seconds of solid work.
 *
 * A cost setting high enough to freeze the tab is a real possibility, which is why `K006`
 * warns before it happens rather than the code capping it. Capping would silently produce a
 * hash that does not match what the parameters claim.
 */

function formatBytes(count: number): string {
  if (count < 1024) return `${count} bytes`;
  if (count < 1024 * 1024) return `${(count / 1024).toFixed(0)} KiB`;
  if (count < 1024 * 1024 * 1024) return `${(count / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(count / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

function costFields(r: ResolvedKdf): ToolResultField[] {
  switch (r.toolId) {
    case "evpkdf":
      return [
        { label: "Construction", value: `EVP_BytesToKey with ${r.hashId.toUpperCase()}` },
        {
          label: "Iterations",
          value: r.iterations.toLocaleString(),
          hint:
            r.iterations === 1
              ? "OpenSSL's default, and what `openssl enc -k` used. Reproduces old files exactly."
              : "Non-default. `openssl enc` passes 1 unless told otherwise, so this will not match its output.",
        },
        /**
         * The key/IV split, which is the whole reason anyone derives 48 bytes.
         *
         * `EVP_BytesToKey` produces one stream and the caller cuts it: the first `keyLen` bytes
         * are the key and the next `ivLen` the IV. Showing where the cut falls for the common AES
         * sizes saves counting hex by eye, which is exactly the sort of thing to get wrong.
         */
        ...(r.keyLength >= 48
          ? [
              {
                label: "AES-256-CBC split",
                value: "key = first 32 bytes, IV = next 16",
                hint: "OpenSSL derives key and IV from one stream; the caller decides where to cut.",
              },
            ]
          : []),
      ];
    case "pbkdf2":
      return [
        { label: "Construction", value: `PBKDF2-HMAC-${r.hashId.toUpperCase()}` },
        { label: "Iterations", value: r.iterations.toLocaleString() },
      ];
    case "hkdf":
      return [
        { label: "Construction", value: `HKDF-${r.hashId.toUpperCase()}` },
        {
          label: "Salt",
          value: r.salt.length === 0 ? "(none, treated as zeros)" : `${r.salt.length} bytes`,
          hint:
            r.salt.length === 0
              ? "RFC 5869 permits an absent salt and substitutes a string of zeros. A legitimate choice, not an omission."
              : undefined,
        },
      ];
    case "scrypt":
      return [
        { label: "Construction", value: "scrypt" },
        {
          label: "Parameters",
          value: `N=${r.scryptN}, r=${r.scryptR}, p=${r.scryptP}`,
          // The number needed to judge whether the setting is reasonable, and not obvious
          // from the three parameters on their own.
          hint: `About ${formatBytes(128 * r.scryptN * r.scryptR)} of memory per guess.`,
        },
      ];
    case "argon2":
      return [
        { label: "Construction", value: r.argon2Variant },
        {
          label: "Parameters",
          value: `m=${r.argon2MemoryKib} KiB, t=${r.argon2Time}, p=${r.argon2Parallelism}`,
          hint: `About ${formatBytes(r.argon2MemoryKib * 1024)} of memory per guess.`,
        },
      ];
    case "bcryptpbkdf": {
      // One `bcrypt_hash` call per round per output block, and each of those runs 129 full
      // EksBlowfish key expansions -- the salted one plus the 128 in its loop.
      const blocks = Math.ceil(r.keyLength / 32);
      return [
        { label: "Construction", value: "bcrypt-PBKDF" },
        {
          label: "Rounds",
          value: r.rounds.toLocaleString(),
          hint: `${(blocks * r.rounds * 129).toLocaleString()} EksBlowfish key expansions in total${r.rounds === OPENSSH_DEFAULT_ROUNDS ? ", at `ssh-keygen`'s default" : ""}.`,
        },
        ...(r.keyLength >= 48
          ? [
              {
                label: "AES-256-CTR split",
                value: "key = first 32 bytes, IV = next 16",
                hint: "What OpenSSH cuts out of this stream for an `OPENSSH PRIVATE KEY` file.",
              },
            ]
          : []),
        {
          label: "Output is not a prefix",
          value: "Bytes are interleaved with a stride, not concatenated.",
          hint: "Asking for 32 bytes and asking for 64 give unrelated first 32. Deliberate, and unlike PBKDF2.",
        },
      ];
    }
    case "bcrypt":
      return [
        { label: "Construction", value: "bcrypt" },
        {
          label: "Cost",
          value: String(r.bcryptCost),
          hint: `2^${r.bcryptCost} = ${(2 ** r.bcryptCost).toLocaleString()} key-setup rounds.`,
        },
      ];
    default:
      return [];
  }
}

/** Derives, and returns the PHC encoding as well for the tools that define one. */
function derive(r: ResolvedKdf): { bytes: Uint8Array; encoded?: string } {
  switch (r.toolId) {
    case "evpkdf":
      return {
        bytes: deriveEvpKdf(r.hashId, r.password, r.salt, r.iterations, r.keyLength),
      };

    case "pbkdf2":
      return { bytes: derivePbkdf2(r.hashId, r.password, r.salt, r.iterations, r.keyLength) };

    case "hkdf":
      return { bytes: deriveHkdf(r.hashId, r.ikm, r.salt, r.info, r.keyLength) };

    case "scrypt": {
      const bytes = deriveScrypt(
        r.password,
        r.salt,
        r.scryptN,
        r.scryptR,
        r.scryptP,
        r.keyLength,
      );
      return {
        bytes,
        // The PHC form for scrypt records ln = log2(N), not N itself.
        encoded: formatPhc({
          id: "scrypt",
          params: {
            ln: String(Math.log2(r.scryptN)),
            r: String(r.scryptR),
            p: String(r.scryptP),
          },
          salt: r.salt,
          hash: bytes,
        }),
      };
    }

    case "argon2": {
      const bytes = deriveArgon2(
        r.argon2Variant,
        r.password,
        r.salt,
        r.argon2MemoryKib,
        r.argon2Time,
        r.argon2Parallelism,
        r.keyLength,
        r.argon2Secret,
        r.argon2AssociatedData,
      );
      return {
        bytes,
        encoded: formatPhc({
          id: r.argon2Variant,
          // 19 is Argon2 version 1.3, which RFC 9106 specifies and noble implements.
          version: 19,
          params: {
            m: String(r.argon2MemoryKib),
            t: String(r.argon2Time),
            p: String(r.argon2Parallelism),
          },
          salt: r.salt,
          hash: bytes,
        }),
      };
    }

    case "bcryptpbkdf":
      return { bytes: deriveBcryptPbkdf(r.password, r.salt, r.rounds, r.keyLength) };

    case "yescrypt":
      return { bytes: deriveYescrypt(r.password, r.salt, r.keyLength) };

    case "balloon":
      return { bytes: deriveBalloon(r.hashId, r.password, r.salt) };

    case "sp800-108":
      return { bytes: deriveSp800108(r.hashId, r.password, r.keyLength) };

    case "openpgp-s2k":
      return { bytes: deriveOpenPgpS2k(r.hashId, r.password, r.keyLength, "iterated-salted", r.salt) };

    case "ssh-kdf":
      return { bytes: deriveSshKdf(r.hashId, r.password, r.salt, r.keyLength) };

    case "tls12-prf":
      return { bytes: deriveTls12Prf(r.hashId, r.password, r.keyLength, "master secret", r.salt) };

    case "catena":
      return { bytes: deriveCatena(r.hashId, r.password, r.salt) };

    case "ansi-x963":
      return { bytes: deriveAnsiX963(r.hashId, r.password, r.keyLength, r.salt) };

    case "bcrypt": {
      const encoded = hashBcrypt(r.passwordText, r.bcryptCost);
      /**
       * bcrypt's output is the string, not raw bytes, and its format is not PHC despite the
       * dollar signs. The bytes returned are the ASCII of that string, so the result panel
       * has something to render in every output encoding rather than special-casing this one
       * tool.
       */
      return { bytes: new TextEncoder().encode(encoded), encoded };
    }

    default:
      throw new Error(`No derive path for KDF tool: ${r.toolId}`);
  }
}

function describePhcParams(phc: PhcString): string {
  const params = Object.entries(phc.params)
    .map(([k, v]) => `${k}=${v}`)
    .join(", ");
  const version = phc.version === undefined ? "" : ` v=${phc.version}`;
  return `${phc.id}${version}${params ? `, ${params}` : ""}, ${phc.salt.length}-byte salt`;
}

/**
 * Re-derives using the stored hash's own parameters, then compares in constant time.
 *
 * Taking the parameters from the stored string rather than from the form is the whole point.
 * Reading them from the form would produce a check that fails whenever the cost settings had
 * been changed since the hash was written, which is precisely when it most needs to work.
 */
function verify(r: ResolvedKdf): ToolResult {
  const stored = r.expected!.trim();

  if (r.toolId === "bcrypt") {
    const matched = verifyBcrypt(r.passwordText, stored);
    const cost = bcryptCostOf(stored);
    return {
      text: matched ? "MATCH" : "NO MATCH",
      fields: [
        {
          label: "Result",
          value: matched ? "The password matches this hash." : "The password does not match.",
        },
        cost === undefined
          ? { label: "Stored hash", value: "Could not read a bcrypt cost from it." }
          : { label: "Cost in stored hash", value: String(cost) },
      ],
    };
  }

  const parsed = parsePhc(stored);
  if (!parsed.ok) return { error: parsed.error };
  const phc = parsed.value;

  let recomputed: Uint8Array;

  if (r.toolId === "argon2") {
    if (!phc.id.startsWith("argon2")) {
      return { error: `That is a ${phc.id} hash, not an Argon2 one.` };
    }
    const m = phcNumber(phc, "m");
    const t = phcNumber(phc, "t");
    const p = phcNumber(phc, "p");
    if (m === undefined || t === undefined || p === undefined) {
      return { error: "The stored hash is missing one of its m, t or p parameters." };
    }
    const variant = phc.id === "argon2i" || phc.id === "argon2d" ? phc.id : "argon2id";
    // The secret and associated data are NOT in the PHC string by design — a pepper that
    // travelled with the hash would not be a pepper. They come from the form, which means
    // verification only succeeds if the same ones are supplied again.
    recomputed = deriveArgon2(
      variant,
      r.password,
      phc.salt,
      m,
      t,
      p,
      phc.hash.length,
      r.argon2Secret,
      r.argon2AssociatedData,
    );
  } else {
    if (phc.id !== "scrypt") {
      return { error: `That is a ${phc.id} hash, not an scrypt one.` };
    }
    const ln = phcNumber(phc, "ln");
    const blockR = phcNumber(phc, "r");
    const parallelP = phcNumber(phc, "p");
    if (ln === undefined || blockR === undefined || parallelP === undefined) {
      return { error: "The stored hash is missing one of its ln, r or p parameters." };
    }
    recomputed = deriveScrypt(
      r.password,
      phc.salt,
      2 ** ln,
      blockR,
      parallelP,
      phc.hash.length,
    );
  }

  const matched = timingSafeEqual(recomputed, phc.hash);
  return {
    text: matched ? "MATCH" : "NO MATCH",
    fields: [
      {
        label: "Result",
        value: matched ? "The password matches this hash." : "The password does not match.",
      },
      { label: "Parameters used", value: describePhcParams(phc) },
      ...(matched
        ? []
        : [
            {
              label: "Recomputed",
              value: encodeHex(recomputed),
              hint: `The stored hash holds ${encodeHex(phc.hash)}.`,
            },
          ]),
    ],
  };
}

/**
 * The `input` argument is deliberately unused.
 *
 * A KDF's inputs are its password and salt, which are options rather than the tool's byte
 * input, so the manifest sets `supportsFile: false` and the input panel has nothing to
 * contribute. Accepting and ignoring the parameter keeps the `ToolDefinition` signature
 * uniform, which is what lets one workbench serve every family.
 */
export async function computeKdf(spec: KdfSpec, _input: Uint8Array): Promise<ToolResult> {
  const result = resolveKdf(spec);
  if (!result.ok) return { error: result.problem };

  const r = result.resolved;

  try {
    if (r.mode === "verify") return verify(r);

    const { bytes, encoded } = derive(r);
    return {
      bytes,
      fields: [
        ...costFields(r),
        ...(encoded === undefined
          ? []
          : [
              {
                label: "Encoded form",
                value: encoded,
                hint: "Self-describing: this string carries the parameters and salt, so it is what you store and what Verify mode reads.",
              },
            ]),
      ],
    };
  } catch (error) {
    // noble throws on out-of-range parameters, such as an Argon2 memory below 8p KiB.
    return { error: error instanceof Error ? error.message : String(error) };
  }
}
