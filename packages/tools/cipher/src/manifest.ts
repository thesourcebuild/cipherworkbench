import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import {
  CIPHER_TOOLS,
  hasConditionalCipherStreaming,
  type CipherToolMeta,
} from "./catalogue/tool-meta";

/**
 * `latin1` is offered here and in no other family.
 *
 * Decrypted output is very often text, and rendering it as bytes when the user is trying to
 * read a message is unhelpful. It is still not the default — the first entry is hex, because
 * plenty of decrypted output is not text and mojibake would be worse than honest bytes.
 */
const CIPHER_OUTPUT_ENCODINGS: readonly OutputEncoding[] = [
  "hex-upper",
  "hex",
  "base64",
  "base64url",
  "latin1",
];

const FERNET_OUTPUT_ENCODINGS: readonly OutputEncoding[] = [
  "base64url",
  "hex-upper",
  "hex",
  "base64",
  "latin1",
];

/** StandardPBEStringEncryptor emits Base64 by default or uppercase hexadecimal when configured. */
const JASYPT_OUTPUT_ENCODINGS: readonly OutputEncoding[] = [
  "base64",
  "hex-upper",
  "hex",
  "utf-8",
  "latin1",
];

function toManifest(meta: CipherToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "cipher",
    category: meta.category,
    tags: [...meta.tags],
    summary: meta.summary,
    // The first family where `inverse` is decryption rather than verification.
    directions: ["forward", "inverse"],
    security: meta.security,
    outputEncodings:
      meta.id === "fernet"
        ? FERNET_OUTPUT_ENCODINGS
        : meta.id === "jasypt"
          ? JASYPT_OUTPUT_ENCODINGS
          : CIPHER_OUTPUT_ENCODINGS,
    readsInput: true,
    supportsVerify: meta.id !== "cipher-image",
    supportsFile: true,
    // Static true means every configuration streams; conditional support is resolved from the spec.
    streaming: meta.streaming ?? false,
    ...(hasConditionalCipherStreaming(meta) ? { conditionalStreaming: true } : {}),
    ...(meta.id === "cipher-image"
      ? {
          sourcePolicy: {
            semantics: "bytes" as const,
            accept: [".bmp", "image/bmp", "image/x-ms-bmp"],
          },
        }
      : {}),
  };
}

export const CIPHER_MANIFESTS: readonly ToolManifest[] = CIPHER_TOOLS.map(toManifest);
