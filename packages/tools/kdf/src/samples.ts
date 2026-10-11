import type { ToolSample } from "@ocs/engine";
import {
  OPTION_MODE,
  OPTION_PASSWORD,
  OPTION_EXPECTED,
  OPTION_SALT,
  OPTION_USERNAME,
  OPTION_IKM,
  OPTION_INFO,
} from "./pure";

const BCRYPT_SAMPLES: readonly ToolSample[] = [
  {
    id: "simple",
    label: "Simple password (password)",
    note: "The canonical sample password.",
    text: "password",
  },
  {
    id: "passphrase",
    label: "Passphrase (correct horse battery staple)",
    note: "High-entropy multi-word passphrase from XKCD 936.",
    text: "correct horse battery staple",
  },
  {
    id: "boundary-72",
    label: "72-byte boundary password",
    note: "Exactly 72 bytes long: the maximum password length processed before Eksblowfish truncation.",
    text: "This is exactly 72 bytes long to test the bcrypt limit 12345678901234567",
  },
  {
    id: "truncated-long",
    label: "Long password (> 72 bytes, truncated)",
    note: "Exceeds 72 bytes. Unhashed bcrypt ignores trailing bytes; pre-hash variants hash all bytes.",
    text: "This password exceeds the seventy-two byte limit of standard bcrypt and any trailing characters are ignored",
  },
  {
    id: "hashcat",
    label: "Hashcat test vector (hashcat)",
    note: "Standard password used in Hashcat modes 3200, 25600, 25800, 30600, and 28400.",
    text: "hashcat",
  },
  {
    id: "verify-sample",
    label: "Verify mode check (abc)",
    note: "OpenBSD test vector in Verify mode with matching stored hash.",
    text: "abc",
    options: {
      [OPTION_MODE]: "verify",
      [OPTION_PASSWORD]: "abc",
      [OPTION_EXPECTED]: "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i",
    },
  },
];

const ARGON2_SAMPLES: readonly ToolSample[] = [
  {
    id: "simple",
    label: "Simple password (password)",
    note: "The canonical sample password with 16-byte salt.",
    text: "password",
    options: {
      [OPTION_SALT]: "00".repeat(16),
      saltEncoding: "hex",
    },
  },
  {
    id: "passphrase",
    label: "Passphrase (correct horse battery staple)",
    note: "High-entropy multi-word passphrase with 16-byte salt.",
    text: "correct horse battery staple",
    options: {
      [OPTION_SALT]: "00".repeat(16),
      saltEncoding: "hex",
    },
  },
];

const SCRYPT_SAMPLES: readonly ToolSample[] = [
  {
    id: "simple",
    label: "Simple password (password)",
    note: "The canonical sample password.",
    text: "password",
  },
  {
    id: "passphrase",
    label: "Passphrase (correct horse battery staple)",
    note: "High-entropy multi-word passphrase from XKCD 936.",
    text: "correct horse battery staple",
  },
  {
    id: "rfc7914",
    label: "RFC 7914 vector (password & NaCl)",
    note: "Standard RFC 7914 test vector with salt 'NaCl'.",
    text: "password",
    options: {
      [OPTION_PASSWORD]: "password",
      [OPTION_SALT]: "NaCl",
      saltEncoding: "utf-8",
    },
  },
];

const PBKDF2_SAMPLES: readonly ToolSample[] = [
  {
    id: "simple",
    label: "Simple password (password)",
    note: "The canonical sample password.",
    text: "password",
  },
  {
    id: "passphrase",
    label: "Passphrase (correct horse battery staple)",
    note: "High-entropy multi-word passphrase from XKCD 936.",
    text: "correct horse battery staple",
  },
  {
    id: "rfc6070",
    label: "RFC 6070 vector (password & salt)",
    note: "Standard RFC 6070 test vector with salt 'salt'.",
    text: "password",
    options: {
      [OPTION_PASSWORD]: "password",
      [OPTION_SALT]: "salt",
      saltEncoding: "utf-8",
    },
  },
];

const HKDF_SAMPLES: readonly ToolSample[] = [
  {
    id: "rfc5869-case1",
    label: "RFC 5869 Case 1 (22 bytes IKM)",
    note: "Standard RFC 5869 test vector with hex IKM, salt, and info.",
    text: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    options: {
      [OPTION_IKM]: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      ikmEncoding: "hex",
      [OPTION_SALT]: "000102030405060708090a0b0c",
      saltEncoding: "hex",
      [OPTION_INFO]: "f0f1f2f3f4f5f6f7f8f9",
      infoEncoding: "hex",
    },
  },
];

const HTPASSWD_SAMPLES: readonly ToolSample[] = [
  {
    id: "simple",
    label: "Simple password (password)",
    note: "Sample password with default username 'alice'.",
    text: "password",
    options: {
      [OPTION_USERNAME]: "alice",
      [OPTION_PASSWORD]: "password",
    },
  },
  {
    id: "passphrase",
    label: "Passphrase (correct horse battery staple)",
    note: "High-entropy passphrase with default username 'alice'.",
    text: "correct horse battery staple",
    options: {
      [OPTION_USERNAME]: "alice",
      [OPTION_PASSWORD]: "correct horse battery staple",
    },
  },
];

const BCRYPTPBKDF_SAMPLES: readonly ToolSample[] = [
  {
    id: "passphrase",
    label: "Passphrase (correct horse battery staple)",
    note: "High-entropy passphrase with salt.",
    text: "correct horse battery staple",
    options: {
      [OPTION_PASSWORD]: "correct horse battery staple",
      [OPTION_SALT]: "salt",
      saltEncoding: "utf-8",
    },
  },
];

const DEFAULT_KDF_SAMPLES: readonly ToolSample[] = [
  {
    id: "simple",
    label: "Simple password (password)",
    note: "The canonical sample password.",
    text: "password",
  },
  {
    id: "passphrase",
    label: "Passphrase (correct horse battery staple)",
    note: "High-entropy multi-word passphrase from XKCD 936.",
    text: "correct horse battery staple",
  },
];

export function samplesFor(toolId: string): readonly ToolSample[] | undefined {
  switch (toolId) {
    case "bcrypt":
      return BCRYPT_SAMPLES;
    case "argon2":
      return ARGON2_SAMPLES;
    case "scrypt":
      return SCRYPT_SAMPLES;
    case "pbkdf2":
      return PBKDF2_SAMPLES;
    case "hkdf":
      return HKDF_SAMPLES;
    case "htpasswd":
      return HTPASSWD_SAMPLES;
    case "bcryptpbkdf":
      return BCRYPTPBKDF_SAMPLES;
    case "evpkdf":
    case "bs-crypt":
    case "crypt3":
      return DEFAULT_KDF_SAMPLES;
    default:
      return undefined;
  }
}
