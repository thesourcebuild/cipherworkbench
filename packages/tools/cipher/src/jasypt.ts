import { cbc } from "@noble/ciphers/aes.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { md5 } from "@noble/hashes/legacy.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { createDes, decryptBlockMode, encryptBlockMode } from "@ocs/algos";

export const JASYPT_PROFILES = ["PBEWithMD5AndDES", "PBEWITHHMACSHA512ANDAES_256"] as const;

export type JasyptProfile = (typeof JASYPT_PROFILES)[number];

export interface JasyptProfileInfo {
  profile: JasyptProfile;
  saltLength: number;
  ivLength: number;
  blockSize: number;
}

const PROFILE_INFO: Record<JasyptProfile, JasyptProfileInfo> = {
  PBEWithMD5AndDES: {
    profile: "PBEWithMD5AndDES",
    saltLength: 8,
    ivLength: 0,
    blockSize: 8,
  },
  PBEWITHHMACSHA512ANDAES_256: {
    profile: "PBEWITHHMACSHA512ANDAES_256",
    saltLength: 16,
    ivLength: 16,
    blockSize: 16,
  },
};

export function jasyptProfileInfo(profile: JasyptProfile): JasyptProfileInfo {
  return PROFILE_INFO[profile];
}

function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

/**
 * SunJCE's PBEKeyFactory accepts only printable ASCII after Jasypt normalizes the Java password to NFC.
 * Both supported algorithms pass through that factory, including the PBKDF2/AES profile.
 */
export function jasyptPasswordBytes(password: string): Uint8Array {
  const normalized = password.normalize("NFC");
  if (normalized.length === 0) throw new Error("Jasypt requires a non-empty password.");

  const bytes = new Uint8Array(normalized.length);
  for (let index = 0; index < normalized.length; index++) {
    const codeUnit = normalized.charCodeAt(index);
    if (codeUnit < 0x20 || codeUnit > 0x7e) {
      throw new Error(
        "The SunJCE Jasypt profiles accept only printable ASCII password characters (U+0020 through U+007E).",
      );
    }
    bytes[index] = codeUnit & 0x7f;
  }
  return bytes;
}

export function deriveJasyptKeyMaterial(
  profile: JasyptProfile,
  password: string,
  salt: Uint8Array,
  iterations: number,
): { key: Uint8Array; iv: Uint8Array } {
  const info = jasyptProfileInfo(profile);
  if (salt.length !== info.saltLength) {
    throw new Error(
      `${profile} needs a ${info.saltLength}-byte salt; this one is ${salt.length}.`,
    );
  }
  if (!Number.isInteger(iterations) || iterations <= 0) {
    throw new Error("Jasypt's key-obtention iterations must be a positive integer.");
  }

  const passwordBytes = jasyptPasswordBytes(password);
  if (profile === "PBEWithMD5AndDES") {
    let material = md5(concatBytes(passwordBytes, salt));
    for (let iteration = 1; iteration < iterations; iteration++) material = md5(material);
    return { key: material.slice(0, 8), iv: material.slice(8, 16) };
  }

  return {
    key: pbkdf2(sha512, passwordBytes, salt, { c: iterations, dkLen: 32 }),
    iv: new Uint8Array(0),
  };
}

export function serializeJasyptFrame(
  profile: JasyptProfile,
  salt: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const info = jasyptProfileInfo(profile);
  if (salt.length !== info.saltLength) {
    throw new Error(
      `${profile} needs a ${info.saltLength}-byte salt; this one is ${salt.length}.`,
    );
  }
  if (iv.length !== info.ivLength) {
    throw new Error(
      `${profile} needs a ${info.ivLength}-byte framed IV; this one is ${iv.length}.`,
    );
  }
  if (ciphertext.length === 0 || ciphertext.length % info.blockSize !== 0) {
    throw new Error(
      `${profile} ciphertext must be a non-empty multiple of ${info.blockSize} bytes.`,
    );
  }
  return concatBytes(salt, iv, ciphertext);
}

export function parseJasyptFrame(
  profile: JasyptProfile,
  framed: Uint8Array,
): {
  salt: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
} {
  const info = jasyptProfileInfo(profile);
  const prefixLength = info.saltLength + info.ivLength;
  const ciphertextLength = framed.length - prefixLength;
  if (ciphertextLength <= 0 || ciphertextLength % info.blockSize !== 0) {
    throw new Error(
      `${profile} input must contain ${info.saltLength} salt bytes${info.ivLength ? `, ${info.ivLength} IV bytes` : ""}, and a non-empty ciphertext in ${info.blockSize}-byte blocks.`,
    );
  }
  return {
    salt: framed.slice(0, info.saltLength),
    iv: framed.slice(info.saltLength, prefixLength),
    ciphertext: framed.slice(prefixLength),
  };
}

export function jasyptEncrypt(
  profile: JasyptProfile,
  password: string,
  plaintext: Uint8Array,
  options: { iterations: number; salt: Uint8Array; iv?: Uint8Array },
): Uint8Array {
  const info = jasyptProfileInfo(profile);
  const framedIv = options.iv ?? new Uint8Array(0);
  if (framedIv.length !== info.ivLength) {
    throw new Error(
      `${profile} needs a ${info.ivLength}-byte IV; this one is ${framedIv.length}.`,
    );
  }
  const material = deriveJasyptKeyMaterial(profile, password, options.salt, options.iterations);
  const ciphertext =
    profile === "PBEWithMD5AndDES"
      ? encryptBlockMode(createDes(material.key), "cbc", plaintext, {
          iv: material.iv,
          padding: "pkcs5",
        })
      : cbc(material.key, framedIv).encrypt(plaintext);
  return serializeJasyptFrame(profile, options.salt, framedIv, ciphertext);
}

export function jasyptDecrypt(
  profile: JasyptProfile,
  password: string,
  framed: Uint8Array,
  iterations: number,
): Uint8Array {
  const parsed = parseJasyptFrame(profile, framed);
  const material = deriveJasyptKeyMaterial(profile, password, parsed.salt, iterations);
  return profile === "PBEWithMD5AndDES"
    ? decryptBlockMode(createDes(material.key), "cbc", parsed.ciphertext, {
        iv: material.iv,
        padding: "pkcs5",
      })
    : cbc(material.key, parsed.iv).decrypt(parsed.ciphertext);
}
