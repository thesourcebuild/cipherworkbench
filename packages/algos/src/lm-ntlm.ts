/**
 * Microsoft Windows LM (LAN Manager) and NTLM password hashes:
 * - LM Hash: Split-DES with standard magic plaintext "KGS!@#$%"
 * - NTLM Hash: MD4 of little-endian UTF-16 password string
 */

import { createDes } from "./des";
import { md4 } from "./md4";

function expandKey7to8(k7: Uint8Array): Uint8Array {
  const k8 = new Uint8Array(8);
  k8[0] = k7[0]! & 0xfe;
  k8[1] = ((k7[0]! << 7) | (k7[1]! >>> 1)) & 0xfe;
  k8[2] = ((k7[1]! << 6) | (k7[2]! >>> 2)) & 0xfe;
  k8[3] = ((k7[2]! << 5) | (k7[3]! >>> 3)) & 0xfe;
  k8[4] = ((k7[3]! << 4) | (k7[4]! >>> 4)) & 0xfe;
  k8[5] = ((k7[4]! << 3) | (k7[5]! >>> 5)) & 0xfe;
  k8[6] = ((k7[5]! << 2) | (k7[6]! >>> 6)) & 0xfe;
  k8[7] = (k7[6]! << 1) & 0xfe;
  return k8;
}

export function lmHash(password: string): string {
  const upper = password.toUpperCase();
  const passBytes = new Uint8Array(14);
  for (let i = 0; i < Math.min(14, upper.length); i++) {
    passBytes[i] = upper.charCodeAt(i) & 0xff;
  }

  const magic = new TextEncoder().encode("KGS!@#$%");
  const k1 = expandKey7to8(passBytes.subarray(0, 7));
  const k2 = expandKey7to8(passBytes.subarray(7, 14));

  const des1 = createDes(k1);
  const des2 = createDes(k2);

  const out1 = new Uint8Array(8);
  const out2 = new Uint8Array(8);
  des1.encryptBlock(magic, out1);
  des2.encryptBlock(magic, out2);

  const combined = new Uint8Array(16);
  combined.set(out1, 0);
  combined.set(out2, 8);

  return Array.from(combined)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function ntlmHash(password: string): string {
  const utf16 = new Uint8Array(password.length * 2);
  for (let i = 0; i < password.length; i++) {
    const code = password.charCodeAt(i);
    utf16[i * 2] = code & 0xff;
    utf16[i * 2 + 1] = (code >>> 8) & 0xff;
  }
  const hash = md4(utf16);
  return Array.from(hash)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
