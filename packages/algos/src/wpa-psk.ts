/**
 * WPA-PSK (Wi-Fi Protected Access Pre-Shared Key):
 * IEEE 802.11i Pairwise Master Key (PMK) derivation using PBKDF2-HMAC-SHA1 with 4096 iterations.
 */

import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha1 } from "@noble/hashes/legacy.js";

export function wpaPsk(passphrase: string, ssid: string): Uint8Array {
  const passBytes = new TextEncoder().encode(passphrase);
  const saltBytes = new TextEncoder().encode(ssid);
  return pbkdf2(sha1, passBytes, saltBytes, { c: 4096, dkLen: 32 });
}
