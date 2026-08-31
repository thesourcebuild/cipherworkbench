/**
 * RC4-drop[N] Stream Cipher.
 * Standard RC4 (Rivest Cipher 4 / ARC4) with the initial N bytes of keystream discarded
 * to mitigate Fluhrer-Mantin-Shamir (FMS) weak key and initial state correlation attacks.
 * Common parameterizations: RC4-drop768, RC4-drop1024, RC4-drop3072.
 */

export function rc4DropCrypt(key: Uint8Array, dropBytes: number, data: Uint8Array): Uint8Array {
  // 1. Key-Scheduling Algorithm (KSA)
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;

  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i]! + key[i % key.length]!) & 0xff;
    const temp = s[i]!;
    s[i] = s[j]!;
    s[j] = temp;
  }

  // 2. Discard first `dropBytes` of Pseudo-Random Generation (PRGA)
  let i = 0;
  j = 0;
  for (let d = 0; d < dropBytes; d++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]!) & 0xff;
    const temp = s[i]!;
    s[i] = s[j]!;
    s[j] = temp;
  }

  // 3. Encrypt / Decrypt data
  const out = new Uint8Array(data.length);
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]!) & 0xff;
    const temp = s[i]!;
    s[i] = s[j]!;
    s[j] = temp;
    const keystreamByte = s[(s[i]! + s[j]!) & 0xff]!;
    out[k] = data[k]! ^ keystreamByte;
  }

  return out;
}
