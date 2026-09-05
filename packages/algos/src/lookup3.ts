/**
 * Jenkins Lookup3 (hashlittle):
 * Bob Jenkins' 32-bit mixing function with 12-byte block accumulation (2006).
 */

const u32 = (n: number) => n >>> 0;
const rot = (x: number, k: number) => u32((x << k) | (x >>> (32 - k)));

export function jenkinsLookup3(data: Uint8Array, initval = 0): number {
  let length = data.length;
  let a = u32(0xdeadbeef + length + initval);
  let b = u32(0xdeadbeef + length + initval);
  let c = u32(0xdeadbeef + length + initval);

  let offset = 0;
  const view = new DataView(data.buffer, data.byteOffset, data.length);

  while (length > 12) {
    a = u32(a + view.getUint32(offset, true));
    b = u32(b + view.getUint32(offset + 4, true));
    c = u32(c + view.getUint32(offset + 8, true));

    // mix(a, b, c)
    a = u32(a - c); a ^= rot(c, 4);  c = u32(c + b);
    b = u32(b - a); b ^= rot(a, 6);  a = u32(a + c);
    c = u32(c - b); c ^= rot(b, 8);  b = u32(b + a);
    a = u32(a - c); a ^= rot(c, 16); c = u32(c + b);
    b = u32(b - a); b ^= rot(a, 19); a = u32(a + c);
    c = u32(c - b); c ^= rot(b, 4);  b = u32(b + a);

    offset += 12;
    length -= 12;
  }

  if (length === 0) return c;
  if (length >= 12) c = u32(c + (data[offset + 11]! << 24));
  if (length >= 11) c = u32(c + (data[offset + 10]! << 16));
  if (length >= 10) c = u32(c + (data[offset + 9]! << 8));
  if (length >= 9)  c = u32(c + data[offset + 8]!);
  if (length >= 8)  b = u32(b + (data[offset + 7]! << 24));
  if (length >= 7)  b = u32(b + (data[offset + 6]! << 16));
  if (length >= 6)  b = u32(b + (data[offset + 5]! << 8));
  if (length >= 5)  b = u32(b + data[offset + 4]!);
  if (length >= 4)  a = u32(a + (data[offset + 3]! << 24));
  if (length >= 3)  a = u32(a + (data[offset + 2]! << 16));
  if (length >= 2)  a = u32(a + (data[offset + 1]! << 8));
  if (length >= 1)  a = u32(a + data[offset]!);

  // final(a, b, c)
  c ^= b; c = u32(c - rot(b, 14));
  a ^= c; a = u32(a - rot(c, 11));
  b ^= a; b = u32(b - rot(a, 25));
  c ^= b; c = u32(c - rot(b, 16));
  a ^= c; a = u32(a - rot(c, 4));
  b ^= a; b = u32(b - rot(a, 14));
  c ^= b; c = u32(c - rot(b, 24));

  return u32(c);
}
