import { TagClass, UniversalTag } from "./asn1";

/**
 * Encodes an ASN.1 definite-form length octet sequence (DER).
 */
export function encodeDerLength(length: number): Uint8Array {
  if (length < 128) {
    return new Uint8Array([length]);
  }
  const bytes: number[] = [];
  let temp = length;
  while (temp > 0) {
    bytes.unshift(temp & 0xff);
    temp >>>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

/**
 * Combines tag, length, and value into a complete DER TLV chunk.
 */
export function encodeDerTlv(
  tagNumber: number,
  tagClass: TagClass,
  constructed: boolean,
  valueBytes: Uint8Array,
): Uint8Array {
  if (tagNumber >= 31) {
    throw new Error(`High-tag numbers >= 31 not supported in DER encoder: ${tagNumber}`);
  }
  const tagByte = (tagClass << 6) | (constructed ? 0x20 : 0) | tagNumber;
  const lengthBytes = encodeDerLength(valueBytes.length);
  const result = new Uint8Array(1 + lengthBytes.length + valueBytes.length);
  result[0] = tagByte;
  result.set(lengthBytes, 1);
  result.set(valueBytes, 1 + lengthBytes.length);
  return result;
}

/**
 * Concatenates multiple byte arrays into one.
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((acc, curr) => acc + curr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Encodes a constructed SEQUENCE of children.
 */
export function encodeDerSequence(children: Uint8Array[]): Uint8Array {
  const content = concatBytes(...children);
  return encodeDerTlv(UniversalTag.Sequence, TagClass.Universal, true, content);
}

/**
 * Encodes a constructed SET of children.
 */
export function encodeDerSet(children: Uint8Array[]): Uint8Array {
  const content = concatBytes(...children);
  return encodeDerTlv(UniversalTag.Set, TagClass.Universal, true, content);
}

/**
 * Encodes an ASN.1 INTEGER.
 * Handles positive integers with MSB padding according to two's complement DER rules.
 */
export function encodeDerInteger(value: bigint | number | Uint8Array): Uint8Array {
  let bytes: Uint8Array;
  if (typeof value === "number") {
    value = BigInt(value);
  }
  if (typeof value === "bigint") {
    if (value === 0n) {
      bytes = new Uint8Array([0x00]);
    } else {
      let hex = value.toString(16);
      if (hex.length % 2 !== 0) hex = "0" + hex;
      const numBytes = hex.length / 2;
      bytes = new Uint8Array(numBytes);
      for (let i = 0; i < numBytes; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      }
    }
  } else {
    bytes = value;
  }

  // Remove redundant leading zeros, but keep one if MSB is set
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0x00 && (bytes[start + 1]! & 0x80) === 0) {
    start++;
  }
  const trimmed = bytes.subarray(start);

  // If MSB is set (>= 0x80), prepend 0x00 so it is not treated as a negative number
  if ((trimmed[0] ?? 0) >= 0x80) {
    const padded = new Uint8Array(trimmed.length + 1);
    padded[0] = 0x00;
    padded.set(trimmed, 1);
    return encodeDerTlv(UniversalTag.Integer, TagClass.Universal, false, padded);
  }

  return encodeDerTlv(UniversalTag.Integer, TagClass.Universal, false, trimmed);
}

/**
 * Encodes an ASN.1 BIT STRING.
 */
export function encodeDerBitString(bytes: Uint8Array, unusedBits = 0): Uint8Array {
  const payload = new Uint8Array(bytes.length + 1);
  payload[0] = unusedBits;
  payload.set(bytes, 1);
  return encodeDerTlv(UniversalTag.BitString, TagClass.Universal, false, payload);
}

/**
 * Encodes an ASN.1 OCTET STRING.
 */
export function encodeDerOctetString(bytes: Uint8Array): Uint8Array {
  return encodeDerTlv(UniversalTag.OctetString, TagClass.Universal, false, bytes);
}

/**
 * Encodes an ASN.1 NULL.
 */
export function encodeDerNull(): Uint8Array {
  return new Uint8Array([UniversalTag.Null, 0x00]);
}

/**
 * Encodes an ASN.1 BOOLEAN.
 */
export function encodeDerBoolean(val: boolean): Uint8Array {
  return new Uint8Array([UniversalTag.Boolean, 0x01, val ? 0xff : 0x00]);
}

/**
 * Encodes an ASN.1 OBJECT IDENTIFIER (OID).
 */
export function encodeDerOid(oidStr: string): Uint8Array {
  const parts = oidStr.split(".").map((s) => parseInt(s, 10));
  if (parts.length < 2) {
    throw new Error(`Invalid OID: ${oidStr}`);
  }
  const p0 = parts[0]!;
  const p1 = parts[1]!;
  const bytes: number[] = [p0 * 40 + p1];

  for (let i = 2; i < parts.length; i++) {
    let val = parts[i]!;
    if (val === 0) {
      bytes.push(0);
      continue;
    }
    const stack: number[] = [];
    while (val > 0) {
      stack.push(val & 0x7f);
      val >>>= 7;
    }
    for (let j = stack.length - 1; j >= 0; j--) {
      let b = stack[j]!;
      if (j > 0) b |= 0x80;
      bytes.push(b);
    }
  }

  return encodeDerTlv(UniversalTag.ObjectIdentifier, TagClass.Universal, false, new Uint8Array(bytes));
}

/**
 * Encodes a UTF8String.
 */
export function encodeDerUtf8String(str: string): Uint8Array {
  const bytes = new TextEncoder().encode(str);
  return encodeDerTlv(UniversalTag.UTF8String, TagClass.Universal, false, bytes);
}

/**
 * Encodes a PrintableString.
 */
export function encodeDerPrintableString(str: string): Uint8Array {
  const bytes = new TextEncoder().encode(str);
  return encodeDerTlv(UniversalTag.PrintableString, TagClass.Universal, false, bytes);
}

/**
 * Encodes an IA5String (ASCII).
 */
export function encodeDerIa5String(str: string): Uint8Array {
  const bytes = new TextEncoder().encode(str);
  return encodeDerTlv(UniversalTag.IA5String, TagClass.Universal, false, bytes);
}

/**
 * Encodes a UTCTime (YYMMDDHHMMSSZ).
 */
export function encodeDerUtcTime(date: Date): Uint8Array {
  const pad = (n: number) => n.toString().padStart(2, "0");
  const year = date.getUTCFullYear() % 100;
  const str = `${pad(year)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  return encodeDerTlv(UniversalTag.UTCTime, TagClass.Universal, false, new TextEncoder().encode(str));
}

/**
 * Encodes a GeneralizedTime (YYYYMMDDHHMMSSZ).
 */
export function encodeDerGeneralizedTime(date: Date): Uint8Array {
  const pad = (n: number) => n.toString().padStart(2, "0");
  const year = date.getUTCFullYear();
  const str = `${year}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  return encodeDerTlv(UniversalTag.GeneralizedTime, TagClass.Universal, false, new TextEncoder().encode(str));
}

/**
 * Encodes a validity time according to RFC 5280:
 * UTCTime for years 1950..2049, GeneralizedTime for years >= 2050.
 */
export function encodeDerTime(date: Date): Uint8Array {
  const year = date.getUTCFullYear();
  if (year >= 1950 && year < 2050) {
    return encodeDerUtcTime(date);
  }
  return encodeDerGeneralizedTime(date);
}

/**
 * Encodes a context-specific tagged element: [tagNumber]
 */
export function encodeDerContext(
  tagNumber: number,
  content: Uint8Array,
  constructed = true,
): Uint8Array {
  return encodeDerTlv(tagNumber, TagClass.ContextSpecific, constructed, content);
}

/**
 * Encodes an RDN sequence for a Distinguished Name.
 */
export interface RdnEntry {
  oid: string;
  value: string;
  isPrintable?: boolean;
}

export function encodeDistinguishedName(entries: RdnEntry[]): Uint8Array {
  const rdnSets: Uint8Array[] = [];
  for (const entry of entries) {
    if (!entry.value || entry.value.trim() === "") continue;
    const oidNode = encodeDerOid(entry.oid);
    const valueNode = entry.isPrintable
      ? encodeDerPrintableString(entry.value)
      : encodeDerUtf8String(entry.value);
    const attrTypeAndVal = encodeDerSequence([oidNode, valueNode]);
    const rdnSet = encodeDerSet([attrTypeAndVal]);
    rdnSets.push(rdnSet);
  }
  return encodeDerSequence(rdnSets);
}

/**
 * Converts IEEE P1363 ECDSA signature (r || s) to DER:
 * SEQUENCE { INTEGER r, INTEGER s }
 */
export function ecdsaP1363ToDer(rawSig: Uint8Array): Uint8Array {
  const half = rawSig.length / 2;
  const r = rawSig.subarray(0, half);
  const s = rawSig.subarray(half);
  const rInt = encodeDerInteger(r);
  const sInt = encodeDerInteger(s);
  return encodeDerSequence([rInt, sInt]);
}
