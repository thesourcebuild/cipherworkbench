/**
 * Lightweight, robust ASN.1 BER/DER parser in pure TypeScript.
 *
 * Implements Tag-Length-Value (TLV) parsing conforming to ITU-T X.690 / ISO/IEC 8825-1.
 * Supports all standard primitive and constructed tags, short and long definite form lengths,
 * context-specific tags, strings (UTF8, Printable, IA5, BMP), time (UTCTime, GeneralizedTime),
 * integers, bit strings, and object identifiers (OIDs).
 */

export enum TagClass {
  Universal = 0,
  Application = 1,
  ContextSpecific = 2,
  Private = 3,
}

export enum UniversalTag {
  Boolean = 0x01,
  Integer = 0x02,
  BitString = 0x03,
  OctetString = 0x04,
  Null = 0x05,
  ObjectIdentifier = 0x06,
  Enumerated = 0x0a,
  UTF8String = 0x0c,
  PrintableString = 0x13,
  TeletexString = 0x14,
  IA5String = 0x16,
  UTCTime = 0x17,
  GeneralizedTime = 0x18,
  VisibleString = 0x1a,
  BMPString = 0x1e,
  Sequence = 0x10,
  Set = 0x11,
}

export interface Asn1Node {
  tagClass: TagClass;
  constructed: boolean;
  tagNumber: number;
  headerLength: number;
  length: number;
  raw: Uint8Array;
  valueBytes: Uint8Array;
  children: Asn1Node[];

  // Helper conversion methods
  asBoolean(): boolean;
  asIntegerBigInt(): bigint;
  asIntegerNumber(): number;
  asIntegerHex(): string;
  asBitString(): { unusedBits: number; bytes: Uint8Array };
  asOctetString(): Uint8Array;
  asOid(): string;
  asString(): string;
  asDate(): Date;
  findChild(tagNumber: number, tagClass?: TagClass): Asn1Node | undefined;
  findChildren(tagNumber: number, tagClass?: TagClass): Asn1Node[];
  dump(depth?: number): string;
}

class Asn1NodeImpl implements Asn1Node {
  constructor(
    public tagClass: TagClass,
    public constructed: boolean,
    public tagNumber: number,
    public headerLength: number,
    public length: number,
    public raw: Uint8Array,
    public valueBytes: Uint8Array,
    public children: Asn1Node[] = [],
  ) {}

  asBoolean(): boolean {
    if (this.valueBytes.length === 0) return false;
    return (this.valueBytes[0] ?? 0) !== 0;
  }

  asIntegerBigInt(): bigint {
    if (this.valueBytes.length === 0) return 0n;
    const bytes = this.valueBytes;
    const b0 = bytes[0] ?? 0;
    const isNegative = (b0 & 0x80) !== 0;
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i] ?? 0;
      hex += b.toString(16).padStart(2, "0");
    }
    let value = BigInt("0x" + hex);
    if (isNegative) {
      const bits = BigInt(bytes.length * 8);
      value = value - (1n << bits);
    }
    return value;
  }

  asIntegerNumber(): number {
    return Number(this.asIntegerBigInt());
  }

  asIntegerHex(): string {
    const bytes = this.valueBytes;
    if (bytes.length === 0) return "00";
    let hex = "";
    let start = 0;
    const b0 = bytes[0] ?? 0;
    const b1 = bytes[1] ?? 0;
    if (bytes.length > 1 && b0 === 0x00 && (b1 & 0x80) !== 0) {
      start = 1;
    }
    for (let i = start; i < bytes.length; i++) {
      if (hex.length > 0) hex += ":";
      const b = bytes[i] ?? 0;
      hex += b.toString(16).padStart(2, "0");
    }
    return hex.toLowerCase();
  }

  asBitString(): { unusedBits: number; bytes: Uint8Array } {
    if (this.valueBytes.length === 0) {
      return { unusedBits: 0, bytes: new Uint8Array(0) };
    }
    const unusedBits = this.valueBytes[0] ?? 0;
    const bytes = this.valueBytes.slice(1);
    return { unusedBits, bytes };
  }

  asOctetString(): Uint8Array {
    return this.valueBytes;
  }

  asOid(): string {
    const bytes = this.valueBytes;
    if (bytes.length === 0) return "";
    const first = bytes[0] ?? 0;
    const firstNum = Math.floor(first / 40);
    const secondNum = first % 40;
    const parts: string[] = [firstNum.toString(), secondNum.toString()];

    let current = 0n;
    for (let i = 1; i < bytes.length; i++) {
      const b = bytes[i] ?? 0;
      current = (current << 7n) | BigInt(b & 0x7f);
      if ((b & 0x80) === 0) {
        parts.push(current.toString());
        current = 0n;
      }
    }
    return parts.join(".");
  }

  asString(): string {
    if (this.tagClass === TagClass.Universal && this.tagNumber === UniversalTag.BMPString) {
      const chars: string[] = [];
      for (let i = 0; i + 1 < this.valueBytes.length; i += 2) {
        const b0 = this.valueBytes[i] ?? 0;
        const b1 = this.valueBytes[i + 1] ?? 0;
        const code = (b0 << 8) | b1;
        chars.push(String.fromCharCode(code));
      }
      return chars.join("");
    }
    return new TextDecoder("utf-8", { fatal: false }).decode(this.valueBytes);
  }

  asDate(): Date {
    const str = this.asString();
    if (this.tagNumber === UniversalTag.UTCTime) {
      const m = str.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);
      if (!m || !m[1] || !m[2] || !m[3] || !m[4] || !m[5]) {
        throw new Error(`Invalid UTCTime format: ${str}`);
      }
      let year = parseInt(m[1], 10);
      year += year >= 50 ? 1900 : 2000;
      const month = parseInt(m[2], 10) - 1;
      const day = parseInt(m[3], 10);
      const hours = parseInt(m[4], 10);
      const mins = parseInt(m[5], 10);
      const secs = m[6] ? parseInt(m[6], 10) : 0;
      return new Date(Date.UTC(year, month, day, hours, mins, secs));
    } else if (this.tagNumber === UniversalTag.GeneralizedTime) {
      const m = str.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/);
      if (!m || !m[1] || !m[2] || !m[3] || !m[4] || !m[5] || !m[6]) {
        throw new Error(`Invalid GeneralizedTime format: ${str}`);
      }
      const year = parseInt(m[1], 10);
      const month = parseInt(m[2], 10) - 1;
      const day = parseInt(m[3], 10);
      const hours = parseInt(m[4], 10);
      const mins = parseInt(m[5], 10);
      const secs = parseInt(m[6], 10);
      return new Date(Date.UTC(year, month, day, hours, mins, secs));
    }
    throw new Error(`Tag is not a time tag: ${this.tagNumber}`);
  }

  findChild(tagNumber: number, tagClass: TagClass = TagClass.Universal): Asn1Node | undefined {
    return this.children.find((c) => c.tagNumber === tagNumber && c.tagClass === tagClass);
  }

  findChildren(tagNumber: number, tagClass: TagClass = TagClass.Universal): Asn1Node[] {
    return this.children.filter((c) => c.tagNumber === tagNumber && c.tagClass === tagClass);
  }

  dump(depth = 0): string {
    const pad = "  ".repeat(depth);
    let desc = `${pad}[${tagClassLabel(this.tagClass)}] Tag:${this.tagNumber} Len:${this.length}`;
    if (this.constructed) {
      desc += ` (Constructed, ${this.children.length} items)`;
      return [desc, ...this.children.map((c) => c.dump(depth + 1))].join("\n");
    }

    if (this.tagClass === TagClass.Universal) {
      switch (this.tagNumber) {
        case UniversalTag.Boolean:
          desc += ` = ${this.asBoolean()}`;
          break;
        case UniversalTag.Integer:
          desc += ` = 0x${this.asIntegerHex()}`;
          break;
        case UniversalTag.ObjectIdentifier:
          desc += ` = ${this.asOid()}`;
          break;
        case UniversalTag.UTF8String:
        case UniversalTag.PrintableString:
        case UniversalTag.IA5String:
        case UniversalTag.VisibleString:
        case UniversalTag.BMPString:
          desc += ` = "${this.asString()}"`;
          break;
        case UniversalTag.UTCTime:
        case UniversalTag.GeneralizedTime:
          try {
            desc += ` = ${this.asDate().toISOString()}`;
          } catch {
            desc += ` = ${this.asString()}`;
          }
          break;
        case UniversalTag.BitString:
          desc += ` (BitString ${Math.max(0, this.valueBytes.length - 1)} bytes)`;
          break;
        case UniversalTag.OctetString:
          desc += ` (OctetString ${this.valueBytes.length} bytes)`;
          break;
      }
    }
    return desc;
  }
}

function tagClassLabel(cls: TagClass): string {
  switch (cls) {
    case TagClass.Universal:
      return "UNIVERSAL";
    case TagClass.Application:
      return "APPLICATION";
    case TagClass.ContextSpecific:
      return "CONTEXT";
    case TagClass.Private:
      return "PRIVATE";
  }
}

/**
 * Parse a DER or BER byte array into an Asn1Node tree.
 */
export function parseAsn1(bytes: Uint8Array): Asn1Node {
  if (bytes.length === 0) {
    throw new Error("Cannot parse empty ASN.1 buffer");
  }
  const { node } = parseOne(bytes, 0);
  return node;
}

/**
 * Parse one TLV starting at offset.
 */
export function parseOne(
  bytes: Uint8Array,
  offset: number,
): { node: Asn1Node; nextOffset: number } {
  if (offset >= bytes.length) {
    throw new Error(`Offset ${offset} out of bounds (${bytes.length})`);
  }

  const startOffset = offset;
  const initialByte = bytes[offset++];
  if (initialByte === undefined) {
    throw new Error("Unexpected end of ASN.1 buffer");
  }

  const tagClass = ((initialByte >> 6) & 0x03) as TagClass;
  const constructed = (initialByte & 0x20) !== 0;
  let tagNumber = initialByte & 0x1f;

  if (tagNumber === 0x1f) {
    tagNumber = 0;
    while (offset < bytes.length) {
      const b = bytes[offset++];
      if (b === undefined) break;
      tagNumber = (tagNumber << 7) | (b & 0x7f);
      if ((b & 0x80) === 0) break;
    }
  }

  if (offset >= bytes.length) {
    throw new Error("Unexpected end of ASN.1 buffer while reading length");
  }

  const lenByte = bytes[offset++];
  if (lenByte === undefined) {
    throw new Error("Unexpected end of ASN.1 buffer while reading length");
  }

  let length = 0;

  if (lenByte < 0x80) {
    length = lenByte;
  } else if (lenByte === 0x80) {
    let scan = offset;
    while (scan + 1 < bytes.length) {
      if (bytes[scan] === 0x00 && bytes[scan + 1] === 0x00) {
        break;
      }
      scan++;
    }
    length = scan - offset;
  } else {
    const numOctets = lenByte & 0x7f;
    if (offset + numOctets > bytes.length) {
      throw new Error(`Length octets exceed buffer size at offset ${offset}`);
    }
    for (let i = 0; i < numOctets; i++) {
      const b = bytes[offset++];
      length = (length << 8) | (b ?? 0);
    }
  }

  const headerLength = offset - startOffset;
  const totalLength = headerLength + length;
  if (startOffset + totalLength > bytes.length) {
    throw new Error(
      `TLV length ${totalLength} exceeds available bytes from offset ${startOffset} (total ${bytes.length})`,
    );
  }

  const raw = bytes.slice(startOffset, startOffset + totalLength);
  const valueBytes = bytes.slice(offset, offset + length);
  const nextOffset = offset + length;

  const children: Asn1Node[] = [];
  if (constructed) {
    let childOffset = 0;
    while (childOffset < valueBytes.length) {
      try {
        const { node: child, nextOffset: nextChildOffset } = parseOne(valueBytes, childOffset);
        children.push(child);
        childOffset = nextChildOffset;
      } catch {
        break;
      }
    }
  }

  const node = new Asn1NodeImpl(
    tagClass,
    constructed,
    tagNumber,
    headerLength,
    length,
    raw,
    valueBytes,
    children,
  );

  return { node, nextOffset };
}
