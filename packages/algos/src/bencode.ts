/**
 * Bencode -- BitTorrent Protocol Serialization (BEP 0003).
 *
 * Implements:
 * - Integers: i<integer>e
 * - Byte strings: <length>:<contents>
 * - Lists: l<item1><item2>...e
 * - Dictionaries: d<key1><val1><key2><val2>...e (lexicographically ordered keys)
 * - Bidirectional encoder and parser.
 */

export type BencodeValue =
  | string
  | number
  | bigint
  | Uint8Array
  | BencodeValue[]
  | { [key: string]: BencodeValue };

export function bencodeEncode(value: BencodeValue): Uint8Array {
  const chunks: Uint8Array[] = [];

  function encodeValue(v: BencodeValue) {
    if (typeof v === "number" || typeof v === "bigint") {
      chunks.push(new TextEncoder().encode(`i${v}e`));
    } else if (typeof v === "string") {
      const bytes = new TextEncoder().encode(v);
      chunks.push(new TextEncoder().encode(`${bytes.length}:`));
      chunks.push(bytes);
    } else if (v instanceof Uint8Array) {
      chunks.push(new TextEncoder().encode(`${v.length}:`));
      chunks.push(v);
    } else if (Array.isArray(v)) {
      chunks.push(new TextEncoder().encode("l"));
      for (const item of v) {
        encodeValue(item);
      }
      chunks.push(new TextEncoder().encode("e"));
    } else if (typeof v === "object" && v !== null) {
      chunks.push(new TextEncoder().encode("d"));
      const keys = Object.keys(v).sort();
      for (const k of keys) {
        const kBytes = new TextEncoder().encode(k);
        chunks.push(new TextEncoder().encode(`${kBytes.length}:`));
        chunks.push(kBytes);
        encodeValue(v[k]!);
      }
      chunks.push(new TextEncoder().encode("e"));
    }
  }

  encodeValue(value);

  const totalLen = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(totalLen);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

export function bencodeDecode(data: Uint8Array): BencodeValue {
  let pos = 0;

  function parseNext(): BencodeValue {
    if (pos >= data.length) throw new Error("Unexpected end of Bencode input");

    const byte = data[pos]!;

    // Integer: i...e
    if (byte === 0x69) {
      // 'i'
      pos++;
      const end = data.indexOf(0x65, pos); // 'e'
      if (end === -1) throw new Error("Unterminated Bencode integer");
      const str = new TextDecoder().decode(data.subarray(pos, end));
      pos = end + 1;
      return parseInt(str, 10);
    }

    // List: l...e
    if (byte === 0x6c) {
      // 'l'
      pos++;
      const list: BencodeValue[] = [];
      while (pos < data.length && data[pos] !== 0x65) {
        list.push(parseNext());
      }
      if (pos >= data.length) throw new Error("Unterminated Bencode list");
      pos++; // skip 'e'
      return list;
    }

    // Dict: d...e
    if (byte === 0x64) {
      // 'd'
      pos++;
      const dict: { [key: string]: BencodeValue } = {};
      while (pos < data.length && data[pos] !== 0x65) {
        const keyVal = parseNext();
        const keyStr = typeof keyVal === "string" ? keyVal : new TextDecoder().decode(keyVal as Uint8Array);
        const val = parseNext();
        dict[keyStr] = val;
      }
      if (pos >= data.length) throw new Error("Unterminated Bencode dictionary");
      pos++; // skip 'e'
      return dict;
    }

    // String: <len>:...
    if (byte >= 0x30 && byte <= 0x39) {
      // '0'-'9'
      const colon = data.indexOf(0x3a, pos); // ':'
      if (colon === -1) throw new Error("Invalid Bencode string prefix");
      const lenStr = new TextDecoder().decode(data.subarray(pos, colon));
      const strLen = parseInt(lenStr, 10);
      pos = colon + 1;
      if (pos + strLen > data.length) throw new Error("Bencode string out of bounds");
      const strBytes = data.subarray(pos, pos + strLen);
      pos += strLen;
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(strBytes);
      } catch {
        return strBytes;
      }
    }

    throw new Error(`Unexpected character in Bencode input: 0x${byte.toString(16)} at index ${pos}`);
  }

  return parseNext();
}
