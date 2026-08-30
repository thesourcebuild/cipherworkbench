/**
 * HKDF-Expand-Label -- RFC 8446 Section 7.1 (TLS 1.3 / QUIC / HPKE Key Schedule).
 *
 * Implements structured label and context serialization for HKDF expansion:
 * HkdfLabel = uint16 length || opaque label<7..255> || opaque context<0..255>
 */

export interface HkdfLabelOptions {
  labelPrefix?: string; // default "tls13 "
}

/**
 * Encodes the structured HkdfLabel byte payload
 */
export function formatHkdfLabel(
  length: number,
  label: string | Uint8Array,
  context: Uint8Array = new Uint8Array(0),
  options: HkdfLabelOptions = {},
): Uint8Array {
  const prefix = options.labelPrefix ?? "tls13 ";
  const fullLabelStr = typeof label === "string" ? prefix + label : label;
  const labelBytes = typeof fullLabelStr === "string" ? new TextEncoder().encode(fullLabelStr) : fullLabelStr;

  const totalLen = 2 + 1 + labelBytes.length + 1 + context.length;
  const out = new Uint8Array(totalLen);

  // 1. uint16 length
  out[0] = (length >> 8) & 0xff;
  out[1] = length & 0xff;

  // 2. opaque label<7..255>
  out[2] = labelBytes.length & 0xff;
  out.set(labelBytes, 3);

  // 3. opaque context<0..255>
  const ctxOffset = 3 + labelBytes.length;
  out[ctxOffset] = context.length & 0xff;
  if (context.length > 0) {
    out.set(context, ctxOffset + 1);
  }

  return out;
}

/**
 * Computes HKDF-Expand-Label using standard HKDF expansion function
 */
export function hkdfExpandLabel(
  hkdfExpandFn: (secret: Uint8Array, info: Uint8Array, length: number) => Uint8Array,
  secret: Uint8Array,
  label: string | Uint8Array,
  context: Uint8Array = new Uint8Array(0),
  length: number = 32,
  options: HkdfLabelOptions = {},
): Uint8Array {
  const formattedInfo = formatHkdfLabel(length, label, context, options);
  return hkdfExpandFn(secret, formattedInfo, length);
}
