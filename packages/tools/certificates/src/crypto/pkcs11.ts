/**
 * RFC 7512: The PKCS #11 URI Scheme
 *
 * Implements standard parser, builder, validator, and attribute inspection for PKCS#11 URIs.
 * Used for referencing cryptographic hardware tokens, smart cards, HSMs, and stored keys/certificates
 * without exposing raw key material.
 *
 * Standard Syntax:
 * pkcs11:token=MyToken;object=MyKey;type=private?pin-value=1234&module-path=/usr/lib/opensc-pkcs11.so
 */

export type Pkcs11ObjectType = "cert" | "public" | "private" | "secret-key" | "data";

export interface Pkcs11UriAttributes {
  // Path Attributes (Token & Object Identifiers)
  token?: string;
  manufacturer?: string;
  serial?: string;
  model?: string;
  object?: string;
  type?: Pkcs11ObjectType;
  id?: string;
  idBytes?: Uint8Array;
  idHex?: string;
  slotDescription?: string;
  slotManufacturer?: string;
  slotId?: number;
  libraryDescription?: string;
  libraryManufacturer?: string;
  libraryVersion?: string;

  // Query Attributes (Module & PIN parameters)
  pinValue?: string;
  pinSource?: string;
  moduleName?: string;
  modulePath?: string;

  // Unknown / Vendor Extensions
  customPathAttributes?: Record<string, string>;
  customQueryAttributes?: Record<string, string>;
}

export interface Pkcs11Uri extends Pkcs11UriAttributes {
  rawUri: string;
  canonicalUri: string;
}

/**
 * Percent-encodes characters reserved in RFC 7512 path/query components (; ? & = %).
 */
export function encodePkcs11Value(val: string): string {
  return encodeURIComponent(val)
    .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/~/g, "%7E");
}

/**
 * Decodes RFC 7512 percent-encoded values.
 */
export function decodePkcs11Value(val: string): string {
  try {
    return decodeURIComponent(val);
  } catch {
    return val;
  }
}

/**
 * Converts a byte array to an RFC 7512 percent-encoded CKA_ID string (e.g. "%01%02%03").
 */
export function bytesToPkcs11Id(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const hex = bytes[i]!.toString(16).padStart(2, "0").toUpperCase();
    out += `%${hex}`;
  }
  return out;
}

/**
 * Parses percent-encoded CKA_ID string into raw bytes.
 */
export function pkcs11IdToBytes(idStr: string): Uint8Array {
  // If format is like %01%02%03 or %A1%B2
  const matches = idStr.match(/%[0-9A-Fa-f]{2}/g);
  if (matches && matches.join("").length === idStr.length) {
    const bytes = new Uint8Array(matches.length);
    for (let i = 0; i < matches.length; i++) {
      bytes[i] = parseInt(matches[i]!.slice(1), 16);
    }
    return bytes;
  }

  // If format is plain hex without %
  if (/^[0-9A-Fa-f]+$/.test(idStr) && idStr.length % 2 === 0) {
    const numBytes = idStr.length / 2;
    const bytes = new Uint8Array(numBytes);
    for (let i = 0; i < numBytes; i++) {
      bytes[i] = parseInt(idStr.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  // Fallback to UTF-8 bytes of decoded string
  return new TextEncoder().encode(decodePkcs11Value(idStr));
}

/**
 * Parses an RFC 7512 PKCS#11 URI string into structured attributes.
 */
export function parsePkcs11Uri(uriString: string): Pkcs11Uri {
  const trimmed = uriString.trim();
  if (!trimmed.toLowerCase().startsWith("pkcs11:")) {
    throw new Error("Invalid PKCS#11 URI: must begin with 'pkcs11:' scheme prefix");
  }

  const afterScheme = trimmed.slice(7); // Remove 'pkcs11:'
  const questionIdx = afterScheme.indexOf("?");
  const pathPart = questionIdx === -1 ? afterScheme : afterScheme.slice(0, questionIdx);
  const queryPart = questionIdx === -1 ? "" : afterScheme.slice(questionIdx + 1);

  const result: Pkcs11UriAttributes = {
    customPathAttributes: {},
    customQueryAttributes: {},
  };

  // 1. Parse Path Attributes (semicolon-separated)
  if (pathPart.length > 0) {
    const pathAttrs = pathPart.split(";");
    for (const attr of pathAttrs) {
      if (!attr.trim()) continue;
      const eqIdx = attr.indexOf("=");
      if (eqIdx === -1) {
        throw new Error(`Invalid PKCS#11 URI path attribute: missing '=' in '${attr}'`);
      }
      const rawKey = attr.slice(0, eqIdx).trim().toLowerCase();
      const rawVal = attr.slice(eqIdx + 1).trim();
      const val = decodePkcs11Value(rawVal);

      switch (rawKey) {
        case "token":
          result.token = val;
          break;
        case "manufacturer":
          result.manufacturer = val;
          break;
        case "serial":
          result.serial = val;
          break;
        case "model":
          result.model = val;
          break;
        case "object":
          result.object = val;
          break;
        case "type": {
          const lower = val.toLowerCase();
          if (["cert", "public", "private", "secret-key", "data"].includes(lower)) {
            result.type = lower as Pkcs11ObjectType;
          } else {
            result.type = val as Pkcs11ObjectType;
          }
          break;
        }
        case "id":
          result.id = val;
          result.idBytes = pkcs11IdToBytes(rawVal);
          result.idHex = Array.from(result.idBytes)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          break;
        case "slot-description":
          result.slotDescription = val;
          break;
        case "slot-manufacturer":
          result.slotManufacturer = val;
          break;
        case "slot-id": {
          const num = parseInt(val, 10);
          result.slotId = isNaN(num) ? undefined : num;
          break;
        }
        case "library-description":
          result.libraryDescription = val;
          break;
        case "library-manufacturer":
          result.libraryManufacturer = val;
          break;
        case "library-version":
          result.libraryVersion = val;
          break;
        default:
          result.customPathAttributes![rawKey] = val;
          break;
      }
    }
  }

  // 2. Parse Query Attributes (ampersand or semicolon separated)
  if (queryPart.length > 0) {
    const queryAttrs = queryPart.split(/[&;]/);
    for (const attr of queryAttrs) {
      if (!attr.trim()) continue;
      const eqIdx = attr.indexOf("=");
      if (eqIdx === -1) {
        throw new Error(`Invalid PKCS#11 URI query attribute: missing '=' in '${attr}'`);
      }
      const rawKey = attr.slice(0, eqIdx).trim().toLowerCase();
      const rawVal = attr.slice(eqIdx + 1).trim();
      const val = decodePkcs11Value(rawVal);

      switch (rawKey) {
        case "pin-value":
          result.pinValue = val;
          break;
        case "pin-source":
          result.pinSource = val;
          break;
        case "module-name":
          result.moduleName = val;
          break;
        case "module-path":
          result.modulePath = val;
          break;
        default:
          result.customQueryAttributes![rawKey] = val;
          break;
      }
    }
  }

  const canonicalUri = buildPkcs11Uri(result);

  return {
    ...result,
    rawUri: trimmed,
    canonicalUri,
  };
}

/**
 * Builds an RFC 7512 canonical PKCS#11 URI from attributes.
 */
export function buildPkcs11Uri(attrs: Pkcs11UriAttributes): string {
  const pathParts: string[] = [];

  // Standard path attributes in conventional canonical order
  if (attrs.token !== undefined) {
    pathParts.push(`token=${encodePkcs11Value(attrs.token)}`);
  }
  if (attrs.manufacturer !== undefined) {
    pathParts.push(`manufacturer=${encodePkcs11Value(attrs.manufacturer)}`);
  }
  if (attrs.serial !== undefined) {
    pathParts.push(`serial=${encodePkcs11Value(attrs.serial)}`);
  }
  if (attrs.model !== undefined) {
    pathParts.push(`model=${encodePkcs11Value(attrs.model)}`);
  }
  if (attrs.object !== undefined) {
    pathParts.push(`object=${encodePkcs11Value(attrs.object)}`);
  }
  if (attrs.type !== undefined) {
    pathParts.push(`type=${encodePkcs11Value(attrs.type)}`);
  }
  if (attrs.idBytes !== undefined) {
    pathParts.push(`id=${bytesToPkcs11Id(attrs.idBytes)}`);
  } else if (attrs.id !== undefined) {
    pathParts.push(`id=${attrs.id.startsWith("%") ? attrs.id : encodePkcs11Value(attrs.id)}`);
  }
  if (attrs.slotDescription !== undefined) {
    pathParts.push(`slot-description=${encodePkcs11Value(attrs.slotDescription)}`);
  }
  if (attrs.slotManufacturer !== undefined) {
    pathParts.push(`slot-manufacturer=${encodePkcs11Value(attrs.slotManufacturer)}`);
  }
  if (attrs.slotId !== undefined) {
    pathParts.push(`slot-id=${attrs.slotId}`);
  }
  if (attrs.libraryDescription !== undefined) {
    pathParts.push(`library-description=${encodePkcs11Value(attrs.libraryDescription)}`);
  }
  if (attrs.libraryManufacturer !== undefined) {
    pathParts.push(`library-manufacturer=${encodePkcs11Value(attrs.libraryManufacturer)}`);
  }
  if (attrs.libraryVersion !== undefined) {
    pathParts.push(`library-version=${encodePkcs11Value(attrs.libraryVersion)}`);
  }

  // Custom path attributes sorted for determinism
  if (attrs.customPathAttributes) {
    const keys = Object.keys(attrs.customPathAttributes).sort();
    for (const k of keys) {
      pathParts.push(`${encodePkcs11Value(k)}=${encodePkcs11Value(attrs.customPathAttributes[k]!)}`);
    }
  }

  const queryParts: string[] = [];

  // Query attributes
  if (attrs.pinValue !== undefined) {
    queryParts.push(`pin-value=${encodePkcs11Value(attrs.pinValue)}`);
  }
  if (attrs.pinSource !== undefined) {
    queryParts.push(`pin-source=${encodePkcs11Value(attrs.pinSource)}`);
  }
  if (attrs.moduleName !== undefined) {
    queryParts.push(`module-name=${encodePkcs11Value(attrs.moduleName)}`);
  }
  if (attrs.modulePath !== undefined) {
    queryParts.push(`module-path=${encodePkcs11Value(attrs.modulePath)}`);
  }

  // Custom query attributes
  if (attrs.customQueryAttributes) {
    const keys = Object.keys(attrs.customQueryAttributes).sort();
    for (const k of keys) {
      queryParts.push(`${encodePkcs11Value(k)}=${encodePkcs11Value(attrs.customQueryAttributes[k]!)}`);
    }
  }

  const pathStr = pathParts.join(";");
  const queryStr = queryParts.length > 0 ? `?${queryParts.join("&")}` : "";

  return `pkcs11:${pathStr}${queryStr}`;
}

/**
 * Validates whether a given string is a syntactically valid RFC 7512 PKCS#11 URI.
 */
export function validatePkcs11Uri(uriString: string): {
  valid: boolean;
  error?: string;
  uri?: Pkcs11Uri;
} {
  try {
    const uri = parsePkcs11Uri(uriString);
    return { valid: true, uri };
  } catch (err) {
    return {
      valid: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
