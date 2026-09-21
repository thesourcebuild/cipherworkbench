import { parseAsn1, TagClass, UniversalTag, type Asn1Node } from "./asn1";
import {
  encodeDerContext,
  encodeDerInteger,
  encodeDerNull,
  encodeDerOctetString,
  encodeDerOid,
  encodeDerSequence,
  encodeDerSet,
  encodeDerTlv,
} from "./encoder";
import { detectInputBytes, encodePem } from "./pem";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

export interface Pkcs12ExportOptions {
  certDers: Uint8Array[];
  privateKeyDer?: Uint8Array;
  password?: string;
  friendlyName?: string;
}

export interface Pkcs12ExportResult {
  der: Uint8Array;
  base64: string;
  certCount: number;
  hasPrivateKey: boolean;
  encrypted: boolean;
}

export interface Pkcs12DecodedResult {
  certs: Array<{ pem: string; der: Uint8Array }>;
  privateKey?: { pem: string; der: Uint8Array };
}

/**
 * Encodes a string as an ASN.1 BMPString (UniversalTag 0x1E, UTF-16BE).
 */
function encodeBmpString(str: string): Uint8Array {
  const bytes = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    bytes[i * 2] = (code >> 8) & 0xff;
    bytes[i * 2 + 1] = code & 0xff;
  }
  return encodeDerTlv(UniversalTag.BMPString, TagClass.Universal, false, bytes);
}

/**
 * RFC 7292 Appendix B: PKCS#12 Key Derivation Function.
 * Used for deriving MAC and legacy encryption keys from passwords.
 */
function pkcs12Kdf(
  id: number,
  password: string,
  salt: Uint8Array,
  iterations: number,
  dkLen: number,
): Uint8Array {
  const u = 32; // SHA-256 output length
  const v = 64; // SHA-256 block size

  const D = new Uint8Array(v).fill(id);

  const sLen = v * Math.ceil(salt.length / v);
  const S = new Uint8Array(sLen);
  for (let i = 0; i < sLen; i++) {
    S[i] = salt[i % salt.length]!;
  }

  let P: Uint8Array;
  if (password.length > 0) {
    const bmpBytes = new Uint8Array((password.length + 1) * 2);
    for (let i = 0; i < password.length; i++) {
      const code = password.charCodeAt(i);
      bmpBytes[i * 2] = (code >> 8) & 0xff;
      bmpBytes[i * 2 + 1] = code & 0xff;
    }
    bmpBytes[bmpBytes.length - 2] = 0;
    bmpBytes[bmpBytes.length - 1] = 0;

    const pLen = v * Math.ceil(bmpBytes.length / v);
    P = new Uint8Array(pLen);
    for (let i = 0; i < pLen; i++) {
      P[i] = bmpBytes[i % bmpBytes.length]!;
    }
  } else {
    P = new Uint8Array(0);
  }

  const I = new Uint8Array(S.length + P.length);
  I.set(S, 0);
  I.set(P, S.length);

  const c = Math.ceil(dkLen / u);
  const out = new Uint8Array(c * u);

  for (let i = 1; i <= c; i++) {
    const ai = new Uint8Array(D.length + I.length);
    ai.set(D, 0);
    ai.set(I, D.length);

    let h = sha256(ai);
    for (let iter = 1; iter < iterations; iter++) {
      h = sha256(h);
    }

    out.set(h, (i - 1) * u);

    if (i < c) {
      const B = new Uint8Array(v);
      for (let j = 0; j < v; j++) {
        B[j] = h[j % h.length]!;
      }

      for (let j = 0; j < I.length; j += v) {
        let carry = 1;
        for (let k = v - 1; k >= 0; k--) {
          const sum = I[j + k]! + B[k]! + carry;
          I[j + k] = sum & 0xff;
          carry = sum >> 8;
        }
      }
    }
  }

  return out.slice(0, dkLen);
}

/**
 * Encrypts data using PBES2 with PBKDF2 (HMAC-SHA256) and AES-256-CBC.
 */
async function encryptPbes2AesCbc(
  plaintext: Uint8Array,
  password: string,
): Promise<{ algorithmId: Uint8Array; encryptedData: Uint8Array }> {
  const salt = new Uint8Array(16);
  const iv = new Uint8Array(16);
  globalThis.crypto.getRandomValues(salt);
  globalThis.crypto.getRandomValues(iv);
  const iterations = 10000;

  const subtle = globalThis.crypto.subtle;
  const passwordBytes = new TextEncoder().encode(password);
  const baseKey = await subtle.importKey(
    "raw",
    passwordBytes as unknown as BufferSource,
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const encKey = await subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as unknown as BufferSource,
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt"],
  );

  const ciphertextBuf = await subtle.encrypt(
    { name: "AES-CBC", iv: iv as unknown as BufferSource },
    encKey,
    plaintext as unknown as BufferSource,
  );
  const ciphertext = new Uint8Array(ciphertextBuf);

  // PBKDF2 AlgorithmIdentifier: SEQUENCE { OID 1.2.840.113549.1.5.12, SEQUENCE { salt, iterations, prf (hmacWithSHA256 1.2.840.113549.2.9) } }
  const prfSeq = encodeDerSequence([
    encodeDerOid("1.2.840.113549.2.9"),
    encodeDerNull(),
  ]);
  const pbkdf2Params = encodeDerSequence([
    encodeDerOctetString(salt),
    encodeDerInteger(iterations),
    prfSeq,
  ]);
  const pbkdf2Alg = encodeDerSequence([
    encodeDerOid("1.2.840.113549.1.5.12"),
    pbkdf2Params,
  ]);

  // AES-256-CBC AlgorithmIdentifier: SEQUENCE { OID 2.16.840.1.101.3.4.1.42, OCTET STRING (iv) }
  const aesAlg = encodeDerSequence([
    encodeDerOid("2.16.840.1.101.3.4.1.42"),
    encodeDerOctetString(iv),
  ]);

  // PBES2 AlgorithmIdentifier: SEQUENCE { OID 1.2.840.113549.1.5.13, SEQUENCE { pbkdf2Alg, aesAlg } }
  const pbes2Params = encodeDerSequence([pbkdf2Alg, aesAlg]);
  const algorithmId = encodeDerSequence([
    encodeDerOid("1.2.840.113549.1.5.13"),
    pbes2Params,
  ]);

  return {
    algorithmId,
    encryptedData: encodeDerOctetString(ciphertext),
  };
}

/**
 * Decrypts PBES2 (AES-CBC + PBKDF2) encrypted data.
 */
async function decryptPbes2(
  encAlgNode: Asn1Node,
  encDataBytes: Uint8Array,
  password: string,
): Promise<Uint8Array> {
  const paramsSeq = encAlgNode.children[1];
  if (!paramsSeq || paramsSeq.children.length < 2) {
    throw new Error("Invalid PBES2 parameter sequence in PKCS#12 data.");
  }

  const kdfSeq = paramsSeq.children[0];
  const schemeSeq = paramsSeq.children[1];
  if (!kdfSeq || !schemeSeq) {
    throw new Error("Missing KDF or encryption scheme in PBES2 parameters.");
  }

  // Parse PBKDF2 params
  const kdfParams = kdfSeq.children[1];
  if (!kdfParams || kdfParams.children.length < 2) {
    throw new Error("Invalid PBKDF2 parameters in PBES2.");
  }

  const salt = kdfParams.children[0]!.asOctetString();
  const iterations = kdfParams.children[1]!.asIntegerNumber();

  // Parse AES-CBC IV
  const ivNode = schemeSeq.children[1];
  if (!ivNode) throw new Error("Missing IV for AES-CBC decryption.");
  const iv = ivNode.asOctetString();

  const subtle = globalThis.crypto.subtle;
  const passwordBytes = new TextEncoder().encode(password);
  const baseKey = await subtle.importKey(
    "raw",
    passwordBytes as unknown as BufferSource,
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const decKey = await subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as unknown as BufferSource,
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-CBC", length: 256 },
    false,
    ["decrypt"],
  );

  const decryptedBuf = await subtle.decrypt(
    { name: "AES-CBC", iv: iv as unknown as BufferSource },
    decKey,
    encDataBytes as unknown as BufferSource,
  );
  return new Uint8Array(decryptedBuf);
}

/**
 * Packages certificates and an optional private key into a PKCS#12 (.pfx / .p12) container.
 */
export async function encodePkcs12Archive(
  opts: Pkcs12ExportOptions,
): Promise<Pkcs12ExportResult> {
  if (opts.certDers.length === 0 && !opts.privateKeyDer) {
    throw new Error("Cannot create PKCS#12 archive: at least one certificate or private key is required.");
  }

  const hasPassword = Boolean(opts.password && opts.password.length > 0);
  const safeBags: Uint8Array[] = [];

  // 1. Certificate SafeBags
  for (let i = 0; i < opts.certDers.length; i++) {
    const certDer = opts.certDers[i]!;
    // CertBag: SEQUENCE { certId OID (x509Certificate 1.2.840.113549.1.9.22.1), [0] EXPLICIT OCTET STRING (certDer) }
    const certBagValue = encodeDerSequence([
      encodeDerOid("1.2.840.113549.1.9.22.1"),
      encodeDerContext(0, encodeDerOctetString(certDer), true),
    ]);

    // Optional attributes (friendlyName)
    const label = i === 0 ? opts.friendlyName || "Certificate" : `CA Certificate ${i}`;
    const friendlyNameAttr = encodeDerSequence([
      encodeDerOid("1.2.840.113549.1.9.20"),
      encodeDerSet([encodeBmpString(label)]),
    ]);

    const certSafeBag = encodeDerSequence([
      encodeDerOid("1.2.840.113549.1.12.10.1.3"), // certBag
      encodeDerContext(0, certBagValue, true),
      encodeDerSet([friendlyNameAttr]),
    ]);

    safeBags.push(certSafeBag);
  }

  // 2. Private Key SafeBag (if provided)
  if (opts.privateKeyDer) {
    const friendlyNameAttr = encodeDerSequence([
      encodeDerOid("1.2.840.113549.1.9.20"),
      encodeDerSet([encodeBmpString(opts.friendlyName || "Private Key")]),
    ]);

    if (hasPassword) {
      // ShroudedKeyBag: EncryptedPrivateKeyInfo with PBES2
      const encrypted = await encryptPbes2AesCbc(opts.privateKeyDer, opts.password!);
      const encKeyInfo = encodeDerSequence([encrypted.algorithmId, encrypted.encryptedData]);

      const keySafeBag = encodeDerSequence([
        encodeDerOid("1.2.840.113549.1.12.10.1.2"), // pkcs8ShroudedKeyBag
        encodeDerContext(0, encKeyInfo, true),
        encodeDerSet([friendlyNameAttr]),
      ]);
      safeBags.push(keySafeBag);
    } else {
      // Unencrypted KeyBag: raw PKCS#8 PrivateKeyInfo
      const keySafeBag = encodeDerSequence([
        encodeDerOid("1.2.840.113549.1.12.10.1.1"), // keyBag
        encodeDerContext(0, opts.privateKeyDer, true),
        encodeDerSet([friendlyNameAttr]),
      ]);
      safeBags.push(keySafeBag);
    }
  }

  // 3. SafeContents: SEQUENCE OF SafeBag
  const safeContents = encodeDerSequence(safeBags);

  // 4. AuthenticatedSafe: SEQUENCE OF ContentInfo
  // In our case, a single ContentInfo of type data (1.2.840.113549.1.7.1)
  const authSafeContentInfo = encodeDerSequence([
    encodeDerOid("1.2.840.113549.1.7.1"), // data
    encodeDerContext(0, encodeDerOctetString(safeContents), true),
  ]);
  const authenticatedSafe = encodeDerSequence([authSafeContentInfo]);

  // 5. Wrap AuthenticatedSafe in outer ContentInfo: SEQUENCE { OID data, [0] EXPLICIT OCTET STRING (authenticatedSafe) }
  const authSafeBytes = encodeDerOctetString(authenticatedSafe);
  const outerContentInfo = encodeDerSequence([
    encodeDerOid("1.2.840.113549.1.7.1"),
    encodeDerContext(0, authSafeBytes, true),
  ]);

  // 6. Optional MacData if password is provided
  let macDataNode: Uint8Array | undefined;
  if (hasPassword) {
    const macSalt = new Uint8Array(20);
    globalThis.crypto.getRandomValues(macSalt);
    const macIterations = 10000;

    // Compute HMAC-SHA256 over authenticatedSafe bytes using RFC 7292 Appendix B derived key
    const macKey = pkcs12Kdf(3, opts.password ?? "", macSalt, macIterations, 32);
    const macDigest = hmac(sha256, macKey, authenticatedSafe);

    // DigestInfo: SEQUENCE { AlgorithmIdentifier (SHA-256), OCTET STRING (digest) }
    const digestInfo = encodeDerSequence([
      encodeDerSequence([encodeDerOid("2.16.840.1.101.3.4.2.1"), encodeDerNull()]),
      encodeDerOctetString(macDigest),
    ]);

    macDataNode = encodeDerSequence([
      digestInfo,
      encodeDerOctetString(macSalt),
      encodeDerInteger(macIterations),
    ]);
  }

  // 7. PFX: SEQUENCE { INTEGER 3, authSafe ContentInfo, macData MacData OPTIONAL }
  const pfxElements: Uint8Array[] = [
    encodeDerInteger(3),
    outerContentInfo,
  ];
  if (macDataNode) {
    pfxElements.push(macDataNode);
  }

  const pfxDer = encodeDerSequence(pfxElements);
  let binary = "";
  for (let i = 0; i < pfxDer.length; i++) {
    binary += String.fromCharCode(pfxDer[i]!);
  }
  const base64 = btoa(binary);

  return {
    der: pfxDer,
    base64,
    certCount: opts.certDers.length,
    hasPrivateKey: Boolean(opts.privateKeyDer),
    encrypted: hasPassword,
  };
}

/**
 * Decodes a PKCS#12 (.pfx / .p12) container and extracts certificates and private key as PEM blocks.
 */
export async function decodePkcs12Archive(
  input: Uint8Array,
  password = "",
): Promise<Pkcs12DecodedResult> {
  const { der } = detectInputBytes(input);
  const pfxNode = parseAsn1(der);

  if (pfxNode.tagNumber !== UniversalTag.Sequence || pfxNode.children.length < 2) {
    throw new Error("Invalid PKCS#12 file: expected PFX SEQUENCE.");
  }

  const version = pfxNode.children[0]?.asIntegerNumber();
  if (version !== 3) {
    throw new Error(`Unsupported PKCS#12 version: ${version} (expected 3).`);
  }

  const authSafeContentInfo = pfxNode.children[1];
  if (!authSafeContentInfo || authSafeContentInfo.children.length < 2) {
    throw new Error("Invalid PKCS#12 file: missing AuthenticatedSafe ContentInfo.");
  }

  // Extract authSafe OCTET STRING
  const authSafeContext0 = authSafeContentInfo.children[1];
  let authSafeDer: Uint8Array | undefined;
  if (authSafeContext0) {
    if (authSafeContext0.tagNumber === UniversalTag.OctetString) {
      authSafeDer = authSafeContext0.asOctetString();
    } else if (authSafeContext0.children.length > 0) {
      authSafeDer = authSafeContext0.children[0]?.asOctetString() ?? authSafeContext0.children[0]?.valueBytes;
    }
  }

  if (!authSafeDer) {
    throw new Error("Could not extract AuthenticatedSafe octet string from PKCS#12 data.");
  }

  const authenticatedSafeNode = parseAsn1(authSafeDer);
  const certs: Array<{ pem: string; der: Uint8Array }> = [];
  let privateKey: { pem: string; der: Uint8Array } | undefined;

  for (const ci of authenticatedSafeNode.children) {
    const contentType = ci.children[0]?.asOid();
    const expNode = ci.children[1];
    if (!expNode) continue;

    let safeContentsDer: Uint8Array | undefined;

    if (contentType === "1.2.840.113549.1.7.1") {
      // Unencrypted data
      if (expNode.tagNumber === UniversalTag.OctetString) {
        safeContentsDer = expNode.asOctetString();
      } else if (expNode.children[0]?.tagNumber === UniversalTag.OctetString) {
        safeContentsDer = expNode.children[0]!.asOctetString();
      }
    } else if (contentType === "1.2.840.113549.1.7.6") {
      // encryptedData
      // Sequence { Version, EncryptedContentInfo }
      const encDataSeq = expNode.children[0];
      const encContentInfo = encDataSeq?.children.find((c) => c.children.length >= 2);
      if (encContentInfo) {
        const algId = encContentInfo.children[1];
        const encBytesNode = encContentInfo.children[2];
        if (algId && encBytesNode) {
          const encBytes = encBytesNode.tagNumber === UniversalTag.OctetString
            ? encBytesNode.asOctetString()
            : encBytesNode.valueBytes;
          try {
            safeContentsDer = await decryptPbes2(algId, encBytes, password);
          } catch (err) {
            throw new Error(`Failed to decrypt encryptedData in PKCS#12: ${err instanceof Error ? err.message : String(err)} (is the password correct?)`);
          }
        }
      }
    }

    if (!safeContentsDer) continue;

    let safeContentsNode: Asn1Node;
    try {
      safeContentsNode = parseAsn1(safeContentsDer);
    } catch {
      continue;
    }

    for (const bag of safeContentsNode.children) {
      const bagId = bag.children[0]?.asOid();
      const bagValContext = bag.children[1];
      if (!bagId || !bagValContext) continue;

      // 1. certBag
      if (bagId === "1.2.840.113549.1.12.10.1.3") {
        const certBagNode = bagValContext.children[0];
        if (certBagNode) {
          const certType = certBagNode.children[0]?.asOid();
          const certValContext = certBagNode.children[1];
          if (certType === "1.2.840.113549.1.9.22.1" && certValContext) {
            const certDer = certValContext.tagNumber === UniversalTag.OctetString
              ? certValContext.asOctetString()
              : certValContext.children[0]?.asOctetString() ?? certValContext.valueBytes;
            certs.push({
              der: certDer,
              pem: encodePem("CERTIFICATE", certDer),
            });
          }
        }
      }

      // 2. unencrypted keyBag
      if (bagId === "1.2.840.113549.1.12.10.1.1") {
        const pkcs8Node = bagValContext.children[0] ?? bagValContext;
        const keyDer = pkcs8Node.raw;
        privateKey = {
          der: keyDer,
          pem: encodePem("PRIVATE KEY", keyDer),
        };
      }

      // 3. pkcs8ShroudedKeyBag
      if (bagId === "1.2.840.113549.1.12.10.1.2") {
        const encKeyInfo = bagValContext.children[0];
        if (encKeyInfo && encKeyInfo.children.length >= 2) {
          const algId = encKeyInfo.children[0]!;
          const encDataNode = encKeyInfo.children[1]!;
          const encBytes = encDataNode.tagNumber === UniversalTag.OctetString
            ? encDataNode.asOctetString()
            : encDataNode.valueBytes;

          try {
            const decKeyDer = await decryptPbes2(algId, encBytes, password);
            privateKey = {
              der: decKeyDer,
              pem: encodePem("PRIVATE KEY", decKeyDer),
            };
          } catch (err) {
            throw new Error(`Failed to decrypt private key in PKCS#12 archive: ${err instanceof Error ? err.message : String(err)} (is the password correct?)`);
          }
        }
      }
    }
  }

  return { certs, privateKey };
}
