/**
 * Comprehensive OID dictionary for X.509 certificates and PKCS#10 CSRs.
 */

export const DN_SHORT_NAMES: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.9": "STREET",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.12": "TITLE",
  "2.5.4.4": "SN",
  "2.5.4.42": "GN",
  "2.5.4.5": "serialNumber",
  "1.2.840.113549.1.9.1": "emailAddress",
};

export const DN_LONG_NAMES: Record<string, string> = {
  "2.5.4.3": "Common Name",
  "2.5.4.6": "Country",
  "2.5.4.7": "Locality / City",
  "2.5.4.8": "State / Province",
  "2.5.4.9": "Street Address",
  "2.5.4.10": "Organization",
  "2.5.4.11": "Organizational Unit",
  "2.5.4.12": "Title",
  "2.5.4.4": "Surname",
  "2.5.4.42": "Given Name",
  "2.5.4.5": "Serial Number",
  "1.2.840.113549.1.9.1": "Email Address",
};

export interface SignatureAlgorithmDetails {
  name: string;
  hash?: "SHA-256" | "SHA-384" | "SHA-512" | "SHA-224" | "SHA-1" | "MD5";
  keyType: "rsa" | "ecdsa" | "ed25519" | "ed448" | "dsa" | "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87";
}

export const SIGNATURE_ALGORITHMS: Record<string, SignatureAlgorithmDetails> = {
  // RSA PKCS#1 v1.5
  "1.2.840.113549.1.1.11": { name: "sha256WithRSAEncryption", hash: "SHA-256", keyType: "rsa" },
  "1.2.840.113549.1.1.12": { name: "sha384WithRSAEncryption", hash: "SHA-384", keyType: "rsa" },
  "1.2.840.113549.1.1.13": { name: "sha512WithRSAEncryption", hash: "SHA-512", keyType: "rsa" },
  "1.2.840.113549.1.1.14": { name: "sha224WithRSAEncryption", hash: "SHA-224", keyType: "rsa" },
  "1.2.840.113549.1.1.5": { name: "sha1WithRSAEncryption", hash: "SHA-1", keyType: "rsa" },
  "1.2.840.113549.1.1.4": { name: "md5WithRSAEncryption", hash: "MD5", keyType: "rsa" },
  "1.2.840.113549.1.1.10": { name: "RSASSA-PSS", keyType: "rsa" },

  // ECDSA
  "1.2.840.10045.4.3.2": { name: "ecdsa-with-SHA256", hash: "SHA-256", keyType: "ecdsa" },
  "1.2.840.10045.4.3.3": { name: "ecdsa-with-SHA384", hash: "SHA-384", keyType: "ecdsa" },
  "1.2.840.10045.4.3.4": { name: "ecdsa-with-SHA512", hash: "SHA-512", keyType: "ecdsa" },
  "1.2.840.10045.4.3.1": { name: "ecdsa-with-SHA224", hash: "SHA-224", keyType: "ecdsa" },
  "1.2.840.10045.4.1": { name: "ecdsa-with-SHA1", hash: "SHA-1", keyType: "ecdsa" },

  // EdDSA
  "1.3.101.112": { name: "Ed25519", keyType: "ed25519" },
  "1.3.101.113": { name: "Ed448", keyType: "ed448" },

  // DSA
  "1.2.840.10040.4.3": { name: "dsa-with-sha1", hash: "SHA-1", keyType: "dsa" },

  // Post-Quantum ML-DSA (FIPS 204)
  "2.16.840.1.101.3.4.3.17": { name: "ML-DSA-44", keyType: "ml-dsa-44" },
  "2.16.840.1.101.3.4.3.18": { name: "ML-DSA-65", keyType: "ml-dsa-65" },
  "2.16.840.1.101.3.4.3.19": { name: "ML-DSA-87", keyType: "ml-dsa-87" },
};

export const PUBLIC_KEY_ALGORITHMS: Record<string, string> = {
  "1.2.840.113549.1.1.1": "RSA",
  "1.2.840.10045.2.1": "Elliptic Curve (EC)",
  "1.3.101.112": "Ed25519",
  "1.3.101.113": "Ed448",
  "1.3.101.110": "X25519",
  "1.3.101.111": "X448",
  "1.2.840.10040.4.1": "DSA",
  "2.16.840.1.101.3.4.3.17": "ML-DSA-44 (FIPS 204)",
  "2.16.840.1.101.3.4.3.18": "ML-DSA-65 (FIPS 204)",
  "2.16.840.1.101.3.4.3.19": "ML-DSA-87 (FIPS 204)",
};

export const NAMED_CURVES: Record<string, string> = {
  "1.2.840.10045.3.1.7": "P-256 (secp256r1, prime256v1)",
  "1.3.132.0.34": "P-384 (secp384r1)",
  "1.3.132.0.35": "P-521 (secp521r1)",
  "1.3.132.0.10": "secp256k1 (Koblitz)",
};

export const EXTENSION_NAMES: Record<string, string> = {
  "2.5.29.14": "Subject Key Identifier",
  "2.5.29.15": "Key Usage",
  "2.5.29.17": "Subject Alternative Name",
  "2.5.29.19": "Basic Constraints",
  "2.5.29.20": "CRL Number",
  "2.5.29.21": "CRL Reason Code",
  "2.5.29.27": "Delta CRL Indicator",
  "2.5.29.28": "Issuing Distribution Point",
  "2.5.29.31": "CRL Distribution Points",
  "2.5.29.32": "Certificate Policies",
  "2.5.29.35": "Authority Key Identifier",
  "2.5.29.37": "Extended Key Usage",
  "1.3.6.1.5.5.7.1.1": "Authority Information Access (AIA)",
  "1.3.6.1.4.1.11129.2.4.2": "Certificate Transparency SCT List",
};

export const EXTENDED_KEY_USAGES: Record<string, string> = {
  "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication (serverAuth)",
  "1.3.6.1.5.5.7.3.2": "TLS Web Client Authentication (clientAuth)",
  "1.3.6.1.5.5.7.3.3": "Code Signing (codeSigning)",
  "1.3.6.1.5.5.7.3.4": "Email Protection / S-MIME (emailProtection)",
  "1.3.6.1.5.5.7.3.8": "Time Stamping (timeStamping)",
  "1.3.6.1.5.5.7.3.9": "OCSP Signing (OCSPSigning)",
};

export const KEY_USAGE_FLAGS = [
  "digitalSignature",
  "nonRepudiation",
  "keyEncipherment",
  "dataEncipherment",
  "keyAgreement",
  "keyCertSign",
  "cRLSign",
  "encipherOnly",
  "decipherOnly",
] as const;

export const CSR_ATTRIBUTES: Record<string, string> = {
  "1.2.840.113549.1.9.14": "Extension Request",
  "1.2.840.113549.1.9.7": "Challenge Password",
  "1.2.840.113549.1.9.20": "Friendly Name",
};
