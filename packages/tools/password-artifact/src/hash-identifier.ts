export type HashIdentificationConfidence = "self-describing" | "length-only";

export interface HashIdentificationCandidate {
  name: string;
  confidence: HashIdentificationConfidence;
  evidence: string;
  hashcatMode?: number;
}

interface StructuredFormat {
  name: string;
  pattern: RegExp;
  evidence: string;
  hashcatMode?: number;
}

const STRUCTURED_FORMATS: readonly StructuredFormat[] = [
  {
    name: "Argon2id PHC string",
    pattern: /^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/.-]+\$[A-Za-z0-9+/.-]+$/,
    evidence:
      "The value carries an Argon2id identifier, version, cost parameters, salt, and digest.",
  },
  {
    name: "Argon2i PHC string",
    pattern: /^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/.-]+\$[A-Za-z0-9+/.-]+$/,
    evidence:
      "The value carries an Argon2i identifier, version, cost parameters, salt, and digest.",
  },
  {
    name: "bcrypt",
    pattern: /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/,
    evidence: "The $2a$, $2b$, or $2y$ prefix and fixed bcrypt payload are self-describing.",
    hashcatMode: 3200,
  },
  {
    name: "scrypt PHC string",
    pattern: /^\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/.-]+\$[A-Za-z0-9+/.-]+$/,
    evidence: "The PHC string names scrypt and embeds its work parameters.",
    hashcatMode: 8900,
  },
  {
    name: "Django PBKDF2-SHA256",
    pattern: /^pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/]+={0,2}$/,
    evidence: "The Django prefix names PBKDF2-SHA256 and includes rounds, salt, and digest.",
    hashcatMode: 10000,
  },
  {
    name: "Hashcat PBKDF2-HMAC-SHA256",
    pattern: /^sha256:\d+:[A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}$/,
    evidence:
      "The record explicitly names SHA-256 and carries rounds, Base64 salt, and digest.",
    hashcatMode: 10900,
  },
  {
    name: "sha512crypt",
    pattern: /^\$6\$(?:rounds=\d+\$)?[^$]{1,16}\$[./A-Za-z0-9]{86}$/,
    evidence: "The modular-crypt $6$ prefix identifies sha512crypt.",
    hashcatMode: 1800,
  },
  {
    name: "sha256crypt",
    pattern: /^\$5\$(?:rounds=\d+\$)?[^$]{1,16}\$[./A-Za-z0-9]{43}$/,
    evidence: "The modular-crypt $5$ prefix identifies sha256crypt.",
    hashcatMode: 7400,
  },
  {
    name: "md5crypt",
    pattern: /^\$1\$[^$]{1,8}\$[./A-Za-z0-9]{22}$/,
    evidence: "The modular-crypt $1$ prefix identifies md5crypt.",
    hashcatMode: 500,
  },
  {
    name: "phpass",
    pattern: /^\$[PH]\$[./A-Za-z0-9]{31}$/,
    evidence: "The $P$ or $H$ prefix and portable phpass payload identify the format.",
    hashcatMode: 400,
  },
  {
    name: "LDAP SHA-1",
    pattern: /^\{SHA\}[A-Za-z0-9+/]{27}=$/i,
    evidence: "The LDAP scheme marker explicitly names unsalted SHA-1.",
    hashcatMode: 101,
  },
  {
    name: "LDAP salted SHA-1",
    pattern: /^\{SSHA\}[A-Za-z0-9+/]+={0,2}$/i,
    evidence: "The LDAP scheme marker explicitly names salted SHA-1.",
    hashcatMode: 111,
  },
  {
    name: "MySQL 4.1/5",
    pattern: /^\*[0-9A-F]{40}$/,
    evidence: "The leading asterisk plus 40 uppercase hex digits is MySQL's stored form.",
    hashcatMode: 300,
  },
];

const RAW_HEX_CANDIDATES: Readonly<
  Record<number, readonly Omit<HashIdentificationCandidate, "confidence" | "evidence">[]>
> = {
  16: [
    { name: "MD4", hashcatMode: 900 },
    { name: "MD5", hashcatMode: 0 },
    { name: "NTLM", hashcatMode: 1000 },
  ],
  20: [
    { name: "SHA-1", hashcatMode: 100 },
    { name: "RIPEMD-160", hashcatMode: 6000 },
  ],
  28: [
    { name: "SHA-224", hashcatMode: 1300 },
    { name: "SHA3-224", hashcatMode: 17300 },
  ],
  32: [
    { name: "SHA-256", hashcatMode: 1400 },
    { name: "SHA3-256", hashcatMode: 17400 },
    { name: "BLAKE2s-256", hashcatMode: 31000 },
  ],
  48: [
    { name: "SHA-384", hashcatMode: 10800 },
    { name: "SHA3-384", hashcatMode: 17500 },
  ],
  64: [
    { name: "SHA-512", hashcatMode: 1700 },
    { name: "SHA3-512", hashcatMode: 17600 },
    { name: "BLAKE2b-512", hashcatMode: 600 },
    { name: "Whirlpool", hashcatMode: 6100 },
  ],
};

/** Structural formats win; bare hex is intentionally returned as an equally ranked candidate set. */
export function identifyHashArtifact(value: string): HashIdentificationCandidate[] {
  const input = value.trim();
  const structured = STRUCTURED_FORMATS.filter((format) => format.pattern.test(input)).map(
    (format) => ({
      name: format.name,
      confidence: "self-describing" as const,
      evidence: format.evidence,
      ...(format.hashcatMode === undefined ? {} : { hashcatMode: format.hashcatMode }),
    }),
  );
  if (structured.length > 0) return structured;

  if (!/^[0-9a-f]+$/i.test(input) || input.length % 2 !== 0) return [];
  const byteLength = input.length / 2;
  return (RAW_HEX_CANDIDATES[byteLength] ?? []).map((candidate) => ({
    ...candidate,
    confidence: "length-only",
    evidence: `${byteLength} raw bytes match this output length; length alone cannot distinguish the algorithm.`,
  }));
}
