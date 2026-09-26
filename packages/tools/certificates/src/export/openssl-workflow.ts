import type { HashAlgorithmType, KeyAlgorithmType } from "../crypto/keys";

export interface OpenSslCertificateOptions {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
  keyType: KeyAlgorithmType;
  hashType: HashAlgorithmType;
  validityDays: number;
  isCa: boolean;
  pathLenConstraint?: number;
  san?: string;
  serverAuth?: boolean;
  clientAuth?: boolean;
  codeSigning?: boolean;
  emailProtection?: boolean;
  customSerialHex?: string;
  issuanceMode?: "self-signed" | "ca-signed";
  signingKeyType?: KeyAlgorithmType;
  ocspResponderUrl?: string;
  caIssuersUrl?: string;
  crlDistributionPoint?: string;
}

export interface OpenSslCsrOptions {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
  keyType: KeyAlgorithmType;
  hashType: HashAlgorithmType;
  san?: string;
  serverAuth?: boolean;
  clientAuth?: boolean;
  codeSigning?: boolean;
  emailProtection?: boolean;
}

function bashQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function opensslDnValue(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("/", "\\/");
}

function subject(options: OpenSslCsrOptions): string {
  const entries = [
    ["C", options.country?.slice(0, 2).toUpperCase()],
    ["ST", options.state],
    ["L", options.locality],
    ["O", options.organization],
    ["OU", options.organizationalUnit],
    ["CN", options.commonName],
  ];
  return entries
    .filter((entry): entry is [string, string] => Boolean(entry[1]))
    .map(([key, value]) => `/${key}=${opensslDnValue(value)}`)
    .join("");
}

function keyCommand(keyType: KeyAlgorithmType): string {
  if (keyType.startsWith("rsa-")) {
    return `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${keyType.slice(4)} -out private.key`;
  }
  if (keyType === "ecdsa-p384") {
    return "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out private.key";
  }
  if (keyType === "ecdsa-p521") {
    return "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp521r1 -out private.key";
  }
  if (keyType === "ed25519") {
    return "openssl genpkey -algorithm ED25519 -out private.key";
  }
  if (keyType.startsWith("ml-dsa-")) {
    return `openssl genpkey -algorithm ${keyType.toUpperCase()} -out private.key`;
  }
  return "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out private.key";
}

function digestFlag(options: OpenSslCsrOptions): string | undefined {
  if (options.keyType === "ed25519" || options.keyType.startsWith("ml-dsa-")) return undefined;
  return `-${options.hashType}`;
}

function sanEntry(raw: string): string {
  const lower = raw.toLowerCase();
  if (lower.startsWith("dns:")) return `DNS:${raw.slice(4).trim()}`;
  if (lower.startsWith("ip:")) return `IP:${raw.slice(3).trim()}`;
  if (lower.startsWith("email:")) return `email:${raw.slice(6).trim()}`;
  if (lower.startsWith("uri:")) return `URI:${raw.slice(4).trim()}`;
  if (lower.startsWith("spiffe:")) {
    const rest = raw.slice(7).trim();
    const uri = rest.startsWith("spiffe://")
      ? rest
      : rest.startsWith("//")
        ? `spiffe:${rest}`
        : `spiffe://${rest}`;
    return `URI:${uri}`;
  }
  if (raw.includes("@")) return `email:${raw}`;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(raw)) return `IP:${raw}`;
  if (raw.includes(":") && !raw.includes("://")) {
    const clean = raw.replace(/^\[|\]$/g, "");
    if (/^[0-9a-fA-F:]+$/.test(clean) && clean.includes(":")) {
      return `IP:${clean}`;
    }
  }
  if (raw.includes("://")) return `URI:${raw}`;
  return `DNS:${raw}`;
}

function sanValue(options: OpenSslCsrOptions): string {
  return (options.san || options.commonName)
    .split(/[\n,;]+/)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map(sanEntry)
    .join(",");
}

function ekuValue(options: OpenSslCsrOptions): string | undefined {
  const usages = [
    options.serverAuth !== false ? "serverAuth" : undefined,
    options.clientAuth !== false ? "clientAuth" : undefined,
    options.codeSigning ? "codeSigning" : undefined,
    options.emailProtection ? "emailProtection" : undefined,
  ].filter((usage): usage is string => usage !== undefined);
  return usages.length > 0 ? usages.join(",") : undefined;
}

function csrExtensionArgs(
  options: OpenSslCsrOptions,
  isCa = false,
  includeBasicConstraints = true,
): string[] {
  const basicConstraints = isCa ? "critical,CA:TRUE" : "CA:FALSE";
  const keyUsage = isCa
    ? "critical,digitalSignature,keyCertSign,cRLSign"
    : options.keyType.startsWith("rsa-")
      ? "critical,digitalSignature,keyEncipherment"
      : "critical,digitalSignature";
  const extensions = [
    ...(includeBasicConstraints ? [`basicConstraints=${basicConstraints}`] : []),
    `keyUsage=${keyUsage}`,
    `subjectAltName=${sanValue(options)}`,
  ];
  const eku = !isCa ? ekuValue(options) : undefined;
  if (eku) extensions.push(`extendedKeyUsage=${eku}`);
  return extensions.map((extension) => `-addext ${bashQuote(extension)}`);
}

function certificateExtensionArgs(options: OpenSslCertificateOptions): string[] {
  const args = csrExtensionArgs(options, options.isCa);
  if (options.isCa && options.pathLenConstraint !== undefined) {
    args[0] = `-addext ${bashQuote(`basicConstraints=critical,CA:TRUE,pathlen:${options.pathLenConstraint}`)}`;
  }
  args.push(`-addext ${bashQuote("subjectKeyIdentifier=hash")}`);
  if (options.ocspResponderUrl || options.caIssuersUrl) {
    const aia = [
      options.ocspResponderUrl ? `OCSP;URI:${options.ocspResponderUrl}` : undefined,
      options.caIssuersUrl ? `caIssuers;URI:${options.caIssuersUrl}` : undefined,
    ].filter((entry): entry is string => entry !== undefined);
    args.push(`-addext ${bashQuote(`authorityInfoAccess=${aia.join(",")}`)}`);
  }
  if (options.crlDistributionPoint) {
    args.push(
      `-addext ${bashQuote(`crlDistributionPoints=URI:${options.crlDistributionPoint}`)}`,
    );
  }
  return args;
}

function command(executable: string, args: readonly (string | undefined)[]): string {
  return [executable, ...args.filter((arg): arg is string => arg !== undefined)].join(" ");
}

export function buildCertificateOpenSslWorkflow(options: OpenSslCertificateOptions): string {
  const subjectDigest = digestFlag(options);
  const signingDigest = digestFlag({
    ...options,
    keyType: options.signingKeyType ?? options.keyType,
  });
  const serial = options.customSerialHex
    ? `-set_serial 0x${options.customSerialHex}`
    : undefined;
  const extensions = certificateExtensionArgs(options);
  const commands = [keyCommand(options.keyType)];

  if (options.issuanceMode === "ca-signed") {
    commands.push(
      command("openssl req -new", [
        "-key private.key",
        "-out request.csr",
        subjectDigest,
        `-subj ${bashQuote(subject(options))}`,
        ...extensions,
      ]),
      command("openssl x509 -req", [
        "-in request.csr",
        "-CA ca.crt",
        "-CAkey ca.key",
        "-CAcreateserial",
        "-copy_extensions copy",
        "-out certificate.crt",
        `-days ${options.validityDays}`,
        signingDigest,
        serial,
      ]),
    );
  } else {
    commands.push(
      command("openssl req -x509 -new", [
        "-key private.key",
        "-out certificate.crt",
        `-days ${options.validityDays}`,
        signingDigest,
        serial,
        `-subj ${bashQuote(subject(options))}`,
        ...extensions,
      ]),
    );
  }

  return commands.join("\n");
}

export function buildCsrOpenSslWorkflow(options: OpenSslCsrOptions): string {
  return [
    keyCommand(options.keyType),
    command("openssl req -new", [
      "-key private.key",
      "-out request.csr",
      digestFlag(options),
      `-subj ${bashQuote(subject(options))}`,
      ...csrExtensionArgs(options, false, false),
    ]),
  ].join("\n");
}
