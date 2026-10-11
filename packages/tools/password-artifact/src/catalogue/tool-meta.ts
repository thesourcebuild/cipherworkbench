export type PasswordArtifactKind =
  | "hash-identifier"
  | "grafana"
  | "gitea"
  | "ssh"
  | "truecrypt"
  | "luks"
  | "dmg"
  | "bitlocker"
  | "kdbx"
  | "zip"
  | "office"
  | "pdf"
  | "rar"
  | "sevenzip"
  | "gpg";

export interface PasswordArtifactToolMeta {
  id: string;
  label: string;
  kind: PasswordArtifactKind;
  category: string;
  tags: readonly string[];
  summary: string;
  accept?: readonly string[];
  maxFileBytes?: number;
}

export const PASSWORD_ARTIFACT_TOOLS: readonly PasswordArtifactToolMeta[] = [
  {
    id: "hash-identifier",
    label: "Hash Identifier",
    kind: "hash-identifier",
    category: "Identification",
    tags: ["hash identification", "hash type", "password hash", "PHC", "hashcat mode"],
    summary:
      "Rank plausible password-hash formats from structural markers without pretending raw lengths are unique.",
  },
  {
    id: "grafana2hashcat",
    label: "grafana2hashcat",
    kind: "grafana",
    category: "Hashcat extraction",
    tags: ["Grafana", "PBKDF2-HMAC-SHA256", "hashcat", "mode 10900", "password audit"],
    summary:
      "Convert Grafana digest,salt records to Hashcat mode 10900 input using Grafana's 10,000 rounds.",
  },
  {
    id: "gitea2hashcat",
    label: "gitea2hashcat",
    kind: "gitea",
    category: "Hashcat extraction",
    tags: ["Gitea", "PBKDF2-HMAC-SHA256", "hashcat", "mode 10900", "password audit"],
    summary:
      "Convert Gitea salt and password-digest records to canonical Hashcat mode 10900 input.",
  },
  {
    id: "ssh2john",
    label: "ssh2john",
    kind: "ssh",
    category: "John extraction",
    tags: ["OpenSSH", "private key", "sshng", "John the Ripper", "password audit"],
    summary:
      "Extract canonical John sshng descriptors from encrypted legacy PEM and openssh-key-v1 private keys.",
    accept: [".key", ".pem", "application/x-pem-file", "text/plain"],
    maxFileBytes: 4 * 1024 * 1024,
  },
  {
    id: "truecrypt2john",
    label: "truecrypt2john",
    kind: "truecrypt",
    category: "John extraction",
    tags: ["TrueCrypt", "volume", "John the Ripper", "password audit"],
    summary:
      "Extract canonical John descriptors from TrueCrypt primary and hidden volume headers.",
    accept: [".tc", ".img", ".bin", "application/octet-stream"],
  },
  {
    id: "luks2john",
    label: "luks2john",
    kind: "luks",
    category: "John extraction",
    tags: ["LUKS1", "dm-crypt", "disk encryption", "John the Ripper", "password audit"],
    summary:
      "Extract the canonical John descriptor from a supported LUKS1 AES/cbc-essiv:sha256 volume.",
    accept: [".img", ".bin", "application/octet-stream"],
  },
  {
    id: "dmg2john",
    label: "dmg2john",
    kind: "dmg",
    category: "John extraction",
    tags: ["DMG", "FileVault", "disk image", "John the Ripper", "password audit"],
    summary: "Extract canonical John dmg descriptors from encrypted DMG v1 and v2 file images.",
    accept: [
      ".dmg",
      ".sparseimage",
      "application/x-apple-diskimage",
      "application/octet-stream",
    ],
  },
  {
    id: "bitlocker2john",
    label: "bitlocker2john",
    kind: "bitlocker",
    category: "John extraction",
    tags: ["BitLocker", "FVE", "recovery password", "John the Ripper", "password audit"],
    summary:
      "Extract canonical John descriptors for BitLocker password and recovery-password VMKs.",
    accept: [".img", ".bin", ".vhd", ".vhdx", "application/octet-stream"],
  },
  {
    id: "kdbx2john",
    label: "kdbx2john",
    kind: "kdbx",
    category: "John extraction",
    tags: ["KeePass", "KDBX3", "KDBX4", "John the Ripper", "password audit"],
    summary:
      "Extract canonical John keepass descriptors from KDBX 3.0/3.1 and KDBX 4 databases without keyfiles.",
    accept: [".kdbx", "application/octet-stream"],
  },
  {
    id: "zip2john",
    label: "zip2john",
    kind: "zip",
    category: "John extraction",
    tags: ["ZIP", "ZIP64", "ZipCrypto", "WinZip AES", "John the Ripper"],
    summary:
      "Extract canonical John pkzip and zip2 descriptors from ZIP/ZIP64 archives with traditional or WinZip AES encryption.",
    accept: [".zip", "application/zip", "application/octet-stream"],
  },
  {
    id: "office2john",
    label: "office2john",
    kind: "office",
    category: "John extraction",
    tags: ["Microsoft Office", "OOXML", "RC4", "CryptoAPI", "agile encryption"],
    summary:
      "Extract canonical John descriptors from legacy Excel/Word RC4 and OOXML 2007/2010/2013 encryption metadata.",
    accept: [".doc", ".xls", ".docx", ".xlsx", ".pptx", "application/octet-stream"],
  },
  {
    id: "pdf2john",
    label: "pdf2john",
    kind: "pdf",
    category: "John extraction",
    tags: ["PDF", "Standard security handler", "RC4", "AES", "John the Ripper"],
    summary:
      "Extract canonical John pdf descriptors for Standard security-handler revisions 2 through 6 with classic trailers.",
    accept: [".pdf", "application/pdf", "application/octet-stream"],
    maxFileBytes: 64 * 1024 * 1024,
  },
  {
    id: "rar2john",
    label: "rar2john",
    kind: "rar",
    category: "John extraction",
    tags: ["RAR3", "RAR5", "archive encryption", "John the Ripper"],
    summary:
      "Extract canonical John RAR3 file/header-encryption and RAR5 password-check descriptors.",
    accept: [".rar", "application/vnd.rar", "application/octet-stream"],
  },
  {
    id: "7z2john",
    label: "7z2john",
    kind: "sevenzip",
    category: "John extraction",
    tags: ["7-Zip", "AES", "encrypted header", "folder coder", "John the Ripper"],
    summary:
      "Extract canonical John 7z descriptors from one-stream AES encrypted headers and folders with supported coder metadata.",
    accept: [".7z", "application/x-7z-compressed", "application/octet-stream"],
  },
  {
    id: "gpg2john",
    label: "gpg2john",
    kind: "gpg",
    category: "John extraction",
    tags: ["OpenPGP", "GPG", "secret key", "S2K", "John the Ripper"],
    summary:
      "Extract canonical John gpg descriptors from armored or binary encrypted v2-v4 secret keys and symmetric material.",
    accept: [
      ".gpg",
      ".pgp",
      ".asc",
      "application/pgp-encrypted",
      "application/octet-stream",
      "text/plain",
    ],
    maxFileBytes: 16 * 1024 * 1024,
  },
];

export const PASSWORD_ARTIFACT_TOOL_IDS = PASSWORD_ARTIFACT_TOOLS.map((tool) => tool.id) as [
  string,
  ...string[],
];

export function requirePasswordArtifactTool(toolId: string): PasswordArtifactToolMeta {
  const tool = PASSWORD_ARTIFACT_TOOLS.find((candidate) => candidate.id === toolId);
  if (!tool) throw new Error(`Unknown password artifact tool: ${toolId}`);
  return tool;
}
