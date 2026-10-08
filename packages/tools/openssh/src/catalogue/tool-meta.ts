export interface OpenSshToolMeta {
  readonly id: string;
  readonly label: string;
  readonly category: string;
  readonly tags: readonly string[];
  readonly summary: string;
}

export const OPENSSH_TOOLS: readonly OpenSshToolMeta[] = [
  {
    id: "ssh-keygen",
    label: "SSH Keygen",
    category: "Key Management",
    tags: [
      "ssh",
      "keygen",
      "openssh",
      "ed25519",
      "rsa",
      "ecdsa",
      "authorized_keys",
      "randomart",
      "drunken-bishop",
      "bubblebabble",
    ],
    summary:
      "Generates OpenSSH keypairs, authorized_keys entries, openssh-key-v1 files, fingerprints, and Drunken Bishop randomart.",
  },
] as const;

export const OPENSSH_TOOL_IDS = OPENSSH_TOOLS.map((t) => t.id);

export function requireOpenSshTool(id: string): OpenSshToolMeta {
  const tool = OPENSSH_TOOLS.find((t) => t.id === id);
  if (!tool) throw new Error(`Unknown OpenSSH tool: ${id}`);
  return tool;
}
