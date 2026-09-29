export interface PkiGraphNode {
  title: string;
  role: "Root CA" | "Intermediate CA" | "Server Leaf" | "Client Leaf" | "Self-Signed";
  subjectDn: string;
  issuerDn?: string;
  serialNumberHex?: string;
  keyType: string;
  fingerprintSha256: string;
  validityRange: string;
  san?: string;
  isCa?: boolean;
  pathLenConstraint?: number;
  status?: "valid" | "expired" | "not-yet-valid";
}

/**
 * Generates an ASCII/Unicode box-and-arrow PKI hierarchy diagram
 * for display in console, terminals, and markdown code blocks.
 */
export function generatePkiHierarchyDiagram(nodes: PkiGraphNode[]): string {
  if (nodes.length === 0) return "";

  const lines: string[] = [];

  // 1. Single Self-Signed
  if (nodes.length === 1) {
    const n = nodes[0]!;
    lines.push(
      "┌────────────────────────────────────────────────────────────────────────┐",
      `│ 🏛️ [Self-Signed Certificate: ${n.title}]`,
      `│    Subject: ${n.subjectDn}`,
      ...(n.san ? [`│    SAN: ${n.san}`] : []),
      `│    Key: ${n.keyType.toUpperCase()} | SHA-256: ${n.fingerprintSha256.slice(0, 23)}...`,
      `│    Validity: ${n.validityRange}`,
      "└────────────────────────────────────────────────────────────────────────┘",
    );
    return lines.join("\n");
  }

  // 2. Multi-tier hierarchy (Root CA -> [Intermediate CA] -> Server + Client)
  const root = nodes.find((n) => n.role === "Root CA") ?? nodes[0]!;
  const intermediate = nodes.find((n) => n.role === "Intermediate CA");
  const server = nodes.find((n) => n.role === "Server Leaf") ?? nodes[1]!;
  const client = nodes.find((n) => n.role === "Client Leaf");

  // Print Root CA
  lines.push(
    "┌────────────────────────────────────────────────────────────────────────┐",
    `│ 🏛️ [Tier 1: Root Certificate Authority (CA:TRUE)]`,
    `│    Subject: ${root.subjectDn}`,
    `│    Key: ${root.keyType.toUpperCase()} | SHA-256: ${root.fingerprintSha256.slice(0, 23)}...`,
    `│    Validity: ${root.validityRange}`,
    "└────────────────────────────────────────────────────────────────────────┘",
  );

  if (intermediate) {
    const pathLenStr = intermediate.pathLenConstraint !== undefined ? `, pathlen:${intermediate.pathLenConstraint}` : "";
    lines.push(
      "                               │",
      "                     [signs]   │",
      "                               ▼",
      "┌────────────────────────────────────────────────────────────────────────┐",
      `│ 🏢 [Tier 2: Intermediate Issuing CA (CA:TRUE${pathLenStr})]`,
      `│    Subject: ${intermediate.subjectDn}`,
      `│    Key: ${intermediate.keyType.toUpperCase()} | SHA-256: ${intermediate.fingerprintSha256.slice(0, 23)}...`,
      `│    Validity: ${intermediate.validityRange}`,
      "└────────────────────────────────────────────────────────────────────────┘",
    );
  }

  if (client) {
    // 2-leaf split: Server + Client
    lines.push(
      "                      │                                   │",
      "            [signs]   │                                   │ [signs]",
      "                      ▼                                   ▼",
      "┌───────────────────────────────────┐   ┌────────────────────────────────┐",
      `│ 💻 [Server Leaf: ${server.title}]`,
      `│    Subject: ${server.subjectDn.length > 25 ? server.subjectDn.slice(0, 23) + "..." : server.subjectDn}`,
      ...(server.san ? [`│    SAN: ${server.san.length > 27 ? server.san.slice(0, 25) + "..." : server.san}`] : []),
      `│    Key: ${server.keyType.toUpperCase()}`,
      `│    SHA-256: ${server.fingerprintSha256.slice(0, 17)}...`,
      "└───────────────────────────────────┘   └────────────────────────────────┘",
      `                                        │ 📱 [Client Leaf: ${client.title}]`,
      `                                        │    Subject: ${client.subjectDn.length > 25 ? client.subjectDn.slice(0, 23) + "..." : client.subjectDn}`,
      `                                        │    Key: ${client.keyType.toUpperCase()}`,
      `                                        │    SHA-256: ${client.fingerprintSha256.slice(0, 17)}...`,
      "                                        └────────────────────────────────┘",
    );
  } else {
    // Single leaf (Server or End-Entity)
    lines.push(
      "                               │",
      "                     [signs]   │",
      "                               ▼",
      "┌────────────────────────────────────────────────────────────────────────┐",
      `│ 💻 [End-Entity / Leaf Server: ${server.title}]`,
      `│    Subject: ${server.subjectDn}`,
      ...(server.san ? [`│    SAN: ${server.san}`] : []),
      `│    Key: ${server.keyType.toUpperCase()} | SHA-256: ${server.fingerprintSha256.slice(0, 23)}...`,
      `│    Validity: ${server.validityRange}`,
      "└────────────────────────────────────────────────────────────────────────┘",
    );
  }

  return lines.join("\n");
}
