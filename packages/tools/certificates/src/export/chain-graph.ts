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

function padEndVisual(str: string, targetWidth: number): string {
  let visualWidth = 0;
  for (const ch of str) {
    const cp = ch.codePointAt(0);
    if (cp !== undefined) {
      if ((cp >= 0x1f300 && cp <= 0x1faff) || (cp >= 0x2600 && cp <= 0x27bf)) {
        visualWidth += 2;
      } else if (cp === 0xfe0f) {
        visualWidth += 0;
      } else {
        visualWidth += 1;
      }
    }
  }
  const paddingNeeded = Math.max(0, targetWidth - visualWidth);
  return str + " ".repeat(paddingNeeded);
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
    // 2-leaf split: Server + Client side-by-side
    const serverLines = [
      `│ 💻 [Server Leaf: ${server.title}]`,
      `│    Subject: ${server.subjectDn.length > 22 ? server.subjectDn.slice(0, 19) + "..." : server.subjectDn}`,
      ...(server.san ? [`│    SAN: ${server.san.length > 25 ? server.san.slice(0, 22) + "..." : server.san}`] : []),
      `│    Key: ${server.keyType.toUpperCase()}`,
      `│    SHA-256: ${server.fingerprintSha256.slice(0, 17)}...`,
    ];

    const clientLines = [
      `│ 📱 [Client Leaf: ${client.title}]`,
      `│    Subject: ${client.subjectDn.length > 22 ? client.subjectDn.slice(0, 19) + "..." : client.subjectDn}`,
      ...(client.validityRange ? [`│    Validity: ${client.validityRange}`] : []),
      `│    Key: ${client.keyType.toUpperCase()}`,
      `│    SHA-256: ${client.fingerprintSha256.slice(0, 17)}...`,
    ];

    const maxRows = Math.max(serverLines.length, clientLines.length);

    lines.push(
      "                      │                                   │",
      "            [signs]   │                                   │ [signs]",
      "                      ▼                                   ▼",
      "┌───────────────────────────────────┐   ┌────────────────────────────────┐",
    );

    for (let i = 0; i < maxRows; i++) {
      const s = serverLines[i] ?? "│";
      const c = clientLines[i] ?? "│";
      lines.push(padEndVisual(s, 40) + c);
    }

    lines.push(
      "└───────────────────────────────────┘   └────────────────────────────────┘",
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
