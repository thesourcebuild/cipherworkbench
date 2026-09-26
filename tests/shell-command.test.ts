import { describe, expect, it } from "vitest";
import {
  formatShellCommands,
  type ShellCommandVariants,
} from "../packages/ui/src/shell-command";

const commands: ShellCommandVariants = [
  {
    comment: "Create a certificate",
    parts: ["openssl req -x509", "-key ca.key", "-out ca.crt"],
  },
];

describe("shell command formatting", () => {
  it("uses each shell's multiline continuation and comment syntax", () => {
    expect(formatShellCommands(commands, "bash", "multiline")).toBe(
      "# Create a certificate\nopenssl req -x509 \\\n  -key ca.key \\\n  -out ca.crt",
    );
    expect(formatShellCommands(commands, "powershell", "multiline")).toBe(
      "# Create a certificate\nopenssl req -x509 `\n  -key ca.key `\n  -out ca.crt",
    );
    expect(formatShellCommands(commands, "cmd", "multiline")).toBe(
      "REM Create a certificate\nopenssl req -x509 ^\n  -key ca.key ^\n  -out ca.crt",
    );
  });

  it("joins command parts for single-line copy", () => {
    expect(formatShellCommands(commands, "bash", "single-line")).toBe(
      "# Create a certificate\nopenssl req -x509 -key ca.key -out ca.crt",
    );
  });

  it("uses shell-specific command variants", () => {
    const variants: ShellCommandVariants = {
      bash: [{ parts: ["cat server.crt intermediate.crt > server-chain.pem"] }],
      powershell: [
        { parts: ["Get-Content server.crt, intermediate.crt | Set-Content server-chain.pem"] },
      ],
      cmd: [{ parts: ["type server.crt intermediate.crt > server-chain.pem"] }],
    };

    expect(formatShellCommands(variants, "cmd", "single-line")).toBe(
      "type server.crt intermediate.crt > server-chain.pem",
    );
  });
});
