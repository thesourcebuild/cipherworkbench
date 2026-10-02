import { describe, expect, it } from "vitest";
import {
  formatShellCommands,
  canWrapShellCommands,
  formatByteSize,
  getInlineTextSample,
  describeInputExclusion,
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

  it("formats multi-line comments with appropriate comment prefixes for each shell", () => {
    const multiLineComment: ShellCommandVariants = [
      {
        comment: "Note 1: Input exceeds limit\nNote 2: Use file mode instead",
        parts: ["openssl dgst -sha256 input.txt"],
      },
    ];

    expect(formatShellCommands(multiLineComment, "bash", "single-line")).toBe(
      "# Note 1: Input exceeds limit\n# Note 2: Use file mode instead\nopenssl dgst -sha256 input.txt",
    );
    expect(formatShellCommands(multiLineComment, "powershell", "single-line")).toBe(
      "# Note 1: Input exceeds limit\n# Note 2: Use file mode instead\nopenssl dgst -sha256 input.txt",
    );
    expect(formatShellCommands(multiLineComment, "cmd", "single-line")).toBe(
      "REM Note 1: Input exceeds limit\nREM Note 2: Use file mode instead\nopenssl dgst -sha256 input.txt",
    );
  });

  it("handles byte size formatting", () => {
    expect(formatByteSize(100)).toBe("100 B");
    expect(formatByteSize(3862)).toBe("3.8 KB");
    expect(formatByteSize(1024 * 1024 * 5)).toBe("5.0 MB");
  });

  it("identifies safe inline text vs large/multiline input", () => {
    const enc = new TextEncoder();
    expect(getInlineTextSample(enc.encode("hello world"))).toBe("hello world");
    expect(getInlineTextSample(enc.encode(""))).toBe("");
    expect(getInlineTextSample(undefined)).toBeUndefined();
    // Multi-line text
    expect(getInlineTextSample(enc.encode("line1\nline2"))).toBeUndefined();
    // Text exceeding 256 chars
    expect(getInlineTextSample(enc.encode("a".repeat(300)))).toBeUndefined();
    // Binary
    expect(getInlineTextSample(new Uint8Array([0x00, 0x01, 0x02]))).toBeUndefined();
  });

  it("describes exclusions properly with helpful notes", () => {
    const enc = new TextEncoder();
    const lorem3862 = enc.encode("Lorem ipsum ".repeat(322));
    const descLarge = describeInputExclusion(lorem3862);
    expect(descLarge.note).toContain("Input exceeds inline shell limit");
    expect(descLarge.note).toContain("save to input.txt or use File mode");
    expect(descLarge.defaultFileName).toBe("input.txt");

    const descMulti = describeInputExclusion(enc.encode("line1\nline2"));
    expect(descMulti.note).toContain("Input is multi-line");
    expect(descMulti.defaultFileName).toBe("input.txt");

    const descBin = describeInputExclusion(new Uint8Array([0x00, 0xff, 0xfe]));
    expect(descBin.note).toContain("Input is binary");
    expect(descBin.defaultFileName).toBe("input.bin");
  });

  it("determines whether commands have wrappable multi-line parts", () => {
    // Single-part command: cannot wrap
    const singlePart = [{ parts: ["openssl x509 -in cert.pem -text -noout"] }];
    expect(canWrapShellCommands(singlePart, "bash")).toBe(false);

    // Multi-part command: can wrap
    const multiPart = [{ parts: ["openssl x509", "-in cert.pem", "-text", "-noout"] }];
    expect(canWrapShellCommands(multiPart, "bash")).toBe(true);

    // Formatting multiPart in multiline vs single-line
    expect(formatShellCommands(multiPart, "bash", "multiline")).toBe(
      "openssl x509 \\\n  -in cert.pem \\\n  -text \\\n  -noout",
    );
    expect(formatShellCommands(multiPart, "bash", "single-line")).toBe(
      "openssl x509 -in cert.pem -text -noout",
    );
  });
});
