const HEX_50_BYTES = /^[0-9a-f]{100}$/i;
const HEX_16_BYTES = /^[0-9a-f]{32}$/i;

function decodeHex(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function records(input: string): string[] {
  const lines = input.split(/\r\n|\n|\r/);
  if (lines.at(-1) === "") lines.pop();
  if (lines.length === 0 || lines.some((line) => line.length === 0)) {
    throw new Error("Input must contain one non-empty record per line.");
  }
  return lines;
}

export function convertGrafanaToHashcat(input: string): string {
  const output = records(input).map((line, index) => {
    const match = /^([0-9a-f]{64}),([^,]+)$/i.exec(line);
    if (!match) {
      throw new Error(
        `Line ${index + 1}: expected exactly 64 hex digest characters, a comma, and a non-empty Grafana salt.`,
      );
    }
    const [, digest, salt] = match as RegExpExecArray & [string, string, string];
    return `sha256:10000:${base64(new TextEncoder().encode(salt))}:${base64(decodeHex(digest))}`;
  });
  return `${output.join("\n")}\n`;
}

export function convertGiteaToHashcat(input: string): string {
  const output = records(input).map((line, index) => {
    const match = /^([0-9a-f]+)(?:\||:)([0-9a-f]+)$/i.exec(line);
    if (!match) {
      throw new Error(
        `Line ${index + 1}: expected one hex salt and one hex digest separated by ':' or '|'.`,
      );
    }
    const [, first, second] = match as RegExpExecArray & [string, string, string];
    const salt = HEX_16_BYTES.test(first)
      ? first
      : HEX_16_BYTES.test(second)
        ? second
        : undefined;
    const digest = HEX_50_BYTES.test(first)
      ? first
      : HEX_50_BYTES.test(second)
        ? second
        : undefined;
    if (!salt || !digest) {
      throw new Error(
        `Line ${index + 1}: Gitea's default PBKDF2 record requires a 16-byte hex salt and a 50-byte hex digest.`,
      );
    }
    return `sha256:50000:${base64(decodeHex(salt))}:${base64(decodeHex(digest))}`;
  });
  return `${output.join("\n")}\n`;
}
