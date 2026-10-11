import type { ToolFileSource, ToolResult, ToolResultField } from "@ocs/engine";
import type { PasswordArtifactSpec } from "./spec";
import { requirePasswordArtifactTool } from "./catalogue/tool-meta";
import { OPTION_BITLOCKER_OFFSET, OPTION_TRUECRYPT_BOOT_MODE } from "./catalogue/options";
import { convertGiteaToHashcat, convertGrafanaToHashcat } from "./converters";
import { identifyHashArtifact } from "./hash-identifier";
import { basename, memoryFileSource, readChunked } from "./extractors/binary";

const decoder = new TextDecoder("utf-8", { fatal: true });

function identify(input: string): ToolResult {
  const values = input.split(/\r\n|\n|\r/).filter((line) => line.length > 0);
  if (values.length === 0) return { error: "Enter at least one hash value to identify." };

  const sections = values.map((value, valueIndex) => {
    const candidates = identifyHashArtifact(value);
    if (candidates.length === 0) return `Hash ${valueIndex + 1}: no supported format matched.`;
    const lines = candidates.map((candidate, candidateIndex) => {
      const mode =
        candidate.hashcatMode === undefined ? "" : `; Hashcat mode ${candidate.hashcatMode}`;
      return `${candidateIndex + 1}. ${candidate.name} [${candidate.confidence}${mode}]\n   ${candidate.evidence}`;
    });
    return `Hash ${valueIndex + 1}:\n${lines.join("\n")}`;
  });

  return {
    text: sections.join("\n\n"),
    suggestedFilename: "hash-identification.txt",
    mimeType: "text/plain;charset=utf-8",
  };
}

export async function computePasswordArtifact(
  spec: PasswordArtifactSpec,
  input: Uint8Array,
): Promise<ToolResult> {
  try {
    const value = decoder.decode(input);
    switch (requirePasswordArtifactTool(spec.variant).kind) {
      case "hash-identifier":
        return identify(value);
      case "grafana":
        return {
          text: convertGrafanaToHashcat(value),
          suggestedFilename: "grafana-hashcat.txt",
          mimeType: "text/plain;charset=utf-8",
        };
      case "gitea":
        return {
          text: convertGiteaToHashcat(value),
          suggestedFilename: "gitea-hashcat.txt",
          mimeType: "text/plain;charset=utf-8",
        };
      case "ssh":
      case "truecrypt":
      case "luks":
      case "dmg":
      case "bitlocker":
      case "kdbx":
      case "zip":
      case "office":
      case "pdf":
      case "rar":
      case "sevenzip":
      case "gpg":
        return computePasswordArtifactFile(spec, memoryFileSource(input, "input"));
    }
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

function extractionResult(source: ToolFileSource, text: string): ToolResult {
  return {
    text,
    suggestedFilename: `${basename(source.metadata.name)}.john`,
    mimeType: "text/plain;charset=utf-8",
  };
}

export async function computePasswordArtifactFile(
  spec: PasswordArtifactSpec,
  source: ToolFileSource,
): Promise<ToolResult> {
  try {
    const kind = requirePasswordArtifactTool(spec.variant).kind;
    switch (kind) {
      case "hash-identifier":
      case "grafana":
      case "gitea": {
        const bytes = await readChunked(
          source,
          0,
          source.metadata.size,
          4 * 1024 * 1024,
          "Password artifact text file",
        );
        return computePasswordArtifact(spec, bytes);
      }
      case "ssh": {
        const { extractSsh } = await import("./extractors/ssh2john");
        return extractionResult(source, await extractSsh(source));
      }
      case "truecrypt": {
        const { extractTrueCrypt } = await import("./extractors/truecrypt2john");
        return extractionResult(
          source,
          await extractTrueCrypt(source, {
            bootMode: spec.options[OPTION_TRUECRYPT_BOOT_MODE] === true,
          }),
        );
      }
      case "luks": {
        const { extractLuks } = await import("./extractors/luks2john");
        return extractionResult(source, await extractLuks(source));
      }
      case "dmg": {
        const { extractDmg } = await import("./extractors/dmg2john");
        return extractionResult(source, await extractDmg(source));
      }
      case "bitlocker": {
        const { extractBitLocker } = await import("./extractors/bitlocker2john");
        const value = spec.options[OPTION_BITLOCKER_OFFSET];
        const offset = typeof value === "number" ? value : 0;
        return extractionResult(source, await extractBitLocker(source, offset));
      }
      case "kdbx": {
        const { extractKdbx } = await import("./extractors/kdbx2john");
        return extractionResult(source, await extractKdbx(source));
      }
      case "zip": {
        const { extractZip } = await import("./extractors/zip2john");
        return extractionResult(source, await extractZip(source));
      }
      case "office": {
        const { extractOffice } = await import("./extractors/office2john");
        return extractionResult(source, await extractOffice(source));
      }
      case "pdf": {
        const { extractPdf } = await import("./extractors/pdf2john");
        return extractionResult(source, await extractPdf(source));
      }
      case "rar": {
        const { extractRar } = await import("./extractors/rar2john");
        return extractionResult(source, await extractRar(source));
      }
      case "sevenzip": {
        const { extractSevenZip } = await import("./extractors/sevenzip2john");
        return extractionResult(source, await extractSevenZip(source));
      }
      case "gpg": {
        const { extractGpg } = await import("./extractors/gpg2john");
        return extractionResult(source, await extractGpg(source));
      }
    }
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

export function passwordArtifactInfo(spec: PasswordArtifactSpec): ToolResultField[] {
  switch (requirePasswordArtifactTool(spec.variant).kind) {
    case "hash-identifier":
      return [
        {
          label: "Method",
          value:
            "Structural signatures first; raw length only as ambiguity-preserving candidates",
        },
      ];
    case "grafana":
      return [
        { label: "Hashcat mode", value: "10900 (PBKDF2-HMAC-SHA256)" },
        { label: "Iterations", value: "10000" },
      ];
    case "gitea":
      return [
        { label: "Hashcat mode", value: "10900 (PBKDF2-HMAC-SHA256)" },
        { label: "Iterations", value: "50000 (Gitea default PBKDF2 parameters)" },
      ];
    case "ssh":
      return [{ label: "Output", value: "John $sshng$ descriptor" }];
    case "truecrypt":
      return [{ label: "Support", value: "Primary and hidden headers; no keyfiles" }];
    case "luks":
      return [{ label: "Support", value: "LUKS1 AES / cbc-essiv:sha256 / SHA-1" }];
    case "dmg":
      return [{ label: "Support", value: "Encrypted DMG v1 and v2 file images" }];
    case "bitlocker":
      return [{ label: "Support", value: "Password and recovery-password VMKs" }];
    case "kdbx":
      return [{ label: "Support", value: "KDBX 3.0/3.1 and 4.0/4.1; no external keyfile" }];
    case "zip":
      return [
        {
          label: "Support",
          value: "ZIP/ZIP64; ZipCrypto methods 0/8 and WinZip AES AE-1/AE-2",
        },
      ];
    case "office":
      return [
        {
          label: "Support",
          value: "Excel/Word RC4 and CryptoAPI; OOXML standard and agile 2007/2010/2013",
        },
      ];
    case "pdf":
      return [
        {
          label: "Support",
          value: "Standard security-handler revisions 2-6; classic trailer/encryption objects",
        },
      ];
    case "rar":
      return [
        {
          label: "Support",
          value: "RAR3 -p/-hp and RAR5 file/header password-check records; no SFX",
        },
      ];
    case "sevenzip":
      return [
        {
          label: "Support",
          value:
            "7z version 0 one-stream AES folders and encrypted headers; supported single coder/filter",
        },
      ];
    case "gpg":
      return [
        {
          label: "Support",
          value: "Armored/binary OpenPGP v2-v4 encrypted primary secret keys and SKESK data",
        },
      ];
  }
}
