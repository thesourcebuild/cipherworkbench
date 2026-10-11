import type { ToolComputeContext, ToolResult, ToolResultField } from "@ocs/engine";
import { optString } from "@ocs/contracts/pure";
import type * as OpenPgp from "openpgp";
import type {
  Key,
  KeyID,
  Message,
  PartialConfig,
  PrivateKey,
  PublicKey,
} from "openpgp";
import {
  OPTION_OPENPGP_KEY_PASSPHRASE,
  OPTION_OPENPGP_PASSWORD,
  OPTION_OPENPGP_PRIVATE_KEYS,
  OPTION_OPENPGP_RECIPIENT_KEYS,
  OPTION_OPENPGP_VERIFICATION_KEYS,
  readOpenPgpCompression,
  readOpenPgpOperation,
  readOpenPgpOutput,
  readOpenPgpProtection,
  type OpenPgpOutput,
} from "./pure";
import type { FormatSpec } from "./spec";

type OpenPgpModule = typeof OpenPgp;
type Verification = { keyID: KeyID; verified: Promise<true> };

const ARMOR_PREFIX = "-----BEGIN PGP ";

/** The implementation is intentionally absent from manifests and the format definition chunk. */
async function loadOpenPgp(): Promise<OpenPgpModule> {
  return import("openpgp");
}

export async function computeOpenPgp(
  spec: FormatSpec,
  input: Uint8Array,
  context?: ToolComputeContext,
): Promise<ToolResult> {
  const operation = readOpenPgpOperation(spec.options);
  try {
    const openpgp = await loadOpenPgp();
    const config = openPgpConfig(openpgp, spec);

    switch (operation) {
      case "password-encrypt": {
        const password = requiredOption(spec, OPTION_OPENPGP_PASSWORD, "message password");
        const message = await createFileMessage(openpgp, input, context);
        const output = await encrypt(openpgp, {
          message,
          passwords: [password],
          config,
          output: readOpenPgpOutput(spec.options),
        });
        return encryptedResult(openpgp, output, context, readOpenPgpOutput(spec.options), []);
      }
      case "password-decrypt": {
        const password = requiredOption(spec, OPTION_OPENPGP_PASSWORD, "message password");
        const message = await readMessage(openpgp, input, config);
        const decrypted = await openpgp.decrypt({
          message,
          passwords: [password],
          format: "binary",
          config,
        });
        return recoveredResult(decrypted.data, decrypted.filename, context);
      }
      case "public-key-encrypt": {
        const recipients = await readPublicKeys(
          openpgp,
          requiredOption(spec, OPTION_OPENPGP_RECIPIENT_KEYS, "recipient public key"),
          config,
        );
        const message = await createFileMessage(openpgp, input, context);
        const output = await encrypt(openpgp, {
          message,
          encryptionKeys: recipients,
          config,
          output: readOpenPgpOutput(spec.options),
        });
        return encryptedResult(
          openpgp,
          output,
          context,
          readOpenPgpOutput(spec.options),
          recipientFields(recipients),
        );
      }
      case "private-key-decrypt": {
        const privateKeys = await readUnlockedPrivateKeys(openpgp, spec, config);
        const message = await readMessage(openpgp, input, config);
        const decrypted = await openpgp.decrypt({
          message,
          decryptionKeys: privateKeys,
          format: "binary",
          config,
        });
        return recoveredResult(decrypted.data, decrypted.filename, context);
      }
      case "sign": {
        const signingKeys = await readUnlockedPrivateKeys(openpgp, spec, config);
        const message = await createFileMessage(openpgp, input, context);
        const output = await sign(
          openpgp,
          message,
          signingKeys,
          readOpenPgpOutput(spec.options),
          config,
        );
        return signedResult(
          output,
          context,
          readOpenPgpOutput(spec.options),
          signerFields(signingKeys, "Created"),
        );
      }
      case "verify": {
        const verificationKeys = await readPublicKeys(
          openpgp,
          requiredOption(spec, OPTION_OPENPGP_VERIFICATION_KEYS, "signer public key"),
          config,
        );
        const message = await readMessage(openpgp, input, config);
        const filename = message.getFilename() ?? "";
        const verified = await openpgp.verify({
          message,
          verificationKeys,
          expectSigned: false,
          format: "binary",
          config,
        });
        const signatureResult = await verifySignatures(verified.signatures, verificationKeys);
        if (signatureResult.error) {
          return { error: signatureResult.error, fields: signatureResult.fields };
        }
        return recoveredResult(verified.data, filename, context, signatureResult.fields);
      }
      case "encrypt-and-sign": {
        const recipients = await readPublicKeys(
          openpgp,
          requiredOption(spec, OPTION_OPENPGP_RECIPIENT_KEYS, "recipient public key"),
          config,
        );
        const signingKeys = await readUnlockedPrivateKeys(openpgp, spec, config);
        const message = await createFileMessage(openpgp, input, context);
        const output = await encrypt(openpgp, {
          message,
          encryptionKeys: recipients,
          signingKeys,
          config,
          output: readOpenPgpOutput(spec.options),
        });
        return encryptedResult(openpgp, output, context, readOpenPgpOutput(spec.options), [
          ...recipientFields(recipients),
          ...signerFields(signingKeys, "Created"),
        ]);
      }
      case "decrypt-and-verify": {
        const privateKeys = await readUnlockedPrivateKeys(openpgp, spec, config);
        const verificationKeys = await readPublicKeys(
          openpgp,
          requiredOption(spec, OPTION_OPENPGP_VERIFICATION_KEYS, "signer public key"),
          config,
        );
        const message = await readMessage(openpgp, input, config);
        const decrypted = await openpgp.decrypt({
          message,
          decryptionKeys: privateKeys,
          verificationKeys,
          expectSigned: false,
          format: "binary",
          config,
        });
        const signatureResult = await verifySignatures(decrypted.signatures, verificationKeys);
        if (signatureResult.error) {
          return { error: signatureResult.error, fields: signatureResult.fields };
        }
        return recoveredResult(
          decrypted.data,
          decrypted.filename,
          context,
          signatureResult.fields,
        );
      }
    }
  } catch (error) {
    return { error: friendlyError(operation, error) };
  }
}

function openPgpConfig(openpgp: OpenPgpModule, spec: FormatSpec): PartialConfig {
  const compression = readOpenPgpCompression(spec.options);
  const protection = readOpenPgpProtection(spec.options);
  return {
    preferredCompressionAlgorithm: openpgp.enums.compression[compression],
    aeadProtect: protection !== "mdc",
    preferredAEADAlgorithm:
      protection === "aead-ocb" ? openpgp.enums.aead.ocb : openpgp.enums.aead.gcm,
    allowUnauthenticatedMessages: false,
    allowUnauthenticatedStream: false,
  };
}

async function createFileMessage(
  openpgp: OpenPgpModule,
  input: Uint8Array,
  context: ToolComputeContext | undefined,
): Promise<Message<Uint8Array>> {
  const filename = safeFilename(context?.filename);
  return openpgp.createMessage({ binary: input, ...(filename ? { filename } : {}) });
}

async function readMessage(
  openpgp: OpenPgpModule,
  input: Uint8Array,
  config: PartialConfig,
): Promise<Message<Uint8Array>> {
  const armored = armoredText(input);
  const message =
    armored === undefined
      ? await openpgp.readMessage({ binaryMessage: input, config })
      : await openpgp.readMessage({ armoredMessage: armored, config });
  // `format: "binary"` on decrypt/verify determines the recovered type; the parser's
  // generic otherwise incorrectly ties an armored transport string to UTF-8 literal data.
  return message as unknown as Message<Uint8Array>;
}

async function readPublicKeys(
  openpgp: OpenPgpModule,
  raw: string,
  config: PartialConfig,
): Promise<PublicKey[]> {
  const material = keyMaterial(raw);
  let keys: Key[];
  try {
    keys =
      typeof material === "string"
        ? (
            await Promise.all(
              armoredKeyBlocks(material).map((armoredKeys) =>
                openpgp.readKeys({ armoredKeys, config }),
              ),
            )
          ).flat()
        : await openpgp.readKeys({ binaryKeys: material, config });
  } catch (error) {
    throw new Error(`Could not read the public key material: ${errorMessage(error)}`);
  }
  if (keys.length === 0) throw new Error("The public-key input contains no OpenPGP keys.");
  if (keys.some((key) => key.isPrivate())) {
    throw new Error("A public-key field contains a private key. Export and use its public key instead.");
  }
  return keys as PublicKey[];
}

async function readUnlockedPrivateKeys(
  openpgp: OpenPgpModule,
  spec: FormatSpec,
  config: PartialConfig,
): Promise<PrivateKey[]> {
  const raw = requiredOption(spec, OPTION_OPENPGP_PRIVATE_KEYS, "private key");
  const material = keyMaterial(raw);
  let keys: PrivateKey[];
  try {
    keys =
      typeof material === "string"
        ? (
            await Promise.all(
              armoredKeyBlocks(material).map((armoredKeys) =>
                openpgp.readPrivateKeys({ armoredKeys, config }),
              ),
            )
          ).flat()
        : await openpgp.readPrivateKeys({ binaryKeys: material, config });
  } catch (error) {
    throw new Error(`Could not read the private key material: ${errorMessage(error)}`);
  }
  if (keys.length === 0) throw new Error("The private-key input contains no OpenPGP private keys.");

  const passphrase = optString(spec.options, OPTION_OPENPGP_KEY_PASSPHRASE);
  return Promise.all(
    keys.map(async (key) => {
      if (key.isDecrypted()) return key;
      if (!passphrase) throw new Error("This private key is protected; enter its passphrase.");
      try {
        return await openpgp.decryptKey({ privateKey: key, passphrase, config });
      } catch {
        throw new Error("The private-key passphrase is wrong, or the secret key is damaged.");
      }
    }),
  );
}

async function encrypt(
  openpgp: OpenPgpModule,
  options: {
    message: Message<Uint8Array>;
    encryptionKeys?: PublicKey[];
    signingKeys?: PrivateKey[];
    passwords?: string[];
    config: PartialConfig;
    output: OpenPgpOutput;
  },
): Promise<string | Uint8Array> {
  const common = {
    message: options.message,
    ...(options.encryptionKeys ? { encryptionKeys: options.encryptionKeys } : {}),
    ...(options.signingKeys ? { signingKeys: options.signingKeys } : {}),
    ...(options.passwords ? { passwords: options.passwords } : {}),
    config: options.config,
  };
  return options.output === "armor"
    ? openpgp.encrypt<Uint8Array>({ ...common, format: "armored" })
    : openpgp.encrypt<Uint8Array>({ ...common, format: "binary" });
}

async function sign(
  openpgp: OpenPgpModule,
  message: Message<Uint8Array>,
  signingKeys: PrivateKey[],
  output: OpenPgpOutput,
  config: PartialConfig,
): Promise<string | Uint8Array> {
  return output === "armor"
    ? openpgp.sign<Uint8Array>({ message, signingKeys, format: "armored", config })
    : openpgp.sign<Uint8Array>({ message, signingKeys, format: "binary", config });
}

async function encryptedResult(
  openpgp: OpenPgpModule,
  output: string | Uint8Array,
  context: ToolComputeContext | undefined,
  format: OpenPgpOutput,
  fields: ToolResultField[],
): Promise<ToolResult> {
  const parsed =
    typeof output === "string"
      ? await openpgp.readMessage({ armoredMessage: output })
      : await openpgp.readMessage({ binaryMessage: output });
  const aead = parsed.packets.some(
    (packet) =>
      packet instanceof openpgp.AEADEncryptedDataPacket ||
      (packet instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket &&
        (packet as unknown as { version?: number }).version === 2),
  );
  return packetResult(output, context, format, "encrypted", [
    {
      label: "Integrity protection",
      value: aead ? "RFC 9580 AEAD" : "MDC (SEIPD v1)",
      hint: aead
        ? "Authentication is integrated into each AEAD chunk."
        : "Modification detection is checked before plaintext is returned.",
    },
    ...fields,
  ]);
}

function signedResult(
  output: string | Uint8Array,
  context: ToolComputeContext | undefined,
  format: OpenPgpOutput,
  fields: ToolResultField[],
): ToolResult {
  return packetResult(output, context, format, "signed", fields);
}

function packetResult(
  output: string | Uint8Array,
  context: ToolComputeContext | undefined,
  format: OpenPgpOutput,
  kind: "encrypted" | "signed",
  fields: ToolResultField[],
): ToolResult {
  const source = safeFilename(context?.filename) || "message.bin";
  const suggestedFilename = `${source}${format === "armor" ? ".asc" : ".pgp"}`;
  const mimeType =
    kind === "encrypted"
      ? "application/pgp-encrypted"
      : format === "armor"
        ? "text/plain"
        : "application/octet-stream";
  return typeof output === "string"
    ? { text: output, fields, suggestedFilename, mimeType }
    : { bytes: output, fields, suggestedFilename, mimeType };
}

function recoveredResult(
  data: Uint8Array,
  literalFilename: string,
  context: ToolComputeContext | undefined,
  fields: ToolResultField[] = [],
): ToolResult {
  const packetName = safeFilename(literalFilename);
  const sourceName = safeFilename(context?.filename);
  const suggestedFilename =
    packetName || stripOpenPgpExtension(sourceName) || "openpgp-output.bin";
  return {
    bytes: data,
    fields: [
      {
        label: "Literal filename",
        value: packetName || "(not present)",
        hint: "Taken from the authenticated OpenPGP literal-data packet.",
      },
      ...fields,
    ],
    suggestedFilename,
    mimeType: "application/octet-stream",
  };
}

async function verifySignatures(
  signatures: readonly Verification[],
  keys: readonly PublicKey[],
): Promise<{ fields: ToolResultField[]; error?: string }> {
  if (signatures.length === 0) {
    return { fields: [], error: "The OpenPGP message contains no signature." };
  }

  const fields: ToolResultField[] = [];
  let invalid = 0;
  for (let index = 0; index < signatures.length; index++) {
    const signature = signatures[index]!;
    let valid = true;
    let problem = "";
    try {
      await signature.verified;
    } catch (error) {
      valid = false;
      invalid++;
      problem = errorMessage(error);
    }
    const key = keys.find((candidate) =>
      candidate.getKeyIDs().some((keyID) => keyID.equals(signature.keyID)),
    );
    const suffix = signatures.length === 1 ? "" : ` ${index + 1}`;
    fields.push(
      {
        label: `Signature${suffix}`,
        value: valid ? "Valid" : "Invalid",
        ...(problem ? { hint: problem } : {}),
      },
      { label: `Signing key ID${suffix}`, value: signature.keyID.toHex().toUpperCase() },
      ...identityFields(key, suffix),
    );
  }
  return invalid === 0
    ? { fields }
    : {
        fields,
        error: `${invalid} of ${signatures.length} OpenPGP signature${signatures.length === 1 ? "" : "s"} failed verification.`,
      };
}

function recipientFields(keys: readonly PublicKey[]): ToolResultField[] {
  return [
    {
      label: "Recipients",
      value: String(keys.length),
      hint: keys.map((key) => key.getKeyID().toHex().toUpperCase()).join(", "),
    },
  ];
}

function signerFields(keys: readonly PrivateKey[], status: string): ToolResultField[] {
  return keys.flatMap((key, index) => {
    const suffix = keys.length === 1 ? "" : ` ${index + 1}`;
    return [
      { label: `Signature${suffix}`, value: status },
      { label: `Signing key ID${suffix}`, value: key.getKeyID().toHex().toUpperCase() },
      ...identityFields(key, suffix),
    ];
  });
}

function identityFields(key: Key | undefined, suffix: string): ToolResultField[] {
  if (!key) return [];
  const users = key.getUserIDs();
  return [
    { label: `Signer fingerprint${suffix}`, value: key.getFingerprint().toUpperCase() },
    { label: `Signer identity${suffix}`, value: users.length > 0 ? users.join("; ") : "(no user ID)" },
  ];
}

function keyMaterial(raw: string): string | Uint8Array {
  const value = raw.trim();
  if (value.includes(ARMOR_PREFIX)) return value;
  const encoded = value.replace(/^base64:/i, "").replace(/\s+/g, "");
  if (encoded === "" || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
    throw new Error("Binary OpenPGP key material must be supplied as Base64 or prefixed with 'base64:'.");
  }
  try {
    const binary = atob(encoded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new Error("The binary OpenPGP key material is not valid Base64.");
  }
}

function armoredKeyBlocks(value: string): string[] {
  const blocks = value.match(
    /-----BEGIN PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----[\s\S]*?-----END PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----/g,
  );
  if (!blocks?.length) throw new Error("The key input does not contain an OpenPGP key block.");
  return blocks;
}

function armoredText(input: Uint8Array): string | undefined {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(input).replace(/^\uFEFF/, "");
    return text.trimStart().startsWith(ARMOR_PREFIX) ? text : undefined;
  } catch {
    return undefined;
  }
}

function requiredOption(spec: FormatSpec, id: string, label: string): string {
  const value = optString(spec.options, id);
  if (!value?.trim()) throw new Error(`Enter the ${label}.`);
  return value;
}

function safeFilename(value: string | undefined): string {
  if (!value) return "";
  const basename = value.replace(/\\/g, "/").split("/").pop()?.replace(/[\0-\x1F\x7F]/g, "").trim() ?? "";
  if (basename === "." || basename === "..") return "";
  let result = "";
  for (const character of basename) {
    if (new TextEncoder().encode(result + character).length > 255) break;
    result += character;
  }
  return result;
}

function stripOpenPgpExtension(value: string): string {
  return value.replace(/\.(?:pgp|gpg|asc)$/i, "");
}

function friendlyError(operation: string, error: unknown): string {
  const message = errorMessage(error);
  if (/session key|decrypt|modification detected|authentication tag|integrity/i.test(message)) {
    const credential = operation === "password-decrypt" ? "password" : "private key";
    return `Could not decrypt the OpenPGP message. The ${credential} may be wrong, or the message failed its integrity check. ${message}`;
  }
  return message;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
