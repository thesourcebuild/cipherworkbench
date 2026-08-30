import { createOptionCatalogue, type OptionCatalogue, type OptionDef } from "@ocs/engine";
import {
  OPTION_ARGON2_AD,
  OPTION_ARGON2_MEMORY,
  OPTION_ARGON2_PARALLELISM,
  OPTION_ARGON2_SECRET,
  OPTION_ARGON2_TIME,
  OPTION_ARGON2_VARIANT,
  OPTION_BCRYPT_COST,
  OPTION_EXPECTED,
  OPTION_HASH,
  OPTION_IKM,
  OPTION_INFO,
  OPTION_ITERATIONS,
  OPTION_KEY_LENGTH,
  OPTION_MODE,
  OPTION_PASSWORD,
  OPTION_ROUNDS,
  OPTION_SALT,
  OPTION_SCRYPT_N,
  OPTION_SCRYPT_P,
  OPTION_SCRYPT_R,
  OWASP_ARGON2_MEMORY_KIB,
  OWASP_BCRYPT_COST,
  OWASP_PBKDF2_SHA256,
  OPENSSH_DEFAULT_ROUNDS,
  OPENSSH_KEY_IV_BYTES,
  OWASP_SCRYPT_N,
  RECOMMENDED_SALT_BYTES,
} from "../pure";
import { ARGON2_VARIANTS, KDF_HASHES, requireKdfTool } from "./tool-meta";
import type { KdfOptionGroup } from "./groups";

/**
 * The mode switch, shown only for the three tools that can verify.
 *
 * PBKDF2 and HKDF have no standard textual encoding, so their output carries none of the
 * parameters needed to check it later — there is nothing to verify against. Offering the
 * switch there would imply a capability that does not exist.
 */
const MODE_OPTION: OptionDef<KdfOptionGroup> = {
  id: OPTION_MODE,
  label: "Mode",
  group: "mode",
  kind: "enum",
  choices: [
    { value: "derive", label: "Derive", summary: "Produce a new hash" },
    { value: "verify", label: "Verify", summary: "Check a password against a stored hash" },
  ],
  summary: "Produce a hash, or check one.",
  detail:
    "Verify mode reads the parameters and salt out of the stored hash string and recomputes with them, which is how checking a password actually works: you never decrypt a hash, you re-derive and compare. The comparison is constant-time.",
  order: 10,
};

const PASSWORD_OPTION: OptionDef<KdfOptionGroup> = {
  id: OPTION_PASSWORD,
  label: "Password",
  group: "secret",
  kind: "password",
  arg: { placeholder: "The password or passphrase" },
  secret: true,
  summary: "The low-entropy input these functions exist to protect.",
  detail:
    "Treated as UTF-8 bytes. This is the value the whole cost parameterisation is for: a password has perhaps 30 bits of entropy, so the only defence is making each guess expensive. Never included in a share link.",
  order: 10,
};

const SALT_OPTION: OptionDef<KdfOptionGroup> = {
  id: OPTION_SALT,
  label: "Salt",
  group: "secret",
  kind: "bytes",
  bytesLength: { min: 1, max: 1024, generate: RECOMMENDED_SALT_BYTES },
  defaultBytesEncoding: "utf-8",
  summary: "Unique per password. Not secret.",
  detail:
    "A salt stops one precomputed table from attacking every stored password at once, and stops two identical passwords producing identical hashes. It does not need to be secret and is normally stored alongside the hash, which is why it is not marked secret here and does travel in a share link. What it does need is to be different for every password: 16 random bytes is the usual choice.",
  order: 20,
};

const EXPECTED_OPTION: OptionDef<KdfOptionGroup> = {
  id: OPTION_EXPECTED,
  label: "Stored hash",
  group: "mode",
  kind: "text",
  arg: { placeholder: "$argon2id$v=19$m=19456,t=2,p=1$..." },
  availableOn: ["verify"],
  summary: "The hash string to check against.",
  detail:
    "Paste the whole thing, including the dollar-delimited prefix. The parameters and salt are read out of it, so nothing else needs filling in. That self-describing format is exactly what makes these three verifiable and PBKDF2 not.",
  order: 20,
};

function keyLengthOption(defaultLen: number): OptionDef<KdfOptionGroup> {
  return {
    id: OPTION_KEY_LENGTH,
    label: "Key length",
    group: "output",
    kind: "number",
    arg: { placeholder: String(defaultLen), unit: "bytes", min: 1, max: 1024, step: 1 },
    summary: "How many bytes to derive.",
    detail:
      "Ask for what you will use. For a symmetric key that means 16 or 32 bytes; for password storage the length barely matters above the hash's output size, since the result is compared rather than used.",
    order: 10,
  };
}

const HASH_OPTION: OptionDef<KdfOptionGroup> = {
  id: OPTION_HASH,
  label: "Hash",
  group: "cost",
  kind: "enum",
  choices: KDF_HASHES.map((h) => ({
    value: h.id,
    label: h.label,
    summary: `${h.outputLen}-byte output`,
  })),
  summary: "Which HMAC to iterate.",
  detail:
    "Changes both the output size and the per-iteration cost, which is why the recommended iteration count differs per hash: SHA-512 does roughly three times the work of SHA-256 per pass, so it needs proportionally fewer.",
  order: 10,
};

const PBKDF2_OPTIONS: readonly OptionDef<KdfOptionGroup>[] = [
  PASSWORD_OPTION,
  SALT_OPTION,
  HASH_OPTION,
  {
    id: OPTION_ITERATIONS,
    label: "Iterations",
    group: "cost",
    kind: "number",
    arg: {
      placeholder: String(OWASP_PBKDF2_SHA256),
      unit: "iterations",
      min: 1,
      max: 10_000_000,
      step: 1000,
    },
    summary: "The only cost knob PBKDF2 has.",
    detail:
      "Each iteration is one HMAC. That is the whole design, and its weakness: iterations parallelise almost perfectly on a GPU, so an attacker's advantage over a server scales with hardware in a way memory-hard functions prevent. OWASP currently recommends 600,000 for SHA-256.",
    order: 20,
  },
  keyLengthOption(32),
];

/**
 * EvpKDF reuses PBKDF2's shape exactly -- password, salt, hash, iteration count, output length --
 * because that is genuinely what `EVP_BytesToKey` takes. Only the defaults and the help text
 * differ, and both differ for the same reason: this tool exists to reproduce old output, so its
 * defaults are the historical ones rather than the safe ones.
 */
const EVPKDF_OPTIONS: readonly OptionDef<KdfOptionGroup>[] = [
  PASSWORD_OPTION,
  // `openssl enc` writes an 8-byte salt after the `Salted__` magic, and nothing else uses another
  // size, so the generate button offers exactly that.
  { ...SALT_OPTION, bytesLength: { min: 0, max: 64, generate: 8 } },
  HASH_OPTION,
  {
    id: OPTION_ITERATIONS,
    label: "Iterations",
    group: "cost",
    kind: "number",
    arg: { placeholder: "1", unit: "iterations", min: 1, max: 100_000, step: 1 },
    summary: "OpenSSL's count. 1 is the historical default and what -k used.",
    detail:
      "The number of times each block's digest is fed back through the hash. `openssl enc` used 1 for about twenty years, which is the setting that makes this construction unfit for passwords -- a single MD5 over an 8-byte salt is essentially free to brute-force. Raising it does not make this a modern KDF, because the work still parallelises perfectly and there is no memory cost: use PBKDF2, scrypt or Argon2 for anything new. This is here to read old data.",
    order: 20,
  },
  // 48 bytes is AES-256-CBC's key plus IV, which is the commonest thing anyone derives here.
  keyLengthOption(48),
];

const HKDF_OPTIONS: readonly OptionDef<KdfOptionGroup>[] = [
  {
    id: OPTION_IKM,
    label: "Input key material",
    group: "secret",
    kind: "bytes",
    bytesLength: { min: 1, max: 4096, generate: 32 },
    defaultBytesEncoding: "hex",
    secret: true,
    summary: "Material that is already high-entropy.",
    detail:
      "A Diffie-Hellman shared secret, a master key, output from a CSPRNG. HKDF assumes this is already unguessable and does no work to slow anyone down. That assumption is the entire reason it is fast, and why putting a password here provides no protection whatsoever.",
    order: 10,
  },
  { ...SALT_OPTION, bytesLength: { min: 0, max: 1024, generate: 32 } },
  HASH_OPTION,
  {
    id: OPTION_INFO,
    label: "Info / context",
    group: "cost",
    /**
     * A `bytes` option rather than `text`, because RFC 5869 defines info as an octet string
     * and its own test vectors use raw bytes (0xf0..0xf9) that no text encoding produces.
     * The default encoding is UTF-8, so typing "client write key" still behaves exactly as
     * a text field would — but hex is reachable when a spec calls for it.
     */
    kind: "bytes",
    bytesLength: { min: 0, max: 1024 },
    defaultBytesEncoding: "utf-8",
    summary: "Domain separation. Not secret.",
    detail:
      "Binds the output to a purpose, so one shared secret can yield several unrelated keys. TLS 1.3 derives every traffic key this way, distinguished only by this string. Not secret, and it travels in a share link. Usually ASCII text; switch the encoding to hex if a specification gives it as bytes.",
    order: 20,
  },
  keyLengthOption(32),
];

const SCRYPT_OPTIONS: readonly OptionDef<KdfOptionGroup>[] = [
  MODE_OPTION,
  EXPECTED_OPTION,
  PASSWORD_OPTION,
  SALT_OPTION,
  {
    id: OPTION_SCRYPT_N,
    label: "Cost (N)",
    group: "cost",
    kind: "number",
    arg: { placeholder: String(OWASP_SCRYPT_N), min: 2, max: 1 << 22, step: 1 },
    summary: "Must be a power of two. Sets both time and memory.",
    detail:
      "Memory used is roughly 128 * N * r bytes, so N is the dominant cost and doubling it doubles both time and RAM. That coupling is the point: an attacker cannot trade memory for speed the way they can with PBKDF2. OWASP's floor is 2^17 = 131072, which with r=8 comes to about 128 MiB.",
    order: 10,
  },
  {
    id: OPTION_SCRYPT_R,
    label: "Block size (r)",
    group: "cost",
    kind: "number",
    arg: { placeholder: "8", min: 1, max: 64, step: 1 },
    summary: "Bytes per mixing block. 8 is standard.",
    detail:
      "Tunes the size of each memory access. Raising it improves resistance to attackers with fast, narrow memory; 8 is what every published recommendation uses and there is rarely a reason to change it.",
    order: 20,
  },
  {
    id: OPTION_SCRYPT_P,
    label: "Parallelism (p)",
    group: "cost",
    kind: "number",
    arg: { placeholder: "1", min: 1, max: 16, step: 1 },
    summary: "Independent chains. 1 is standard.",
    detail:
      "Multiplies the work without multiplying the memory. Useful only when you want more cost than memory allows; it hands the attacker the same parallelism, so it is the least valuable of the three knobs.",
    order: 30,
  },
  keyLengthOption(32),
];

const ARGON2_OPTIONS: readonly OptionDef<KdfOptionGroup>[] = [
  MODE_OPTION,
  EXPECTED_OPTION,
  PASSWORD_OPTION,
  SALT_OPTION,
  {
    id: OPTION_ARGON2_VARIANT,
    label: "Variant",
    group: "cost",
    kind: "enum",
    choices: ARGON2_VARIANTS.map((v) => ({ value: v.id, label: v.label, summary: v.summary })),
    summary: "Argon2id unless you have a specific reason.",
    detail:
      "Argon2d indexes memory based on the password, which maximises GPU resistance and leaks timing. Argon2i indexes independently of it, which resists side channels and is weaker against a GPU. Argon2id does the first pass one way and the rest the other, getting most of both, which is why RFC 9106 recommends it by default.",
    order: 10,
  },
  {
    id: OPTION_ARGON2_MEMORY,
    label: "Memory",
    group: "cost",
    kind: "number",
    arg: {
      placeholder: String(OWASP_ARGON2_MEMORY_KIB),
      unit: "KiB",
      min: 8,
      max: 4 << 20,
      step: 1024,
    },
    summary: "The dominant cost. More is better.",
    detail:
      "Memory is what makes Argon2 expensive to attack in hardware: cores are cheap and RAM is not. RFC 9106's first recommendation is 2 GiB, its second 64 MiB with t=3; OWASP's floor is 19 MiB with t=2. Raise this before raising time.",
    order: 20,
  },
  {
    id: OPTION_ARGON2_TIME,
    label: "Iterations (t)",
    group: "cost",
    kind: "number",
    arg: { placeholder: "2", min: 1, max: 64, step: 1 },
    summary: "Passes over the memory.",
    detail:
      "Multiplies time without changing memory. Prefer more memory to more passes when you have the choice, because memory is the axis an attacker finds hardest to buy.",
    order: 30,
  },
  {
    id: OPTION_ARGON2_PARALLELISM,
    label: "Parallelism (p)",
    group: "cost",
    kind: "number",
    arg: { placeholder: "1", min: 1, max: 16, step: 1 },
    summary: "Lanes. Match your available cores.",
    detail:
      "Splits the memory into independent lanes. It does not change total work, so it is a latency knob rather than a cost one, and it must be recorded with the hash because changing it changes the output.",
    order: 40,
  },
  {
    id: OPTION_ARGON2_SECRET,
    label: "Secret (pepper)",
    group: "cost",
    kind: "bytes",
    bytesLength: { min: 0, max: 64, generate: 32 },
    defaultBytesEncoding: "hex",
    secret: true,

    summary: "Optional server-side value, kept out of the database.",
    detail:
      "RFC 9106 calls this the secret; everyone else calls it a pepper. It is mixed into the initial state and is deliberately NOT part of the output string, so a stolen password table cannot be attacked without also stealing your application config. The catch is the same fact from the other side: lose it and every stored hash becomes unverifiable. Leave it empty unless you have somewhere safe to keep it.",
    order: 50,
  },
  {
    id: OPTION_ARGON2_AD,
    label: "Associated data",
    group: "cost",
    kind: "bytes",
    bytesLength: { min: 0, max: 256 },
    defaultBytesEncoding: "utf-8",
    summary: "Optional context binding. Not secret.",
    detail:
      "Binds the hash to something outside the password — a user id, a tenant, a purpose — so a hash cannot be lifted from one record and dropped into another. Like the secret it is not recorded in the output string, so it has to be supplied again to verify. Unlike the secret it is not confidential.",
    order: 60,
  },
  keyLengthOption(32),
];

const BCRYPT_OPTIONS: readonly OptionDef<KdfOptionGroup>[] = [
  MODE_OPTION,
  EXPECTED_OPTION,
  PASSWORD_OPTION,
  {
    id: OPTION_BCRYPT_COST,
    label: "Cost",
    group: "cost",
    kind: "number",
    arg: {
      placeholder: String(OWASP_BCRYPT_COST),
      unit: "log2 rounds",
      min: 4,
      max: 20,
      step: 1,
    },
    summary: "Logarithmic: each step doubles the work.",
    detail:
      "The number of key-setup rounds is 2^cost, so 12 is four times the work of 10. bcrypt has no memory parameter — its working set is a fixed 4 KB, small enough to fit in GPU cache, which is the main reason it has aged less well than scrypt or Argon2. 10 is the current floor; 12 is comfortable on server hardware.",
    order: 10,
  },
];

const BCRYPT_PBKDF_OPTIONS: readonly OptionDef<KdfOptionGroup>[] = [
  PASSWORD_OPTION,
  SALT_OPTION,
  {
    id: OPTION_ROUNDS,
    label: "Rounds",
    group: "cost",
    kind: "number",
    arg: {
      placeholder: String(OPENSSH_DEFAULT_ROUNDS),
      unit: "rounds",
      min: 1,
      max: 4096,
      step: 1,
    },
    summary: "`ssh-keygen -a`. Linear, unlike bcrypt's cost.",
    detail:
      "Each round is 129 full EksBlowfish key expansions -- roughly bcrypt at cost 7 -- so doubling this doubles the work. Note that the units are NOT bcrypt's: there the parameter is a log2 exponent, so 16 would mean 65,536 rounds. Here 16 means 16, and it is what `ssh-keygen` has defaulted to since 2013. Raising it is the only way to make an encrypted private key more expensive to attack.",
    order: 10,
  },
  /**
   * 48 bytes: AES-256-CTR's key plus its IV, which is exactly what OpenSSH cuts out of this
   * stream for a private-key file. The same reasoning as EvpKDF's default.
   */
  keyLengthOption(OPENSSH_KEY_IV_BYTES),
];

const CACHE = new Map<string, OptionCatalogue<KdfOptionGroup>>();

/**
 * One entry per tool, and a miss throws.
 *
 * This was a chain of conditionals ending in `: BCRYPT_OPTIONS`, which is the same shape of bug
 * that has now shipped three times elsewhere in this repo: a tool added to a family silently
 * inherits another tool's form, with every test still passing. bcrypt-PBKDF would have arrived
 * with bcrypt's log2 cost field and no salt at all.
 */
const GENERIC_KDF_OPTIONS: readonly OptionDef<KdfOptionGroup>[] = [
  PASSWORD_OPTION,
  SALT_OPTION,
  keyLengthOption(32),
];

const OPTIONS_BY_TOOL: Readonly<Record<string, readonly OptionDef<KdfOptionGroup>[]>> = {
  evpkdf: EVPKDF_OPTIONS,
  pbkdf2: PBKDF2_OPTIONS,
  hkdf: HKDF_OPTIONS,
  scrypt: SCRYPT_OPTIONS,
  argon2: ARGON2_OPTIONS,
  bcrypt: BCRYPT_OPTIONS,
  bcryptpbkdf: BCRYPT_PBKDF_OPTIONS,
  yescrypt: GENERIC_KDF_OPTIONS,
  balloon: GENERIC_KDF_OPTIONS,
  "sp800-108": GENERIC_KDF_OPTIONS,
  "openpgp-s2k": GENERIC_KDF_OPTIONS,
  "ssh-kdf": GENERIC_KDF_OPTIONS,
  "tls12-prf": GENERIC_KDF_OPTIONS,
  catena: GENERIC_KDF_OPTIONS,
  "ansi-x963": GENERIC_KDF_OPTIONS,
  hpke: GENERIC_KDF_OPTIONS,
  bip39: GENERIC_KDF_OPTIONS,
  bip32: GENERIC_KDF_OPTIONS,
  "hkdf-label": GENERIC_KDF_OPTIONS,
};

export function kdfCatalogueFor(toolId: string): OptionCatalogue<KdfOptionGroup> {
  let catalogue = CACHE.get(toolId);
  if (!catalogue) {
    requireKdfTool(toolId);
    const options = OPTIONS_BY_TOOL[toolId];
    if (!options) throw new Error(`No option catalogue for KDF tool: ${toolId}`);
    catalogue = createOptionCatalogue<KdfOptionGroup>(options);
    CACHE.set(toolId, catalogue);
  }
  return catalogue;
}
