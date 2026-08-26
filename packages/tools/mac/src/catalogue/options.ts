import {
  createOptionCatalogue,
  type OptionCatalogue,
  type OptionDef,
  type OptionEnumChoice,
} from "@ocs/engine";
import {
  OPTION_CUSTOMIZATION,
  OPTION_HASH,
  OPTION_KEY,
  OPTION_KMAC_VARIANT,
  OPTION_OUTPUT_LENGTH,
  OPTION_TRUNCATE,
  OPTION_SKEIN_STATE,
  TAG_ASCON_PRF,
  TAG_HIGHWAY,
  TAG_HMAC,
  TAG_KMAC,
  TAG_SKEIN_MAC,
} from "../pure";
import { HMAC_HASHES, KMAC_VARIANTS, requireMacTool } from "./tool-meta";
import type { MacOptionGroup } from "./groups";

/**
 * The key option, shared by all four tools.
 *
 * `secret: true` is the load-bearing flag: it masks the field, keeps the value out of
 * share links and out of anything persisted, and is what `validateCatalogue` checks for on
 * a `password` kind. `bytesLength` differs per tool — Poly1305 demands exactly 32 bytes,
 * CMAC one of AES's three sizes, HMAC anything — so this is a factory rather than a
 * constant.
 *
 * So does the **default encoding**, and it is not a stylistic choice. The key is bytes, and the
 * field holds text, so something has to say how one becomes the other; whatever this declares is
 * what the form's selector starts on and what `decodeBytesOption` falls back to. HMAC gets `utf-8`
 * because an HMAC key in practice is a typed string — a shared secret out of a config file, an API
 * token — and because that is what the reference this app is measured against does: with the key
 * `1234` and the message `123456789`, reading the key as text gives
 * `1a317d78de6906810199224081c464ef1673ca4c19e30f5d61b4e048748dfb48` and reading it as the two
 * bytes `0x12 0x34` gives `208e58cc…`. Both are correct HMACs of different keys, which is exactly
 * why the default matters: nothing about the output says which one you got.
 *
 * The other three keep `hex`, and for a reason rather than by omission. Poly1305 takes exactly 32
 * bytes and CMAC one of AES's three sizes, so a typed passphrase is almost always the wrong length
 * and would be refused rather than silently misread; KMAC's published vectors in NIST SP 800-185
 * are byte strings, and anyone using it is working from that document.
 *
 * Changing this default is safe in a way it would not be for a non-secret option: keys are never
 * written to a share link or to saved state, so there is no stored value whose meaning could shift
 * underneath it.
 */
function keyOption(
  bytesLength: OptionDef["bytesLength"],
  detail: string,
  defaultBytesEncoding: OptionDef["defaultBytesEncoding"] = "hex",
): OptionDef<MacOptionGroup> {
  return {
    id: OPTION_KEY,
    label: "Key",
    group: "key",
    kind: "bytes",
    bytesLength,
    defaultBytesEncoding,
    secret: true,
    summary: "The shared secret.",
    detail,
    order: 10,
  };
}

function hashChoices(): OptionEnumChoice[] {
  return HMAC_HASHES.map((hash) => ({
    value: hash.id,
    label: hash.label,
    summary: `${hash.outputLen}-byte tag`,
    // HMAC over a collision-broken hash is not itself broken — HMAC-MD5 has no practical
    // forgery — but it is not something to choose for new work, and the form should say so
    // where the choice is made.
    ...(hash.legacy ? { insecure: true } : {}),
    /**
     * A group heading for everything past the modern set.
     *
     * This list grew from sixteen to forty-eight when it was extended to cover PHP's
     * `hash_hmac_algos()`, and forty-eight flat entries is a scroll rather than a choice. The
     * ungrouped ones stay at the top, which keeps SHA-256 where a reader's eye already is.
     */
    ...(hash.group ? { group: hash.group } : {}),
  }));
}

const HMAC_OPTIONS: readonly OptionDef<MacOptionGroup>[] = [
  keyOption(
    { min: 1, max: 4096, generate: 32 },
    "Read as UTF-8 text by default, so typing `secret` uses those six bytes; the selector beside the field switches to hex, Base64 or Latin-1 for a key that is raw bytes. Worth checking before comparing against another tool — a key of `1234` is four bytes as text and two as hex, and both produce a perfectly valid HMAC of a different key. Length itself is unrestricted: internally a key shorter than the hash's block size is zero-padded and one longer is hashed down to a single digest first, so a 200-byte key for SHA-256 carries no more strength than 64 bytes of randomness would, and a 4-byte key carries almost none. Aim for at least the digest length: 32 bytes for SHA-256.",
    "utf-8",
  ),
  {
    id: OPTION_HASH,
    label: "Hash",
    group: "algorithm",
    kind: "enum",
    choices: hashChoices(),
    availableOn: [TAG_HMAC],
    summary: "Which digest to key.",
    detail:
      "HMAC's security rests on the hash's resistance to a keyed-collision attack, which is a weaker requirement than plain collision resistance — which is why HMAC-SHA1 and even HMAC-MD5 have no practical forgery despite both hashes being broken for signatures. Legacy choices are offered for reproducing existing values, not for new work.",
    order: 10,
  },
  {
    id: OPTION_TRUNCATE,
    label: "Truncate to",
    group: "output",
    kind: "number",
    arg: { placeholder: "full", unit: "bytes", min: 1, max: 64, step: 1 },
    availableOn: [TAG_HMAC],
    summary: "Keep only the leading bytes of the tag. Leave empty for the full digest.",
    detail:
      "Truncating an HMAC is standard practice — IPsec uses HMAC-SHA-256 cut to 128 bits, and RFC 2104 explicitly permits it — but it directly sets the forgery probability: an n-byte tag can be guessed with probability 2^-8n per attempt. RFC 2104 recommends never going below half the digest length, and never below 80 bits.",
    order: 10,
  },
];

const KMAC_OPTIONS: readonly OptionDef<MacOptionGroup>[] = [
  keyOption(
    { min: 1, max: 4096, generate: 32 },
    "KMAC keys the sponge directly rather than nesting two hashes, so there is no block-size padding step and no length extension to defend against. Any length is accepted; 32 bytes matches KMAC128's security level.",
  ),
  {
    id: OPTION_KMAC_VARIANT,
    label: "Variant",
    group: "algorithm",
    kind: "enum",
    choices: KMAC_VARIANTS.map((v) => ({
      value: v.id,
      label: v.label,
      summary: `${v.outputLen}-byte default output`,
    })),
    availableOn: [TAG_KMAC],
    summary: "KMAC128 or KMAC256.",
    detail:
      "The number is the sponge's security level in bits, not the output length — KMAC128 will happily produce 64 bytes, but only 128 bits of that is security. Pick the variant to match the strength you need and the output length to match what the protocol asks for.",
    order: 10,
  },
  {
    id: OPTION_CUSTOMIZATION,
    label: "Customization string",
    group: "algorithm",
    kind: "text",
    arg: { placeholder: "(none)" },
    availableOn: [TAG_KMAC],
    summary: "Domain separation. Part of the standard, not a second key.",
    detail:
      'SP 800-185\'s customization string separates uses of the same key: KMAC with S="email" and KMAC with S="file" produce unrelated tags even under one key. That is genuinely useful and it is not secret — treat it as a protocol constant, not as extra entropy. It is included in share links for exactly that reason.',
    order: 20,
  },
  {
    id: OPTION_OUTPUT_LENGTH,
    label: "Output length",
    group: "output",
    kind: "number",
    arg: { placeholder: "32", unit: "bytes", min: 1, max: 1024, step: 1 },
    availableOn: [TAG_KMAC],
    summary: "How many bytes of tag to produce.",
    detail:
      "KMAC is built on cSHAKE, so the requested length is bound into the computation — asking for 32 bytes and asking for 64 and truncating give *different* answers. That is the opposite of how truncating an HMAC behaves, and it is deliberate: the length is part of the domain separation.",
    order: 10,
  },
];

const POLY1305_OPTIONS: readonly OptionDef<MacOptionGroup>[] = [
  keyOption(
    { exact: [32], generate: 32 },
    "Exactly 32 bytes, and single-use. The first 16 bytes are the polynomial evaluation point r (with some bits cleared) and the second 16 are the addend s. Authenticating two messages under one key lets an attacker solve for r and forge arbitrarily — which is why real protocols derive a fresh key per message from a nonce rather than reusing one.",
  ),
];

const SIPHASH_OPTIONS: readonly OptionDef<MacOptionGroup>[] = [
  keyOption(
    { exact: [16], generate: 16 },
    "Exactly 16 bytes, as two 64-bit words. Every language runtime that uses SipHash generates one per process at startup, which is what makes hash-table order unpredictable to an attacker and is the entire security argument. There is no key-stretching step: 16 bytes in, used directly.",
  ),
];

/**
 * HighwayHash: a 32-byte key and a width.
 *
 * The width is a select rather than a number field because the three are separate functions, not
 * truncations: 64 bits runs four finalisation rounds, 128 runs six and combines the lanes differently,
 * and 256 runs ten and ends in a reduction modulo a GF(2^256) polynomial. Asking for 16 bytes of the
 * 256-bit form would give something no other implementation produces.
 */
const HIGHWAY_OPTIONS: readonly OptionDef<MacOptionGroup>[] = [
  keyOption(
    { exact: [32], generate: 32 },
    "Exactly 32 bytes, as four 64-bit words. Required and not padded: HighwayHash has no notion of a short key, and there is no key-stretching step. The reference's own golden values use the key 00 01 02 ... 1f, which is what makes them reproducible here.",
  ),
  {
    id: OPTION_OUTPUT_LENGTH,
    label: "Output width",
    group: "output",
    kind: "enum",
    choices: [
      { value: "8", label: "64 bits", summary: "Four finalisation rounds" },
      { value: "16", label: "128 bits", summary: "Six rounds, lanes crossed" },
      { value: "32", label: "256 bits", summary: "Ten rounds and a modular reduction" },
    ],
    availableOn: [TAG_HIGHWAY],
    summary: "Which of the three widths to produce.",
    detail:
      "Three separate functions rather than one truncated three ways: each width runs a different number of finalisation rounds and combines the state differently, so the 128-bit output is not the first sixteen bytes of the 256-bit one. Truncating by hand gives a wrong answer with no error.",
    order: 10,
  },
];

const CMAC_OPTIONS: readonly OptionDef<MacOptionGroup>[] = [
  keyOption(
    { exact: [16, 24, 32], generate: 16 },
    "An AES key: 16, 24 or 32 bytes for AES-128, AES-192 or AES-256. CMAC derives two subkeys from it internally, which is what fixes CBC-MAC's length-extension weakness on variable-length messages.",
  ),
];

/**
 * Skein-MAC: a key of any length, a state size, and an output length.
 *
 * The state size is a choice rather than three tools because it is the same construction each time --
 * which is the opposite of how the *hash* family files Skein, where three state sizes are three tools.
 * The difference is that a MAC's state size is a strength parameter chosen once, while a hash's is part
 * of the algorithm's name that people search for.
 */
const SKEIN_MAC_OPTIONS: readonly OptionDef<MacOptionGroup>[] = [
  keyOption(
    { min: 1, max: 4096, generate: 32 },
    "Any length, and unlike HMAC there is no block-size ceiling: UBI absorbs a long key in blocks rather than hashing it down first, so 200 bytes of key really is 200 bytes of key. Aim for at least the state size.",
    "hex",
  ),
  {
    id: OPTION_SKEIN_STATE,
    label: "State size",
    group: "algorithm",
    kind: "enum",
    choices: [
      { value: "32", label: "Skein-256", summary: "256-bit state, 72 rounds" },
      { value: "64", label: "Skein-512", summary: "512-bit state \u2014 the authors' choice" },
      { value: "128", label: "Skein-1024", summary: "1024-bit state, 80 rounds" },
    ],
    availableOn: [TAG_SKEIN_MAC],
    summary: "Which Threefish the MAC is built on.",
    detail:
      "Skein-512 is the variant the designers nominate: 512 bits of state at the same speed as the 256-bit version on 64-bit hardware. The 1024-bit state is the conservative choice and buys nothing against any known attack. All three take any key and produce any output length.",
    order: 10,
  },
  {
    id: OPTION_OUTPUT_LENGTH,
    label: "Tag length",
    group: "output",
    kind: "number",
    arg: { placeholder: "64", unit: "bytes", min: 1, max: 1024, step: 1 },
    availableOn: [TAG_SKEIN_MAC],
    summary: "How many bytes of tag to produce.",
    detail:
      "Skein binds the output length into its configuration block, so a 32-byte tag is not the first half of a 64-byte one \u2014 they are different functions. That is the same behaviour as KMAC and the opposite of truncating an HMAC. The default matches the state size.",
    order: 10,
  },
];

/** Ascon-MAC: one key size, one tag size, nothing to choose. */
const ASCON_MAC_OPTIONS: readonly OptionDef<MacOptionGroup>[] = [
  keyOption(
    { exact: [16], generate: 16 },
    "Exactly 16 bytes. Ascon's security claim is 128-bit across the board \u2014 key and tag are both that width.",
    "hex",
  ),
];

/** Ascon-PRF and Ascon-PRFShort: the same key, plus an output length. */
function asconPrfOptions(max: number, defaultLen: number): readonly OptionDef<MacOptionGroup>[] {
  return [
    keyOption(
      { exact: [16], generate: 16 },
      "Exactly 16 bytes, as with Ascon-MAC.",
      "hex",
    ),
    {
      id: OPTION_OUTPUT_LENGTH,
      label: "Output length",
      group: "output",
      kind: "number",
      arg: { placeholder: String(defaultLen), unit: "bytes", min: 1, max, step: 1 },
      availableOn: [TAG_ASCON_PRF],
      summary: "How many bytes to squeeze.",
      detail:
        max === 16
          ? "At most 16 bytes: PRFShort squeezes from the two state words the key was XORed back over, and there is no second permutation to produce more."
          : "The length is not bound into the computation, so 16 bytes is genuinely the first 16 of a 64-byte request \u2014 unlike KMAC and Skein, where the length changes the function. That makes Ascon-PRF usable as a keyed stream for deriving several independent values from one key.",
      order: 10,
    },
  ];
}

const CACHE = new Map<string, OptionCatalogue<MacOptionGroup>>();

export function macCatalogueFor(toolId: string): OptionCatalogue<MacOptionGroup> {
  let catalogue = CACHE.get(toolId);
  if (!catalogue) {
    requireMacTool(toolId);
    /**
     * One entry per tool, and no default.
     *
     * The chain this replaced ended in `: CMAC_OPTIONS`, which meant a tool added to `MAC_TOOLS` with
     * no entry here would silently inherit CMAC's catalogue -- a 16/24/32-byte key and nothing else.
     * The cipher family shipped exactly that bug with its Salsa tools; a `Record` whose miss throws
     * turns it into an immediate, named failure instead.
     */
    const byTool: Record<string, readonly OptionDef<MacOptionGroup>[]> = {
      hmac: HMAC_OPTIONS,
      kmac: KMAC_OPTIONS,
      poly1305: POLY1305_OPTIONS,
      cmac: CMAC_OPTIONS,
      siphash: SIPHASH_OPTIONS,
      highwayhash: HIGHWAY_OPTIONS,
      skeinmac: SKEIN_MAC_OPTIONS,
      asconmac: ASCON_MAC_OPTIONS,
      asconprf: asconPrfOptions(1024, 32),
      asconprfs: asconPrfOptions(16, 16),
    };
    const options = byTool[toolId];
    if (!options) throw new Error(`No option catalogue for MAC tool "${toolId}".`);
    catalogue = createOptionCatalogue<MacOptionGroup>(options);
    CACHE.set(toolId, catalogue);
  }
  return catalogue;
}
