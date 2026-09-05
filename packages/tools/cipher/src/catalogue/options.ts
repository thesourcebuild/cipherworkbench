import type { BytesEncoding } from "@ocs/contracts/encoding";
import { createOptionCatalogue, type OptionCatalogue, type OptionDef } from "@ocs/engine";
import {
  AES_KEY_SIZES,
  AES_KEY_STRING_SIZES,
  OPTION_KEY_SIZE,
  OPTION_PADDING,
  CHACHA_KEY_SIZE,
  OPTION_AAD,
  OPTION_COUNTER,
  OPTION_DIRECTION,
  OPTION_DROP,
  OPTION_EFFECTIVE_KEY_BITS,
  OPTION_ANUBIS_VARIANT,
  OPTION_GOST_SBOX,
  OPTION_RC5_ROUNDS,
  OPTION_TWEAK,
  OPTION_KEY,
  OPTION_MODE,
  OPTION_PARAM_SET,
  OPTION_NONCE,
  OPTION_TAG_LEN,
  OPTION_TIMESTAMP_FORMAT,
  OPTION_TIMESTAMP,
  OPTION_TTL,
  OPTION_CONTEXT,
  OPTION_SALT,
  TAG_CHACHA_COUNTER,
  TAG_IV_MANUAL,
  TAG_RC4,
} from "../pure";
import {
  AES_MODES,
  COBBLESTONE_INSTANCES,
  getAesMode,
  requireCipherTool,
  type AesModeMeta,
  type CipherInstance,
  type CipherParamSet,
  type CipherToolMeta,
} from "./tool-meta";
import type { CipherOptionGroup } from "./groups";
import { keySourceOptions, keySourceTag } from "@ocs/kdf/key-source";

const DIRECTION_OPTION: OptionDef<CipherOptionGroup> = {
  id: OPTION_DIRECTION,
  label: "Direction",
  group: "direction",
  kind: "enum",
  choices: [
    { value: "encrypt", label: "Encrypt", summary: "Plaintext in, ciphertext out" },
    { value: "decrypt", label: "Decrypt", summary: "Ciphertext in, plaintext out" },
  ],
  summary: "Which way the bytes go.",
  detail:
    "Decrypting expects the ciphertext in the input panel, as hex or Base64 rather than as text. For an authenticated mode the tag is appended to the ciphertext, which is how every implementation transmits it, so paste both together exactly as you received them.",
  order: 10,
};

function keyOption(
  bytesLength: OptionDef["bytesLength"],
  summary: string,
  detail: string,
  defaultBytesEncoding: BytesEncoding = "utf-8",
): OptionDef<CipherOptionGroup> {
  return {
    id: OPTION_KEY,
    label: "Key",
    group: "key",
    kind: "bytes",
    bytesLength,
    /*
     * `utf-8` by default for ciphers, except token recipes like Fernet that use `base64url`.
     */
    defaultBytesEncoding,
    secret: true,
    /*
     * Only while the key is typed rather than derived. One line here covers all eleven call sites --
     * and it is why `cipherVariantTags` must return a key-source tag for *every* tool: the 45 with no
     * mode returned `undefined` before, and `isAvailableOn` reads a missing tag as "not available", so
     * this gate would have deleted their key field outright.
     */
    availableOn: [keySourceTag("directinput")],
    summary,
    detail,
    order: 10,
  };
}

/**
 * One nonce option per tool, not one per mode.
 *
 * `ToolDefinition.catalogue` is a single value resolved once per tool, so three separate
 * nonce definitions sharing an id — which is what the first version of this file had —
 * collapse into one in `createOptionCatalogue`'s id map and trip `validateCatalogue`'s
 * duplicate check. The mode-specific length is therefore accepted as a set here and
 * enforced by `C005`, which can see the mode and say precisely which length is wanted.
 *
 * Deliberately not marked secret. A nonce travels in the clear beside the ciphertext in
 * every real protocol; hiding it would misrepresent how it is used and strip it from share
 * links for no benefit. What matters is that it never repeats, which is `C003`'s job.
 */
function nonceOption(
  bytesLength: OptionDef["bytesLength"],
  label: string,
  summary: string,
  detail: string,
  availableOn?: readonly string[],
  defaultBytesEncoding: BytesEncoding = "utf-8",
): OptionDef<CipherOptionGroup> {
  return {
    id: OPTION_NONCE,
    label,
    group: "key",
    kind: "bytes",
    bytesLength,
    /*
     * `utf-8` by default, except recipes like Fernet that use `base64url`.
     */
    defaultBytesEncoding,
    /*
     * Gated on a *conjunction*, encoded as a tag because `isAvailableOn` cannot express one.
     *
     * The field has to appear when the mode takes an IV **and** the IV is the user's to supply -- a
     * KDF set to derive the key and IV supplies it instead, and a field that rendered and was ignored
     * is this repo's most-repeated defect. `isAvailableOn` ORs its list, so "cbc and not derived" is
     * unwriteable there; `cipherVariantTags` emits `iv:cbc` only while the IV is manual, and this asks
     * for that instead of for `cbc`.
     *
     * A tool with no modes at all -- ChaCha, Ascon, every shaped cipher -- asks for `iv:manual`, which
     * is emitted on the same condition. Done here rather than at the nine call sites so none of them
     * can be the one that forgets.
     */
    availableOn: availableOn ? availableOn.map((id) => `iv:${id}`) : [TAG_IV_MANUAL],
    summary,
    detail,
    order: 20,
  };
}

function aadOption(availableOn?: readonly string[]): OptionDef<CipherOptionGroup> {
  return {
    id: OPTION_AAD,
    label: "AAD - Additional Authenticated Data",
    group: "aead",
    kind: "bytes",
    bytesLength: { min: 0, max: 4096 },
    defaultBytesEncoding: "utf-8",
    ...(availableOn ? { availableOn } : {}),
    summary: "Authenticated but not encrypted.",
    detail:
      "Covered by the tag and left in the clear: a message header, a record id, a protocol version. It binds the ciphertext to its context, so a valid ciphertext cannot be replayed under a different header. It must be supplied identically when decrypting, or the tag will not verify.",
    order: 10,
  };
}

/**
 * The tag-length control, for the modes where the tag length is a choice.
 *
 * One definition rather than one per catalogue, because CCM is offered on four ciphers now and the
 * sentence explaining what a 4-byte tag costs should not be written four times. The choices come from
 * the modes themselves: CCM allows any even 4 to 16 and OCB any 1 to 16, and the even subset is what is
 * offered for both, since a 5-byte tag has no protocol behind it and every byte removed doubles an
 * attacker's forgery odds. Note the asymmetry: truncating CCM's tag really does just shorten the tag,
 * while OCB folds the tag length into its nonce formatting, so choosing 12 there changes the
 * *ciphertext* -- a 16-byte-tag output truncated to 12 is not the same thing.
 */
function tagLenOption(modes: readonly AesModeMeta[]): OptionDef<CipherOptionGroup> {
  const labels: Record<number, string> = {
    16: "16 bytes. The default, and what most protocols use.",
    14: "14 bytes",
    12: "12 bytes. IPsec and 802.15.4 use this.",
    10: "10 bytes",
    8: "8 bytes. Bluetooth LE uses this.",
    6: "6 bytes",
    4: "4 bytes. One forgery in 4 billion attempts.",
  };
  const offered = [...new Set(modes.flatMap((m) => m.tagLens ?? []))].sort((a, b) => b - a);

  return {
    id: OPTION_TAG_LEN,
    label: "Tag length",
    group: "algorithm",
    kind: "enum",
    choices: offered.map((bytes) => ({
      value: String(bytes),
      label: `${bytes * 8}-bit`,
      summary: labels[bytes] ?? `${bytes} bytes`,
      // Anything under 80 bits is a real forgery risk rather than a size trade-off.
      ...(bytes < 10 ? { insecure: true } : {}),
    })),
    availableOn: modes.filter((m) => m.tagLens).map((m) => m.id),
    summary: "How many bytes of authentication tag to append.",
    detail:
      "The tag length is the forgery probability: an n-byte tag can be guessed with probability 2^-8n per attempt, and an attacker who can retry cheaply will. Sixteen bytes is the default for good reason; the shorter options exist because constrained protocols specify them — 802.15.4 uses 4, 8 and 16, Bluetooth LE uses 4. Never choose a short tag to save space in a context where an attacker can submit many guesses.",
    order: 20,
  };
}

/** Modes that take an IV or nonce at all — everything except ECB. */
const MODES_WITH_NONCE = AES_MODES.filter((m) => m.nonceLen > 0).map((m) => m.id);
/** Modes whose key is one ordinary AES key, so the sizes are AES's own three. */
const ORDINARY_AES_MODES = AES_MODES.filter((mode) => !mode.keyLengths).map((mode) => mode.id);

/**
 * What a given key-string length is *called* under a mode that splits it.
 *
 * The naming is the reason these modes get a dropdown at all. A 32-byte XTS key contains no 256-bit
 * AES: it is two AES-128 keys, so it is XTS-AES-128, and a field that called it "AES-256" is what
 * makes people report XTS as broken. RFC 5297 names its own sizes after the whole key string, so
 * AES-SIV-CMAC-256 really is the 32-byte one; GCM-SIV is named after the underlying AES.
 */
function aesKeySizeLabel(modeId: string, bytes: number): string {
  if (modeId === "xts") return `XTS-AES-${(bytes / 2) * 8}`;
  if (modeId === "aessiv") return `AES-SIV-CMAC-${bytes * 8}`;
  return `AES-${bytes * 8}-GCM-SIV`;
}

function aesKeySizeSummary(modeId: string, bytes: number): string {
  const half = bytes / 2;
  if (modeId === "xts") return `${bytes} bytes -- two AES-${half * 8} keys`;
  if (modeId === "aessiv") return `${bytes} bytes -- an AES-${half * 8} CMAC key and a CTR key`;
  return `${bytes} bytes`;
}
/**
 * How ECB and CBC pad a message that is not a whole number of blocks.
 *
 * Gated on those two modes and nothing else, which is a fact about the modes rather than a
 * simplification: every other mode over a block cipher either turns it into a keystream -- CTR, OFB,
 * CFB and the AEADs, whose ciphertext is the plaintext's length -- or defines its own handling. XTS
 * steals ciphertext so a sector encrypts to exactly a sector, and AES-KW/KWP carry RFC 3394/5649's
 * own scheme, which is what the "with padding" in KWP's name refers to.
 *
 * Shared by every block cipher rather than written per tool, because the schemes are properties of the
 * block size and not of the cipher.
 */
const PADDING_OPTION: OptionDef<CipherOptionGroup> = {
  id: OPTION_PADDING,
  label: "Padding",
  group: "algorithm",
  kind: "enum",
  choices: [
    {
      /*
       * PKCS#5 is a separate entry even though it produces the same bytes, and that is the deliberate
       * reversal of the first version of this list.
       *
       * The reasoning that left it out -- two indistinguishable choices are worse than one -- is the
       * opposite of what this repo does everywhere else. The checksum family lists LRC beside the
       * two's-complement checksum and BCC beside XOR, because the protocols name them separately, with
       * `sameAs` making the result panel say the coincidence is expected. Somebody holding a Java
       * `DES/CBC/PKCS5Padding` value wants to pick that name and see it match; the result's Padding
       * hint is what tells them the two are one scheme.
       */
      value: "pkcs7",
      label: "PKCS#7",
      summary: "The default. RFC 5652",
    },
    {
      value: "pkcs5",
      label: "PKCS#5",
      summary: "The same bytes as PKCS#7",
    },
    {
      value: "iso7816",
      label: "ISO 9797-1 method 2",
      summary: "0x80 then zeros",
    },
    {
      value: "x923",
      label: "ANSI X9.23",
      summary: "Zeros then a length byte",
    },
    {
      value: "iso10126",
      label: "ISO 10126",
      summary: "Random bytes then a length byte",
    },
    {
      value: "zero",
      label: "Zero padding",
      summary: "Zeros; removal is ambiguous",
    },
    {
      value: "none",
      label: "None",
      summary: "Input must be whole blocks",
    },
  ],
  availableOn: ["ecb", "cbc"],
  summary: "How a partial final block is filled.",
  detail:
    "PKCS#7 is the default and what everything interoperates on: the padding is the number of bytes added, repeated, and a message that is already a whole number of blocks gains a *full* block -- not waste, but what makes the padding unambiguous, since otherwise a message ending in 0x01 could not be told from one padded with a single byte. PKCS#5 is the same algorithm and produces identical bytes; it is listed separately because protocols and libraries name it separately (Java's PKCS5Padding), and the result panel says the two coincide. Strictly PKCS#5 is defined only for an 8-byte block and every library widens it by aliasing PKCS#7. ISO 9797-1 padding method 2 writes a single 0x80 and then zeros, and is what EMV and most smartcard traffic uses. ANSI X9.23 writes zeros and puts the count in the last byte. ISO 10126 writes *random* bytes and then the count, which was withdrawn in 2007 and means encrypting the same input twice gives different ciphertext -- decryption is unaffected, since the count is the last byte. Zero padding fills with zeros, which cannot be removed unambiguously: trailing zeros in the plaintext are indistinguishable from padding and are stripped with it, so use it only to reproduce something that already exists. None does not pad and therefore refuses an input that is not already whole blocks -- it is also what reproduces NIST's SP 800-38A ECB and CBC examples, whose plaintexts are block-aligned and published unpadded.",
  order: 30,
};

/** Modes that authenticate, and so accept AAD. */
const MODES_WITH_AAD = AES_MODES.filter((m) => m.aead).map((m) => m.id);

const AES_OPTIONS: readonly OptionDef<CipherOptionGroup>[] = [
  DIRECTION_OPTION,
  {
    id: OPTION_MODE,
    label: "Mode",
    group: "algorithm",
    kind: "enum",
    choices: AES_MODES.map((m) => ({
      value: m.id,
      label: m.label,
      summary: m.summary,
      ...(m.insecure ? { insecure: true } : {}),
    })),
    summary: "How blocks are chained. The single most consequential setting here.",
    detail:
      "AES itself is a 16-byte block permutation and nothing more; the mode is what turns it into something that can encrypt a message. Choosing badly here is far more damaging than choosing a shorter key: AES-256 in ECB mode leaks the structure of your plaintext, while AES-128 in GCM does not. Use GCM unless you have a specific reason, or GCM-SIV if you cannot guarantee unique nonces.",
    order: 10,
  },
  {
    /**
     * AES's key size, declared rather than inferred from the length of what was pasted.
     *
     * Three things follow from having it, and the first is why it was asked for: Generate produces
     * *this* many bytes instead of always 32, so pressing it on a tool set to AES-128 gives an
     * AES-128 key. The second is that a wrong-length key now gets a message naming the size that was
     * chosen, rather than "one of 16, 24, 32" which tells a reader nothing about their mistake. The
     * third is that the form states which AES is in use before anything is typed.
     *
     * **Every mode gets it, including the three that split the key.** It used to stand down under XTS
     * and SIV, on the reasoning that their key is not one AES key -- true, and the wrong conclusion:
     * it left the only way to ask for XTS-AES-256 being to know that it means 64 bytes and paste
     * them. Choices carry their own `availableOn` now, so the select offers XTS-AES-128 and
     * XTS-AES-256 under XTS, the three AES-SIV-CMAC sizes under SIV, and AES-128/256-GCM-SIV under
     * GCM-SIV -- one option, one id, one stored value, and the names those modes actually use.
     *
     * Generated from `AES_MODES`, so a mode added later with its own key lengths appears here with
     * nothing to remember. `readAesKeySizeBytes` accepts the union of all of them and
     * `cipherKeyLengths` narrows a mode's list by whatever is selected, which is what stops the
     * control rendering and reaching nothing.
     *
     * **Mode comes first, then this, then Key source.** The three are the choices that decide which
     * function runs, and that is the order they are read in: what the cipher does with its blocks, how
     * long its key is, and where the key comes from. An earlier version put this above Mode on the
     * grounds that the key size is a property of *which AES* while the mode is a property of how it is
     * used; that reading is defensible and was reversed on request, and it had a real wart -- this
     * control's own visibility is gated on the mode, so it sat above the thing that decides whether it
     * exists.
     */
    id: OPTION_KEY_SIZE,
    label: "Key size",
    group: "algorithm",
    kind: "enum",
    /*
     * The value is the length of the whole key *string* in bits, which is what makes one option serve
     * every mode: 256 means 32 bytes under GCM and under XTS alike. What differs is the name, and the
     * name is the whole point -- 32 bytes is AES-256 under GCM and XTS-AES-128 under XTS, because XTS
     * splits it into two AES-128 keys. Two choices therefore share a value with different labels and
     * different tags, and only one of the pair is ever on screen.
     *
     * Generated from the modes rather than listed, so a mode added later with its own key lengths
     * appears here without anyone remembering to.
     */
    choices: [
      ...AES_KEY_SIZES.map((bytes) => ({
        value: String(bytes * 8),
        label: `AES-${bytes * 8}`,
        summary: `${bytes} bytes`,
        availableOn: ORDINARY_AES_MODES,
      })),
      ...AES_MODES.filter((mode) => mode.keyLengths).flatMap((mode) =>
        mode.keyLengths!.map((bytes) => ({
          value: String(bytes * 8),
          label: aesKeySizeLabel(mode.id, bytes),
          summary: aesKeySizeSummary(mode.id, bytes),
          availableOn: [mode.id],
        })),
      ),
    ],
    summary: "Which AES, and how long a key Generate makes.",
    detail:
      "AES-128, AES-192 and AES-256 are the same cipher over a longer key and more rounds, and the difference between them matters far less than the mode does -- AES-128 has no known practical weakness, and AES-256 does not compensate for ECB. What this control changes here is concrete rather than theoretical: Generate produces a key of this size, and a key of any other length is refused with this size named. XTS and SIV do not offer it because their key lengths are properties of those modes: an XTS key is two AES keys and SIV's is split between a CMAC and a CTR.",
    order: 12,
  },
  keyOption(
    /*
     * The union across every mode, not AES's own three: XTS adds 64 and AES-SIV adds 48 and 64. One
     * catalogue serves all thirteen modes, so declaring only 16/24/32 made the form call a valid
     * 64-byte XTS key invalid -- which is the bug `acceptedByteLengths` exists to close, and leaving a
     * stale narrow union here would be leaving the trap in place for whoever reads this next.
     * `cipherAcceptedByteLengths` narrows it to the selected mode; this is only the outer bound.
     */
    { exact: [...AES_KEY_STRING_SIZES], generate: 32 },
    "Set by the Key size.",
    "The length always follows the Key size chosen above, and Generate produces it. What that size *means* depends on the mode, which is why the control names it rather than only stating a number of bits. Under the ordinary modes it is one AES key of 16, 24 or 32 bytes. Under XTS it is two: a 32-byte key string is XTS-AES-128, two AES-128 keys, the first enciphering the data and the second the tweak -- there is no 256-bit AES anywhere in it. AES-SIV (RFC 5297) splits its 32, 48 or 64 bytes between a CMAC key and a CTR key. GCM-SIV offers only 16 and 32, because RFC 8452 defines no AES-192 variant. A key of any other length is refused with the selected size named.",
  ),
  nonceOption(
    /**
     * A range rather than a list, because the modes disagree and the resolver is where the precise
     * answer belongs.
     *
     * GCM and GCM-SIV want 12; CBC, CTR, OFB, CFB and XTS want a full block; CCM accepts 7 to 13 and
     * OCB 1 to 15. `C005` names the exact requirement for whichever mode is selected -- which it can do
     * and this control cannot, since one catalogue serves every mode.
     */
    { min: 1, max: 16, generate: 12 },
    "IV / nonce",
    "12 bytes for GCM, 16 for CBC, CTR and XTS, 7 to 13 for CCM, 1 to 15 for OCB.",
    "GCM and GCM-SIV take 96 bits, which every specification uses and every security proof assumes. CBC, CTR, OFB and CFB take a full 16-byte block, and so does XTS, where this field is the data unit number rather than an IV. CCM's width trades against the message: the nonce and the length field share a block, so 13 bytes caps the message at 64 KiB -- which is why 802.15.4 and WPA2 use 13 and TLS uses 12. Under GCM a repeated nonce is catastrophic: two messages under one nonce reveal the XOR of their plaintexts and leak the authentication subkey, after which forgery is arbitrary. CBC's IV must additionally be unpredictable rather than merely unique. None of them is secret; all are normally sent alongside the ciphertext.",
    MODES_WITH_NONCE,
  ),
  PADDING_OPTION,
  tagLenOption(AES_MODES),
  aadOption(MODES_WITH_AAD),
];

const CHACHA_POLY_OPTIONS: readonly OptionDef<CipherOptionGroup>[] = [
  DIRECTION_OPTION,
  keyOption(
    { exact: [CHACHA_KEY_SIZE], generate: CHACHA_KEY_SIZE },
    "Exactly 32 bytes.",
    "ChaCha20 has one key size, which removes a decision that never had a good answer.",
  ),
  nonceOption(
    { exact: [12], generate: 12 },
    "Nonce",
    "12 bytes. Public, and must never repeat under one key.",
    "96 bits, per RFC 8439. A repeat is worse here than for a plain stream cipher: Poly1305's one-time key is derived from the nonce, so reusing one hands over the authentication key as well as the XOR of the plaintexts. At 96 bits, randomly chosen nonces have a real collision probability after a few billion messages, which is precisely what XChaCha20 exists to fix.",
  ),
  aadOption(),
];

const XCHACHA_POLY_OPTIONS: readonly OptionDef<CipherOptionGroup>[] = [
  DIRECTION_OPTION,
  keyOption(
    { exact: [CHACHA_KEY_SIZE], generate: CHACHA_KEY_SIZE },
    "Exactly 32 bytes.",
    "One key size, as with ChaCha20-Poly1305.",
  ),
  nonceOption(
    { exact: [24], generate: 24 },
    "Nonce",
    "24 bytes. Wide enough to generate at random and forget about.",
    "192 bits, which is the entire point of the variant. At that width a randomly generated nonce will not collide within any realistic number of messages, so you can generate one per message and stop tracking counters. Internally it hashes the first 16 bytes into a subkey and runs ChaCha20 with the remaining 8.",
  ),
  aadOption(),
];

/**
 * Ascon-AEAD128. One key size, one nonce size, one tag size -- SP 800-232 offers no variants.
 *
 * The nonce is a full 128 bits, which is worth saying out loud in the detail text: it is wide enough
 * to pick at random for every message, unlike GCM's 96-bit one.
 */
const ASCON_OPTIONS: readonly OptionDef<CipherOptionGroup>[] = [
  DIRECTION_OPTION,
  keyOption(
    { exact: [16], generate: 16 },
    "Exactly 16 bytes.",
    "128 bits, and the only size the standard defines. Ascon's security claim is 128-bit across the board -- key, nonce and tag are all that width.",
  ),
  nonceOption(
    { exact: [16], generate: 16 },
    "Nonce",
    "16 bytes. Public, and must never repeat under one key.",
    "128 bits, which is wide enough to generate at random for every message and never track what has been used -- the property GCM's 96-bit nonce does not have. A repeat is as damaging here as for any AEAD: it reveals the XOR of the two plaintexts and undermines the tag.",
  ),
  aadOption(),
];

/**
 * AEGIS-128L and AEGIS-256.
 *
 * The tag-length control is the only option in this family that changes the *size* of the output
 * rather than its value, which is why the summary says what 32 bytes buys: the draft's 256-bit tag is
 * key-committing, so a ciphertext cannot be made to decrypt correctly under a second key.
 */
function aegisOptions(
  keyLen: 16 | 32,
  nonceLen: 16 | 32,
): readonly OptionDef<CipherOptionGroup>[] {
  return [
    DIRECTION_OPTION,
    keyOption(
      { exact: [keyLen], generate: keyLen },
      `Exactly ${keyLen} bytes.`,
      keyLen === 16
        ? "128 bits, as AEGIS-128L defines. The L is for the doubled 1024-bit state, not for the key."
        : "256 bits, split into two halves that seed different parts of the state.",
    ),
    nonceOption(
      { exact: [nonceLen], generate: nonceLen },
      "Nonce",
      `${nonceLen} bytes. Public, and must never repeat under one key.`,
      `${nonceLen * 8} bits, which is wide enough to generate at random per message. Reuse is worse here than for AES-GCM: repeating a nonce under one key lets an attacker recover the internal state itself, not just the XOR of two plaintexts.`,
    ),
    {
      id: OPTION_TAG_LEN,
      label: "Tag length",
      group: "algorithm",
      kind: "enum",
      choices: [
        { value: "16", label: "128-bit", summary: "16 bytes. The common choice." },
        {
          value: "32",
          label: "256-bit",
          summary: "32 bytes, and key-committing.",
        },
      ],
      summary: "How many bytes of authentication tag to append.",
      detail:
        "Both are specified. The 256-bit tag is not merely longer: it makes the construction committing, so a single ciphertext cannot be made to decrypt to two different plaintexts under two different keys — an attack GCM and ChaCha20-Poly1305 are both open to. Decryption must be given the same length that encryption produced.",
      order: 30,
    },
    aadOption(),
  ];
}

/**
 * Raw ChaCha, for the four unauthenticated tools in the family.
 *
 * Parameterised by nonce length because ChaCha20-original uses the pre-RFC layout -- 64 bits of nonce
 * and 64 of counter, where RFC 8439 has 96 and 32. That is the only difference between the two tools,
 * and it is a real incompatibility rather than a presentation choice: the same key and the same eight
 * bytes give a different keystream unless the counter is zero.
 */
function chachaRawOptions(
  nonceLen: 8 | 12,
  nonceNote: string,
): readonly OptionDef<CipherOptionGroup>[] {
  return [
    DIRECTION_OPTION,
    keyOption(
      { exact: [CHACHA_KEY_SIZE], generate: CHACHA_KEY_SIZE },
      "Exactly 32 bytes.",
      "One key size.",
    ),
    nonceOption(
      { exact: [nonceLen], generate: nonceLen },
      "Nonce",
      `${nonceLen} bytes, ${nonceNote}.`,
      `${nonceLen * 8} bits. With no authentication on top, a repeated nonce reveals the XOR of the two plaintexts and nothing stops an attacker altering the ciphertext.`,
    ),
    {
      id: OPTION_COUNTER,
      label: "Initial counter",
      group: "algorithm",
      kind: "number",
      arg: { placeholder: "0", min: 0, max: 4294967295, step: 1 },
      availableOn: [TAG_CHACHA_COUNTER],
      summary: "The starting block counter.",
      detail:
        "RFC 8439's own test vectors use 0 and 1, which is the main reason this is exposed: reproducing them requires setting it. In a protocol it is normally 0, or 1 where a Poly1305 key was derived from block 0.",
      order: 20,
    },
  ];
}

const RC4_OPTIONS: readonly OptionDef<CipherOptionGroup>[] = [
  DIRECTION_OPTION,
  keyOption(
    // RC4 accepts any length from 1 to 256, so this is a range rather than a set.
    { min: 1, max: 256, generate: 16 },
    "1 to 256 bytes.",
    "RC4 accepts any length and derives no real strength from a long one: the bias in its keystream is present regardless of the key.",
  ),
  {
    id: OPTION_DROP,
    label: "Drop bytes",
    group: "algorithm",
    kind: "number",
    arg: { placeholder: "0", unit: "bytes", min: 0, max: 65536, step: 256 },
    availableOn: [TAG_RC4],
    summary: "Discard this many keystream bytes first. The RC4-drop variant.",
    detail:
      "The historical mitigation for the Fluhrer-Mantin-Shamir bias, which is measurable in the first few hundred bytes of RC4 keystream. RC4-drop768 and RC4-drop3072 were the common settings. It does not make RC4 safe, since later biases remain, but reproducing an old implementation means knowing whether it did this.",
    order: 20,
  },
];

/**
 * The Salsa family. Key is always 32 bytes; the nonce is what distinguishes them.
 *
 * No AAD option for the AEAD one, and that is faithful rather than an omission: NaCl's secretbox takes
 * no associated data at all. Offering an empty field that silently did nothing would be worse than not
 * offering it.
 */
function salsaOptions(
  nonceLen: 8 | 24,
  detail: string,
): readonly OptionDef<CipherOptionGroup>[] {
  return [
    DIRECTION_OPTION,
    keyOption(
      { exact: [CHACHA_KEY_SIZE], generate: CHACHA_KEY_SIZE },
      "Exactly 32 bytes.",
      "Salsa20 and its extended-nonce variants all take a 256-bit key.",
    ),
    nonceOption(
      { exact: [nonceLen], generate: nonceLen },
      "Nonce",
      `${nonceLen} bytes.`,
      detail,
    ),
  ];
}

const FERNET_OPTIONS: readonly OptionDef<CipherOptionGroup>[] = [
  DIRECTION_OPTION,
  keyOption(
    { exact: [32], generate: 32 },
    "32 bytes: 16-byte HMAC signing key and 16-byte AES-128 encryption key (Base64url-encoded).",
    "A Fernet key is 32 bytes (256 bits), typically represented as a URL-safe Base64 string. The first 16 bytes sign the message with HMAC-SHA256, and the second 16 bytes encrypt the message with AES-128 in CBC mode.",
    "base64url",
  ),
  nonceOption(
    { exact: [0, 16], generate: 16 },
    "IV",
    "16 bytes, or empty for a fresh random IV.",
    "Fernet generates a random 16-byte initialization vector per message. Provide an explicit value to reproduce published test vectors.",
    undefined,
    "base64url",
  ),
  {
    id: OPTION_TIMESTAMP_FORMAT,
    label: "Timestamp format",
    group: "aead",
    kind: "enum",
    choices: [
      {
        value: "auto",
        label: "Auto (current time)",
        summary: "Record current system time when generating tokens.",
      },
      {
        value: "iso8601",
        label: "ISO 8601 (date & time)",
        summary: "e.g. 2026-08-28T22:06:49.784Z or 1985-10-26T01:20:00-07:00",
      },
      {
        value: "epoch",
        label: "Unix epoch (seconds)",
        summary: "Raw integer seconds since Jan 1 1970 UTC e.g. 499162800",
      },
    ],
    summary: "How the creation timestamp is provided.",
    detail:
      "Fernet stores an 8-byte big-endian Unix timestamp in every token. Choose Auto to use current time, or select ISO 8601 or Unix Epoch to supply a custom timestamp.",
    order: 25,
  },
  {
    id: OPTION_TIMESTAMP,
    label: "Timestamp",
    group: "aead",
    kind: "text",
    arg: { placeholder: "e.g. 2026-08-28T22:06:49.784Z or 499162800" },
    summary: "Creation timestamp in ISO 8601 or Unix epoch seconds.",
    detail:
      "Recorded in the token header as a 64-bit unsigned big-endian integer. Accepts ISO 8601 date strings (e.g. 2026-08-28T22:06:49.784Z) or seconds since epoch.",
    order: 30,
  },
  {
    id: OPTION_TTL,
    label: "TTL (seconds)",
    group: "aead",
    kind: "number",
    arg: { placeholder: "Optional TTL in seconds e.g. 60", min: 0 },
    summary: "Time-to-live limit for decryption.",
    detail:
      "When decrypting, specifies the maximum allowed age of the token in seconds. If the token is older than the TTL, decryption fails with an expiration error.",
    order: 40,
  },
];

function cobblestoneOptions(instances: readonly CipherInstance[]): readonly OptionDef<CipherOptionGroup>[] {
  return [
    DIRECTION_OPTION,
    {
      id: OPTION_PARAM_SET,
      label: "Parameter set",
      group: "algorithm",
      kind: "enum",
      choices: instances.map((inst) => ({
        value: inst.id,
        label: inst.label,
        summary: inst.summary,
      })),
      summary: "Which Cobblestone instantiation to run.",
      detail:
        "Cobblestone-128 uses SHA-512 with AES-128-GCM and a 16-byte key; this is the primary recommendation. Cobblestone-256 uses SHA-512 with AES-256-GCM and a 32-byte key for compliance-oriented environments. Both use 16 KiB chunks and HKDF-Expand key commitment.",
      order: 5,
    },
    keyOption(
      { exact: [16, 32], generate: 16 },
      "16 bytes for Cobblestone-128, 32 bytes for Cobblestone-256.",
      "Input key material used with HKDF-Expand (SHA-512) to derive the single-use AEAD key, base nonce, and 32-byte key commitment.",
    ),
    {
      id: OPTION_CONTEXT,
      label: "Context / Domain separation",
      group: "aead",
      kind: "bytes",
      bytesLength: { min: 0, max: 4096 },
      defaultBytesEncoding: "utf-8",
      summary: "Application context bound into key derivation. May be empty.",
      detail:
        "Binds the ciphertext to an application domain or purpose string. Decryption fails with a commitment error unless the identical context is supplied.",
      order: 20,
    },
    {
      id: OPTION_SALT,
      label: "Salt",
      group: "key",
      kind: "bytes",
      bytesLength: { exact: [0, 24], generate: 24 },
      defaultBytesEncoding: "utf-8",
      availableOn: [TAG_IV_MANUAL],
      summary: "24-byte per-message salt. Leave empty for a fresh random salt.",
      detail:
        "Cobblestone prepends 24 bytes of salt to the ciphertext before the 32-byte commitment. Leave empty when encrypting to draw fresh random bytes.",
      order: 30,
    },
  ];
}

const COBBLESTONE_OPTIONS: readonly OptionDef<CipherOptionGroup>[] = cobblestoneOptions(COBBLESTONE_INSTANCES);

/**
 * A block cipher this repo implements: DES, 3DES, SM4.
 *
 * Built from the tool's own `block` metadata rather than hand-written per cipher, so adding Camellia or
 * ARIA is a metadata entry and a binding rather than another eighty lines here. The mode list is the
 * tool's, which is what keeps GCM and the key-wrap modes out of a menu for a cipher that has neither.
 */
function blockCipherOptions(tool: CipherToolMeta): readonly OptionDef<CipherOptionGroup>[] {
  const toolId = tool.id;
  const block = tool.block!;
  const paramSets = tool.paramSets;
  const modes = block.modes
    .map((id) => getAesMode(id))
    .filter((mode): mode is NonNullable<typeof mode> => mode !== undefined);

  return [
    DIRECTION_OPTION,
    /**
     * The parameter set, where there is more than one.
     *
     * First in the form after the direction, because the block size it picks decides the IV length
     * and the key length -- a reader who sets the key first and the set second would have to redo
     * the key. No `availableOn`: the catalogue is built per tool, so this option exists only on the
     * two tools that declare sets and needs no gating.
     */
    ...(paramSets
      ? [
          {
            id: OPTION_PARAM_SET,
            label: "Parameter set",
            group: "algorithm" as const,
            kind: "enum" as const,
            choices: paramSets.map((set) => ({
              value: set.id,
              label: set.label,
              summary: set.summary,
            })),
            summary: "Block and key size. Each pairing is a different function.",
            detail: paramSetDetailFor(toolId),
            order: 5,
          } satisfies OptionDef<CipherOptionGroup>,
        ]
      : []),
    {
      id: OPTION_MODE,
      label: "Mode",
      group: "algorithm",
      kind: "enum",
      choices: modes.map((m) => ({
        value: m.id,
        label: m.label,
        summary: m.summary,
        ...(m.insecure ? { insecure: true } : {}),
      })),
      summary: "How blocks are chained.",
      detail:
        "The same modes AES offers, over a different block permutation. GCM and CCM authenticate and are available wherever the block is 128 bits — SM4-GCM and SM4-CCM are the pair RFC 8998 specifies for TLS 1.3, and Camellia and ARIA get both for free, because neither mode needs anything but a 128-bit block. The classical five do not authenticate, so anything relying on the data being unaltered needs a MAC as well — and with a 64-bit block, CBC and CFB additionally need the total encrypted under one key kept well below a few gigabytes, because a block collision then leaks plaintext relationships.",
      order: 10,
    },
    keyOption(
      /**
       * A list of exact lengths, or a range for the one cipher that takes one.
       *
       * Blowfish accepts 4 to 56 bytes, so `exact` cannot express it. The metadata carries `keyRange`
       * in that case and this reads whichever is present -- and throws if neither is, because a block
       * cipher with no key constraint would accept a one-byte key and fail deep inside the schedule.
       */
      keyLengthFor(toolId, block, paramSets, tool.defaultParamSet),
      block.keyRange
        ? `${block.keyRange.min} to ${block.keyRange.max} bytes.`
        : paramSets
          ? "Set by the parameter set above."
          : block.keyLengths.length === 1
            ? `Exactly ${block.keyLengths[0]} bytes.`
            : `${block.keyLengths.join(" or ")} bytes.`,
      /**
       * A `Record`, not a chain, and this one had already gone wrong.
       *
       * The chain it replaces ended in SM4's sentence -- "One key size, 128 bits, as GB/T 32907
       * specifies" -- which was the default arm, so Camellia and ARIA both claimed it. Both take
       * three key sizes and neither has anything to do with GB/T 32907. Same footgun as the
       * catalogue selector below, in the same file, one function apart.
       */
      keyNoteFor(toolId),
    ),
    nonceOption(
      /**
       * Every length any offered mode accepts, because one catalogue serves all of them.
       *
       * A chaining mode's IV is exactly one block, and an AEAD's nonce belongs to the *mode* -- GCM's
       * 96 bits and CCM's 7-to-13-byte range are the same on Camellia as on AES. `resolveCipher`
       * narrows this union to the one mode selected, which is where the message can name it.
       */
      { exact: nonceLengthsFor(modes, block.size), generate: block.size },
      "IV / nonce",
      nonceSummaryFor(modes, block.size),
      `Every mode except ECB needs one. For CBC, CFB, OFB and CTR it is exactly one block — ${block.size} bytes — while GCM takes 12 and CCM 7 to 13, because those are properties of the mode rather than of the cipher. It is not secret and travels with the ciphertext, but CBC's must be unpredictable rather than merely unique, and CTR's and GCM's must never repeat under one key.`,
      // ECB is the one mode that takes none, which is its entire problem.
      modes.filter((m) => m.nonceLen > 0).map((m) => m.id),
    ),
    /*
     * Padding, for the block-aligned modes this tool actually offers. Absent from a cipher that has
     * neither -- there is no such tool today, and gating on the mode list rather than adding it
     * unconditionally means a future one gets the right form for free.
     */
    ...(modes.some((m) => m.blockAligned) ? [PADDING_OPTION] : []),
    ...(toolId === "rc2" ? [EFFECTIVE_KEY_BITS_OPTION] : []),
    ...(toolId === "rc5" ? [RC5_ROUNDS_OPTION] : []),
    ...(toolId === "threefish" ? [TWEAK_OPTION] : []),
    ...(toolId === "gost28147" ? [GOST_SBOX_OPTION] : []),
    ...(toolId === "anubis" ? [ANUBIS_VARIANT_OPTION] : []),
    ...(modes.some((m) => m.tagLens) ? [tagLenOption(modes)] : []),
    ...(modes.some((m) => m.aead)
      ? [aadOption(modes.filter((m) => m.aead).map((m) => m.id))]
      : []),
  ];
}

/**
 * RC2's effective key length, and the only option in this family that belongs to one cipher.
 *
 * It is not gated with `availableOn` because the axis here is the *tool*, not a variant of one: no
 * other cipher has this parameter, so the control is added to RC2's catalogue and absent from every
 * other. A `number` rather than an `enum` because the specification allows any value from 1 to 1024
 * and real files use 40, 64 and 128 -- offering a select would mean guessing which three matter.
 */
const EFFECTIVE_KEY_BITS_OPTION: OptionDef<CipherOptionGroup> = {
  id: OPTION_EFFECTIVE_KEY_BITS,
  label: "Effective key bits",
  group: "algorithm",
  kind: "number",
  arg: { placeholder: "64", min: 1, max: 1024, step: 8 },
  summary: "How much of the key RC2 is allowed to use. Leave empty for the key's full length.",
  detail:
    "RC2's key schedule deliberately throws strength away: this says how many key bits should actually matter, and the schedule masks the expanded key down to that. It is a parameter of the cipher, not a property of the key \u2014 so a 128-bit key with 40 effective bits has 40 bits of strength, and two tools must agree on *both* numbers to produce the same ciphertext. That is the usual reason RC2 output differs between implementations: OpenSSL defaults this to the key length in bits, as this tool does, while several others default it to 1024. S/MIME and PKCS#12 files from the export era typically carry 40 or 64.",
  order: 15,
};

/**
 * RC5's round count: the second option here that belongs to one cipher, and for the same reason.
 *
 * "RC5-32/12/16" names three parameters and the middle one is the rounds. It is not a strength
 * preference -- 12 and 16 rounds are different functions, and a value produced at one will never match
 * the other -- so it belongs beside the key rather than in a security note. Twelve is the default
 * because it is what the deployments used and therefore what an old file was made with.
 */
const RC5_ROUNDS_OPTION: OptionDef<CipherOptionGroup> = {
  id: OPTION_RC5_ROUNDS,
  label: "Rounds",
  group: "algorithm",
  kind: "number",
  arg: { placeholder: "12", min: 0, max: 255 },
  summary: "How many rounds RC5 performs. 12 is the classic naming; 16 is the later advice.",
  detail:
    'RC5 is parameterised as RC5-w/r/b -- word size, rounds, key bytes -- and this is r. Twelve is what "RC5" almost always means and what the deployments used; the designers raised their recommendation to 16 after a differential attack broke 12 rounds with about 2^44 chosen plaintexts. Zero rounds is legal and is not a mistake to refuse: it reduces to two subkey additions, it has a published test vector, and its existence is what makes the round count visibly a parameter. Two implementations must agree on all three numbers to produce the same ciphertext, which is the usual reason RC5 output differs.',
  order: 15,
};

/**
 * Threefish's tweak, and it is neither a key nor an IV.
 *
 * Sixteen bytes mixed into every fourth subkey. Its job is to make one key into a family of
 * independent permutations indexed by the tweak -- which is what disk encryption wants for the sector
 * number and what Skein uses for domain separation. It is not secret, so `secret` is not set; it is not
 * required to be unique either, which is what separates it from a nonce.
 *
 * `bytesLength` is `exact: [0, 16]` rather than absent, because `validateCatalogue` requires every
 * bytes option to declare one -- and the pair of legal lengths is exactly right. Empty decodes to zero
 * bytes and the binding reads that as the all-zero tweak, which is what the published zero-tweak
 * vectors use. Anything between 1 and 15 is refused by the form with a message naming both, rather
 * than zero-extended: encrypting under a tweak nobody asked for is worse than an error.
 */
const TWEAK_OPTION: OptionDef<CipherOptionGroup> = {
  id: OPTION_TWEAK,
  label: "Tweak",
  group: "key",
  kind: "bytes",
  bytesLength: { exact: [0, 16] },
  defaultBytesEncoding: "hex",
  summary: "Threefish's third input: 16 bytes, or empty for all zeroes.",
  detail:
    "A tweak turns one key into a family of independent permutations, indexed by the tweak value. It is not secret and it does not have to be unique -- which is exactly what separates it from an IV, and why it has its own field rather than reusing one: a CBC IV and a tweak are both in play at once. Disk encryption puts the sector number here; Skein puts the block position and a type code, which is how it keeps a tree hash's nodes from colliding with its leaves. Leave it empty for the all-zero tweak, which is the case the published vectors use. A partly filled tweak is refused rather than padded, because encrypting under a tweak nobody asked for is worse than an error.",
  order: 40,
};

/**
 * GOST 28147-89's S-box set: the fourth option here belonging to a single cipher.
 *
 * A genuine parameter rather than a preference. The 1989 standard leaves the tables to the deploying
 * organisation, so two implementations of "GOST" that disagree about them agree about nothing -- which
 * is the whole difficulty of interoperating with it, and the reason this is a control rather than a
 * hardcoded choice. Only the two published sets are offered: a set nobody published is a set nobody can
 * check output against.
 */
/**
 * Anubis's variant: the fifth option here belonging to a single cipher.
 *
 * Same shape as GOST's S-box set and the same reason for existing -- the submission was revised during
 * NESSIE and the tweak replaced the S-box, so two implementations of "Anubis" can disagree about the
 * tables and agree about nothing. A value someone is holding came from one of the two, and both have
 * published vectors, so both are offered rather than one being chosen for them.
 */
const ANUBIS_VARIANT_OPTION: OptionDef<CipherOptionGroup> = {
  id: OPTION_ANUBIS_VARIANT,
  label: "Variant",
  group: "algorithm",
  kind: "enum",
  choices: [
    {
      value: "tweaked",
      label: "Tweaked (NESSIE final)",
      summary: "The revised S-box, shared with Khazad",
    },
    {
      value: "original",
      label: "Original submission",
      summary: "The first S-box, before the tweak",
    },
  ],
  summary: "Which revision. The tweak replaced the S-box, so the two agree on nothing.",
  detail:
    "Anubis was revised during NESSIE evaluation and the change was its 8-by-8 S-box; everything else -- the involutory matrix, the key schedule, the round count -- is identical. So the two variants produce completely unrelated ciphertext from the same key, and there is nothing in the output to say which produced it. Tweaked is the final version and the default. It is also the one whose S-box is Khazad's, entry for entry, since the two ciphers were revised together -- which is why this tool stores one table rather than two.",
  order: 16,
};

const GOST_SBOX_OPTION: OptionDef<CipherOptionGroup> = {
  id: OPTION_GOST_SBOX,
  label: "S-box set",
  group: "algorithm",
  kind: "enum",
  choices: [
    {
      value: "test",
      label: "D-Test (id-GostR3411-94-TestParamSet)",
      summary: "The standard's own example set",
    },
    {
      value: "crypto",
      label: "CryptoPro (id-Gost28147-89-CryptoPro-A-ParamSet)",
      summary: "The set Russian PKI uses",
    },
  ],
  summary: "Which published table set. The 1989 standard leaves this to the deployer.",
  detail:
    "GOST 28147-89 specifies everything except its eight S-boxes, which the deploying organisation chooses -- so the tables are as much part of the key material as the key is, and two tools must agree on both to produce the same ciphertext. That is the usual reason GOST output differs between implementations. D-Test is the set the standard prints as an example and the one almost every published vector uses; CryptoPro's A set is what Russian PKI deployed. These are the same tables GOST R 34.11-94, the hash built on this cipher, uses -- so they are already checked by that hash's published vectors.",
  order: 15,
};

/** The `bytesLength` for a block cipher's key: its list of exact sizes, or its range. */
/**
 * What the Parameter set control says, per tool.
 *
 * A `Record` with a throwing lookup rather than a chain ending in Simon and Speck's sentence, which is
 * what this was: Kalyna would have arrived describing itself as one of "ten block/key pairings" whose
 * "word size sets the block", none of which is true of an SPN. Sixth time this file has needed the same
 * discipline, and the fifth bug of the shape was exactly this -- a default arm that was true of every
 * tool that existed when it was written.
 */
function paramSetDetailFor(toolId: string): string {
  const details: Record<string, string> = {
    present:
      '80 or 128 bits, and the two are the same cipher with different key expansions -- the S-box, the bit permutation and all 31 rounds are shared. The 80-bit set is the standardised one and the only one with published vectors; the 128-bit schedule comes from an appendix the authors prefaced with "we do not expect it to be used", so nothing external checks it. Prefer 80 unless you are reproducing something specific.',
    rectangle:
      "Two key sizes, and they are separate designs rather than one cipher taking a longer key: the schedules share only the S-box and the round constants. The block is 64 bits either way, so changing this changes the key length and nothing else -- unlike Simon, Speck or SKINNY, where the block moves with the set.",
    cham: "Three sets, named block-size/key-size. The two 128-bit-block sets differ only in key length and round count -- 80 rounds at a 128-bit key, 96 at 256 -- while CHAM-64/128 is a genuinely different cipher over 16-bit words. Changing this changes the block size, so the IV length moves with it.",
    simeck:
      "Two sets. The word size sets the block and the key is always four words, so Simeck32/64 has a 32-bit block and a 64-bit key while Simeck64/128 has twice both. The round count follows: 32 and 44. Simeck48/96 also exists and is not offered, because no reachable source publishes a vector for it and this catalogue does not ship what it cannot check.",
    skinny:
      "Six sets, named block-tweakey. The block is 64 or 128 bits and the tweakey is one, two or three times it, which gives the six -- and the round count rises with both, from 32 to 56. Changing this changes the block size and the key length together. The three-lane sets are the ones the tweakable constructions built on SKINNY use, because the third lane is where a per-block tweak would go.",
    speck:
      "Simon and Speck are each defined at ten block/key pairings, and they are not modes or truncations of one another -- the word size sets the block, the key word count sets the key, and both together decide the round count. Changing this changes the IV length and the key length with it, which is why it sits above both. The block size is the part with a practical consequence: at 32 bits, ciphertext blocks start repeating after about 256 kilobytes under one key.",
    simon:
      "Simon and Speck are each defined at ten block/key pairings, and they are not modes or truncations of one another -- the word size sets the block, the key word count sets the key, and both together decide the round count. Changing this changes the IV length and the key length with it, which is why it sits above both. The block size is the part with a practical consequence: at 32 bits, ciphertext blocks start repeating after about 256 kilobytes under one key.",
    /**
     * Threefish, and this entry is the reason `paramSetDetailFor` exists.
     *
     * Before it, every tool with parameter sets rendered Simon and Speck's sentence -- so Threefish's
     * control claimed it was one of "ten block/key pairings" whose "word size sets the block", which is
     * three wrong statements about a cipher that has three sets and a key equal to its block. The
     * throwing lookup is what turned that from invisible prose into a failing test.
     */
    threefish:
      "Threefish is defined at three widths -- 256, 512 and 1024 bits -- and the key is always exactly as wide as the block, which is unusual and is why this control changes the key length as well. All three run 72 rounds except the 1024-bit variant, which runs 80. The tweak stays sixteen bytes at every width.",
    kalyna:
      "DSTU 7624 defines five pairings: the key is either the block size or twice it, and the round count follows the key (10, 14, 14, 18, 18). Changing this changes both the key length and the IV length, which is why it sits above both -- and it changes the *function*, since a key twice the block width draws two round keys per rotation of the key material where an equal-width key draws one. The 256- and 512-bit blocks are unusual enough to be worth stating plainly: they raise the safe data limit per key far beyond anything reachable, and they mean CBC and CTR need a 32- or 64-byte IV.",
  };
  const detail = details[toolId];
  if (!detail) throw new Error(`No parameter-set explanation for cipher tool "${toolId}".`);
  return detail;
}

/**
 * What a shaped cipher's key, nonce and instance controls say, per tool.
 *
 * A throwing `Record` for the same reason as everywhere else in this file. All three are here rather
 * than in three records because they read as one paragraph about one cipher.
 */
function shapeNotesFor(toolId: string): { key: string; nonce: string; instance?: string } {
  const notes: Record<string, { key: string; nonce: string; instance?: string }> = {
    snow3g: {
      key: "Exactly 128 bits. There is no key schedule: the key, its complement and the IV are loaded straight into the sixteen LFSR stages and 32 mixing rounds do the work. In LTE this is CK or the integrity key, which the network derives rather than choosing.",
      nonce:
        "Exactly 128 bits, and it enters only four of the sixteen stages. In 128-EEA1 it is not chosen freely: it is built from the 32-bit COUNT, the 5-bit BEARER and the direction bit, each written into two of its words -- so reproducing a captured LTE bearer means constructing those sixteen bytes yourself before pasting them here.",
    },
    sosemanuk: {
      key: "128, 192 or 256 bits, and the security claim is 128 whichever you pick -- the designers state it explicitly, so a 256-bit key here buys key-recovery margin rather than 256 bits of strength. The key goes through Serpent's own schedule at 24 rounds instead of 32, which is why a SOSEMANUK key has the same shape as a Serpent one. The primitive accepts shorter keys, because Serpent's padding bit makes every length well defined and the reference's own vector uses five bytes; the form offers the specification's three, since a one-byte key would be eight bits of security.",
      nonce:
        "Exactly 128 bits, and it must be unique per key: the IV is injected by running Serpent24 over it, and the states after the 12th, 18th and 24th rounds *all three* seed the generator -- so two messages under one key and one IV produce the same keystream, with the usual consequence.",
    },
    trivium: {
      key: "Exactly 80 bits. There is no key schedule -- the key is loaded straight into the first register and the 1,152 warm-up rounds are what mix it. Note the loading order: the byte that lands at the start of the state is the *last* one, most significant bit first, which is what eSTREAM's published vectors assume.",
      nonce:
        "32, 64 or 80 bits. The specification defines 80 and eSTREAM published verified vectors for all three, which is why the shorter two are offered -- they are not zero-padded 80-bit IVs but genuinely shorter loads, so an IV of four bytes and the same four bytes followed by six zeros give different keystreams.",
    },
    rabbit: {
      key: "Exactly 128 bits. The key setup runs the cipher four times to fill the 513-bit state, then folds the state words back into the counters -- so every key bit reaches every counter before any output is produced.",
      nonce:
        "Sixty-four bits, or empty. Empty is not the same as eight zero bytes: with no IV the keystream starts from the state the key setup left, and with an all-zero IV four more setup iterations run over XORed counters. RFC 4503 publishes both, and they are unrelated -- so an implementation that silently substituted zeros for an absent IV would produce a plausible keystream matching nothing.",
    },
    zuc128: {
      key: "128 bits, and the only size 128-EEA3 defines. 3GPP derives it from the LTE or 5G key hierarchy rather than choosing it directly, so a value here is normally one you have captured or been given.",
      nonce:
        "128 bits. In 128-EEA3 this is not a free choice: it is built from the 32-bit count, the 5-bit bearer identity and the 1-bit direction, with the rest zero and the whole thing repeated in the upper half. Supplying an arbitrary sixteen bytes is legal for the cipher and will not match a captured LTE frame -- which is the usual reason two ZUC outputs disagree.",
    },
    zuc256: {
      key: "256 bits. The larger key is the whole point of the variant; the core is unchanged and only the LFSR loading differs.",
      nonce:
        "200 bits -- 25 bytes, which is unusual and is what the design specifies. The top two bits of nine of those bytes are discarded by the loading, which is why the standard's own all-ones vector writes 0x3f rather than 0xff in that stretch.",
    },
    hc128: {
      key: "128 bits, the only size HC-128 defines. The 1280-word setup that follows it is the cost of this cipher: fast to run, slow to key, so it is wrong for many short messages under different keys.",
      nonce:
        "128 bits, and it goes through the same expansion as the key -- there is no cheap re-keying path here. With no authentication on top, a repeat reveals the XOR of the two plaintexts and nothing detects a modified ciphertext.",
    },
    hc256: {
      key: "256 bits as specified, and 128 is accepted because eSTREAM published vectors for it: a short key is *duplicated* to fill 256 bits rather than zero-padded, which is what the reference implementation does. So a 16-byte key and that key written twice give the same keystream -- worth knowing before concluding that two tools disagree.",
      nonce:
        "256 bits as specified, and 128 accepted on the same terms -- a short IV is repeated to fill the buffer. Never reuse one under a key: this is a raw stream cipher with no tag.",
    },
    grainv1: {
      key: "80 bits, which is Grain v1's entire security claim and the reason Grain-128 exists. There is no attack on the full cipher; 80 bits is simply below what anything should rely on now.",
      nonce:
        "64 bits. It fills the low 64 bits of the LFSR and the remaining sixteen are set to all ones -- padding the specification requires, not zero-fill. At 64 bits a randomly chosen IV starts risking collisions after a few billion messages, so Grain expects a counter.",
    },
    grain128: {
      key: "128 bits. Twice Grain v1's width, and with a lower-degree feedback function -- the extra key length bought the margin the algebraic complexity was providing.",
      nonce:
        "96 bits, filling the low three words of the LFSR with the top four bytes set to all ones. Same reasoning as Grain v1: unique per message, and a counter rather than a random draw.",
    },
    acorn: {
      key: "Exactly 128 bits. There is no key schedule -- the key is clocked into the state a bit at a time and the 1,792 initialisation steps are what mix it, with the key fed round again for the last 1,536 of them.",
      nonce:
        "Exactly 128 bits, and this is the one AEAD here where reuse is unforgiving: the designers state plainly that a key must never be used twice with the same nonce, and unlike Deoxys-II there is no misuse resistance to fall back on. Use a counter.",
    },
    deoxysii: {
      key: "Exactly 256 bits, and both halves matter differently: the second sixteen bytes seed TK2 and the first sixteen seed TK3, which run through different LFSRs. There is one schedule for the key and a second, cheaper one for the tweak, which is what lets the mode change the tweak per block without rekeying.",
      nonce:
        "Exactly 120 bits -- fifteen bytes, not sixteen, because the sixteenth byte of the block is where the mode writes its domain prefix. This is the one AEAD here where repeating a nonce is not catastrophic: it leaks whether two messages were identical and nothing else, which is what the two-pass design buys. Still choose a fresh one per message; misuse resistance is a safety net rather than a licence.",
    },
    norx: {
      key: "Exactly 128 bits. It enters twice: once into the rate during initialisation and once into the capacity after the first permutation, then twice more during finalisation -- which is what makes the tag depend on the key rather than only on the state.",
      nonce:
        "Exactly 128 bits, and unique per key. NORX is a sponge with no misuse resistance, so a repeated nonce under one key exposes the XOR of the two messages in the usual way.",
    },
    xoodyak: {
      key: "128 bits, and the only size Cyclist's keyed mode defines here. The key and the nonce are absorbed together with a length byte, which is what keeps a short nonce from colliding with a longer one that begins the same way.",
      nonce:
        "128 bits. Wide enough to choose at random for every message and never track what has been used -- the property GCM's 96-bit nonce does not have.",
    },
    morus: {
      key: "The parameter set decides the length: 16 bytes at MORUS-640-128 and MORUS-1280-128, 32 at MORUS-1280-256. Note the first two take the *same* key length and are different ciphers, so choose the set deliberately rather than by key size.",
      nonce:
        "Exactly 128 bits at every set, and never repeated under one key -- MORUS is a stream construction, so a repeated nonce XORs two plaintexts together. That caveat is academic next to the bigger one: the full cipher has a published keystream correlation, so the plaintext leaks whatever you do with the nonce.",
      instance:
        "Three sets. MORUS-640-128 uses 32-bit words and a 16-byte block; both MORUS-1280 sets use 64-bit words and a 32-byte block, differing only in the key -- the 128-bit key is *repeated* to fill the 256-bit register rather than zero-extended. MORUS-1280-256 is the submission's primary member and the one the 2018 correlation attack is stated against.",
    },
    ketjejr: {
      key: "Exactly 128 bits. It is *overwritten* into the state as a key pack -- a length byte, the key, a 0x01 terminator -- rather than XORed, which is what lets the nonce follow it in the same 25-byte state.",
      nonce:
        "Up to 48 bits, and the limit is arithmetic rather than a design choice: an 18-byte key pack plus the nonce plus two frame bits have to fit in Keccak-p[200]'s 25 bytes, which leaves six. Public, and never repeated under one key -- this is a MonkeyDuplex, so a repeated nonce leaks the keystream directly.",
    },
    schwaemm: {
      key: "The parameter set above decides the length: 16, 24 or 32 bytes. Press Generate after choosing a set, not before.",
      nonce:
        "The parameter set decides this too, and it is the *first* number in the name -- Schwaemm256-128 takes a 256-bit nonce and a 128-bit key. Public, and never repeated under one key.",
      instance:
        "Four instances, named `<nonceBits>-<keyBits>` as the submission names them. Schwaemm256-128 is the primary recommendation; 128-128 is the smallest state and the fastest for short messages; 256-256 is the only one whose tag is wide enough to commit to the key, so a single ciphertext cannot be made to decrypt correctly under two different keys. Changing this changes the key length, the nonce length *and* the tag length together.",
    },
    giftcofb: {
      key: "128 bits, the only size. GIFT-COFB's state is only 64 bits wider than the block, which is what makes it the smallest block-cipher-based finalist.",
      nonce:
        "128 bits, and it goes through the cipher once before anything else. With no authentication failure to hide behind, a repeat is as damaging here as under GCM.",
    },
    photonbeetle: {
      key: "128 bits. The key and nonce together *are* the initial state, which is why both are exactly half of it.",
      nonce:
        "128 bits, forming the second half of the initial state. Never reuse one under a key.",
      instance:
        "The rate: 32 bits or 128. That is the whole choice, and it is a hardware-versus-throughput trade rather than a security one -- both have the same 128-bit claim. The 32-bit rate runs four times as many permutations for the same message and needs a quarter of the circuit, which is why the submission names it the primary member for the smallest targets.",
    },
    romulus: {
      key: "128 bits, and all three modes take the same key -- the mode is a property of how the cipher is driven, not of the key.",
      nonce: "128 bits. Under Romulus-M a repeat is survivable; under N and T it is not.",
      instance:
        "Three modes over one tweakable block cipher, and they are three different security properties rather than three speeds. **N** is the primary member: one cipher call per block, single pass, and it needs a nonce that never repeats. **M** is misuse-resistant -- a repeated nonce leaks only whether two messages were identical -- and pays for it with a second pass over the message, so nothing can be encrypted until the whole plaintext is known. **T** is leakage-resilient: the session key is rekeyed every block, so a side-channel attacker watching many encryptions learns nothing about the long-term key.",
    },
    elephant: {
      key: "128 bits for all three instances.",
      nonce:
        "96 bits. Elephant is counter mode underneath, so the nonce is what the counter counts from -- a repeat reveals the XOR of the two plaintexts outright.",
      instance:
        "Three permutations under one construction, and the names are the specification's. **Dumbo** is Spongent-pi[160] at 80 rounds and is the primary member -- the smallest of the three. **Jumbo** widens the permutation to 176 bits for more margin. **Delirium** uses Keccak-f[200] instead, which is the right choice on hardware that already has a Keccak core, and is the only one of the three with a 128-bit tag rather than a 64-bit one. Changing this changes the tag length.",
    },
    isap: {
      key: "128 bits. What matters about ISAP's key is not its length but how little of it is exposed: it is used only inside a rekeying function that absorbs one bit of input at a time.",
      nonce:
        "128 bits. It seeds both the rekeying and the MAC, so a repeat is as damaging as for any AEAD -- ISAP's guarantee is about side channels, not about nonce misuse.",
      instance:
        "Two permutations crossed with two round-count profiles. **A** uses Ascon-p and **K** uses Keccak-p[400]; the **A** suffix on 128A means reduced rounds, which is a large difference here rather than a small one -- the rekeying loop runs once per key bit, so one round against twelve is twelvefold in the dominant cost. ISAP-A-128A is the primary member. Pick a K variant only for hardware that already has a Keccak core.",
    },
    grain128aead: {
      key: "128 bits. It is mixed into the registers twice: once as their initial value and again over 64 clocks after the first 320, which is the step plain Grain-128 does not have.",
      nonce:
        "96 bits, filling three of the four LFSR words with the fourth set to all ones but its top bit. Never reuse one -- this is a stream cipher with a tag bolted on, not an AEAD with a nonce-misuse story.",
    },
    tinyjambu: {
      key: "The parameter set above decides the length: 16, 24 or 32 bytes. The key is not expanded at all -- the feedback function reads one key word per 32 bits of permutation, cycling through them, which is why a longer key means a longer cycle rather than a bigger schedule.",
      nonce:
        "96 bits at every key size, absorbed as three 32-bit words with a frame constant between them.",
      instance:
        "Three key sizes, and the only other thing that changes is the length of the wide permutation -- 1024, 1152 or 1280 rounds. The narrow permutation is 640 for all three. TinyJAMBU-128 is the primary member; the larger keys buy margin against multi-key attacks rather than against anything known.",
    },
    adiantum: {
      key: "256 bits (32 bytes). Used for ChaCha12 encryption and derived AES/Poly1305 evaluation.",
      nonce: "96 bits (12 bytes) tweak / IV. Uniquely identifies each sector or disk block.",
    },
    hctr2: {
      key: "256 bits (32 bytes). Used for AES-CTR, AES-ECB middle permutation, and POLYVAL keying.",
      nonce: "128 bits (16 bytes) tweak. Sector / block index for wide-block encryption.",
    },
    spritz: {
      key: "128 or 256 bits (16 or 32 bytes). Squeezed through Spritz sponge initial state.",
      nonce: "Optional IV (0, 8, or 16 bytes). Spritz absorbs the IV into its sponge state.",
    },
    crypto1: {
      key: "48 bits (6 bytes). The secret key stored on the Mifare Classic RFID card / sector.",
      nonce: "32 bits (4 bytes) UID / challenge nonce from the RFID card.",
    },
    "dect-dsc": {
      key: "64 bits (8 bytes) cordless authentication / encryption key.",
      nonce: "32 to 40 bits (4-5 bytes) initialization vector from DECT standard frame counter.",
    },
    gea: {
      key: "64 bits (8 bytes) GPRS ciphering key Kc.",
      nonce: "32 bits (4 bytes) frame counter direction vector.",
    },
    "snow-v": {
      key: "256 bits (32 bytes). 3GPP 5G New Radio secret key.",
      nonce: "128 bits (16 bytes) initialization vector.",
    },
    isaac: {
      key: "128 or 256 bits (16 or 32 bytes) seed for ISAAC CSPRNG state.",
      nonce: "No IV needed (stream state initialized from key seed).",
    },
    pcg64: {
      key: "64 or 128 bits (8 or 16 bytes) seed for PCG64 / PCG-DXSM state.",
      nonce: "No IV needed (stream state initialized from seed).",
    },
    xoshiro256: {
      key: "256 bits (32 bytes) seed for four 64-bit state registers.",
      nonce: "No IV needed.",
    },
    "a5-1": {
      key: "64 bits (8 bytes) GSM mobile station secret key Kc.",
      nonce: "22 bits (3 bytes) frame counter Fn.",
    },
    "rc4-drop": {
      key: "40 to 256 bits (5 to 32 bytes) RC4 key.",
      nonce: "No IV needed.",
    },
    mickey: {
      key: "80 bits (10 bytes) secret key for MICKEY 2.0.",
      nonce: "0 to 80 bits (up to 10 bytes) initialization vector.",
    },
    "a5-2": {
      key: "64 bits (8 bytes) GSM mobile station secret key Kc.",
      nonce: "22 bits (3 or 4 bytes) frame counter Fn.",
    },
  };
  const note = notes[toolId];
  if (!note) throw new Error(`No key and nonce explanation for shaped cipher "${toolId}".`);
  return note;
}

/**
 * A cipher whose whole form is a key, a nonce and -- for an AEAD -- associated data, built from the
 * tool's own `shape` metadata.
 *
 * The counterpart to `blockCipherOptions`, and the reason six stream ciphers and nine NIST lightweight
 * AEADs arrived in this family without fifteen more hand-written option blocks. The tools with a control
 * of their own -- RC4's drop, ChaCha's initial counter -- keep their bespoke catalogues; see the note on
 * `CipherToolMeta.shape`.
 */
function shapedCipherOptions(tool: CipherToolMeta): readonly OptionDef<CipherOptionGroup>[] {
  const shape = tool.shape!;
  const keyLengths = [...shape.keyLengths];
  const nonceLengths = [...shape.nonceLengths];
  const notes = shapeNotesFor(tool.id);
  const instances = shape.instances;
  const list = (lengths: readonly number[]): string =>
    lengths.length === 1 ? `Exactly ${lengths[0]} bytes.` : `${lengths.join(" or ")} bytes.`;

  return [
    DIRECTION_OPTION,
    /**
     * The instance, where there is more than one -- and it reuses `OPTION_PARAM_SET` rather than
     * inventing a second "which configuration" id.
     *
     * First in the form after the direction, for the same reason a block cipher's parameter set is: it
     * decides how many bytes the Generate buttons produce. No `availableOn`: the catalogue is built per
     * tool, so this option exists only on the tools that declare instances.
     */
    ...(instances
      ? [
          {
            id: OPTION_PARAM_SET,
            label: "Parameter set",
            group: "algorithm" as const,
            kind: "enum" as const,
            choices: instances.map((instance) => ({
              value: instance.id,
              label: instance.label,
              summary: instance.summary,
            })),
            summary: "Which named instance of this construction to run.",
            /**
             * Required rather than optional, and the throw is the point: a tool that declares
             * instances and no explanation for them would render a select with an empty help panel.
             */
            detail:
              notes.instance ??
              (() => {
                throw new Error(
                  `Cipher tool "${tool.id}" declares instances but no explanation.`,
                );
              })(),
            order: 5,
          } satisfies OptionDef<CipherOptionGroup>,
        ]
      : []),
    keyOption(
      // Generate the widest the cipher accepts: a key whose length nobody chose should be the
      // strongest available, which is the same rule `keyLengthFor` applies to Blowfish's range.
      { exact: keyLengths, generate: keyLengths[keyLengths.length - 1]! },
      instances && keyLengths.length > 1 ? "Set by the parameter set above." : list(keyLengths),
      notes.key,
    ),
    nonceOption(
      { exact: nonceLengths, generate: nonceLengths[nonceLengths.length - 1]! },
      "IV / nonce",
      instances && nonceLengths.length > 1
        ? "Set by the parameter set above. Public, and must never repeat under one key."
        : `${list(nonceLengths).replace(/\.$/, "")}. Public, and must never repeat under one key.`,
      notes.nonce,
    ),
    // The AAD field exists exactly when the construction authenticates. See `shape.tagLen`.
    ...(shape.tagLen !== undefined ? [aadOption()] : []),
  ];
}

function keyLengthFor(
  toolId: string,
  block: { keyLengths: readonly number[]; keyRange?: { min: number; max: number } },
  paramSets?: readonly CipherParamSet[],
  /**
   * Which set the form opens on, so Generate produces the length that set actually wants.
   *
   * This was `paramSets.find((set) => set.id === "128-128")`, a literal that happened to name Simon's
   * and Speck's default. Kalyna also has a `128-128`, so the bug would not have shown there either --
   * but Threefish has already cost this repo six failures for exactly this shape of mistake
   * (`seedKeyLength` reading the last key length against a 512-bit default set), and a hardcoded id is
   * how the next one arrives. The tool declares its default; read that.
   */
  defaultParamSet?: string,
): OptionDef["bytesLength"] {
  /**
   * A parameterised cipher declares the union of its sets' key lengths.
   *
   * `ToolDefinition.catalogue` is resolved once per tool and cannot know which set is selected, so
   * the control has to accept all seven lengths Simon and Speck between them use. The resolver then
   * enforces the one the selected set requires, where the message can name it. Declaring only the
   * default set's length here would make nine of the ten sets unusable; declaring the union and
   * *not* narrowing in the resolver would hand a 32-byte key to Speck32/64.
   */
  if (paramSets) {
    const lengths = [...new Set(paramSets.map((set) => set.keyLength))].sort((a, b) => a - b);
    const generate =
      paramSets.find((set) => set.id === defaultParamSet)?.keyLength ??
      lengths[lengths.length - 1]!;
    return { exact: lengths, generate };
  }
  if (block.keyRange) {
    // Generate the maximum: a key someone did not choose the length of should be the strongest one.
    return { min: block.keyRange.min, max: block.keyRange.max, generate: block.keyRange.max };
  }
  const last = block.keyLengths[block.keyLengths.length - 1];
  if (last === undefined) {
    throw new Error(`Block cipher "${toolId}" declares neither key lengths nor a key range.`);
  }
  return { exact: [...block.keyLengths], generate: last };
}

/** What to say about a block cipher's key, per cipher. */
function keyNoteFor(toolId: string): string {
  if (toolId === "speck" || toolId === "simon") {
    const name = toolId === "speck" ? "Speck" : "Simon";
    return `The parameter set above decides the key length -- ${name} is defined at ten block/key pairings and each takes exactly one size. Press Generate after choosing a set, not before.`;
  }
  const simonSpeck = /^(simon|speck)(\d+)-(\d+)$/.exec(toolId);
  if (simonSpeck) {
    const [, family, blockBits, keyBits] = simonSpeck as unknown as [
      string,
      string,
      string,
      string,
    ];
    const name = family === "speck" ? "Speck" : "Simon";
    return `Exactly ${keyBits} bits, which is what the ${blockBits} in ${name}${blockBits}/${keyBits} is paired with. Each of the ten sizes in this family is a different function rather than a truncation of another: the word size sets the block, the key word count sets the key, and both together decide the round count -- and for Simon, which of five constant sequences the schedule draws on.`;
  }
  const notes: Record<string, string> = {
    des: "Eight bytes, of which 56 bits are used — every eighth bit is a parity bit the algorithm never reads. OpenSSL accepts a key with wrong parity and so does this, because refusing one that works everywhere else would be an opinion rather than the standard.",
    "3des":
      "24 bytes for three-key 3DES (`des-ede3`), or 16 for the two-key variant (`des-ede`), where the third key repeats the first. Two-key is meaningfully weaker: a meet-in-the-middle attack brings it to roughly 80 bits.",
    sm4: "One key size, 128 bits, as GB/T 32907 specifies.",
    belt: "128, 192 or 256 bits, all three defined by STB 34.101.31. There is no key schedule at all: the 256-bit key *is* the eight 32-bit subkeys, used 56 times over, and a 128- or 192-bit key is extended to 256 by the standard's own rule before that. Encryption and decryption index those subkeys in orders that are not reverses of each other, which is why STB publishes a decrypt vector separately.",
    camellia:
      "128, 192 or 256 bits, matching AES exactly — RFC 3713 defines Camellia as a drop-in at all three sizes, and its 18- or 24-round schedule is chosen by the key length.",
    aria: "128, 192 or 256 bits, again matching AES. RFC 5794's rounds — 12, 14 or 16 — follow from the key size.",
    magma:
      "Exactly 256 bits, which GOST R 34.12-2015 fixes. It becomes eight 32-bit subkeys used in order three times and then in reverse, and every bit of it is used — there is no parity byte as in DES.",
    blowfish:
      "Anything from 4 to 56 bytes — the only variable-length key here. A short key is *cycled* rather than padded: a 4-byte key repeats itself four and a half times across the eighteen P-array words, which is the specification and not a shortcut. Keying is deliberately slow, running the cipher 521 times to rewrite every table; that property is what `bcrypt` is built on.",
    present:
      "Exactly 80 bits, which is the variant standardised in ISO/IEC 29192-2 and below every current recommendation for new work. PRESENT-128 exists and has a different key schedule; it is not offered here, because no vector for it was reachable to check it against.",
    /**
     * All twenty Simon and Speck variants take one key size each, and it is in the tool's own name --
     * so one note serves the lot rather than twenty near-identical ones.
     *
     * Which is why this is a function rather than a `Record` entry per id: the family defines ten
     * (block, key) pairs each, every one of them a different function rather than a truncation, and
     * writing them out would be twenty chances for one to drift from its metadata.
     */
    twofish:
      "128, 192 or 256 bits, matching AES. The key does more work here than in most ciphers: Twofish derives its S-boxes from it, so keying costs more than encrypting a block does.",
    serpent:
      "128, 192 or 256 bits. A shorter key is padded with a single one bit and then zeros \u2014 not zeros alone \u2014 so an all-zero 128-bit key is *not* the same as an all-zero 256-bit key. That trips people comparing output between tools.",
    kuznyechik:
      "Exactly 256 bits, which GOST R 34.12-2015 fixes for this cipher as it does for Magma. The key becomes ten 128-bit round keys through eight Feistel steps per pair.",
    seed: "One key size, 128 bits, as KS X 1213 and RFC 4269 specify.",
    cast5:
      "40 to 128 bits in 8-bit steps. The size changes more than the strength: RFC 2144 uses twelve rounds for a key of 80 bits or fewer and sixteen above that, so padding a 10-byte key to 11 bytes with a zero changes the cipher rather than leaving it alone.",
    idea: "One key size, 128 bits.",
    rc2: "1 to 128 bytes, and on its own it does not determine the strength \u2014 the separate effective-key-length control below does. Two implementations must agree on both to produce the same ciphertext, which is the usual reason RC2 output differs between tools.",
    cast6:
      "128, 160, 192, 224 or 256 bits \u2014 every 32-bit step RFC 2612 defines. A shorter key is zero-padded to 256 bits by the key schedule before anything else happens, which is what makes the intermediate sizes legal rather than special.",
    rc6: "128, 192 or 256 bits, matching AES exactly \u2014 RC6 was submitted as a drop-in replacement. Unlike AES, the round count does not change with the key size: twenty rounds, always.",
    rc5: "1 to 255 bytes, and the round-count control below matters as much: RC5-32/12/16 names three parameters and two implementations must agree on all three. The key is loaded into little-endian words, so a 1-byte key and its zero-padded 4-byte form expand to the same schedule \u2014 which is a fact about the specification rather than a shortcut here.",
    threefish:
      "The same size as the block: 32, 64 or 128 bytes, chosen by the parameter set above. That is unusual and it is the design \u2014 Threefish has no key schedule that compresses. It extends the key by one word, the XOR of all of them with a constant, so the subkey sequence cycles through Nw+1 words instead of repeating. Press Generate after choosing a width, not before.",
    tea: "Exactly 128 bits, in four big-endian words. Note that TEA's effective key size is 126 bits rather than 128: every key has three equivalents that encrypt identically, which is part of why it was superseded.",
    xtea: "Exactly 128 bits, in four big-endian words \u2014 the same key TEA takes, which is what makes the two so easy to confuse. XTEA selects one of the four words per half-round from bits of the running sum, where TEA uses all four in the same order every round; that is the whole difference in the schedule.",
    xxtea:
      "Exactly 128 bits, four 32-bit words, and there is no key schedule -- but unlike TEA the word used in each step is selected by `(p & 3) ^ ((sum >> 2) & 3)`, so it depends on both the position in the block and the round. That is the difference between XTEA's repair and XXTEA's: XTEA varies the word by round, XXTEA varies it by round *and* position.",
    skipjack:
      "Exactly 80 bits, and there is no key schedule at all. Round k reads bytes 4k through 4k+3 modulo 10, so because 4 and 10 share a factor the 32 rounds see the key in a five-round cycle. Eighty bits is the cipher's real weakness \u2014 the design has no practical attack, and the key size has been within reach of dedicated hardware for two decades.",
    lea: "128, 192 or 256 bits, and unusually the three are three different *key schedules* rather than one parameterised by length \u2014 a 128-bit key repeats one derived word three times per round, a 192-bit key uses six distinct ones, and a 256-bit key walks eight through a rotating index. The round count follows: 24, 28, 32.",
    noekeon:
      "Exactly 128 bits, used as it arrives. This is direct-key mode: there is no key schedule at all, which is the design's whole point and also its weakness \u2014 a related-key attack exists on it, and Noekeon's own indirect mode was defined to prevent exactly that.",
    shacal2:
      "128 to 512 bits, zero-padded to 512. The key *is* SHA-256's 512-bit message block, which is why it can be larger than the 256-bit block \u2014 the schedule expands nothing, it runs the message schedule. There is no weak key length here in the usual sense; a shorter key is simply a message block with zeros in it.",
    gost28147:
      "Exactly 256 bits, and it is not the whole story: the S-box set below is as much part of the key material as this is. The key becomes eight 32-bit subkeys used in order three times and then in reverse \u2014 no expansion, no constants, and every bit used.",
    clefia:
      "128, 192 or 256 bits, and the length changes the round count as well as the schedule: 18, 22 or 26 rounds. A 192-bit key is completed internally with the complement of its own first two words, which is why it is a distinct schedule rather than a padded 256-bit one -- so padding a 16-byte key to 24 bytes with zeros gives a different cipher, not the same one.",
    mars: "128, 192 or 256 bits. Unlike AES the round count does not change with it -- 32 rounds always -- so a longer key buys key-search resistance and nothing else. The submission defines lengths up to 448 bits; the three offered here are the three with published vectors.",
    cham: "The parameter set decides the length: 16 bytes for CHAM-64/128 and CHAM-128/128, 32 for CHAM-128/256. There is no key schedule worth the name -- each key word yields two round keys by XORing three rotations of itself, and the round keys are then reused cyclically, which is why the round *index* has to enter the state to stop every round being identical.",
    simeck:
      "The parameter set decides the length: 8 bytes at Simeck32/64 and 16 at Simeck64/128. The schedule holds four words and advances them with the cipher's own round function, so there is no separate schedule to specify -- and the words load in reverse, the first byte pair becoming the *last* register, which is what the published vectors assume.",
    skinny:
      "The parameter set decides the length: one, two or three lanes of the block size, so 8 to 48 bytes. SKINNY's third input is properly a *tweak*, and this tool spends the whole tweakey on key material -- which is what the standardised block cipher does and what its published vectors use. Only the first lane is a plain permutation; lanes two and three get an LFSR after it, which is why a two- or three-lane key is not the same as a longer one-lane key.",
    sparx:
      "Exactly 128 bits, held as eight 16-bit words. The schedule advances them with the cipher's own S-box -- Speck's round function -- and adds the iteration number, which is the only constant in the whole design. Note the schedule works at 16 bits while the cipher works at 32: those are the same words at two widths.",
    chaskeylts:
      "Exactly 128 bits, and there is no key schedule whatsoever. Chaskey-LTS is an Even-Mansour construction: the key is XORed in before the permutation and again after, unchanged. That makes the key the only thing breaking the permutation's symmetry, which is why reusing one across messages in ECB is even less advisable here than usual.",
    twine:
      "Exactly 80 bits, held as twenty nibbles. The schedule rotates them twice per round -- the first four by one, then all twenty by four -- and folds in two S-box outputs and a round constant. TWINE-128 uses a different schedule over 32 nibbles and is not offered, since no reachable source publishes a vector for it.",
    led: "Exactly 80 bits, and this is the one cipher here with **no key schedule at all**: the twenty key nibbles are XORed into the state unchanged, once every four rounds, at an offset that advances by sixteen and wraps at twenty. That is deliberate -- LED's security argument is about related keys, and a schedule is what related-key attacks exploit.",
    prince:
      "Exactly 128 bits, and the two halves do different jobs: the first whitens the block at both ends and the second is the round key for all twelve rounds. The trailing whitening word is the first half rotated right by one bit -- a rotation, not a shift, so the bit that falls off the bottom comes back at the top. Decryption needs no separate key: swapping the two whitening words and XORing one constant into the round key inverts the cipher, which is what PRINCE exists for.",
    lblock:
      "Exactly 80 bits. The register rotates left by twenty-nine bits per round -- three bytes and five bits, so no shift in the expression is a multiple of eight -- and then two of the cipher's ten S-boxes and a round counter go in. Those two boxes, S8 and S9, are used nowhere else.",
    rectangle:
      "The parameter set decides the length: 10 bytes at RECTANGLE-64-80 and 16 at 64-128. The two schedules are genuinely different functions rather than one parameterised by length -- the shorter holds five 16-bit rows and rotates a word by twelve, the longer holds eight and rotates bytes -- and they share only the S-box and the round constants.",
    pride:
      "Exactly 128 bits, and there is no key schedule. The first eight bytes whiten the block before the first round and after the last; the second eight are the round key for every one of the twenty rounds, distinguished only by four round constants *added* -- not XORed -- to its odd bytes. So the same key material is reused twenty times, which is deliberate and is why the constants are the only thing separating the rounds.",
    piccolo:
      "Exactly 80 bits, held as five 16-bit words. The whitening keys are **byte-interleaved** from those words rather than sliced out of them -- the high byte of one word with the low byte of another -- and the round keys come from a five-case cycle over the same material XORed with a constant. Piccolo-128 uses a different cycle and is not offered, since no reachable source publishes a vector for it.",
    robin:
      "Exactly 128 bits, and there is no key schedule at all: the key is XORed in before the first round and after every round, unchanged. That is the LS-design shape -- the security comes from the L-box and S-box rather than from key expansion. Note this cipher has a full-cipher invariant-subspace attack with weak-key classes, so a key here is not simply a key; Robin* is the fixed member.",
    robinstar:
      "Exactly 128 bits, XORed in unchanged before the first round and after every round -- no key schedule, as with every LS-design. Robin* differs from Robin *only* in its round constant, so the two share every table and a key means the same thing to both.",
    fantomas:
      "Exactly 128 bits, XORed in unchanged before the first round and after every round. No key schedule, as with every LS-design -- but unlike Robin, Fantomas's S-box and L-box are not involutions, so decryption needs its own tables rather than reusing these.",
    roadrunner80:
      "Exactly 80 bits, and the ten bytes are consumed **one at a time modulo ten** rather than as aligned words: each substitute-linear-key layer takes four bytes from a running cursor, so a layer straddles the end of the key and the same byte lands in a different position each round. That is the real difference from RoadRunneR-128, whose sixteen bytes divide by four -- an implementation treating this as the wider one with a shorter key is correct for two layers and wrong thereafter.",
    roadrunner128:
      "Exactly 128 bits, read as four aligned 32-bit words: each layer XORs one word, and a counter steps four bytes per layer. Twelve rounds rather than the 80-bit variant's ten. There is no expansion -- the key material *is* the round keys, reused in a fixed cycle.",
    lilliput:
      "Exactly 80 bits, held as twenty nibbles. The schedule is the bulk of this cipher: two coupled feedback state machines advance the twenty nibbles once per round, and each round key is eight nibbles read from fixed positions, bit-transposed through a multiply-by-four-modulo-31 pattern, passed through the S-box, and XORed with the round number split across two nibbles. There is no wider key: LILLIPUT is defined at 80 bits only, and the 128-bit key belongs to Lilliput-AE, which is a separate tweakable authenticated-encryption scheme rather than a key size of this cipher.",
    kasumi:
      "Exactly 128 bits. The schedule is eight 16-bit words plus the same eight XORed with a fixed constant, and every one of the 64 subkeys is a rotation of one of those sixteen -- so there is no expansion and no way for a key bit not to matter. Note this is 3G's *cipher* key, which the network derives from the subscriber key rather than choosing directly.",
    anubis:
      "16, 20, 24, 28, 32, 36 or 40 bytes -- 128 to 320 bits in 32-bit steps, which is more choices than any other cipher here offers. The round count follows the key: 12 rounds at 128 bits up to 18 at 320, so changing the key length changes the function rather than only its strength. The schedule runs the cipher's own diffusion over the key words, with round constants taken from the S-box.",
    saferp:
      "Exactly 128, 192 or 256 bits, and the round count follows: 8, 12 or 16. The schedule appends a parity byte, rotates the whole thing left three bits per round key, and adds a bias word derived from powers of 45 -- which is where SAFER+'s weakness lies, so a longer key here buys less than the number suggests.",
    khazad:
      "Exactly 128 bits, consumed as two 64-bit halves that feed a nine-round schedule built from the cipher's own round function. Because the cipher is involutional, decryption uses the same nine round keys in reverse rather than a second schedule.",
    misty1:
      "Exactly 128 bits, in eight big-endian 16-bit words. The schedule is unusually short -- eight applications of the cipher's own FI function -- and every one of the 32 expanded words is derived from it, so there are no weak lengths and nothing is zero-padded.",
    hight:
      "Exactly 128 bits. The schedule is addition rather than substitution: the eight whitening bytes are the key's own bytes reordered, and each of the 128 round-key bytes is a key byte plus one of 128 constants that come from a 7-bit LFSR. Every key bit is used and none is expanded.",
    kalyna:
      "The parameter set above decides the length: DSTU 7624 pairs each block size with a key of the same width or twice it, and the round count follows the key. Press Generate after choosing a set, not before -- a 32-byte key is legal for both Kalyna-128/256 and Kalyna-256/256, so the length alone does not say which cipher you are running.",
    keeloq:
      "Exactly 64 bits (8 bytes). The secret manufacturing or vehicle transmitter hopping key.",
    saturnin:
      "Exactly 256 bits (32 bytes). Used across all super-rounds for 256-bit post-quantum block cipher security.",
    shacal1:
      "128 to 512 bits (16 to 64 bytes). Zero-padded to the 512-bit SHA-1 message schedule block.",
    qarma:
      "Exactly 128 bits (16 bytes) for QARMA-64. Used as w0 and k0 for ARM pointer authentication.",
    mantis:
      "Exactly 128 bits (16 bytes). Divided into k0 and k1 with alpha-reflection memory encryption.",
    craft:
      "Exactly 128 bits (16 bytes). Consumed as 64-bit halves K0 and K1 with periodic tweakey cycling.",
    midori:
      "Exactly 128 bits (16 bytes). Consumed as two 64-bit halves K0 and K1 for ultra-low energy encryption.",
    square:
      "Exactly 128 bits (16 bytes). Expanded into nine 128-bit round keys for the 8-round Substitution-Permutation Network.",
    multi2:
      "Exactly 256 or 320 bits (32 or 40 bytes). System key for 32-round Feistel scrambling in MPEG-2 transport streams.",
  };
  const note = notes[toolId];
  if (!note)
    throw new Error(`No key note for block cipher "${toolId}". Add one to keyNoteFor.`);
  return note;
}

/** The union of nonce lengths across the modes a block cipher offers, ascending. */
function nonceLengthsFor(modes: readonly AesModeMeta[], blockSize: number): number[] {
  const lengths = new Set<number>();
  for (const mode of modes) {
    if (mode.nonceLen === 0) continue;
    if (mode.nonceLens) for (const n of mode.nonceLens) lengths.add(n);
    else lengths.add(mode.aead ? mode.nonceLen : blockSize);
  }
  return [...lengths].sort((a, b) => a - b);
}

function nonceSummaryFor(modes: readonly AesModeMeta[], blockSize: number): string {
  const parts = [`${blockSize} bytes for the chaining modes`];
  if (modes.some((m) => m.id === "gcm")) parts.push("12 for GCM");
  if (modes.some((m) => m.id === "ccm")) parts.push("7 to 13 for CCM");
  return `${parts.join(", ")}.`;
}

const CACHE = new Map<string, OptionCatalogue<CipherOptionGroup>>();

export function cipherCatalogueFor(toolId: string): OptionCatalogue<CipherOptionGroup> {
  let catalogue = CACHE.get(toolId);
  if (!catalogue) {
    const tool = requireCipherTool(toolId);
    /**
     * One arm per tool, and no default.
     *
     * The chain this replaced ended in `: RC4_OPTIONS`, which meant a tool added to `CIPHER_TOOLS`
     * without an entry here silently inherited RC4's catalogue -- a 1-to-256-byte key and a "Drop
     * bytes" control. That is exactly what happened when the Salsa tools were added, and no test
     * noticed, because the tests passed keys of a valid length. A `Record` with a lookup that throws
     * turns the same mistake into an immediate, named failure.
     */
    const byTool: Record<string, readonly OptionDef<CipherOptionGroup>[]> = {
      aes: AES_OPTIONS,
      chacha20poly1305: CHACHA_POLY_OPTIONS,
      xchacha20poly1305: XCHACHA_POLY_OPTIONS,
      chacha20: chachaRawOptions(12, "per RFC 8439"),
      chacha12: chachaRawOptions(12, "the RFC 8439 layout with twelve rounds"),
      chacha8: chachaRawOptions(12, "the RFC 8439 layout with eight rounds"),
      chacha20orig: chachaRawOptions(8, "the original layout, with a 64-bit counter"),
      ascon: ASCON_OPTIONS,
      aegis128l: aegisOptions(16, 16),
      aegis256: aegisOptions(32, 32),
      rc4: RC4_OPTIONS,
      xsalsa20poly1305: salsaOptions(
        24,
        "192 bits, which is what the X in the name buys: wide enough to pick at random for every message without tracking what has been used. libsodium generates one per `secretbox` call for exactly that reason.",
      ),
      xsalsa20: salsaOptions(
        24,
        "192 bits. With no authentication on top, a repeat reveals the XOR of the two plaintexts and nothing detects a modified ciphertext.",
      ),
      salsa20: salsaOptions(
        8,
        "64 bits, the original width. Small enough that random choice risks a collision, so Salsa20 expects a counter rather than a random nonce — which is precisely the problem XSalsa20 was introduced to remove.",
      ),
      fernet: FERNET_OPTIONS,
      cobblestone: COBBLESTONE_OPTIONS,
    };

    const options =
      byTool[toolId] ??
      (tool.block
        ? blockCipherOptions(tool)
        : tool.shape
          ? shapedCipherOptions(tool)
          : (() => {
              throw new Error(
                `No option catalogue for cipher tool "${toolId}". Add one to byTool, or give the tool a \`block\` or \`shape\` description.`,
              );
            })());
    /*
     * Key derivation, added to every tool at the one place they all pass through.
     *
     * Spliced here rather than into each of the fifteen hand-written option lists and two builders,
     * so no tool can be the one that misses it -- and so a tool added later gets it without anyone
     * remembering. Every control is gated on a key source, so a tool left on Custom renders exactly
     * what it rendered before and `visibleOptionGroups` keeps the Key derivation heading off screen.
     *
     * `keySourceOptions` comes from `@ocs/kdf/key-source`, which is where the six derivations live:
     * there is one PBKDF2 in this repo, not two, and the KDF family's own prose is reused rather than
     * retyped. That module deliberately excludes `bcryptjs`, so nothing here drags a password-hashing
     * library into the cipher chunk.
     */
    const withDerivation = [
      ...options,
      ...keySourceOptions<CipherOptionGroup>({
        // The select sits in the rail with Mode and Key size -- the three choices that decide which
        // function runs. The password and salt stay in the Input panel, where the Key field was.
        select: "algorithm",
        input: "key",
        settings: "derivation",
      }),
    ];
    catalogue = createOptionCatalogue<CipherOptionGroup>(withDerivation);
    CACHE.set(toolId, catalogue);
  }
  return catalogue;
}
