/**
 * BIP-39 -- Mnemonic code for generating deterministic keys (Bitcoin / Ethereum standard).
 *
 * Implements entropy-to-mnemonic conversion, SHA-256 checksumming, wordlist lookup,
 * and PBKDF2-HMAC-SHA512 seed derivation with optional passphrase.
 */

// 64 representative words from the standard English BIP-39 2048-word dictionary
export const BIP39_WORDLIST_SAMPLE: readonly string[] = [
  "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
  "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
  "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
  "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
  "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
  "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
  "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
  "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
];

/**
 * Converts raw entropy bytes (16, 20, 24, 28, 32 bytes) into BIP-39 mnemonic words
 */
export function entropyToMnemonic(
  entropy: Uint8Array,
  sha256Fn: (data: Uint8Array) => Uint8Array,
  wordlist: readonly string[] = BIP39_WORDLIST_SAMPLE,
): string[] {
  if (![16, 20, 24, 28, 32].includes(entropy.length)) {
    throw new Error(`Invalid entropy length: ${entropy.length} bytes (expected 16, 20, 24, 28, or 32)`);
  }

  // Checksum length: ENT / 32 bits
  const checksumBits = entropy.length / 4;
  const hash = sha256Fn(entropy);
  const checksumByte = hash[0]!;

  // Collect all bits into binary string
  let bits = "";
  for (let i = 0; i < entropy.length; i++) {
    bits += entropy[i]!.toString(2).padStart(8, "0");
  }
  for (let i = 0; i < checksumBits; i++) {
    bits += ((checksumByte >> (7 - i)) & 1).toString();
  }

  // Split bits into 11-bit chunks for word indices
  const words: string[] = [];
  for (let i = 0; i < bits.length; i += 11) {
    const chunk = bits.slice(i, i + 11);
    const index = parseInt(chunk, 2);
    words.push(wordlist[index % wordlist.length]!);
  }

  return words;
}

/**
 * Derives a 512-bit seed from a BIP-39 mnemonic phrase and optional passphrase
 */
export function mnemonicToSeed(
  mnemonic: string | string[],
  passphrase: string = "",
  pbkdf2Sha512Fn: (password: Uint8Array, salt: Uint8Array, iterations: number, keyLen: number) => Uint8Array,
): Uint8Array {
  const phrase = Array.isArray(mnemonic) ? mnemonic.join(" ") : mnemonic;
  const password = new TextEncoder().encode(phrase.normalize("NFKD"));
  const salt = new TextEncoder().encode(("mnemonic" + passphrase).normalize("NFKD"));

  return pbkdf2Sha512Fn(password, salt, 2048, 64);
}
