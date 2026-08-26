/**
 * Anubis and SAFER+ vectors, extracted by script from LibTomCrypt's own self-tests.
 *
 * **Why LibTomCrypt.** These two were the last algorithms on this repo's blocked list, and the block was
 * a source problem: Anubis's NESSIE file is not mirrored where Khazad's is, and SAFER+'s original AES
 * submission pages are gone. Bouncy Castle has neither, Crypto++ has SAFER-K and SAFER-SK but not
 * SAFER+ (an eight-byte block, so not the same cipher), Botan has neither, and FELICS has neither.
 * LibTomCrypt has both, each with a built-in self-test carrying published values -- and it is the first
 * time that library has been used here, so it belongs in the source map.
 *
 * | Set | Source | Count |
 * |---|---|---|
 * | `ANUBIS_VECTORS.original` | `src/ciphers/anubis.c`, the `#ifndef LTC_ANUBIS_TWEAK` block | 14 |
 * | `ANUBIS_VECTORS.tweaked` | the same file's `#else` block | 14 |
 * | `SAFERP_VECTORS` | `src/ciphers/safer/saferp.c` | 3 |
 *
 * **The two Anubis blocks are in the opposite order from the two table blocks**, and getting that
 * backwards is the trap: the tables are guarded `#if defined(LTC_ANUBIS_TWEAK)` and the tests
 * `#ifndef`, so the first *test* block pairs with the second *table* block. Reading them in file order
 * gives two ciphers each reproducing the other's vectors exactly -- which looks like two bugs and is
 * one label error.
 *
 * Anubis's fourteen are two per key length across all seven lengths, which is what makes them worth
 * more than their count: the round number is `8 + keylen/4`, so every one of the seven exercises a
 * different number of rounds and a different key-schedule length.
 */

export interface BlockVector {
  readonly key: string;
  readonly plaintext: string;
  readonly ciphertext: string;
}

/** Keyed by variant, because the tweak replaced the S-box and both are published. */
export const ANUBIS_VECTORS: Readonly<Record<"original" | "tweaked", readonly BlockVector[]>> = {
  original: [
  { key: "80000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "f06860fc6730e818f132c78af4132afe" },
  { key: "00000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "a866848007745c89fc5eb5bad4fe326d" },
  { key: "8000000000000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "bd5e32be5167a8e272d7950f83c68c31" },
  { key: "0000000000000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "4c1f862e11ebceebfeb973c9dfef7adb" },
  { key: "800000000000000000000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "17ac57449d596166d0c79e047cc758f0" },
  { key: "000000000000000000000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "7152b4eb1daa36fd57145f57049f7074" },
  { key: "80000000000000000000000000000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "a2f0a6b917932a3bef08e87a58d6f853" },
  { key: "00000000000000000000000000000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "f0cafc788b4b4e538bc4326af5b91b5f" },
  { key: "8000000000000000000000000000000000000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "e086ac456b3ce513edf5dfddd63b7193" },
  { key: "0000000000000000000000000000000000000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "5001b9f521c1c12900d5ec982b9ee821" },
  { key: "800000000000000000000000000000000000000000000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "e8f4af2b21a0879b4195b9717579047c" },
  { key: "000000000000000000000000000000000000000000000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "e6a6a5bc8b636fe2bda7a753ab4022e0" },
  { key: "80000000000000000000000000000000000000000000000000000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "1704d72cc68576024bcc3980d822eaa4" },
  { key: "00000000000000000000000000000000000000000000000000000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "7a41e67d4fd864f044a83c73817e53d8" },
  ],
  tweaked: [
  { key: "80000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "b835bdc334829d8371bfa371e4b3c4fd" },
  { key: "00000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "e6141eafebe0593c48e1cdf21bbaa189" },
  { key: "8000000000000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "9759794b5ca0707324efb35867cad4b3" },
  { key: "0000000000000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "b80dfb9be4a15887b376d5021895c12e" },
  { key: "800000000000000000000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "7d623b52c74c64d8ebc72d579785438f" },
  { key: "000000000000000000000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "b10a59dd5d5d8d67ecee4ac4be4fa84f" },
  { key: "80000000000000000000000000000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "689e05946a94438fe78e373d249792f5" },
  { key: "00000000000000000000000000000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "ddb7b0b4e9b49b9c3820250b47c21f89" },
  { key: "8000000000000000000000000000000000000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "9600f07691692987f5e597dbdbaf1b0a" },
  { key: "0000000000000000000000000000000000000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "699cafdd94c7bc6044fe02058a6eefbd" },
  { key: "800000000000000000000000000000000000000000000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "0fc7a2c01117ac43525edf6cf396336c" },
  { key: "000000000000000000000000000000000000000000000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "ad084fed55a6943e7e5eed05a19d41b4" },
  { key: "80000000000000000000000000000000000000000000000000000000000000000000000000000000", plaintext: "00000000000000000000000000000000", ciphertext: "fee20e2a9dc583baa3a6d6a6f2e806a5" },
  { key: "00000000000000000000000000000000000000000000000000000000000000000000000000000001", plaintext: "00000000000000000000000000000000", ciphertext: "863dcc4a60349c28a7daa43b0ad7fdc7" },
  ],
};

/** One per key length: 16, 24 and 32 bytes, which is 8, 12 and 16 rounds. */
export const SAFERP_VECTORS: readonly BlockVector[] = [
  { key: "2923be84e16cd6ae529049f1f1bbe9eb", plaintext: "b3a6db3c870c3e99245e0d1c06b747de", ciphertext: "e01fb60a0cff54467f0d59f90939a5dc" },
  { key: "48d38f75e6d91d2ae5c0f72b788187440e5f5000d4618dbe", plaintext: "7b0515073b33821f187092da6454ceb1", ciphertext: "5c88043f395f640096828210c16fdb85" },
  { key: "f3a88dfebef2eb71ffa0d03b75068c7e8778734dd0be82bedbc246412b8cfa30", plaintext: "7f70f0a754863295aa5b68130be6fcf5", ciphertext: "580b1924ace5cad5aa416999dc68998a" },
];

/**
 * LibTomCrypt's literal first bias row, for the derivation check.
 *
 * `saferp.ts` computes all 512 bias bytes from two exponentiation rules; this is what says the rules
 * are the right ones rather than merely self-consistent.
 */
export const SAFERP_BIAS_ROW_0: readonly number[] = [70, 151, 177, 186, 163, 183, 16, 10, 197, 55, 179, 201, 90, 40, 172, 100];
