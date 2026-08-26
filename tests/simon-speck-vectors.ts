/**
 * The twenty Simon and Speck test vectors from the designers' paper, plus the ten from the NSA's
 * implementation guide.
 *
 * Two sources for the same ciphers, and they print their words in opposite orders: the paper uses
 * big-endian words most significant first, while the guide's `BytesToWords` reads the whole byte
 * string little-endian -- so the guide's values are the paper's reversed end to end. Both are kept
 * because the overlap is a second independent check on the ten variants the guide covers, and
 * because the disagreement is exactly the kind of thing that looks like a bug in an implementation.
 *
 * Extracted by script from the two PDFs (eprint 2013/404 appendices B and C, and
 * ImplementationGuide1.1 sections 9 to 18), with every length checked against the variant it claims.
 */
export interface SimonSpeckVector {
  readonly family: "simon" | "speck";
  readonly blockBits: number;
  readonly keyBits: number;
  readonly key: string;
  readonly plaintext: string;
  readonly ciphertext: string;
}

/** Appendices B and C of the paper. Big-endian words, most significant first. */
export const SIMON_SPECK_PAPER_VECTORS: readonly SimonSpeckVector[] = [
  { family: "simon", blockBits: 32, keyBits: 64, key: "1918111009080100", plaintext: "65656877", ciphertext: "c69be9bb" },
  { family: "simon", blockBits: 48, keyBits: 72, key: "1211100a0908020100", plaintext: "6120676e696c", ciphertext: "dae5ac292cac" },
  { family: "simon", blockBits: 48, keyBits: 96, key: "1a19181211100a0908020100", plaintext: "72696320646e", ciphertext: "6e06a5acf156" },
  { family: "simon", blockBits: 64, keyBits: 96, key: "131211100b0a090803020100", plaintext: "6f7220676e696c63", ciphertext: "5ca2e27f111a8fc8" },
  { family: "simon", blockBits: 64, keyBits: 128, key: "1b1a1918131211100b0a090803020100", plaintext: "656b696c20646e75", ciphertext: "44c8fc20b9dfa07a" },
  { family: "simon", blockBits: 96, keyBits: 96, key: "0d0c0b0a0908050403020100", plaintext: "2072616c6c69702065687420", ciphertext: "602807a462b469063d8ff082" },
  { family: "simon", blockBits: 96, keyBits: 144, key: "1514131211100d0c0b0a0908050403020100", plaintext: "74616874207473756420666f", ciphertext: "ecad1c6c451e3f59c5db1ae9" },
  { family: "simon", blockBits: 128, keyBits: 128, key: "0f0e0d0c0b0a09080706050403020100", plaintext: "63736564207372656c6c657661727420", ciphertext: "49681b1e1e54fe3f65aa832af84e0bbc" },
  { family: "simon", blockBits: 128, keyBits: 192, key: "17161514131211100f0e0d0c0b0a09080706050403020100", plaintext: "206572656874206e6568772065626972", ciphertext: "c4ac61effcdc0d4f6c9c8d6e2597b85b" },
  { family: "simon", blockBits: 128, keyBits: 256, key: "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", plaintext: "74206e69206d6f6f6d69732061207369", ciphertext: "8d2b5579afc8a3a03bf72a87efe7b868" },
  { family: "speck", blockBits: 32, keyBits: 64, key: "1918111009080100", plaintext: "6574694c", ciphertext: "a86842f2" },
  { family: "speck", blockBits: 48, keyBits: 72, key: "1211100a0908020100", plaintext: "20796c6c6172", ciphertext: "c049a5385adc" },
  { family: "speck", blockBits: 48, keyBits: 96, key: "1a19181211100a0908020100", plaintext: "6d2073696874", ciphertext: "735e10b6445d" },
  { family: "speck", blockBits: 64, keyBits: 96, key: "131211100b0a090803020100", plaintext: "74614620736e6165", ciphertext: "9f7952ec4175946c" },
  { family: "speck", blockBits: 64, keyBits: 128, key: "1b1a1918131211100b0a090803020100", plaintext: "3b7265747475432d", ciphertext: "8c6fa548454e028b" },
  { family: "speck", blockBits: 96, keyBits: 96, key: "0d0c0b0a0908050403020100", plaintext: "65776f68202c656761737520", ciphertext: "9e4d09ab717862bdde8f79aa" },
  { family: "speck", blockBits: 96, keyBits: 144, key: "1514131211100d0c0b0a0908050403020100", plaintext: "656d6974206e69202c726576", ciphertext: "2bf31072228a7ae440252ee6" },
  { family: "speck", blockBits: 128, keyBits: 128, key: "0f0e0d0c0b0a09080706050403020100", plaintext: "6c617669757165207469206564616d20", ciphertext: "a65d9851797832657860fedf5c570d18" },
  { family: "speck", blockBits: 128, keyBits: 192, key: "17161514131211100f0e0d0c0b0a09080706050403020100", plaintext: "726148206665696843206f7420746e65", ciphertext: "1be4cf3a13135566f9bc185de03c1886" },
  { family: "speck", blockBits: 128, keyBits: 256, key: "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", plaintext: "65736f6874206e49202e72656e6f6f70", ciphertext: "4109010405c0f53e4eeeb48d9c188f43" },
];

/**
 * Sections 9 to 18 of the implementation guide. The same ten variants, byte-reversed.
 *
 * The guide covers only the 64- and 128-bit block sizes, which is what its own README says.
 */
export const SIMON_SPECK_GUIDE_VECTORS: readonly SimonSpeckVector[] = [
  { family: "simon", blockBits: 64, keyBits: 96, key: "0001020308090a0b10111213", plaintext: "636c696e6720726f", ciphertext: "c88f1a117fe2a25c" },
  { family: "simon", blockBits: 64, keyBits: 128, key: "0001020308090a0b1011121318191a1b", plaintext: "756e64206c696b65", ciphertext: "7aa0dfb920fcc844" },
  { family: "simon", blockBits: 128, keyBits: 128, key: "000102030405060708090a0b0c0d0e0f", plaintext: "2074726176656c6c6572732064657363", ciphertext: "bc0b4ef82a83aa653ffe541e1e1b6849" },
  { family: "simon", blockBits: 128, keyBits: 192, key: "000102030405060708090a0b0c0d0e0f1011121314151617", plaintext: "72696265207768656e20746865726520", ciphertext: "5bb897256e8d9c6c4f0ddcfcef61acc4" },
  { family: "simon", blockBits: 128, keyBits: 256, key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", plaintext: "697320612073696d6f6f6d20696e2074", ciphertext: "68b8e7ef872af73ba0a3c8af79552b8d" },
  { family: "speck", blockBits: 64, keyBits: 96, key: "0001020308090a0b10111213", plaintext: "65616e7320466174", ciphertext: "6c947541ec52799f" },
  { family: "speck", blockBits: 64, keyBits: 128, key: "0001020308090a0b1011121318191a1b", plaintext: "2d4375747465723b", ciphertext: "8b024e4548a56f8c" },
  { family: "speck", blockBits: 128, keyBits: 128, key: "000102030405060708090a0b0c0d0e0f", plaintext: "206d616465206974206571756976616c", ciphertext: "180d575cdffe60786532787951985da6" },
  { family: "speck", blockBits: 128, keyBits: 192, key: "000102030405060708090a0b0c0d0e0f1011121314151617", plaintext: "656e7420746f20436869656620486172", ciphertext: "86183ce05d18bcf9665513133acfe41b" },
  { family: "speck", blockBits: 128, keyBits: 256, key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", plaintext: "706f6f6e65722e20496e2074686f7365", ciphertext: "438f189c8db4ee4e3ef5c00504010941" },
];
