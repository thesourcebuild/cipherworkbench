import { describe, expect, it } from "vitest";
import {
  albertiCipher,
  gronsfeldCipher,
  jeffersonCipher,
  portaCipher,
} from "@ocs/algos";

describe("Jefferson / M-94 Cylinder Cipher", () => {
  it("performs reversible encryption and decryption", () => {
    const plaintext = "DEFEND THE EAST WALL AT DAWN";
    const encrypted = jeffersonCipher(plaintext, { offset: 5, mode: "encrypt" });
    expect(encrypted).not.toBe(plaintext);

    const decrypted = jeffersonCipher(encrypted, { offset: 5, mode: "decrypt" });
    expect(decrypted).toBe(plaintext);
  });

  it("supports custom disk permutations", () => {
    const plaintext = "HELLO WORLD";
    const customOrder = [5, 12, 1, 9, 24, 3, 17, 2, 8, 14, 20];
    const encrypted = jeffersonCipher(plaintext, { diskOrder: customOrder, offset: 3, mode: "encrypt" });
    const decrypted = jeffersonCipher(encrypted, { diskOrder: customOrder, offset: 3, mode: "decrypt" });
    expect(decrypted).toBe(plaintext);
  });

  it("preserves lowercase and non-alphabet characters", () => {
    const input = "Secret 123! Message.";
    const encrypted = jeffersonCipher(input, { offset: 7, mode: "encrypt" });
    expect(encrypted).toContain("123!");
    const decrypted = jeffersonCipher(encrypted, { offset: 7, mode: "decrypt" });
    expect(decrypted).toBe(input);
  });
});

describe("Alberti Cipher Disk", () => {
  it("encrypts and decrypts with static key alignment", () => {
    const plaintext = "ATTACCA";
    const encrypted = albertiCipher(plaintext, { indexLetter: "A", period: 0, mode: "encrypt" });
    expect(encrypted).toBeTruthy();

    const decrypted = albertiCipher(encrypted, { indexLetter: "A", period: 0, mode: "decrypt" });
    expect(decrypted).toBe(plaintext);
  });

  it("encrypts and decrypts with stepping period", () => {
    const plaintext = "CONCORDIA RES PARVAE CRESCUNT";
    const encrypted = albertiCipher(plaintext, { indexLetter: "M", period: 4, mode: "encrypt" });
    const decrypted = albertiCipher(encrypted, { indexLetter: "M", period: 4, mode: "decrypt" });
    expect(decrypted).toBe(plaintext);
  });
});

describe("Porta Cipher", () => {
  it("exhibits exact reciprocal property (encrypt == decrypt)", () => {
    const plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG";
    const key = "FORTIFICATION";

    const ciphertext = portaCipher(plaintext, { key });
    expect(ciphertext).not.toBe(plaintext);

    const recovered = portaCipher(ciphertext, { key });
    expect(recovered).toBe(plaintext);
  });

  it("substitutes within complementary half-alphabets", () => {
    // Key A: A-M shifts 0 -> maps to N-Z (A->N, B->O, etc.)
    expect(portaCipher("A", { key: "A" })).toBe("N");
    expect(portaCipher("B", { key: "A" })).toBe("O");
    expect(portaCipher("N", { key: "A" })).toBe("A");
    expect(portaCipher("O", { key: "A" })).toBe("B");

    // Key B is identical to Key A in Porta
    expect(portaCipher("A", { key: "B" })).toBe("N");
  });
});

describe("Gronsfeld Cipher", () => {
  it("encrypts with a numeric key", () => {
    // Plaintext: "GRONSFELD"
    // Key: "2015"
    // G (6) + 2 = I (8)
    // R (17) + 0 = R (17)
    // O (14) + 1 = P (15)
    // N (13) + 5 = S (18)
    // S (18) + 2 = U (20)
    // F (5) + 0 = F (5)
    // E (4) + 1 = F (5)
    // L (11) + 5 = Q (16)
    // D (3) + 2 = F (5)
    const plaintext = "GRONSFELD";
    const encrypted = gronsfeldCipher(plaintext, { key: "2015", mode: "encrypt" });
    expect(encrypted).toBe("IRPSUFFQF");

    const decrypted = gronsfeldCipher(encrypted, { key: "2015", mode: "decrypt" });
    expect(decrypted).toBe(plaintext);
  });

  it("handles mixed case and punctuation", () => {
    const input = "Excellence in 2026!";
    const encrypted = gronsfeldCipher(input, { key: "1234", mode: "encrypt" });
    const decrypted = gronsfeldCipher(encrypted, { key: "1234", mode: "decrypt" });
    expect(decrypted).toBe(input);
  });
});
