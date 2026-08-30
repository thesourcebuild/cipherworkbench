/**
 * Solitaire (Pontifex) Playing Card Stream Cipher.
 * Designed by Bruce Schneier for Neal Stephenson's novel "Cryptonomicon".
 *
 * State: 54-card deck represented as numbers 1..54:
 * - Clubs: 1..13
 * - Diamonds: 14..26
 * - Hearts: 27..39
 * - Spades: 40..52
 * - Joker A: 53
 * - Joker B: 53 (or 54 during tracking)
 */

export interface SolitaireOptions {
  passphrase?: string;
  direction?: "encrypt" | "decrypt";
}

export class SolitaireDeck {
  private cards: number[];

  constructor(passphrase?: string) {
    // Initial standard ordered deck: 1..54
    this.cards = Array.from({ length: 54 }, (_, i) => i + 1);
    if (passphrase) {
      this.keyDeck(passphrase);
    }
  }

  /**
   * Keys the deck using a passphrase.
   */
  public keyDeck(passphrase: string): void {
    const clean = passphrase.toUpperCase().replace(/[^A-Z]/g, "");
    for (let i = 0; i < clean.length; i++) {
      this.step();
      const n = clean.charCodeAt(i) - 64; // A=1, B=2...
      this.countCut(n);
    }
  }

  /**
   * Step 1: Move Joker A (card 53) down 1 position (if at bottom, wrap below card 1).
   */
  private stepJokerA(): void {
    const idx = this.cards.indexOf(53);
    if (idx === 53) {
      // Bottom card: moves under first card
      this.cards.splice(idx, 1);
      this.cards.splice(1, 0, 53);
    } else {
      this.cards.splice(idx, 1);
      this.cards.splice(idx + 1, 0, 53);
    }
  }

  /**
   * Step 2: Move Joker B (card 54) down 2 positions.
   */
  private stepJokerB(): void {
    const idx = this.cards.indexOf(54);
    if (idx === 53) {
      // At bottom -> moves below card 2
      this.cards.splice(idx, 1);
      this.cards.splice(2, 0, 54);
    } else if (idx === 52) {
      // Second from bottom -> moves below card 1
      this.cards.splice(idx, 1);
      this.cards.splice(1, 0, 54);
    } else {
      this.cards.splice(idx, 1);
      this.cards.splice(idx + 2, 0, 54);
    }
  }

  /**
   * Step 3: Triple Cut.
   * Swap the cards above the first joker with the cards below the second joker.
   */
  private tripleCut(): void {
    const idxA = this.cards.indexOf(53);
    const idxB = this.cards.indexOf(54);
    const first = Math.min(idxA, idxB);
    const second = Math.max(idxA, idxB);

    const top = this.cards.slice(0, first);
    const mid = this.cards.slice(first, second + 1);
    const bot = this.cards.slice(second + 1);

    this.cards = [...bot, ...mid, ...top];
  }

  /**
   * Step 4: Count Cut using value n (or the bottom card's value).
   */
  private countCut(countVal?: number): void {
    const bottomCard = this.cards[53]!;
    const val = countVal ?? (bottomCard >= 53 ? 53 : bottomCard);
    if (val === 53) return; // No change if bottom card is a joker

    const topCut = this.cards.slice(0, val);
    const remaining = this.cards.slice(val, 53);
    this.cards = [...remaining, ...topCut, bottomCard];
  }

  /**
   * Perform one complete round of shuffling (Steps 1-4).
   */
  public step(): void {
    this.stepJokerA();
    this.stepJokerB();
    this.tripleCut();
    this.countCut();
  }

  /**
   * Get the next output keystream character (1..26 -> A..Z), skipping jokers.
   */
  public nextKey(): number {
    while (true) {
      this.step();
      const topCard = this.cards[0]!;
      const val = topCard >= 53 ? 53 : topCard;
      const outputCard = this.cards[val]!;

      if (outputCard >= 53) {
        // Output card is a joker -> discard and repeat
        continue;
      }

      // Convert card value (1..52) to letter value (1..26)
      return (outputCard > 26 ? outputCard - 26 : outputCard);
    }
  }
}

export function solitaireEncrypt(text: string, options: SolitaireOptions = {}): string {
  const deck = new SolitaireDeck(options.passphrase);
  let result = "";

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const upper = ch.toUpperCase();
    const p = upper.charCodeAt(0) - 65;
    if (p < 0 || p >= 26) {
      result += ch;
      continue;
    }

    const k = deck.nextKey();
    const c = (p + k) % 26;
    const outChar = String.fromCharCode(65 + c);
    result += ch === ch.toLowerCase() ? outChar.toLowerCase() : outChar;
  }

  return result;
}

export function solitaireDecrypt(text: string, options: SolitaireOptions = {}): string {
  const deck = new SolitaireDeck(options.passphrase);
  let result = "";

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const upper = ch.toUpperCase();
    const c = upper.charCodeAt(0) - 65;
    if (c < 0 || c >= 26) {
      result += ch;
      continue;
    }

    const k = deck.nextKey();
    const p = (c - k + 26) % 26;
    const outChar = String.fromCharCode(65 + p);
    result += ch === ch.toLowerCase() ? outChar.toLowerCase() : outChar;
  }

  return result;
}
