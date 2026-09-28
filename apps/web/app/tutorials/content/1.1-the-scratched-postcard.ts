import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "Imagine sending a postcard with a ledger of account numbers or prices. If the postcard gets scratched or rained on during delivery, a digit might become unreadable. To let the recipient verify the numbers without having to call you back, you compute a **checksum**—a tiny verification number written at the bottom of the card.\n\nIn computing, basic checksums add up all bytes or words and keep the remainder (like an 8-bit sum, XOR parity, or the Internet Checksum in IPv4 headers). In consumer forms, barcodes, and credit cards, this idea is refined into a **check digit**—a single appended digit calculated using alternating weights specifically to catch common human typing mistakes.",
  "problem": "How do simple additive checksums detect corrupted data, why do they fail completely when a human accidentally swaps two adjacent numbers, and how do weighted check digits solve this?",
  "steps": [
    {
      "title": "Step 1: Alice computes a simple additive checksum",
      "speaker": "Alice",
      "content": "Alice prepares a 4-value data record: `[35, 60, 15, 80]`. She computes an 8-bit additive sum check: `35 + 60 + 15 + 80 = 190` (`0xBE`). She writes `190` as the checksum at the bottom of the card. If weather smudges the `60` into an `80`, Bob calculates `35 + 80 + 15 + 80 = 210` (`0xD2`). The sum mismatch instantly flags that the record was corrupted in transit!",
      "callout": {
        "type": "info",
        "text": "Simple checksums—like adding bytes together modulo 256, XORing blocks (LRC / BCC / NMEA 0183 GPS), or one's complement 16-bit sums (IPv4 / TCP / UDP header checksums in RFC 1071)—are fast."
      }
    },
    {
      "title": "Step 2: The transposition trap: why simple sums fail",
      "speaker": "Bob",
      "content": "Bob notices a critical weakness in simple addition and XOR checks: arithmetic addition is commutative (`A + B = B + A`). If a clerk enters Alice's records but accidentally transposes two numbers—typing `[60, 35, 15, 80]` instead of `[35, 60, 15, 80]`—the sum is still exactly `190`! The same happens if an accidental typo increases one digit by 1 and decreases another by 1 (compensating errors). Over 70% of human transcription errors are adjacent digit swaps, yet simple checksums are completely blind to them.",
      "callout": {
        "type": "warning",
        "text": "Because addition and XOR are order-independent, simple checksums cannot detect swapped bytes or transposition errors. To catch human mistakes, the position of each digit must change its mathematical weight."
      }
    },
    {
      "title": "Step 3: Alice uses a position-weighted check digit: The Luhn Algorithm",
      "speaker": "Alice",
      "content": "To catch human swaps on account numbers without heavy math, Alice uses a weighted check digit. She takes a 15-digit card number payload: `453201511283036`. The Luhn algorithm (Mod 10) processes digits from right to left, multiplying every second digit by 2 (and adding the digits of products ≥ 10). Because alternating positions have different weights (1 and 2), adjacent numbers no longer produce the same sum when swapped! Alice adds the computed check digit `6` to the end, forming the valid 16-digit card number: `4532015112830366`."
    },
    {
      "title": "Step 4: Bob catches the swapped digits instantly",
      "speaker": "Bob",
      "content": "A checkout clerk mistypes Alice's card number as `4532015112830636` (accidentally transposing the adjacent `36` to `63`). Bob validates the entry using the Luhn algorithm in Cipher Workbench. Because `3` and `6` alternate between doubled and single weight, the total sum shifts from 50 (valid multiple of 10) to 56 (invalid!). The system rejects the typo in the browser before ever sending an invalid request across the payment network.",
      "callout": {
        "type": "info",
        "text": "Hans Peter Luhn patented this algorithm at IBM in 1954. Today, ISO/IEC 7812 mandates Luhn for all Visa, Mastercard, and American Express cards, and the GSMA uses it for every cellular IMEI number in the world."
      }
    }
  ],
  "takeaways": [
    "Simple checksums (additive sums, XOR, one's complement) sum data bytes to detect dropped bytes or transmission noise with near-zero overhead.",
    "Additive checksums are order-independent (commutative), making them incapable of catching transposition errors (swapped digits like 36 ↔ 63) or compensating errors.",
    "Check digits (such as Luhn, ISBN-10, and Verhoeff) apply position-dependent weights to catch 100% of single-digit typos and adjacent transpositions.",
    "Neither checksums nor check digits are cryptographic: they protect against accidental noise and human slip-ups, not deliberate tampering."
  ],
  "seed": {
    "toolId": "luhn",
    "sampleInput": "453201511283036",
    "explanation": "Open Luhn / Mod 10 in Cipher Workbench to test check digit generation, validation, and transposition detection live."
  }
};

export default content;
