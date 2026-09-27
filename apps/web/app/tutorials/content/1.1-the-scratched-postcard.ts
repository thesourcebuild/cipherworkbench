import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "Think of the last digit on your credit card or an ISBN book barcode. It is not part of your account number; it is a calculated 'check digit'. If you type 4532... and accidentally type one number wrong, the check digit math immediately flags the typo before submitting the form.",
  "problem": "What is the simplest, lowest-overhead way to detect human input mistakes without doing complex cryptography?",
  "steps": [
    {
      "title": "Step 1: Alice enters an account number",
      "speaker": "Alice",
      "content": "Alice provides a 15-digit payload: `453201511283036`. The Luhn algorithm doubles every second digit and sums the digits mod 10 to compute the check digit: `4`. The full number is `4532015112830364`."
    },
    {
      "title": "Step 2: A typo happens during entry",
      "speaker": "Bob",
      "content": "A clerk mistypes the number as `4532015112830634` (accidentally swapping the adjacent `36` to `63`)."
    },
    {
      "title": "Step 3: The Check Digit flags the error",
      "speaker": "Bob",
      "content": "Bob runs the Luhn algorithm in Cipher Workbench. The calculated check digit is completely invalid! The system rejects the entry immediately, saving Bob from charging the wrong customer.",
      "callout": {
        "type": "info",
        "text": "Hans Peter Luhn invented this algorithm at IBM in 1954. It is used on every credit card (Visa, Mastercard, Amex) and IMEI phone identifier in the world today."
      }
    }
  ],
  "takeaways": [
    "Checksums are designed to catch human typos and accidental digit transpositions.",
    "They require virtually zero CPU overhead and fit in a single digit.",
    "Checksums offer zero security against malicious tampering: anyone can easily fabricate a valid check digit."
  ],
  "seed": {
    "toolId": "luhn",
    "sampleInput": "453201511283036",
    "explanation": "Open Luhn Checksum in Cipher Workbench to test check digit generation and validation live."
  }
};

export default content;
