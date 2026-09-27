import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  "analogy": "Imagine writing a letter and writing a summary of the letters on the envelope. If a postal worker replaces the entire letter with a fake one and also replaces the summary on the envelope, the recipient has no way to know who wrote either one.",
  "problem": "A cryptographic hash proves the message was not modified in transit, but it proves NOTHING about who created it! How do we tie a message to a specific author?",
  "steps": [
    {
      "title": "Step 1: Alice's false sense of security",
      "speaker": "Alice",
      "content": "Alice sends message: *\"Pay Bob $50\"* along with `Hash(\"Pay Bob $50\")`. She assumes that because SHA-256 is unbreakable, her message is safe."
    },
    {
      "title": "Step 2: Mallory replaces Message AND Hash",
      "speaker": "Mallory",
      "content": "Mallory intercepts the wire. She changes the message to *\"Pay Mallory $50\"*. Then, Mallory runs SHA-256 herself on her fake message and replaces Alice's hash with `Hash(\"Pay Mallory $50\")`!"
    },
    {
      "title": "Step 3: Bob is deceived",
      "speaker": "Bob",
      "content": "Bob receives the fake message and Mallory's new hash. Bob computes the hash of the text. It matches perfectly! Bob approves the payout to Mallory. Bob learned the hard way that **Integrity without Authenticity is an illusion**.",
      "callout": {
        "type": "warning",
        "text": "A hash function takes no key. Anyone with a keyboard can compute SHA-256. To prove authenticity, we must combine the message with a secret known only to Alice and Bob."
      }
    }
  ],
  "takeaways": [
    "Hashes guarantee integrity (the data didn't change), NOT authenticity (who sent it).",
    "An attacker who can modify messages in transit can also recalculate the public hash.",
    "Authenticity requires a secret cryptographic key."
  ],
  "seed": {
    "toolId": "sha256",
    "sampleInput": "Pay Mallory $50",
    "explanation": "Open SHA-256 Workbench and see how Mallory can easily generate a clean, valid hash for any modified text."
  }
};

export default content;
