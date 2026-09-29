import type { TutorialContent } from "../tutorial-types";

const content: TutorialContent = {
  analogy:
    "Mallory cannot pick the lock — but she does not need to. She knocks on the door, and the person inside shouts 'Wrong key!' or 'The key fits but the door is jammed!' Two different error messages. By knocking thousands of times with subtly different keys, she uses those responses as an oracle that reveals the secret, one bit at a time.",
  problem:
    "AES-CBC with PKCS#7 padding is the encryption used in TLS 1.0, XML encryption, and countless older APIs. Why did a single different error message allow Mallory to decrypt any ciphertext without knowing the key?",
  steps: [
    {
      title: "Step 1: PKCS#7 Padding — Why It Exists",
      speaker: "Alice",
      content:
        "AES-CBC operates on 16-byte blocks. If a message is not an exact multiple of 16 bytes, it must be padded. **PKCS#7** fills the remaining bytes with a byte whose value equals the padding length:\n\n- 1 byte missing → append `01`\n- 3 bytes missing → append `03 03 03`\n- 16 bytes (full block) → append a full padding block `10 10 10 ... 10`\n\nOn decryption, Bob strips and validates the padding. If it is invalid, Bob returns an error.",
    },
    {
      title: "Step 2: The Oracle Mallory Needs",
      speaker: "Mallory",
      content:
        "Bob's server has two behaviours:\n\n- `200 OK` — decryption succeeded, padding was valid\n- `500 Error: Invalid Padding` — decryption succeeded, but padding bytes were wrong\n\nMallory does not need plaintext. She just needs Bob to tell her whether **her modified ciphertext decrypts to valid padding**. That single bit of information — valid or invalid — is her oracle.",
      callout: {
        type: "warning",
        text: "POODLE (2014), Lucky Thirteen (2013), the ASP.NET padding oracle (2010), and Serge Vaudenay's original attack (2002) all exploit this exact information leak. (Note: BEAST from 2011 was a chosen-plaintext CBC IV prediction attack, whereas POODLE is the classic TLS padding oracle).",
      },
    },
    {
      title: "Step 3: The Attack — Decrypting One Byte",
      speaker: "Mallory",
      content:
        "CBC decryption: `Plaintext Block N = Decrypt(Cipher Block N) ⊕ Cipher Block N-1`\n\nMallory wants to find the last byte of `Plaintext Block 2`. She modifies the last byte of `Cipher Block 1` and sends the pair to Bob.\n\n1. She replaces the last byte of `Cipher Block 1` with test byte values `G` from 0 to 255.\n2. When Bob returns `200 OK`, the decrypted last byte is `01` (valid 1-byte padding).\n3. From that, Mallory knows: `Decrypt(Cipher Block 2)[last byte] ⊕ G = 01`\n4. Therefore: `Decrypt(Cipher Block 2)[last byte] = 01 ⊕ G`\n5. Therefore: `Plaintext[last byte] = Decrypt(Cipher Block 2)[last byte] ⊕ original Cipher Block 1[last byte]`\n\nRepeat for every byte. **One block of AES-CBC is fully decrypted in at most 256 × 16 = 4096 oracle queries.**",
    },
    {
      title: "Step 4: Real-World Impact",
      speaker: "Eve",
      content:
        "This attack was weaponized against web services and TLS in the wild:\n\n- **Vaudenay's Oracle (2002):** The seminal paper proving that error-message oracles allow full ciphertext recovery without the secret key.\n- **ASP.NET Padding Oracle (2010):** Exploited .NET custom errors to decrypt encrypted viewstate data and auth cookies across thousands of enterprise websites.\n- **POODLE (2014):** Forced browsers to downgrade from TLS to SSL 3.0, where CBC padding bytes were unauthenticated, allowing complete cookie extraction. Led to SSL 3.0 being globally retired.\n- **Lucky Thirteen (2013):** A subtle timing-based padding oracle against TLS 1.1/1.2 that measured microscopic clock differences during HMAC verification.",
    },
    {
      title: "Step 5: The Fix — Authenticated Encryption",
      speaker: "Bob",
      content:
        "The root cause: Bob decrypted first, then checked padding — leaking information about the plaintext before authentication.\n\n**Correct approach (Encrypt-then-MAC):** Verify the HMAC *before* decrypting. If the HMAC fails, reject immediately without attempting decryption or revealing padding status.\n\n**Even better (AEAD):** AES-GCM authenticates before any plaintext is released. There is no padding, no oracle, and no timing leak. This is why TLS 1.3 removed all CBC cipher suites and mandates AES-GCM or ChaCha20-Poly1305.",
      callout: {
        type: "security",
        text: "TLS 1.3 (RFC 8446) removed ALL CBC cipher suites entirely. If your stack still negotiates CBC, upgrade immediately. This attack has been known since 2002 and was exploited in production for over a decade.",
      },
    },
  ],
  takeaways: [
    "Padding oracle attacks decrypt any CBC ciphertext using only a valid/invalid padding signal.",
    "The root cause: checking padding *after* decryption leaks plaintext information through error messages.",
    "POODLE, Lucky Thirteen, and the ASP.NET oracle all exploited padding leaks in production systems.",
    "Fix: always verify authentication (HMAC/tag) **before** decrypting — never leak decryption results on auth failure.",
    "TLS 1.3 eliminated CBC entirely — use AES-GCM or ChaCha20-Poly1305 in all new systems.",
  ],
  seed: {
    toolId: "aes",
    sampleInput: "Secret session token: abc123xyz",
    explanation:
      "Open AES Workbench and compare CBC mode vs GCM mode — notice that GCM includes an authentication tag that must be verified before any plaintext is released.",
  },
};

export default content;
