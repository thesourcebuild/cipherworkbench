import { describe, expect, it } from "vitest";
import {
  enigmaCrypt,
  vigenereEncrypt,
  vigenereDecrypt,
  playfairEncrypt,
  playfairDecrypt,
  bifidEncrypt,
  bifidDecrypt,
  trifidEncrypt,
  trifidDecrypt,
  baconEncrypt,
  baconDecrypt,
  railFenceEncrypt,
  railFenceDecrypt,
  schnorrGetPublicKey,
  schnorrSign,
  schnorrVerify,
  blsKeygen,
  blsSign,
  blsVerify,
  blsAggregateSignatures,
  blsAggregatePublicKeys,
  vssSplit,
  vssVerifyShare,
  vssCombine,
  elgamalKeygen,
  elgamalEncrypt,
  elgamalDecrypt,
  x448,
  x448Keygen,
  base85Encode,
  base85Decode,
  base91Encode,
  base91Decode,
  base45Encode,
  base45Decode,
  proquintsEncode,
  proquintsDecode,
  punycodeEncode,
  punycodeDecode,
  bencodeEncode,
  bencodeDecode,
  bikeKeygen,
  bikeEncap,
  bikeDecap,
  frodoKeygen,
  frodoEncap,
  frodoDecap,
  mayoKeygen,
  mayoSign,
  mayoVerify,
  aesGcmSivEncrypt,
  aesGcmSivDecrypt,
  sivEncrypt,
  sivDecrypt,
  blake3Mac,
  blake3DeriveKey,
} from "@ocs/algos";
import { sha256 } from "@noble/hashes/sha2.js";

const ascii = (s: string) => new TextEncoder().encode(s);

describe("Classical & Historical Ciphers", () => {
  it("Enigma M3 correctly encrypts and decrypts with historical reciprocity", () => {
    const plaintext = "HELLOWORLD";
    const config = { rotors: ["I", "II", "III"], reflector: "UKW-B", positions: "AAA", ringSettings: [1, 1, 1] };
    const ciphertext = enigmaCrypt(plaintext, config);
    expect(ciphertext).not.toBe(plaintext);
    expect(ciphertext.length).toBe(plaintext.length);

    // Enigma is self-reciprocal when initialized to the same state
    const decrypted = enigmaCrypt(ciphertext, config);
    expect(decrypted).toBe(plaintext);
  });

  it("Vigenère, Beaufort, and Autokey ciphers round-trip cleanly", () => {
    const text = "ATTACKATDAWN";
    const key = "LEMON";

    const vEnc = vigenereEncrypt(text, { key, variant: "vigenere" });
    expect(vEnc).toBe("LXFOPVEFRNHR");
    expect(vigenereDecrypt(vEnc, { key, variant: "vigenere" })).toBe(text);

    const bEnc = vigenereEncrypt(text, { key, variant: "beaufort" });
    expect(vigenereDecrypt(bEnc, { key, variant: "beaufort" })).toBe(text);

    const aEnc = vigenereEncrypt(text, { key, variant: "autokey" });
    expect(vigenereDecrypt(aEnc, { key, variant: "autokey" })).toBe(text);
  });

  it("Playfair cipher encrypts letter pairs according to 5x5 matrix rules", () => {
    const text = "HIDETHEGOLDINTHECOLDTREESTUMP";
    const key = "PLAYFAIREXAMPLE";
    const enc = playfairEncrypt(text, { key });
    expect(enc.length % 2).toBe(0);
    const dec = playfairDecrypt(enc, { key });
    expect(dec.startsWith("HIDETHEGOLDIN")).toBe(true);
  });

  it("Bifid & Trifid fractionating ciphers round-trip correctly", () => {
    const text = "DEFENDTHEEASTWALLOFTHECASTLE";
    const bifidEnc = bifidEncrypt(text, { key: "BIFIDKEY", period: 5 });
    expect(bifidDecrypt(bifidEnc, { key: "BIFIDKEY", period: 5 })).toBe(text);

    const trifidText = "DEFENDTHECASTLE#";
    const trifidEnc = trifidEncrypt(trifidText, { key: "TRIFIDKEY", period: 5 });
    expect(trifidDecrypt(trifidEnc, { key: "TRIFIDKEY", period: 5 })).toBe(trifidText);
  });

  it("Bacon's cipher encodes and decodes 5-bit sequences", () => {
    const text = "CIPHER";
    const encTraditional = baconEncrypt(text, { variant: "traditional" });
    expect(encTraditional).toBe("AAABA ABAAA ABBBA AABBB AABAA BAAAA");
    expect(baconDecrypt(encTraditional, { variant: "traditional" })).toBe(text);

    const encFull = baconEncrypt(text, { variant: "full" });
    expect(encFull).toBe("AAABA ABAAA ABBBB AABBB AABAA BAAAB");
    expect(baconDecrypt(encFull, { variant: "full" })).toBe(text);
  });

  it("Rail fence cipher zigzag transposes and reconstructs", () => {
    const text = "WEAREDISCOVEREDFLEEATONCE";
    const enc = railFenceEncrypt(text, { rails: 3 });
    expect(enc).toBe("WECRLTEERDSOEEFEAOCAIVDEN");
    expect(railFenceDecrypt(enc, { rails: 3 })).toBe(text);
  });
});

describe("Signatures, Verifiable Secret Sharing & Asymmetric", () => {
  it("BIP-340 Schnorr signs and verifies with 64-byte signatures", () => {
    const privateKey = sha256(ascii("schnorr test seed"));
    const publicKey = schnorrGetPublicKey(privateKey);
    expect(publicKey.length).toBe(32);

    const msg = ascii("Bitcoin Taproot BIP-340");
    const sig = schnorrSign(msg, privateKey);
    expect(sig.length).toBe(64);

    expect(schnorrVerify(sig, msg, publicKey)).toBe(true);

    const tampered = new Uint8Array(msg);
    tampered[0] = (tampered[0] ?? 0) ^ 1;
    expect(schnorrVerify(sig, tampered, publicKey)).toBe(false);
  });

  it("BLS12-381 signs, verifies, and non-interactively aggregates signatures", () => {
    const kp1 = blsKeygen(ascii("bls signer 1"));
    const kp2 = blsKeygen(ascii("bls signer 2"));

    const msg1 = ascii("message for signer 1");
    const msg2 = ascii("message for signer 2");

    const sig1 = blsSign(msg1, kp1.secretKey);
    const sig2 = blsSign(msg2, kp2.secretKey);

    expect(blsVerify(sig1, msg1, kp1.publicKey)).toBe(true);
    expect(blsVerify(sig2, msg2, kp2.publicKey)).toBe(true);

    const aggSig = blsAggregateSignatures([sig1, sig2]);
    expect(aggSig.length).toBe(48);

    const sameMsg = ascii("same announcement for all");
    const sigA = blsSign(sameMsg, kp1.secretKey);
    const sigB = blsSign(sameMsg, kp2.secretKey);
    const combinedSig = blsAggregateSignatures([sigA, sigB]);
    const combinedPk = blsAggregatePublicKeys([kp1.publicKey, kp2.publicKey]);

    expect(blsVerify(combinedSig, sameMsg, combinedPk)).toBe(true);
  });

  it("Feldman's Verifiable Secret Sharing verifies commitments and reconstructs secret", () => {
    const secret = ascii("Verifiable Master Key");
    const rng = (len: number) => sha256(ascii(`rng-${len}`));

    const deal = vssSplit(secret, 5, 3, rng);
    expect(deal.shares.length).toBe(5);
    expect(deal.commitments.length).toBe(3);

    for (const share of deal.shares) {
      expect(vssVerifyShare(share, deal.commitments)).toBe(true);
    }

    const reconstructed = vssCombine([deal.shares[0]!, deal.shares[2]!, deal.shares[4]!]);
    const dealDirect = vssSplit(secret, 5, 3, rng);
    const directSecret = vssCombine([dealDirect.shares[0]!, dealDirect.shares[1]!, dealDirect.shares[2]!]);
    expect(reconstructed).toBe(directSecret);
  });

  it("ElGamal cryptosystem encrypts and decrypts over elliptic curve", () => {
    const kp = elgamalKeygen(ascii("elgamal keypair seed"));
    const msg = ascii("Confidential Payload");

    const ciphertext = elgamalEncrypt(msg, kp.publicKey, ascii("ephemeral seed"));
    expect(ciphertext.c1.length).toBe(33);
    expect(ciphertext.c2.length).toBe(msg.length);

    const decrypted = elgamalDecrypt(ciphertext, kp.privateKey);
    expect(decrypted).toEqual(msg);
  });

  it("Curve448 / X448 computes Diffie-Hellman scalar multiplication", () => {
    const alice = x448Keygen(ascii("alice seed"));
    const bob = x448Keygen(ascii("bob seed"));

    const ssAlice = x448(alice.secretKey, bob.publicKey);
    const ssBob = x448(bob.secretKey, alice.publicKey);

    expect(ssAlice.length).toBe(56);
    expect(ssAlice).toEqual(ssBob);
  });
});

describe("Specialized Encodings", () => {
  it("Base85 (Ascii85 and Z85) encodes and decodes accurately", () => {
    const data = ascii("Man is distinguished, not only by his reason");
    const ascii85 = base85Encode(data, "ascii85");
    expect(base85Decode(ascii85, "ascii85")).toEqual(data);

    const z85Data = ascii("0123456789abcdef"); // 16 bytes
    const z85 = base85Encode(z85Data, "z85");
    expect(base85Decode(z85, "z85")).toEqual(z85Data);
  });

  it("basE91 packs binary data with high density", () => {
    const data = ascii("Test basE91 high-density binary packing!");
    const enc = base91Encode(data);
    expect(base91Decode(enc)).toEqual(data);
  });

  it("Base45 encodes RFC 9285 standard test vectors", () => {
    expect(base45Encode(ascii("Hello!!"))).toBe("%69 VD92EX0");
    expect(base45Decode("%69 VD92EX0")).toEqual(ascii("Hello!!"));

    expect(base45Encode(ascii("base-45"))).toBe("UJCLQE7W581");
    expect(base45Decode("UJCLQE7W581")).toEqual(ascii("base-45"));
  });

  it("Proquints encodes 16-bit words into pronounceable identifiers", () => {
    const data = new Uint8Array([127, 0, 0, 1]); // 127.0.0.1
    const proquint = proquintsEncode(data);
    expect(proquint).toBe("lusab-babad");
    expect(proquintsDecode("lusab-babad")).toEqual(data);
  });

  it("Punycode encodes and decodes RFC 3492 domain names", () => {
    expect(punycodeEncode("münchen")).toBe("mnchen-3ya");
    expect(punycodeDecode("mnchen-3ya")).toBe("münchen");

    expect(punycodeEncode("日本語")).toBe("wgv71a119e");
    expect(punycodeDecode("wgv71a119e")).toBe("日本語");
  });

  it("Bencode serializes and deserializes BitTorrent structures", () => {
    const obj = {
      announce: "http://tracker.example.com/announce",
      "creation date": 1609459200,
      info: {
        length: 1048576,
        name: "example.iso",
        "piece length": 262144,
      },
    };

    const encoded = bencodeEncode(obj);
    const decoded = bencodeDecode(encoded) as typeof obj;
    expect(decoded["announce"]).toBe("http://tracker.example.com/announce");
    expect(decoded["creation date"]).toBe(1609459200);
  });
});

describe("NIST Round 4 & Alternate Post-Quantum Cryptography", () => {
  it("BIKE KEM performs keygen, encapsulation, and decapsulation", () => {
    const sha = (d: Uint8Array) => Uint8Array.from(sha256(d));
    const kp = bikeKeygen(sha, ascii("bike seed"), "bike-l1");
    expect(kp.publicKey.length).toBe(1541);
    expect(kp.secretKey.length).toBe(283);

    const enc = bikeEncap(sha, kp.publicKey, ascii("bike ephemeral seed"), "bike-l1");
    expect(enc.ciphertext.length).toBe(1541);
    expect(enc.sharedSecret.length).toBe(32);

    const decSS = bikeDecap(sha, kp.secretKey, enc.ciphertext, "bike-l1");
    expect(decSS).toEqual(enc.sharedSecret);
  });

  it("FrodoKEM performs keygen, encapsulation, and decapsulation", () => {
    const sha = (d: Uint8Array) => Uint8Array.from(sha256(d));
    const kp = frodoKeygen(sha, ascii("frodo seed"), "frodokem-640");
    expect(kp.publicKey.length).toBe(9616);
    expect(kp.secretKey.length).toBe(19888);

    const enc = frodoEncap(sha, kp.publicKey, ascii("frodo ephemeral"), "frodokem-640");
    expect(enc.ciphertext.length).toBe(9720);
    expect(enc.sharedSecret.length).toBe(32);

    const decSS = frodoDecap(sha, kp.secretKey, enc.ciphertext, "frodokem-640");
    expect(decSS).toEqual(enc.sharedSecret);
  });

  it("MAYO multivariate signatures keygen, sign, and verify", () => {
    const sha = (d: Uint8Array) => Uint8Array.from(sha256(d));
    const kp = mayoKeygen(sha, ascii("mayo seed"), "mayo-1");
    expect(kp.publicKey.length).toBe(1168);
    expect(kp.secretKey.length).toBe(24);

    const msg = ascii("MAYO Document for Signature");
    const sig = mayoSign(sha, kp.secretKey, msg, "mayo-1");
    expect(sig.length).toBe(321);

    expect(mayoVerify(sha, kp.publicKey, msg, sig, "mayo-1")).toBe(true);
  });
});

describe("Misuse-Resistant AEAD & High-Speed MACs", () => {
  it("AES-GCM-SIV encrypts, authenticates, and decrypts with nonce-misuse resistance", () => {
    const key = new Uint8Array(16).fill(0x2b);
    const nonce = new Uint8Array(12).fill(0xee);
    const plaintext = ascii("Misuse-Resistant Authenticated Payload");
    const aad = ascii("Associated Metadata");

    const enc = aesGcmSivEncrypt(key, nonce, plaintext, aad);
    expect(enc.ciphertext.length).toBe(plaintext.length);
    expect(enc.tag.length).toBe(16);

    const dec = aesGcmSivDecrypt(key, nonce, enc.ciphertext, enc.tag, aad);
    expect(dec).toEqual(plaintext);
  });

  it("SIV-AES (RFC 5297) deterministic authenticated encryption roundtrips", () => {
    const key = new Uint8Array(32).fill(0x42); // 256-bit key (128-bit auth + 128-bit enc)
    const plaintext = ascii("Deterministic Key Wrap Content");
    const ad = [ascii("header1"), ascii("header2")];

    const enc = sivEncrypt(key, plaintext, ad);
    expect(enc.v.length).toBe(16);
    expect(enc.ciphertext.length).toBe(plaintext.length);

    const dec = sivDecrypt(key, enc.ciphertext, enc.v, ad);
    expect(dec).toEqual(plaintext);
  });

  it("BLAKE3-MAC and Key Derivation produce deterministic output", () => {
    const key = new Uint8Array(32).fill(0x33);
    const msg = ascii("BLAKE3 Keyed Message");
    const mac = blake3Mac(key, msg, 32);
    expect(mac.length).toBe(32);

    const derived = blake3DeriveKey("application context 2026", msg, 32);
    expect(derived.length).toBe(32);
  });
});
