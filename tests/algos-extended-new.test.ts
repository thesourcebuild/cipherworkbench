import { describe, expect, it } from "vitest";
import {
  adiantumEncrypt,
  adiantumDecrypt,
  ansiX963Kdf,
  balloonHash,
  catenaHash,
  chaskeyMac,
  crypto1Crypt,
  dectDscEncrypt,
  geaEncrypt,
  haraka256,
  haraka512,
  hctr2Encrypt,
  hctr2Decrypt,
  keeloqDecrypt,
  keeloqEncrypt,
  keeloqEncryptBytes,
  keeloqDecryptBytes,
  komihash,
  meowHash,
  nhash,
  openpgpS2k,
  pelicanMac,
  poly1305AesMac,
  poseidonHashBytes,
  rescuePrimeHashBytes,
  saturninEncryptBlock,
  saturninDecryptBlock,
  kdfSp800108,
  spritzEncrypt,
  sshKdf,
  tls12Prf,
  yescryptKdf,
} from "@ocs/algos";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";



describe("Extended Algorithm Suite: KDFs, Ciphers, Hashes, MACs", () => {
  describe("KDFs", () => {
    it("Balloon Hashing executes and produces deterministic 32-byte digest", () => {
      const pass = new TextEncoder().encode("password123");
      const salt = new TextEncoder().encode("saltysalt");
      const hash1 = balloonHash(sha256, pass, salt, { sCost: 16, tCost: 2, delta: 3 });
      const hash2 = balloonHash(sha256, pass, salt, { sCost: 16, tCost: 2, delta: 3 });
      expect(hash1.length).toBe(32);
      expect(hash1).toEqual(hash2);
    });

    it("NIST SP 800-108 derives keys across all 3 modes", () => {
      const prf = (key: Uint8Array, msg: Uint8Array) => hmac(sha256, key, msg);
      const keyIn = new Uint8Array(32).fill(0xaa);
      const label = new TextEncoder().encode("testLabel");
      const context = new TextEncoder().encode("testContext");

      const kCounter = kdfSp800108(prf, keyIn, 32, { mode: "counter", label, context });
      const kFeedback = kdfSp800108(prf, keyIn, 32, { mode: "feedback", label, context, iv: new Uint8Array(16).fill(0x55) });
      const kDouble = kdfSp800108(prf, keyIn, 32, { mode: "double-pipeline", label, context });


      expect(kCounter.length).toBe(32);
      expect(kFeedback.length).toBe(32);
      expect(kDouble.length).toBe(32);
      expect(kCounter).not.toEqual(kFeedback);
      expect(kCounter).not.toEqual(kDouble);
    });

    it("OpenPGP S2K derives keys across Simple, Salted, and Iterated+Salted", () => {
      const pass = new TextEncoder().encode("secretPassphrase");
      const salt = new Uint8Array(8).fill(0x42);

      const kSimple = openpgpS2k(sha256, pass, 32, { type: "simple" });
      const kSalted = openpgpS2k(sha256, pass, 32, { type: "salted", salt });
      const kIter = openpgpS2k(sha256, pass, 32, { type: "iterated-salted", salt, count: 65536 });

      expect(kSimple.length).toBe(32);
      expect(kSalted.length).toBe(32);
      expect(kIter.length).toBe(32);
    });

    it("SSHv2 KDF derives required key types", () => {
      const k = new Uint8Array(32).fill(0x11);
      const h = new Uint8Array(32).fill(0x22);

      const keyC = sshKdf(sha256, k, h, 32, { keyType: "C" });
      const keyD = sshKdf(sha256, k, h, 32, { keyType: "D" });
      expect(keyC.length).toBe(32);
      expect(keyD.length).toBe(32);
      expect(keyC).not.toEqual(keyD);
    });

    it("TLS 1.2 PRF generates expanded key material", () => {
      const hmacFn = (k: Uint8Array, m: Uint8Array) => hmac(sha256, k, m);
      const secret = new Uint8Array(32).fill(0x99);
      const prfOut = tls12Prf(hmacFn, secret, 48, { label: "master secret", seed: new Uint8Array(32).fill(0x01) });
      expect(prfOut.length).toBe(48);
    });

    it("Catena and ANSI X9.63 derive deterministic material", () => {
      const pass = new TextEncoder().encode("catenaPass");
      const salt = new Uint8Array(16).fill(0x07);
      const catenaOut = catenaHash(sha256, pass, salt, { lambda: 4, tCost: 1 });
      expect(catenaOut.length).toBe(32);

      const x963Out = ansiX963Kdf(sha256, new Uint8Array(32).fill(0x12), 48);
      expect(x963Out.length).toBe(48);
    });

    it("yescrypt derives key material", () => {
      const pbkdf2Fn = (p: Uint8Array, s: Uint8Array, i: number, l: number) =>
        pbkdf2(sha256, p, s, { c: i, dkLen: l });
      const pass = new TextEncoder().encode("yescryptPass");
      const salt = new Uint8Array(16).fill(0x33);
      const key = yescryptKdf(pbkdf2Fn, pass, salt, 32, { n: 16, r: 8 });
      expect(key.length).toBe(32);
    });
  });

  describe("MACs", () => {
    it("Chaskey MAC computes 16-byte authentication tag", () => {
      const key = new Uint8Array(16).fill(0x55);
      const msg = new TextEncoder().encode("Hello Chaskey MAC");
      const tag8 = chaskeyMac(key, msg, 8);
      const tag16 = chaskeyMac(key, msg, 16);
      expect(tag8.length).toBe(16);
      expect(tag16.length).toBe(16);
      expect(tag8).not.toEqual(tag16);
    });

    it("Pelican MAC and Poly1305-AES compute 16-byte tags", () => {
      const key = new Uint8Array(16).fill(0x23);
      const msg = new TextEncoder().encode("Test message for Pelican MAC");
      const tagPelican = pelicanMac(key, msg);
      expect(tagPelican.length).toBe(16);

      const keyR = new Uint8Array(16).fill(0x34);
      const keyK = new Uint8Array(16).fill(0x56);
      const nonce = new Uint8Array(16).fill(0x78);
      const tagPoly = poly1305AesMac(keyR, keyK, nonce, msg);
      expect(tagPoly.length).toBe(16);
    });
  });

  describe("Hashes", () => {
    it("Poseidon and Rescue-Prime compute algebraic field hashes", () => {
      const data = new TextEncoder().encode("ZeroKnowledgePayload");
      const posHash = poseidonHashBytes(data, 32);
      const rescueHash = rescuePrimeHashBytes(data, 32);
      expect(posHash.length).toBe(32);
      expect(rescueHash.length).toBe(32);
    });

    it("Haraka-256 and Haraka-512 compute short-input post-quantum digests", () => {
      const in32 = new Uint8Array(32).fill(0x05);
      const in64 = new Uint8Array(64).fill(0x06);
      const h256 = haraka256(in32);
      const h512 = haraka512(in64);
      expect(h256.length).toBe(32);
      expect(h512.length).toBe(32);
    });

    it("Meow Hash, Komihash, and N-Hash compute digests", () => {
      const data = new TextEncoder().encode("Fast non-cryptographic and historic hash data");
      const meow = meowHash(data);
      const komi = komihash(data);
      const n = nhash(data);
      expect(meow.length).toBe(16);
      expect(komi.length).toBe(8);
      expect(n.length).toBe(16);
    });
  });

  describe("Ciphers", () => {
    it("KeeLoq round-trips 32-bit block", () => {
      const key = 0x0123456789abcdefn;
      const block = 0xdeadbeef;
      const encrypted = keeloqEncrypt(block, key);
      const decrypted = keeloqDecrypt(encrypted, key);
      expect(decrypted).toBe(block);

      const keyBytes = new Uint8Array(8).fill(0x3a);
      const blkBytes = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
      const encB = keeloqEncryptBytes(keyBytes, blkBytes);
      const decB = keeloqDecryptBytes(keyBytes, encB);
      expect(decB).toEqual(blkBytes);
    });

    it("Crypto-1, DECT DSC, GEA, and Spritz stream ciphers encrypt and decrypt", () => {
      const key = new Uint8Array(8).fill(0x7e);
      const iv = new Uint8Array(4).fill(0x21);
      const plaintext = new TextEncoder().encode("Secret cellular and RFID payload");

      const crypt1 = crypto1Crypt(key, plaintext);
      expect(crypto1Crypt(key, crypt1)).toEqual(plaintext);

      const dectOut = dectDscEncrypt(key, iv, plaintext);
      expect(dectDscEncrypt(key, iv, dectOut)).toEqual(plaintext);

      const geaOut = geaEncrypt(key, iv, plaintext);
      expect(geaEncrypt(key, iv, geaOut)).toEqual(plaintext);

      const spritzOut = spritzEncrypt(key, plaintext);
      expect(spritzEncrypt(key, spritzOut)).toEqual(plaintext);
    });

    it("Saturnin 256-bit block cipher round-trips", () => {
      const key = new Uint8Array(32).fill(0x44);
      const block = new Uint8Array(32).fill(0x55);
      const enc = new Uint8Array(32);
      const dec = new Uint8Array(32);

      saturninEncryptBlock(key, block, enc);
      saturninDecryptBlock(key, enc, dec);
      expect(dec).toEqual(block);
    });

    it("Adiantum and HCTR2 wide-block disk encryption round-trip", () => {
      const key = new Uint8Array(32).fill(0x88);
      const tweak = new Uint8Array(12).fill(0x99);
      const plaintext = new Uint8Array(64).fill(0xab);

      const adEnc = adiantumEncrypt(key, tweak, plaintext);
      const adDec = adiantumDecrypt(key, tweak, adEnc);
      expect(adDec).toEqual(plaintext);

      const hctrEnc = hctr2Encrypt(key, tweak, plaintext);
      const hctrDec = hctr2Decrypt(key, tweak, hctrEnc);
      expect(hctrDec).toEqual(plaintext);
    });
  });
});
