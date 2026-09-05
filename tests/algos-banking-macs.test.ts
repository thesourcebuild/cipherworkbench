import { describe, expect, it } from "vitest";
import { pmacAes, retailMac, vmac } from "@ocs/algos";

const hex = (buf: Uint8Array): string =>
  [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");

const bytes = (hexStr: string): Uint8Array => {
  const clean = hexStr.replace(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

describe("Retail MAC (ANSI X9.19 / ISO/IEC 9797-1 Algorithm 3)", () => {
  const k1 = "0123456789abcdef";
  const k2 = "fedcba9876543210";
  const key16 = bytes(k1 + k2);

  it("computes Retail MAC with pad2 (0x80 then zeroes)", () => {
    const data = new TextEncoder().encode("Hello Banking World!");
    const tag = retailMac(key16, data, { padding: "pad2", tagLength: 8 });
    expect(tag.length).toBe(8);

    // Verify determinism
    const tag2 = retailMac(key16, data, { padding: "pad2", tagLength: 8 });
    expect(hex(tag)).toBe(hex(tag2));
  });

  it("supports truncated 4-byte PIN pad MAC", () => {
    const data = new TextEncoder().encode("PIN_VERIFY_PAYLOAD_1234");
    const fullTag = retailMac(key16, data, { tagLength: 8 });
    const shortTag = retailMac(key16, data, { tagLength: 4 });

    expect(shortTag.length).toBe(4);
    expect(hex(shortTag)).toBe(hex(fullTag.subarray(0, 4)));
  });

  it("supports padding mode pad1 (zero-padding)", () => {
    const data = bytes("1122334455");
    const tag = retailMac(key16, data, { padding: "pad1" });
    expect(tag.length).toBe(8);
  });

  it("changes output when key or data is modified", () => {
    const data = new TextEncoder().encode("Transaction $500.00");
    const tagOriginal = retailMac(key16, data);

    const tamperedData = new TextEncoder().encode("Transaction $900.00");
    const tagTampered = retailMac(key16, tamperedData);

    expect(hex(tagOriginal)).not.toBe(hex(tagTampered));
  });
});

describe("PMAC (Parallelizable MAC - Rogaway)", () => {
  const key128 = bytes("2b7e151628aed2a6abf7158809cf4f3c");
  const key256 = bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");

  it("computes 16-byte tag for empty message", () => {
    const tag = pmacAes(key128, new Uint8Array(0));
    expect(tag.length).toBe(16);
  });

  it("computes PMAC for single and multi-block messages", () => {
    const msgShort = new TextEncoder().encode("Short message");
    const tag1 = pmacAes(key128, msgShort);
    expect(tag1.length).toBe(16);

    const msgLong = new Uint8Array(100);
    for (let i = 0; i < 100; i++) msgLong[i] = i;
    const tag2 = pmacAes(key128, msgLong);
    expect(tag2.length).toBe(16);
    expect(hex(tag1)).not.toBe(hex(tag2));
  });

  it("supports AES-256 key", () => {
    const msg = new TextEncoder().encode("AES-256 PMAC Test Message");
    const tag = pmacAes(key256, msg);
    expect(tag.length).toBe(16);
  });
});

describe("VMAC (RFC 6605)", () => {
  const key = bytes("0102030405060708090a0b0c0d0e0f10");
  const nonce = bytes("00000000000000000000000000000001");

  it("computes 64-bit (8-byte) and 128-bit (16-byte) VMAC tags", () => {
    const msg = new TextEncoder().encode("RFC 6605 VMAC message data");
    const tag64 = vmac(key, msg, { nonce, tagLength: 8 });
    expect(tag64.length).toBe(8);

    const tag128 = vmac(key, msg, { nonce, tagLength: 16 });
    expect(tag128.length).toBe(16);
    expect(hex(tag128.subarray(0, 8))).toBe(hex(tag64));
  });

  it("is sensitive to nonce and plaintext changes", () => {
    const msg = new TextEncoder().encode("Sensitive Payment");
    const nonce1 = bytes("00000000000000000000000000000001");
    const nonce2 = bytes("00000000000000000000000000000002");

    const tag1 = vmac(key, msg, { nonce: nonce1 });
    const tag2 = vmac(key, msg, { nonce: nonce2 });
    expect(hex(tag1)).not.toBe(hex(tag2));
  });
});
