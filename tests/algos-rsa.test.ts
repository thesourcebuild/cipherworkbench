import { describe, expect, it } from "vitest";
import { emePkcs1V15Decode, emePkcs1V15Encode } from "@ocs/algos";

describe("RSAES-PKCS1-v1_5 encoding", () => {
  it("frames a message with at least eight nonzero padding bytes", () => {
    const message = new TextEncoder().encode("key");
    const padding = Uint8Array.from({ length: 10 }, (_, index) => index + 1);
    const encoded = emePkcs1V15Encode(message, 16, padding);

    expect(encoded.subarray(0, 2)).toEqual(new Uint8Array([0x00, 0x02]));
    expect(encoded.subarray(2, 12)).toEqual(padding);
    expect(encoded[12]).toBe(0);
    expect(emePkcs1V15Decode(encoded)).toEqual(message);
  });

  it("rejects zero padding bytes and every malformed block shape", () => {
    const message = new Uint8Array([1]);
    expect(() => emePkcs1V15Encode(message, 12, new Uint8Array(8))).toThrow(
      "must not contain zero",
    );

    const wrongType = new Uint8Array(12);
    wrongType[1] = 1;
    wrongType[10] = 0;
    expect(emePkcs1V15Decode(wrongType)).toBeUndefined();

    const shortPadding = new Uint8Array(12).fill(1);
    shortPadding[0] = 0;
    shortPadding[1] = 2;
    shortPadding[8] = 0;
    expect(emePkcs1V15Decode(shortPadding)).toBeUndefined();

    const noSeparator = new Uint8Array(12).fill(1);
    noSeparator[0] = 0;
    noSeparator[1] = 2;
    expect(emePkcs1V15Decode(noSeparator)).toBeUndefined();
  });
});
