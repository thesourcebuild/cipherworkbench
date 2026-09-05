import { describe, expect, it } from "vitest";
import {
  dammCompute,
  dammValidate,
  isbn10Compute,
  isbn10To13,
  isbn10Validate,
  isbn13Compute,
  isbn13To10,
  isbn13Validate,
  luhnCompute,
  luhnIdentify,
  luhnValidate,
  verhoeffCompute,
  verhoeffValidate,
} from "@ocs/algos";

describe("Verhoeff Algorithm", () => {
  it("computes standard check digits", () => {
    expect(verhoeffCompute("236")).toBe(3);
    expect(verhoeffCompute("123456789")).toBe(0);
    expect(verhoeffCompute("142857")).toBe(0);
    expect(verhoeffCompute("8473643")).toBe(6);
  });

  it("validates numbers with trailing check digit", () => {
    expect(verhoeffValidate("2363")).toBe(true);
    expect(verhoeffValidate("1234567890")).toBe(true);
    expect(verhoeffValidate("1428570")).toBe(true);
    expect(verhoeffValidate("84736436")).toBe(true);
  });

  it("detects single digit substitutions", () => {
    // 2363 -> change 3 to 4
    expect(verhoeffValidate("2364")).toBe(false);
    expect(verhoeffValidate("2373")).toBe(false);
  });

  it("detects 100% of adjacent transpositions", () => {
    // 2363 -> transpose 2 and 3: 3263
    expect(verhoeffValidate("3263")).toBe(false);
    // 2363 -> transpose 3 and 6: 2633
    expect(verhoeffValidate("2633")).toBe(false);
  });
});

describe("Damm Algorithm", () => {
  it("computes known check digits", () => {
    expect(dammCompute("572")).toBe(4);
    expect(dammCompute("123456789")).toBe(4);
    expect(dammCompute("0")).toBe(0);
    expect(dammCompute("98765")).toBe(3);
  });

  it("validates numbers with trailing Damm check digit", () => {
    expect(dammValidate("5724")).toBe(true);
    expect(dammValidate("1234567894")).toBe(true);
    expect(dammValidate("987653")).toBe(true);
  });

  it("detects single digit errors and transpositions", () => {
    expect(dammValidate("5725")).toBe(false);
    expect(dammValidate("7524")).toBe(false);
    expect(dammValidate("5274")).toBe(false);
  });
});

describe("Luhn Algorithm (Mod 10)", () => {
  it("computes check digits for standard numbers", () => {
    expect(luhnCompute("7992739871")).toBe(3);
    expect(luhnCompute("123456789")).toBe(7);
    // IMEI TAC prefix
    expect(luhnCompute("35693803564380")).toBe(9);
  });

  it("validates numbers with valid Luhn checksums", () => {
    expect(luhnValidate("79927398713")).toBe(true);
    expect(luhnValidate("1234567897")).toBe(true);
    expect(luhnValidate("356938035643809")).toBe(true);
  });

  it("rejects invalid numbers", () => {
    expect(luhnValidate("79927398714")).toBe(false);
    expect(luhnValidate("1234567898")).toBe(false);
  });

  it("identifies card networks and IMEI", () => {
    const visa = luhnIdentify("4532012345678912");
    expect(visa?.brand).toBe("Visa");

    const mc = luhnIdentify("5412751234123456");
    expect(mc?.brand).toBe("Mastercard");

    const amex = luhnIdentify("378282246310005");
    expect(amex?.brand).toBe("American Express");

    const imei = luhnIdentify("356938035643803");
    expect(imei?.category).toBe("imei");
  });
});

describe("ISBN-10 and ISBN-13", () => {
  it("computes and validates ISBN-10", () => {
    expect(isbn10Compute("030640615")).toBe("2");
    expect(isbn10Compute("080442957")).toBe("X");

    expect(isbn10Validate("0-306-40615-2")).toBe(true);
    expect(isbn10Validate("0-8044-2957-X")).toBe(true);
    expect(isbn10Validate("0-306-40615-3")).toBe(false);
  });

  it("computes and validates ISBN-13 / EAN-13", () => {
    expect(isbn13Compute("978030640615")).toBe(7);
    expect(isbn13Validate("978-0-306-40615-7")).toBe(true);
    expect(isbn13Validate("978-0-306-40615-8")).toBe(false);
  });

  it("converts between ISBN-10 and ISBN-13", () => {
    expect(isbn10To13("0-306-40615-2")).toBe("9780306406157");
    expect(isbn13To10("978-0-306-40615-7")).toBe("0306406152");

    // 979 prefix cannot be converted to ISBN-10
    expect(isbn13To10("979-1-090-63700-9")).toBeNull();
  });
});
