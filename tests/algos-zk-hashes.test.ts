import { describe, it, expect } from "vitest";
import {
  monolithPermute,
  monolithHash,
  neptunePermute,
  neptuneHash,
  reinforcedConcretePermute,
  reinforcedConcreteHash,
  anemoiPermute,
  anemoiHash,
  griffinPermute,
  griffinHash,
} from "@ocs/algos";

describe("Zero-Knowledge & Algebraic Hashes", () => {
  describe("Monolith", () => {
    it("computes deterministic permutation over Goldilocks field", () => {
      const state = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n];
      const p1 = monolithPermute(state, { field: "goldilocks" });
      const p2 = monolithPermute(state, { field: "goldilocks" });
      expect(p1.length).toBe(12);
      expect(p1).toEqual(p2);
      expect(p1[0]).not.toBe(1n);
    });

    it("hashes bytes into 32-byte digest", () => {
      const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const h1 = monolithHash(data);
      const h2 = monolithHash(data);
      expect(h1.length).toBe(32);
      expect(h1).toEqual(h2);
    });
  });

  describe("Neptune", () => {
    it("computes deterministic permutation over BN254 field", () => {
      const state = [1n, 2n, 3n, 4n];
      const p1 = neptunePermute(state);
      const p2 = neptunePermute(state);
      expect(p1.length).toBe(4);
      expect(p1).toEqual(p2);
    });

    it("hashes empty and non-empty data into 32-byte digest", () => {
      const hEmpty = neptuneHash(new Uint8Array(0));
      const hData = neptuneHash(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
      expect(hEmpty.length).toBe(32);
      expect(hData.length).toBe(32);
      expect(hEmpty).not.toEqual(hData);
    });
  });

  describe("Reinforced Concrete", () => {
    it("computes deterministic permutation with Bricks, Concrete, and Bars layers", () => {
      const state = [10n, 20n, 30n];
      const p1 = reinforcedConcretePermute(state);
      const p2 = reinforcedConcretePermute(state);
      expect(p1.length).toBe(3);
      expect(p1).toEqual(p2);
    });

    it("hashes bytes to 32-byte output", () => {
      const h = reinforcedConcreteHash(new Uint8Array([1, 3, 3, 7]));
      expect(h.length).toBe(32);
    });
  });

  describe("Anemoi", () => {
    it("computes Flystel non-linear permutation", () => {
      const state = [1n, 2n, 3n, 4n];
      const p1 = anemoiPermute(state);
      const p2 = anemoiPermute(state);
      expect(p1.length).toBe(4);
      expect(p1).toEqual(p2);
    });

    it("hashes data into 32-byte digest", () => {
      const h = anemoiHash(new TextEncoder().encode("Zero-Knowledge Anemoi Test"));
      expect(h.length).toBe(32);
    });
  });

  describe("Griffin", () => {
    it("computes algebraic permutation", () => {
      const state = [5n, 10n, 15n, 20n];
      const p1 = griffinPermute(state);
      const p2 = griffinPermute(state);
      expect(p1.length).toBe(4);
      expect(p1).toEqual(p2);
    });

    it("hashes data into 32-byte digest", () => {
      const h = griffinHash(new Uint8Array([42, 42, 42]));
      expect(h.length).toBe(32);
    });
  });
});
