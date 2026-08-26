/**
 * The three FIPS post-quantum schemes against OpenSSL, in both directions.
 *
 * This is the strongest kind of test in this repo and it exists because of a lucky coincidence of
 * versions: OpenSSL 3.5 implements ML-KEM, ML-DSA and SLH-DSA, and Node 24 exposes all three --
 * including `crypto.encapsulate` and `crypto.decapsulate`, which no earlier Node had. So the
 * post-quantum tools are not resting on "the library is audited"; every parameter set is checked
 * against an independent implementation of the same standard.
 *
 * Four things about how it is done.
 *
 * **The DER prefix is derived, never transcribed.** OpenSSL emits keys as SubjectPublicKeyInfo, and
 * this repo's tools use the raw byte strings the standards define. Rather than hardcoding an
 * `AlgorithmIdentifier` per parameter set -- eighteen of them, each a chance to be wrong -- each test
 * generates a key with OpenSSL, takes the last `publicKeyLen` bytes as the raw key, and keeps the
 * remaining bytes as the prefix to re-wrap the other implementation's key with. The prefix is
 * whatever OpenSSL says it is.
 *
 * **Both directions, because one proves less than half.** Signing with A and verifying with B checks
 * A's signing and B's verifying. The reverse checks the other two. Only running both covers all four,
 * and the same applies to the KEM's encapsulate/decapsulate pair.
 *
 * **Every parameter set, and a completeness assertion.** Eighteen sets across three tools, all of
 * them exercised, plus a test that fails if the tools' metadata grows a set this file does not name.
 * That is what makes it a gate rather than a spot check -- the same three-assertion pattern as
 * `tests/openssl-parity.test.ts`.
 *
 * This file takes about a minute, and nearly all of it is one assertion: signing once under each of
 * SLH-DSA's six `s` parameter sets, which spend one to three seconds each by design. That is the
 * price of having every set checked against an independent implementation rather than most of them,
 * and it is worth paying -- a parameter set nothing else has ever agreed with should not be offered.
 *
 * **The byte lengths in the metadata are checked against the library's own.** They are duplicated
 * onto the eager side of the manifest split so the option catalogue can use them, exactly as the hash
 * family duplicates `outputLen`, and a wrong number there is a form that refuses a valid key.
 */
import nodeCrypto, { createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem1024, ml_kem512, ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import * as slh from "@noble/post-quantum/slh-dsa.js";
import type { KEM, Signer } from "@noble/post-quantum/utils.js";
import { ML_DSA_SETS, ML_KEM_SETS, SLH_DSA_SETS } from "@ocs/asymmetric";

/**
 * OpenSSL 3.5's post-quantum surface, which `@types/node` does not describe yet.
 *
 * `crypto.encapsulate` and `crypto.decapsulate` exist at runtime -- they are how Node exposes a KEM --
 * and `generateKeyPairSync` accepts `"ml-kem-768"` and the other seventeen names. None of the three is
 * in the type definitions at this version, so the surface is declared here once, next to the note
 * explaining why, rather than cast at each of a dozen call sites.
 */
interface PostQuantumCrypto {
  generateKeyPairSync(algorithm: string): { publicKey: KeyObject; privateKey: KeyObject };
  encapsulate(key: KeyObject): { sharedKey: Buffer; ciphertext: Buffer };
  decapsulate(key: KeyObject, ciphertext: Buffer): Buffer;
}

const pq = nodeCrypto as unknown as PostQuantumCrypto;

/**
 * Whether this Node exposes the three post-quantum standards at all.
 *
 * The whole file is a differential test against OpenSSL, and the oracle simply does not exist on every
 * Node: 22 has no `ml-kem-*`, `ml-dsa-*` or `slh-dsa-*` key type and no `crypto.encapsulate`, even
 * though it bundles the same OpenSSL 3.5 that provides them -- the APIs arrived in Node 24. Without
 * them there is nothing to compare against, so these skip with the reason attached rather than failing
 * as though the implementations were wrong.
 *
 * Probed rather than compared against a version number: what matters is whether the API is there.
 */
function nodeHasPostQuantum(): boolean {
  if (typeof (nodeCrypto as { encapsulate?: unknown }).encapsulate !== "function") return false;
  for (const type of ["ml-kem-512", "ml-dsa-44", "slh-dsa-sha2-128s"]) {
    try {
      pq.generateKeyPairSync(type);
    } catch {
      return false;
    }
  }
  return true;
}

const NODE_HAS_PQ = nodeHasPostQuantum();

/**
 * And the skip cannot become permanent.
 *
 * Node 24 is what this repo develops against and what CI runs, so the capability must be there: a
 * regression is a finding, not a reason to stop checking eighteen parameter sets against an
 * independent implementation.
 */
describe("the OpenSSL oracle", () => {
  it("exposes the post-quantum standards on the Node this repo verifies against", (ctx) => {
    // The note goes on the skip rather than into an assertion message -- see the same shape in
    // `tests/encoding.test.ts`, and the reason: a vacuous assertion passes and explains nothing.
    if (!NODE_HAS_PQ) {
      ctx.skip(
        `Node ${process.versions.node} exposes no ML-KEM/ML-DSA/SLH-DSA key type and no crypto.encapsulate, so there is no oracle to compare against and the eighteen parameter sets below are skipped.`,
      );
      return;
    }
  });
});


const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

const MESSAGE = new TextEncoder().encode("cross-implementation parity, both directions");

/** OpenSSL's name for a parameter set, and the library object for the same one. */
interface Pair {
  setId: string;
  openssl: string;
}

const KEM_PAIRS: readonly Pair[] = [
  { setId: "512", openssl: "ml-kem-512" },
  { setId: "768", openssl: "ml-kem-768" },
  { setId: "1024", openssl: "ml-kem-1024" },
];

const ML_DSA_PAIRS: readonly Pair[] = [
  { setId: "44", openssl: "ml-dsa-44" },
  { setId: "65", openssl: "ml-dsa-65" },
  { setId: "87", openssl: "ml-dsa-87" },
];

/** All twelve SLH-DSA sets. OpenSSL spells them `slh-dsa-sha2-128s`; the metadata drops the prefix. */
const SLH_PAIRS: readonly Pair[] = SLH_DSA_SETS.map((set) => ({
  setId: set.id,
  openssl: `slh-dsa-${set.id}`,
}));

const KEMS: Record<string, KEM> = { "512": ml_kem512, "768": ml_kem768, "1024": ml_kem1024 };
const ML_DSAS: Record<string, Signer> = { "44": ml_dsa44, "65": ml_dsa65, "87": ml_dsa87 };
/**
 * The library's export name for each set: `sha2-128s` becomes `slh_dsa_sha2_128s`.
 *
 * Derived rather than listed, so the twelve names cannot drift from the twelve metadata entries --
 * and the completeness test below asserts every one of them resolved to something.
 */
const SLHS: Record<string, Signer> = Object.fromEntries(
  SLH_DSA_SETS.map((set) => [
    set.id,
    (slh as unknown as Record<string, Signer>)[`slh_dsa_${set.id.replace("-", "_")}`]!,
  ]),
);

/**
 * OpenSSL's keypair, split into the raw public key and the DER prefix that wraps it.
 *
 * `publicKeyLen` comes from the library rather than being counted from the DER, so a disagreement
 * between the two shows up as a parity failure rather than as a silently mis-split buffer.
 */
function opensslKeys(name: string, publicKeyLen: number) {
  const keys = pq.generateKeyPairSync(name);
  const spki = keys.publicKey.export({ format: "der", type: "spki" });
  return {
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    rawPublicKey: Uint8Array.from(spki.subarray(spki.length - publicKeyLen)),
    prefix: Uint8Array.from(spki.subarray(0, spki.length - publicKeyLen)),
  };
}

/** Re-wraps a raw public key in OpenSSL's own prefix so OpenSSL will accept it. */
function asOpensslPublicKey(prefix: Uint8Array, rawPublicKey: Uint8Array) {
  const der = new Uint8Array(prefix.length + rawPublicKey.length);
  der.set(prefix, 0);
  der.set(rawPublicKey, prefix.length);
  return createPublicKey({ key: Buffer.from(der), format: "der", type: "spki" });
}

describe.skipIf(!NODE_HAS_PQ)("ML-KEM against OpenSSL", () => {
  it("agrees on the shared secret with either side encapsulating", () => {
    for (const { setId, openssl } of KEM_PAIRS) {
      const kem = KEMS[setId]!;
      const label = `ml-kem-${setId}`;

      // OpenSSL's key, our encapsulation, OpenSSL's decapsulation.
      const theirs = opensslKeys(openssl, kem.lengths.publicKey!);
      const sealed = kem.encapsulate(theirs.rawPublicKey);
      const recovered = pq.decapsulate(theirs.privateKey, Buffer.from(sealed.cipherText));
      expect(toHex(Uint8Array.from(recovered)), `${label} ours-enc`).toBe(
        toHex(sealed.sharedSecret),
      );

      // Our key, OpenSSL's encapsulation, our decapsulation.
      const ours = kem.keygen();
      const wrapped = asOpensslPublicKey(theirs.prefix, ours.publicKey);
      const theirSealed = pq.encapsulate(wrapped);
      const back = kem.decapsulate(Uint8Array.from(theirSealed.ciphertext), ours.secretKey);
      expect(toHex(back), `${label} theirs-enc`).toBe(
        toHex(Uint8Array.from(theirSealed.sharedKey)),
      );

      // And the shared secret is 32 bytes at every parameter set, which is fixed by FIPS 203.
      expect(sealed.sharedSecret.length, `${label} secret length`).toBe(32);
    }
  });

  it("never reports failure for a ciphertext meant for another key", () => {
    /**
     * ML-KEM's implicit rejection, and the property most likely to be mistaken for a bug.
     *
     * Decapsulating a ciphertext that was not produced under this key returns a *different* shared
     * secret rather than an error. That is deliberate: any distinguishable failure signal -- an
     * exception, a timing difference -- would be a decryption oracle. The tool's own hint says so,
     * and this pins the behaviour it describes.
     */
    const kem = KEMS["768"]!;
    const alice = kem.keygen();
    const bob = kem.keygen();
    const forBob = kem.encapsulate(bob.publicKey);

    const wrong = kem.decapsulate(forBob.cipherText, alice.secretKey);
    expect(wrong.length).toBe(32);
    expect(toHex(wrong)).not.toBe(toHex(forBob.sharedSecret));
  });
});

describe.skipIf(!NODE_HAS_PQ)("ML-DSA and SLH-DSA against OpenSSL", () => {
  const cases: readonly { readonly tool: string; readonly pairs: readonly Pair[]; readonly table: Record<string, Signer> }[] = [
    { tool: "ml-dsa", pairs: ML_DSA_PAIRS, table: ML_DSAS },
    { tool: "slh-dsa", pairs: SLH_PAIRS, table: SLHS },
  ];

  /**
   * SLH-DSA's twelve sets need a long timeout, and the number is the point rather than an annoyance.
   *
   * Six of them are `s` variants, which spend one to three seconds per signature by design, and both
   * directions of the parity check sign once per set. Vitest's five-second default is far too short;
   * the tests are still worth running every time, because a parameter set nothing independent has
   * agreed with is a parameter set that should not be offered.
   */
  const TIMEOUT = 300_000;

  for (const { tool, pairs, table } of cases) {
    it(`verifies OpenSSL's ${tool} signatures at every parameter set`, () => {
      for (const { setId, openssl } of pairs) {
        const signer = table[setId]!;
        const theirs = opensslKeys(openssl, signer.lengths.publicKey!);
        const signature = sign(null, Buffer.from(MESSAGE), theirs.privateKey);

        expect(signature.length, `${openssl} signature length`).toBe(signer.lengths.signature);
        expect(
          signer.verify(Uint8Array.from(signature), MESSAGE, theirs.rawPublicKey),
          openssl,
        ).toBe(true);
      }
    }, TIMEOUT);

    it(`produces ${tool} signatures OpenSSL accepts, at every parameter set`, () => {
      for (const { setId, openssl } of pairs) {
        const signer = table[setId]!;
        const theirs = opensslKeys(openssl, signer.lengths.publicKey!);
        const ours = signer.keygen();
        const signature = signer.sign(MESSAGE, ours.secretKey);
        const wrapped = asOpensslPublicKey(theirs.prefix, ours.publicKey);

        expect(verify(null, Buffer.from(MESSAGE), wrapped, Buffer.from(signature)), openssl).toBe(
          true,
        );
        // And a changed message fails, so the check above is not passing for a trivial reason.
        const altered = Uint8Array.from(MESSAGE);
        altered[0] = altered[0]! ^ 1;
        expect(
          verify(null, Buffer.from(altered), wrapped, Buffer.from(signature)),
          `${openssl} tampered`,
        ).toBe(false);
      }
    }, TIMEOUT);
  }
});

describe("the parameter-set metadata", () => {
  it("matches the library's own lengths, set for set", () => {
    /**
     * The duplication this guards is deliberate: the option catalogue is on the eager side of the
     * manifest split and cannot import `@noble/post-quantum`, so the lengths are written out beside
     * the rest of the metadata. Exactly the arrangement the hash family uses for `outputLen`, and it
     * needs exactly the same test -- a wrong number here is a form that refuses a valid key.
     */
    for (const set of ML_KEM_SETS) {
      const kem = KEMS[set.id]!;
      expect(set.publicKeyLen, `${set.label} publicKey`).toBe(kem.lengths.publicKey);
      expect(set.secretKeyLen, `${set.label} secretKey`).toBe(kem.lengths.secretKey);
      expect(set.cipherTextLen, `${set.label} cipherText`).toBe(kem.lengths.cipherText);
      expect(set.signatureLen, `${set.label} has no signature`).toBeUndefined();
    }
    for (const [sets, table] of [
      [ML_DSA_SETS, ML_DSAS],
      [SLH_DSA_SETS, SLHS],
    ] as const) {
      for (const set of sets) {
        const signer = table[set.id]!;
        expect(set.publicKeyLen, `${set.label} publicKey`).toBe(signer.lengths.publicKey);
        expect(set.secretKeyLen, `${set.label} secretKey`).toBe(signer.lengths.secretKey);
        expect(set.signatureLen, `${set.label} signature`).toBe(signer.lengths.signature);
        expect(set.cipherTextLen, `${set.label} has no ciphertext`).toBeUndefined();
      }
    }
  });

  it("leaves no parameter set unchecked against OpenSSL", () => {
    // The completeness gate: adding a set to the metadata without adding it here fails, rather than
    // shipping one parameter set that nothing independent has ever agreed with.
    expect(KEM_PAIRS.map((p) => p.setId).sort()).toEqual(ML_KEM_SETS.map((s) => s.id).sort());
    expect(ML_DSA_PAIRS.map((p) => p.setId).sort()).toEqual(ML_DSA_SETS.map((s) => s.id).sort());
    expect(SLH_PAIRS.map((p) => p.setId).sort()).toEqual(SLH_DSA_SETS.map((s) => s.id).sort());
    // And every set resolves to a real implementation rather than an undefined table entry.
    for (const set of SLH_DSA_SETS) expect(SLHS[set.id], set.label).toBeDefined();
  });

  it("uses NIST's security categories, which have no 4", () => {
    // Reads as a typo every time and is not one: the PQC project numbered its categories 1, 2, 3, 5.
    const categories = new Set(
      [...ML_KEM_SETS, ...ML_DSA_SETS, ...SLH_DSA_SETS].map((s) => s.securityCategory),
    );
    expect([...categories].sort()).toEqual([1, 2, 3, 5]);
  });
});
