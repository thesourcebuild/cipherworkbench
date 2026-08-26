import type { LintRule } from "@ocs/contracts/diagnostic";
import {
  getRsaHash,
  hashOutputLength,
  matchingHashFor,
  requireAsymmetricTool,
} from "../catalogue/tool-meta";
import {
  OPTION_CURVE,
  OPTION_HASH,
  OPTION_OPERATION,
  OPTION_PARAM_SET,
  OPTION_SCHEME,
  readHash,
  readOperation,
  readScheme,
  withHash,
  withScheme,
} from "../pure";
import { resolveAsymmetric } from "../resolve";
import type { AsymmetricSpec } from "../spec";

export const RULE_CODES = [
  "A001",
  "A002",
  "A003",
  "A004",
  "A005",
  "A006",
  "A007",
  "A008",
  "A009",
  "A010",
  "A011",
] as const;

/** The operation, read without going through the resolver -- the info rules need only this. */
function operationOf(spec: AsymmetricSpec) {
  return readOperation(spec.options, requireAsymmetricTool(spec.variant).operations);
}

export const RULES: readonly LintRule<AsymmetricSpec>[] = [
  {
    /**
     * Everything the resolver refuses: a missing key, a key of the wrong length for the curve,
     * an unparseable encoding, a signature in the wrong format.
     *
     * One rule rather than several, as in the cipher family. The resolver already produces a
     * message naming the specific problem and the curve it applies to; a separate key-length
     * rule would have to duplicate that logic to say the same thing.
     */
    code: "A001",
    check(spec) {
      const result = resolveAsymmetric(spec);
      if (result.ok) return [];
      return [
        {
          code: "A001",
          level: "error",
          message: result.problem,
          optionIds: [result.optionId],
        },
      ];
    },
  },
  {
    /**
     * A collision-broken hash under a signature scheme: MD5 or SHA-1.
     *
     * Which hashes those are comes off `RsaHashMeta.broken` rather than an id list here, so a
     * hash that falls tomorrow gets flagged in the options form and in this rule from one
     * edit. That is the same reason the cipher family reads `security` off its tool metadata.
     *
     * `insecure` rather than `warning`: a chosen-prefix collision for SHA-1 has been produced
     * at practical cost and MD5's has been trivial for fifteen years, and a signature scheme
     * is precisely where a collision becomes a forgery -- two documents, one valid signature.
     * Both stay available because reading old signatures requires them, and the level says
     * what they are for.
     */
    code: "A002",
    check(spec) {
      if (spec.variant === "ed25519") return [];
      const operation = operationOf(spec);
      if (operation === "generate" || operation === "derive") return [];

      const hashId = readHash(spec.options);
      // ECDSA offers a subset of the same names, so an unknown id here is a stale share link.
      const meta = getRsaHash(hashId);
      const broken = spec.variant === "ecdsa" ? hashId === "SHA-1" : (meta?.broken ?? false);
      if (!broken) return [];

      const signing = operation === "sign" || operation === "verify";
      return [
        {
          code: "A002",
          level: "insecure",
          message: signing
            ? `${hashId} signatures are forgeable. Use SHA-256.`
            : `${hashId} is the wrong choice for OAEP. Use SHA-256.`,
          detail: signing
            ? `A signature covers a hash rather than a document, so two documents sharing a hash share a signature. ${hashId === "MD5" ? "MD5 collisions cost seconds on a laptop and were used to forge a real CA certificate in 2008." : "A chosen-prefix collision for SHA-1 has been produced for a cost measured in tens of thousands of dollars, and it is how the attacks on PGP key identities and Git object ids work."} Verifying an old signature is a legitimate reason to select this. Making a new one is not.`
            : "OAEP does not collapse with a weak hash the way a signature does -- it needs the hash to behave as a random oracle rather than to resist collisions. It is still the wrong default and should be a deliberate interop decision rather than an accident.",
          optionIds: [OPTION_HASH],
          fix: {
            label: "Switch to SHA-256",
            apply: (s) => ({ ...s, options: withHash(s.options, "SHA-256") }),
          },
        },
      ];
    },
  },
  {
    /**
     * PKCS#1 v1.5 for a *new* signature.
     *
     * Fires only on sign, not on verify. Checking an existing RS256 JWT or an X.509 certificate
     * requires this scheme, and warning every time someone verifies one would be noise about a
     * choice they did not make.
     */
    code: "A003",
    check(spec) {
      if (spec.variant !== "rsa") return [];
      if (operationOf(spec) !== "sign") return [];
      if (readScheme(spec.options) !== "pkcs1v15") return [];

      return [
        {
          code: "A003",
          level: "warning",
          message: "PKCS#1 v1.5 has no security proof. Prefer RSA-PSS for a new signature.",
          detail:
            "The padding is a fixed pattern rather than a randomised encoding, and it has no reduction to the RSA problem -- which has left a long trail of implementation-specific forgery attacks, most of them exploiting verifiers that parse the padded block loosely. PSS costs nothing extra and is provably secure in the same model. Keep this scheme when something on the other end requires it, which JWT RS256, most certificates and most SSH keys do.",
          optionIds: [OPTION_SCHEME],
          fix: {
            label: "Switch to RSA-PSS",
            apply: (s) => ({ ...s, options: withScheme(s.options, "pss") }),
          },
        },
      ];
    },
  },
  {
    /**
     * A hash weaker than the one the curve is standardised with.
     *
     * The comparison is against `matchingHashFor`, not against the curve's field size directly.
     * Comparing to the field size looks more principled and is wrong: P-521's order is 66 bytes
     * and the largest SHA-2 digest is 64, so every correct ES512 configuration would be flagged.
     * There is no 66-byte hash, and the standards pair P-521 with SHA-512 precisely because that
     * is the closest thing there is.
     *
     * What the rule is really about: ECDSA treats the digest as an integer modulo the curve
     * order, so a 32-byte digest under P-384 leaves the top of that integer at zero and caps the
     * scheme at SHA-256's strength while paying P-384's cost. That is a mismatch, not a break --
     * the signature is valid and verifies anywhere -- hence `warning`.
     */
    code: "A004",
    check(spec) {
      if (spec.variant !== "ecdsa") return [];
      const operation = operationOf(spec);
      if (operation !== "sign" && operation !== "verify") return [];

      const result = resolveAsymmetric(spec);
      if (!result.ok || !result.resolved.curve) return [];
      const curve = result.resolved.curve;
      const hash = readHash(spec.options);
      const better = matchingHashFor(curve.id);
      if (hashOutputLength(hash) >= hashOutputLength(better)) return [];

      return [
        {
          code: "A004",
          level: "warning",
          message: `${hash} is weaker than ${curve.label} deserves, so the signature is only as strong as ${hash}.`,
          detail: `ECDSA treats the digest as an integer modulo the curve order. A ${hashOutputLength(hash)}-byte digest under a curve with a ${curve.secretLen}-byte order leaves the rest of that integer at zero, which caps the scheme at the hash's strength while paying the curve's cost in key size, signature size and computation. ${better} is what ${curve.label} is paired with in JOSE, TLS and SP 800-186. This is a mismatch rather than a break: the signature is valid and will verify anywhere.`,
          optionIds: [OPTION_HASH, OPTION_CURVE],
          fix: {
            label: `Switch to ${better}`,
            apply: (s) => ({ ...s, options: withHash(s.options, better) }),
          },
        },
      ];
    },
  },
  {
    /**
     * The ECDH note, unconditional on derive.
     *
     * Unconditional because the tool cannot see what happens to the bytes next, and using a raw
     * shared secret as a key is both the commonest mistake in this family and invisible: it
     * works, it round-trips, and it is weaker than it looks. Level `info` rather than `warning`
     * -- nothing is wrong with the derivation itself, and this is about the step after it.
     */
    code: "A005",
    check(spec) {
      if (spec.variant !== "ecdh" || operationOf(spec) !== "derive") return [];
      return [
        {
          code: "A005",
          level: "info",
          message: "A shared secret is not a key. Expand it with HKDF before using it.",
          detail:
            "The output is a curve point's coordinate: it has full entropy but is not uniformly distributed over byte strings, and it carries no binding to the context it was agreed in. Every real protocol runs it through a KDF, which both flattens the distribution and mixes in transcript data so the same pair of keys yields different keys for different sessions. The HKDF tool in the KDF family takes this output directly.",
          optionIds: [],
        },
      ];
    },
  },
  {
    /**
     * RSA encryption, and the 190-byte ceiling nobody expects.
     *
     * `info` on the encrypt operation, because the ceiling is not a misconfiguration -- it is
     * what RSA is. The error message in `compute` says the same thing when the input is actually
     * too long; this says it before the attempt, which is when it is useful.
     */
    code: "A006",
    check(spec) {
      if (spec.variant !== "rsa" || operationOf(spec) !== "encrypt") return [];
      const hash = readHash(spec.options);
      const capacity = 256 - 2 * hashOutputLength(hash) - 2;
      return [
        {
          code: "A006",
          level: "info",
          message: `RSA-OAEP carries at most ${capacity} bytes with a 2048-bit key and ${hash}.`,
          detail:
            "RSA encrypts a number smaller than its modulus, and OAEP spends two hash lengths plus two bytes of that on padding. It cannot encrypt a message, and no amount of key size fixes that -- a 4096-bit key raises the ceiling to about 446 bytes. What everything actually does is hybrid encryption: generate a symmetric key, encrypt the data with that using the AES tool, and encrypt the symmetric key here.",
          // No option to point at: the key size field only exists on the generate operation.
          optionIds: [],
        },
      ];
    },
  },
  {
    /**
     * The one thing about key generation the user has to act on.
     *
     * Private keys are marked `secret` in the catalogue, which means they are stripped from
     * share links and never written to the persisted spec -- deliberately, and the reason this
     * app is safe to leave open on a shared screen. The consequence is that a generated key
     * exists only in the result panel, and recomputing replaces it. Saying so as a diagnostic
     * puts it where the user is already looking when something goes wrong.
     */
    code: "A007",
    check(spec) {
      if (operationOf(spec) !== "generate") return [];
      return [
        {
          code: "A007",
          level: "info",
          message: "Copy the private key before doing anything else. Nothing here stores it.",
          detail:
            "Private keys are excluded from share links and from saved state by design, so this one lives only in the result panel below. Changing any setting, or simply recomputing, produces a different key -- there is no way to get this one back. Paste it into the private-key field, or somewhere you trust, before moving on.",
          // The key fields are hidden while generating, so there is nothing to highlight.
          optionIds: [],
        },
      ];
    },
  },
  {
    /**
     * Signing through the in-repo RSA path, whose modular exponentiation is not constant-time.
     *
     * This is the honest cost of covering the ten hashes `crypto.subtle` refuses. Stated as a
     * `warning` on signing only, and deliberately not on verification: verification uses the
     * public exponent and no secret, so there is nothing for timing to leak. The rule exists
     * because the user can act on it — pick a WebCrypto hash, or use a key that is not
     * protecting anything real.
     *
     * Not `insecure`: the signature produced is correct and interoperable, which is what that
     * level would wrongly deny. What is at risk is the key, under an attacker who can time
     * this tab — which in a local single-user workbench is a caveat rather than a hole. Saying
     * so precisely is the point; inflating it would make the panel less trustworthy.
     */
    code: "A008",
    check(spec) {
      if (spec.variant !== "rsa" || operationOf(spec) !== "sign") return [];
      const hashId = readHash(spec.options);
      const meta = getRsaHash(hashId);
      if (!meta || meta.webcrypto) return [];

      return [
        {
          code: "A008",
          level: "warning",
          message: `${hashId} signing runs on this app's own RSA, not the platform's.`,
          detail:
            "WebCrypto implements four hashes for RSA and refuses the rest, and it exposes no raw RSA primitive to build the others on — so this signature was produced by the RFC 8017 code in @ocs/algos, using bigint arithmetic. It is a correct, interoperable signature; OpenSSL verifies it, and tests/openssl-parity.test.ts asserts that on every run. The caveat is that the modular exponentiation is square-and-multiply and its timing depends on the private exponent's bits. There is no remote observer in a local workbench, so this is a thing to know rather than a hole — but if the key protects something real, sign with SHA-256, SHA-384, SHA-512 or SHA-1, which run on the platform's own implementation.",
          optionIds: [OPTION_HASH],
          fix: {
            label: "Switch to SHA-256 (WebCrypto)",
            apply: (s) => ({ ...s, options: withHash(s.options, "SHA-256") }),
          },
        },
      ];
    },
  },
  {
    /**
     * A KEM is not public-key encryption, and this is the misunderstanding worth spending a rule on.
     *
     * Every other tool in this family that takes a public key encrypts something. `encapsulate` does
     * not: it invents a random secret and returns a ciphertext carrying *that*, with no message input
     * anywhere. Someone arriving from RSA-OAEP will look for the input panel, and the input panel is
     * ignored -- so this says what to do instead rather than leaving them to conclude the tool is
     * broken.
     */
    code: "A009",
    check(spec) {
      const result = resolveAsymmetric(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (r.tool.id !== "mlkem") return [];
      if (r.operation !== "encapsulate" && r.operation !== "decapsulate") return [];

      return [
        {
          code: "A009",
          level: "info",
          message: "A KEM establishes a key; it does not encrypt your message.",
          detail:
            "Encapsulation takes a public key and nothing else, and returns a fresh random 32-byte shared secret plus a ciphertext carrying it -- the input panel is not read at all. To protect data, encapsulate, then use the shared secret as an AES-256-GCM or ChaCha20-Poly1305 key. Unlike an ECDH result the secret needs no KDF first: FIPS 203 specifies it as uniformly random output, which is exactly why it is safe to use directly.",
          optionIds: [OPTION_OPERATION],
        },
      ];
    },
  },
  {
    /**
     * SLH-DSA's `s` variants are slow enough that a user will assume the app has hung.
     *
     * Between one and three seconds of synchronous work, which is a diagnostic rather than a defect:
     * it is the parameter set doing what it was designed to do. Saying so beforehand is the whole
     * value -- and naming the `f` alternative gives the reader something to act on, which is the bar
     * a rule has to clear here.
     */
    code: "A010",
    check(spec) {
      const result = resolveAsymmetric(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (r.tool.id !== "slhdsa" || r.operation !== "sign") return [];
      // The trade is encoded in the set id, which is where FIPS 205 puts it.
      if (!r.paramSet?.id.endsWith("s")) return [];

      const faster = r.paramSet.id.replace(/s$/, "f");
      return [
        {
          code: "A010",
          level: "info",
          message: `${r.paramSet.label} signing takes one to three seconds, by design.`,
          detail: `The 's' variants minimise signature size by making the hypertree deeper, which means more hash calls per signature. The '${faster}' set produces a signature roughly twice as large in a fraction of the time, and verification is fast in both. Neither is more secure than the other -- the security category is the same.`,
          optionIds: [OPTION_PARAM_SET],
          fix: {
            label: "Switch to the fast variant",
            apply: (s) => ({
              ...s,
              // Read from the spec handed in, never from the closure: `applyAllFixes` runs every fix
              // in one pass, so another may already have changed the set.
              options: {
                ...s.options,
                [OPTION_PARAM_SET]: String(s.options[OPTION_PARAM_SET] ?? "").replace(/s$/, "f"),
              },
            }),
          },
        },
      ];
    },
  },
  {
    /**
     * Post-quantum keys and signatures are large, and the number is the useful part.
     *
     * Not a warning about anything: it is the fact people need before choosing one of these, and the
     * comparison with Ed25519 is what makes it land. Sized `info` and shown only where a size is
     * actually being produced.
     */
    code: "A011",
    check(spec) {
      const result = resolveAsymmetric(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      const set = r.paramSet;
      if (!set || set.signatureLen === undefined) return [];
      if (r.operation !== "sign" && r.operation !== "generate") return [];

      const ratio = Math.round(set.signatureLen / 64);
      return [
        {
          code: "A011",
          level: "info",
          message: `${set.label} signatures are ${set.signatureLen} bytes — about ${ratio} times an Ed25519 signature.`,
          detail: `The public key is ${set.publicKeyLen} bytes and the private key ${set.secretKeyLen}, against Ed25519's 32 and 32. That size is the price of post-quantum security with today's standards, and it is why deployments are hybrid: TLS pairs ML-KEM with X25519 rather than replacing it, and certificate chains carrying ML-DSA signatures grow by kilobytes per link. Worth knowing before it is a surprise in a protocol with a size limit.`,
          optionIds: [OPTION_PARAM_SET],
        },
      ];
    },
  },
];
