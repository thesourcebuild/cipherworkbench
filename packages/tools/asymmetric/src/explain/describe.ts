import { requireAsymmetricTool } from "../catalogue/tool-meta";
import { resolveAsymmetric } from "../resolve";
import type { AsymmetricSpec } from "../spec";

/** One sentence, shown under the tool header: what these exact settings will do. */
export function describeSpec(spec: AsymmetricSpec): string {
  const tool = requireAsymmetricTool(spec.variant);
  const result = resolveAsymmetric(spec);

  if (!result.ok) return `${tool.label} — ${result.problem}`;

  const r = result.resolved;
  const curve = r.curve?.label;

  /**
   * The post-quantum tools describe themselves first, because the generic arms below all name a curve
   * or an RSA modulus and neither exists here. Their own sentence is also where the size is worth
   * stating: the numbers are the whole reason someone hesitates over these schemes.
   */
  if (r.paramSet) {
    const set = r.paramSet;
    switch (r.operation) {
      case "generate":
        return `Generates a fresh ${set.label} keypair: a ${set.secretKeyLen}-byte private key and a ${set.publicKeyLen}-byte public key.`;
      case "encapsulate":
        return `Generates a shared secret for the holder of that ${set.label} public key, and a ${set.cipherTextLen}-byte ciphertext carrying it. There is no message input.`;
      case "decapsulate":
        return `Recovers the shared secret from a ${set.cipherTextLen}-byte ${set.label} ciphertext. Decapsulation never reports failure -- a ciphertext for another key gives a different secret.`;
      case "sign":
        return `Signs the input with ${set.label}, producing a ${set.signatureLen}-byte signature.`;
      case "verify":
        return `Checks a ${set.signatureLen}-byte ${set.label} signature against the input.`;
      default:
        return `${set.label}.`;
    }
  }

  switch (r.operation) {
    case "generate":
      return spec.variant === "rsa"
        ? `Generates a fresh ${r.modulusBits}-bit RSA keypair and exports it as PEM and JWK.`
        : `Generates a fresh ${curve ?? "Ed25519"} keypair. The private key is shown once and stored nowhere.`;

    case "sign":
      if (spec.variant === "rsa") {
        const scheme = r.scheme === "pkcs1v15" ? "RSASSA-PKCS1-v1_5" : "RSA-PSS";
        return `Signs the input with ${scheme} and ${r.hash}.`;
      }
      if (spec.variant === "ed25519") return "Signs the input with Ed25519. Deterministic.";
      return `Signs the input with ECDSA over ${curve} and ${r.hash}, in ${r.signatureFormat === "der" ? "DER" : "compact"} form. Deterministic, per RFC 6979.`;

    case "verify":
      if (spec.variant === "rsa") {
        const scheme = r.scheme === "pkcs1v15" ? "RSASSA-PKCS1-v1_5" : "RSA-PSS";
        return `Checks the ${r.signature.length}-byte signature against the input under ${scheme} and ${r.hash}.`;
      }
      if (spec.variant === "ed25519") {
        return `Checks the 64-byte Ed25519 signature against the input.`;
      }
      return `Checks the ${r.signature.length}-byte signature against the input under ECDSA over ${curve} and ${r.hash}.`;

    case "encrypt":
      return `Encrypts the input with RSA-OAEP and ${r.hash}${r.oaepLabel.length > 0 ? `, bound to a ${r.oaepLabel.length}-byte label` : ""}.`;

    case "decrypt":
      return `Decrypts the input with RSA-OAEP and ${r.hash}${r.oaepLabel.length > 0 ? `, expecting a ${r.oaepLabel.length}-byte label` : ""}.`;

    case "derive":
      // Naming the KDF requirement in the one-line description as well as in A005: it is the
      // single thing most likely to be got wrong after this tool has done its part correctly.
      return `Derives a shared secret over ${curve} from your private key and their public key. Expand it with HKDF before use.`;

    default:
      /**
       * `encapsulate` and `decapsulate` are handled above, where the parameter set is in scope, so
       * this arm is unreachable -- but the operation union is now wider than the classical tools use,
       * and a `switch` with no default would stop compiling rather than stay honest.
       */
      return tool.label;
  }
}
