import type { ToolResult, ToolResultField, ToolStream } from "@ocs/engine";
import {
  computeAsconPrfShort,
  computeChaskey,
  computeCmac,
  computeHmac,
  computeKmac,
  computePelican,
  computePoly1305,
  computePoly1305Aes,
  computeSiphash,
  computeSiphash13,
  computeSiphash48,
  computeHalfSiphash,
  createAsconMacStream,
  createAsconPrfStream,
  createHighwayStream,
  createHmacStream,
  createSkeinMacStream,
  createKmacStream,
  createPoly1305Stream,
  type MacHasher,
} from "./bindings";
import { requireHmacHash } from "./catalogue/tool-meta";
import { resolveMac, type ResolvedMac } from "./resolve";
import type { MacSpec } from "./spec";

/**
 * Truncation happens here, once, after the full tag is produced — never by asking the
 * primitive for fewer bytes.
 *
 * That distinction matters and goes the opposite way for the two tools that allow it. An
 * HMAC tag may be cut to any length and the prefix is exactly what the standards mean by
 * a truncated HMAC. KMAC's length is bound into the computation, so asking for 32 bytes
 * and truncating 64 give different answers — which is why `truncateTo` is HMAC-only and
 * KMAC's length goes to the primitive instead.
 */
function truncate(tag: Uint8Array, resolved: ResolvedMac): Uint8Array {
  if (resolved.truncateTo === undefined || resolved.truncateTo >= tag.length) return tag;
  return tag.slice(0, resolved.truncateTo);
}

function fields(resolved: ResolvedMac): ToolResultField[] {
  const out: ToolResultField[] = [];

  if (resolved.toolId === "hmac") {
    const hash = requireHmacHash(resolved.hashId);
    out.push({ label: "Construction", value: `HMAC-${hash.label}` });
    out.push({ label: "Key length", value: `${resolved.key.length} bytes` });
    if (resolved.key.length < hash.outputLen) {
      out.push({
        label: "Key strength",
        value: `${resolved.key.length * 8} bits`,
        // Said next to the result rather than only in Checks: this is the number that
        // bounds the whole thing, and it is invisible otherwise.
        hint: `Below ${hash.label}'s ${hash.outputLen}-byte output, so the key — not the hash — is the limit on forgery resistance.`,
      });
    }
    if (resolved.truncateTo !== undefined) {
      out.push({
        label: "Truncated",
        value: `${resolved.truncateTo} of ${hash.outputLen} bytes`,
        hint: `Forgery succeeds with probability 2^-${resolved.truncateTo * 8} per attempt.`,
      });
    }
  }

  if (resolved.toolId === "kmac") {
    out.push({
      label: "Construction",
      value: `${resolved.kmacVariant === "kmac256" ? "KMAC256" : "KMAC128"}, ${resolved.kmacOutputLen}-byte output`,
    });
    out.push({
      label: "Customization",
      value:
        resolved.customization.length === 0
          ? "(none)"
          : new TextDecoder().decode(resolved.customization),
      hint: "Domain separation, not a secret. The same key under a different customization string gives unrelated tags.",
    });
  }

  if (resolved.toolId === "poly1305") {
    out.push({
      label: "Key use",
      value: "Single message only",
      hint: "Authenticating a second message under this key lets an attacker solve for it and forge freely.",
    });
  }

  if (resolved.toolId === "cmac") {
    const bits = resolved.key.length * 8;
    out.push({ label: "Construction", value: `AES-${bits}-CMAC` });
  }

  return out;
}

export async function computeMac(spec: MacSpec, input: Uint8Array): Promise<ToolResult> {
  const result = resolveMac(spec);
  // An absent or wrong-length key is the normal state of a half-filled form, so it comes
  // back as a rendered result rather than an exception.
  if (!result.ok) return { error: result.problem };

  const r = result.resolved;
  let tag: Uint8Array;

  /**
   * Anything the binding refuses becomes a rendered result too, not a throw.
   *
   * Ascon-PRFShort is the case that made this necessary: its input is capped at 16 bytes, which a user
   * reaches by typing a seventeenth character rather than by misconfiguring anything. The resolver
   * cannot catch it -- the limit is on the *input*, which the resolver never sees -- so the guard has to
   * be here, and the same wrapper covers any future binding-level refusal for free.
   */
  try {
    switch (r.toolId) {
      case "hmac":
        tag = computeHmac(r.hashId, r.key, input);
        break;
      case "kmac":
        tag = computeKmac(r.kmacVariant, r.key, input, r.kmacOutputLen, r.customization);
        break;
      case "poly1305":
        tag = computePoly1305(r.key, input);
        break;
      case "cmac":
        tag = computeCmac(r.key, input);
        break;
      case "siphash":
        tag = computeSiphash(r.key, input);
        break;
      case "siphash13":
        tag = computeSiphash13(r.key, input);
        break;
      case "siphash48":
        tag = computeSiphash48(r.key, input);
        break;
      case "halfsiphash":
        tag = computeHalfSiphash(r.key, input);
        break;
      case "highwayhash": {
        const hasher = createHighwayStream(r.key, r.outputLen);
        hasher.update(input);
        tag = hasher.digest();
        break;
      }
      case "skeinmac": {
        const hasher = createSkeinMacStream(r.key, r.skeinState, r.outputLen);
        hasher.update(input);
        tag = hasher.digest();
        break;
      }
      case "asconmac": {
        const hasher = createAsconMacStream(r.key);
        hasher.update(input);
        tag = hasher.digest();
        break;
      }
      case "asconprf": {
        const hasher = createAsconPrfStream(r.key, r.outputLen);
        hasher.update(input);
        tag = hasher.digest();
        break;
      }
      case "asconprfs":
        tag = computeAsconPrfShort(r.key, input, r.outputLen);
        break;
      case "chaskey":
        tag = computeChaskey(r.key, input);
        break;
      case "pelican":
        tag = computePelican(r.key, input);
        break;
      case "poly1305-aes":
        tag = computePoly1305Aes(r.key, input);
        break;
      default:
        return { error: `No compute path for MAC tool: ${r.toolId}` };
    }
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }

  return { bytes: truncate(tag, r), fields: fields(r) };
}

export function createMacStream(spec: MacSpec): ToolStream {
  const result = resolveMac(spec);
  if (!result.ok) {
    // Still a usable stream: it consumes the file and reports the problem, so the caller
    // needs no separate path for "the key is not filled in yet".
    return { update: () => {}, finish: () => ({ error: result.problem }) };
  }

  const r = result.resolved;
  let hasher: MacHasher | undefined;

  switch (r.toolId) {
    case "hmac":
      hasher = createHmacStream(r.hashId, r.key);
      break;
    case "kmac":
      hasher = createKmacStream(r.kmacVariant, r.key, r.kmacOutputLen, r.customization);
      break;
    case "poly1305":
      hasher = createPoly1305Stream(r.key);
      break;
    case "skeinmac":
      hasher = createSkeinMacStream(r.key, r.skeinState, r.outputLen);
      break;
    case "asconmac":
      hasher = createAsconMacStream(r.key);
      break;
    case "asconprf":
      hasher = createAsconPrfStream(r.key, r.outputLen);
      break;
    case "highwayhash":
      hasher = createHighwayStream(r.key, r.outputLen);
      break;
    default:
      // CMAC, SipHash and Ascon-PRFShort: all genuinely one-shot. See the note below.
      hasher = undefined;
  }

  if (!hasher) {
    /**
     * CMAC cannot stream — noble exposes it one-shot — and Ascon-PRFShort cannot either, since its
     * input is capped at 16 bytes and that length is baked into the initialising value. Buffering the
     * whole input and computing at the end is the honest fallback: it produces the right answer and
     * uses memory proportional to the file, which the input panel already warns about for any tool
     * whose manifest says `streaming: false`.
     *
     * HMAC used to be in this list for SM3, which was wrong twice over: the generic implementation
     * streams every hash now, and it always could have.
     */
    const chunks: Uint8Array[] = [];
    let length = 0;
    let finished = false;
    return {
      update(chunk) {
        if (finished) throw new Error("Cannot update a MAC stream after finish().");
        chunks.push(chunk.slice());
        length += chunk.length;
      },
      finish() {
        if (finished) throw new Error("finish() called twice on the same MAC stream.");
        finished = true;
        const joined = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) {
          joined.set(chunk, offset);
          offset += chunk.length;
        }
        const tag =
          r.toolId === "cmac"
            ? computeCmac(r.key, joined)
            : computeHmac(r.hashId, r.key, joined);
        return { bytes: truncate(tag, r), fields: fields(r) };
      },
    };
  }

  let finished = false;
  return {
    update(chunk) {
      if (finished) throw new Error("Cannot update a MAC stream after finish().");
      hasher!.update(chunk);
    },
    finish() {
      if (finished) throw new Error("finish() called twice on the same MAC stream.");
      finished = true;
      return { bytes: truncate(hasher!.digest(), r), fields: fields(r) };
    },
  };
}
