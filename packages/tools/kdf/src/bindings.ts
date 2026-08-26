import bcryptjs from "bcryptjs";

/**
 * bcrypt, and nothing else.
 *
 * The six key *derivations* moved to `./key-source.ts` and are re-exported below, so every existing
 * caller is unchanged. The split is not tidiness: `bcryptjs` is imported at module scope here, so any
 * import from this file drags a password-hashing library into the importer's chunk -- and the cipher
 * family now derives keys through the same functions while never hashing a password.
 *
 * bcrypt comes from `bcryptjs` because `@noble` has none -- see the note in
 * `packages/algos/WHY-NOT-A-LIBRARY.md`. Unlike the hash gaps it is pure ESM with zero dependencies
 * and works unchanged in a browser, so there was no reason to write another one.
 */

/**
 * bcrypt takes the password as a string, not bytes.
 *
 * That is not this wrapper being lazy — bcrypt is *defined* over a NUL-terminated C string,
 * which is where its 72-byte limit and its historical NUL-byte truncation bugs come from.
 * Passing bytes would require choosing an encoding anyway, and UTF-8 is what every
 * implementation uses.
 */
export function hashBcrypt(password: string, cost: number): string {
  return bcryptjs.hashSync(password, bcryptjs.genSaltSync(cost));
}

export function verifyBcrypt(password: string, stored: string): boolean {
  try {
    return bcryptjs.compareSync(password, stored);
  } catch {
    // compareSync throws on a malformed hash string rather than returning false.
    return false;
  }
}

/** Reads the cost out of a bcrypt hash so Verify mode can report what it used. */
export function bcryptCostOf(stored: string): number | undefined {
  try {
    return bcryptjs.getRounds(stored);
  } catch {
    return undefined;
  }
}

/**
 * The derivations, re-exported so this module stays the KDF family's single binding entry point.
 *
 * `export *` rather than a list, so a seventh derivation added next door needs no edit here.
 */
export * from "./key-source";
