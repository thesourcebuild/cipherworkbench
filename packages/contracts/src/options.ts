import { z } from "zod";

/**
 * Option values are stored in an open record keyed by a tool's own option id
 * rather than as named schema fields. This is deliberate: each tool family's
 * option catalogue (in `packages/tools/<family>`) is the single source of truth
 * for the UI, the reference docs, and the lint rules, so adding support for a
 * new option is a one-line data change with no schema migration.
 *
 * Note there is no `Uint8Array` member. Key/IV/nonce/salt material is held as a
 * *string plus its own encoding option* (see `BytesOption` in @ocs/engine), not
 * as raw bytes — so a spec stays JSON-serialisable for saved state and
 * share links, and so the UI can round-trip what the user actually typed rather
 * than a decoded form of it.
 */
export const OptionValue = z.union([z.boolean(), z.string(), z.number(), z.array(z.string())]);
export type OptionValue = z.infer<typeof OptionValue>;

export const OptionValues = z.record(z.string(), OptionValue);
export type OptionValues = z.infer<typeof OptionValues>;
