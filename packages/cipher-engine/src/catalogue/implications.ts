import type { OptionCatalogue, OptionDef } from "./options";
import { encodingOptionId } from "./options";

/** Transitive closure of `implies` for one option id. */
export function impliedBy(
  catalogue: OptionCatalogue,
  id: string,
  seen = new Set<string>(),
): Set<string> {
  const def = catalogue.get(id);
  if (!def?.implies) return seen;
  for (const child of def.implies) {
    if (seen.has(child)) continue;
    seen.add(child);
    impliedBy(catalogue, child, seen);
  }
  return seen;
}

/**
 * Every option id made redundant by the currently active options.
 * The form uses this to grey out controls and explain why.
 */
export function redundantOptionIds(
  catalogue: OptionCatalogue,
  active: readonly string[],
): Map<string, string> {
  const result = new Map<string, string>();
  for (const id of active) {
    for (const implied of impliedBy(catalogue, id)) {
      if (active.includes(implied)) result.set(implied, id);
    }
  }
  return result;
}

/** Pairs of active options that contradict each other. */
export function conflictingPairs(
  catalogue: OptionCatalogue,
  active: readonly string[],
): [string, string][] {
  const set = new Set(active);
  const pairs: [string, string][] = [];
  for (const id of active) {
    const def = catalogue.get(id);
    for (const other of def?.conflictsWith ?? []) {
      if (!set.has(other)) continue;
      const pair: [string, string] = id < other ? [id, other] : [other, id];
      if (!pairs.some(([a, b]) => a === pair[0] && b === pair[1])) pairs.push(pair);
    }
  }
  return pairs;
}

/** Options that are active but whose prerequisites are not. */
export function unmetRequirements(
  catalogue: OptionCatalogue,
  active: readonly string[],
): [string, string][] {
  const set = new Set(active);
  const missing: [string, string][] = [];
  for (const id of active) {
    for (const need of catalogue.get(id)?.requires ?? []) {
      if (!set.has(need)) missing.push([id, need]);
    }
  }
  return missing;
}

/**
 * Sanity check for a tool's catalogue data, exercised by every tool family's
 * test suite. Catalogue data is the bulk of this repo and none of it is
 * type-checkable beyond its shape — a `bytes` option with no length spec, or an
 * `implies` pointing at a deleted id, compiles perfectly and then misbehaves at
 * runtime. This is the guard that turns those into test failures.
 */
export function validateCatalogue(options: readonly OptionDef[]): string[] {
  const problems: string[] = [];
  const ids = new Set<string>();
  const ordersByGroup = new Map<string, Map<number, string>>();

  for (const o of options) {
    if (ids.has(o.id)) problems.push(`duplicate option id: ${o.id}`);
    ids.add(o.id);

    let groupOrders = ordersByGroup.get(o.group);
    if (!groupOrders) {
      groupOrders = new Map();
      ordersByGroup.set(o.group, groupOrders);
    }
    const clash = groupOrders.get(o.order);
    if (clash) {
      problems.push(`duplicate order ${o.order} in group ${o.group}: ${clash} and ${o.id}`);
    }
    groupOrders.set(o.order, o.id);

    if (o.kind === "enum" && (!o.choices || o.choices.length === 0)) {
      problems.push(`enum option ${o.id} has no choices`);
    }
    if (o.kind !== "enum" && o.choices) {
      problems.push(`non-enum option ${o.id} declares choices`);
    }
    if ((o.kind === "text" || o.kind === "number" || o.kind === "password") && !o.arg) {
      problems.push(`value option ${o.id} has no arg spec`);
    }
    if (o.kind === "bytes" && !o.bytesLength) {
      problems.push(`bytes option ${o.id} has no bytesLength spec`);
    }
    // A `list` decodes each element the same way a `bytes` option decodes its single value, so
    // both may carry a length spec and an encoding; nothing else may.
    if (o.kind !== "bytes" && o.kind !== "list" && o.bytesLength) {
      problems.push(`${o.id} is a ${o.kind} option and cannot declare bytesLength`);
    }
    if (o.kind !== "bytes" && o.kind !== "list" && o.defaultBytesEncoding) {
      problems.push(`${o.id} is a ${o.kind} option and cannot declare defaultBytesEncoding`);
    }
    if (o.kind !== "list" && o.maxItems !== undefined) {
      problems.push(`${o.id} is a ${o.kind} option and cannot declare maxItems`);
    }
    if (o.kind === "list" && o.maxItems !== undefined && o.maxItems < 1) {
      problems.push(`list option ${o.id} has a maxItems of ${o.maxItems}`);
    }
    if (o.arg?.multiline && o.kind !== "text" && o.kind !== "password") {
      problems.push(`${o.id} sets multiline on a ${o.kind} option, which cannot render it`);
    }
    if (o.kind === "password" && !o.secret) {
      problems.push(`password option ${o.id} is not marked secret`);
    }
  }

  // Second pass: everything that needs the complete id set. Checking these in the
  // loop above would only see ids declared *before* the current entry, so a
  // forward reference — or a collision with an entry further down the list —
  // would pass silently.
  for (const o of options) {
    for (const ref of [
      ...(o.implies ?? []),
      ...(o.conflictsWith ?? []),
      ...(o.requires ?? []),
    ]) {
      if (!ids.has(ref)) problems.push(`${o.id} references unknown option ${ref}`);
    }
    // A `bytes` option's companion encoding selector is synthesised by the form
    // from `encodingOptionId(id)`, so a real catalogue entry under that name
    // would render twice and fight over the same key.
    if ((o.kind === "bytes" || o.kind === "list") && ids.has(encodingOptionId(o.id))) {
      problems.push(
        `${o.id} collides with the synthesised encoding option ${encodingOptionId(o.id)}`,
      );
    }
  }

  return problems;
}
