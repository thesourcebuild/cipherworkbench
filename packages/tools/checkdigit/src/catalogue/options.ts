import { createOptionCatalogue, type OptionCatalogue, type OptionDef } from "@ocs/engine";
import type { CheckDigitOptionGroup } from "./groups";

const ALL: readonly OptionDef<CheckDigitOptionGroup>[] = [];

const CACHE = new Map<string, OptionCatalogue<CheckDigitOptionGroup>>();

export function checkDigitCatalogueFor(
  toolId: string,
  _exposes: readonly string[],
): OptionCatalogue<CheckDigitOptionGroup> {
  let catalogue = CACHE.get(toolId);
  if (!catalogue) {
    catalogue = createOptionCatalogue<CheckDigitOptionGroup>([]);
    CACHE.set(toolId, catalogue);
  }
  return catalogue;
}

export function checkDigitOptionsFor(
  toolId: string,
  exposes: readonly string[],
): readonly OptionDef<CheckDigitOptionGroup>[] {
  return checkDigitCatalogueFor(toolId, exposes).options;
}

export const ALL_CHECK_DIGIT_OPTIONS = ALL;
