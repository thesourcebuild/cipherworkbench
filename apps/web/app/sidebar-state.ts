import type { ToolFamily, ToolManifest } from "@ocs/engine";

/**
 * Initial collapsed keys for the two-level sidebar tree.
 *
 * Expands the family and category containing the selected tool (falling back to the first family
 * if the tool is not found). All other families and categories are collapsed so that only the
 * relevant section is open on page load or filter reset.
 */
export function getInitialCollapsed(
  manifests: readonly ToolManifest[],
  families: readonly ToolFamily[],
  selectedId: string,
): Set<string> {
  const target = manifests.find((m) => m.id === selectedId);
  const targetFamily = target?.family ?? families[0] ?? "crc";
  const targetCategory = target?.category;
  const initial = new Set<string>();

  for (const f of families) {
    if (f !== targetFamily) {
      initial.add(`family:${f}`);
    }
  }

  for (const manifest of manifests) {
    if (manifest.family === targetFamily && targetCategory && manifest.category !== targetCategory) {
      initial.add(`cat:${targetFamily}/${manifest.category}`);
    }
  }

  return initial;
}
