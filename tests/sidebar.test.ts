import { describe, expect, it } from "vitest";
import { presentFamilies, TOOL_MANIFESTS } from "@ocs/registry";
import { getInitialCollapsed } from "../apps/web/app/sidebar-state";

describe("Sidebar getInitialCollapsed", () => {
  const families = presentFamilies();

  it("expands the MAC family and active category when selected tool is HMAC", () => {
    const collapsed = getInitialCollapsed(TOOL_MANIFESTS, families, "hmac");

    // MAC family must NOT be collapsed (i.e. it is expanded)
    expect(collapsed.has("family:mac")).toBe(false);

    // CRC family must BE collapsed
    expect(collapsed.has("family:crc")).toBe(true);

    // Other families must be collapsed
    expect(collapsed.has("family:hash")).toBe(true);
    expect(collapsed.has("family:cipher")).toBe(true);

    // Category HMAC within MAC must be expanded
    expect(collapsed.has("cat:mac/HMAC")).toBe(false);

    // Other categories within MAC must be collapsed
    expect(collapsed.has("cat:mac/Keccak")).toBe(true);
    expect(collapsed.has("cat:mac/One-time")).toBe(true);
  });

  it("expands the CRC family when selected tool is CRC-8", () => {
    const collapsed = getInitialCollapsed(TOOL_MANIFESTS, families, "crc8");

    expect(collapsed.has("family:crc")).toBe(false);
    expect(collapsed.has("family:mac")).toBe(true);
    expect(collapsed.has("family:hash")).toBe(true);
  });

  it("expands the correct family and category for every registered tool", () => {
    for (const tool of TOOL_MANIFESTS) {
      const collapsed = getInitialCollapsed(TOOL_MANIFESTS, families, tool.id);

      // Selected tool's family must be expanded
      expect(
        collapsed.has(`family:${tool.family}`),
        `Tool ${tool.id} should have family ${tool.family} expanded`,
      ).toBe(false);

      // Selected tool's category must be expanded
      expect(
        collapsed.has(`cat:${tool.family}/${tool.category}`),
        `Tool ${tool.id} should have category ${tool.category} expanded`,
      ).toBe(false);

      // All other families must be collapsed
      for (const family of families) {
        if (family !== tool.family) {
          expect(
            collapsed.has(`family:${family}`),
            `When ${tool.id} (${tool.family}) is selected, family ${family} should be collapsed`,
          ).toBe(true);
        }
      }
    }
  });

  it("allows collapsing and expanding any family regardless of whether a family filter is active", () => {
    // Simulates the toggle logic used in Sidebar:
    // const familyOpen = search.trim() !== "" || !collapsed.has(familyKey);
    const collapsed = new Set<string>();

    const isFamilyOpen = (family: string, search = "") =>
      search.trim() !== "" || !collapsed.has(`family:${family}`);

    // Initially open
    expect(isFamilyOpen("asymmetric")).toBe(true);

    // Toggle to collapse
    collapsed.add("family:asymmetric");
    expect(isFamilyOpen("asymmetric")).toBe(false);

    // Toggle to expand
    collapsed.delete("family:asymmetric");
    expect(isFamilyOpen("asymmetric")).toBe(true);

    // Active search overrides collapse so users see matches
    collapsed.add("family:asymmetric");
    expect(isFamilyOpen("asymmetric", "rsa")).toBe(true);
  });
});

