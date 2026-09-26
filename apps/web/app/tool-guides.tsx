import type { ComponentType } from "react";

export interface ToolGuideDef {
  title: string;
  subtitle?: string;
  badge?: string;
  load: () => Promise<{ default: ComponentType }>;
}

/**
 * Registry of interactive guides for tools across all families.
 * Each tool guide is loaded dynamically on demand when the user opens the guide modal.
 */
const TOOL_GUIDES: Record<string, ToolGuideDef> = {
  "cert-creator": {
    title: "X.509 Certificate Architecture & Modern PKI Guide",
    subtitle:
      "Dual-stack (IPv4 & IPv6) TLS validation, mTLS hierarchies, and deployment standards",
    badge: "PKI Guide ↗",
    load: () => import("@ocs/certificates/guide"),
  },
};

/**
 * Retrieve the guide definition for a tool if one is registered.
 */
export function getToolGuide(toolId: string): ToolGuideDef | undefined {
  return TOOL_GUIDES[toolId];
}
