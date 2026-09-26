"use client";

import type { ComponentType, ReactNode } from "react";
import type { OptionValue } from "@ocs/contracts";
import type { ToolDefinition, ToolSpecBase } from "@ocs/engine";
import type { ComputeState } from "./use-compute";
import { CertCreatorWorkbench } from "./cert-creator-workbench";
import { CsrWorkbench } from "./csr-workbench";

export interface CustomWorkbenchProps {
  tool: ToolDefinition<ToolSpecBase>;
  spec: ToolSpecBase;
  setOptionValue: (id: string, value: OptionValue | undefined) => void;
  recompute: () => void;
  canRecompute: boolean;
  state: ComputeState;
  tag?: string | readonly string[];
  inputStep?: ReactNode;
  generateLength?: (optionId: string) => number | undefined;
  acceptedByteLengths?: (optionId: string) => readonly number[] | undefined;
}

const CUSTOM_WORKBENCHES: Record<string, ComponentType<CustomWorkbenchProps>> = {
  "cert-creator": CertCreatorWorkbench as ComponentType<CustomWorkbenchProps>,
  "csr-creator": CsrWorkbench as ComponentType<CustomWorkbenchProps>,
  "csr-signer": CsrWorkbench as ComponentType<CustomWorkbenchProps>,
};

/**
 * Returns a custom specialized interactive workbench if one is registered for the tool ID,
 * otherwise undefined to indicate the tool uses the standard generic workbench panels.
 */
export function getCustomWorkbench(
  toolId: string,
): ComponentType<CustomWorkbenchProps> | undefined {
  return CUSTOM_WORKBENCHES[toolId];
}
