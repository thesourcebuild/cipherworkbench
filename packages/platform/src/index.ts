import type { PlatformApi } from "@ocs/contracts";
import { isDesktopHost } from "./bridge";
import { electronPlatform } from "./electron";
import { webPlatform } from "./web";

export * from "./bridge";
export { webPlatform } from "./web";
export { electronPlatform } from "./electron";

let cached: PlatformApi | undefined;

/**
 * Chosen at runtime, not build time: the web app and the Electron renderer load
 * the same static bundle, so there is only one build of the UI. The bridge is
 * present or it is not.
 */
export function platform(): PlatformApi {
  cached ??= isDesktopHost() ? electronPlatform : webPlatform;
  return cached;
}

/** Test seam. */
export function __setPlatform(api: PlatformApi | undefined): void {
  cached = api;
}
