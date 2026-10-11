export interface ObjectUrlResource {
  url: string;
  revoke(): void;
}

export interface ObjectUrlApi {
  createObjectURL(blob: Blob): string;
  revokeObjectURL(url: string): void;
}

/** Creates a BMP object URL with an idempotent cleanup function for React effects and tests. */
export function createBmpObjectUrl(
  content: Blob | Uint8Array,
  api: ObjectUrlApi = URL,
): ObjectUrlResource {
  const blob = new Blob([content as unknown as BlobPart], { type: "image/bmp" });
  const url = api.createObjectURL(blob);
  let live = true;
  return {
    url,
    revoke() {
      if (!live) return;
      live = false;
      api.revokeObjectURL(url);
    },
  };
}
