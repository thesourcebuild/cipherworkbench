"use client";

import { useEffect, useState } from "react";
import { Panel } from "@ocs/ui";
import { createBmpObjectUrl } from "./cipher-image-object-url";

function useBmpObjectUrl(content: Blob | Uint8Array | undefined): string | undefined {
  const [url, setUrl] = useState<string>();

  useEffect(() => {
    if (!content) {
      setUrl(undefined);
      return;
    }
    const resource = createBmpObjectUrl(content);
    setUrl(resource.url);
    return () => resource.revoke();
  }, [content]);

  return url;
}

interface CipherImagePreviewProps {
  source?: File;
  transformed?: Uint8Array;
}

export function CipherImagePreview({ source, transformed }: CipherImagePreviewProps) {
  const sourceUrl = useBmpObjectUrl(source);
  const transformedUrl = useBmpObjectUrl(transformed);
  if (!sourceUrl && !transformedUrl) return null;

  return (
    <Panel
      title="Bitmap preview"
      description="Compare the preserved source structure with the AES-ECB pixel transform."
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <PreviewCard label="Before" url={sourceUrl} hook="before" />
        <PreviewCard label="After" url={transformedUrl} hook="after" />
      </div>
      <p className="mt-3 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
        ECB encrypts identical 16-byte blocks identically, so repeated colors and silhouettes
        can remain visible. The final pixel bytes that do not fill a block are unchanged; this
        keeps the BMP length valid but leaves those bytes in plaintext.
      </p>
    </Panel>
  );
}

function PreviewCard({
  label,
  url,
  hook,
}: {
  label: string;
  url?: string;
  hook: "before" | "after";
}) {
  return (
    <figure className="min-w-0 overflow-hidden rounded-lg border border-slate-200 bg-[linear-gradient(45deg,#e2e8f0_25%,transparent_25%),linear-gradient(-45deg,#e2e8f0_25%,transparent_25%),linear-gradient(45deg,transparent_75%,#e2e8f0_75%),linear-gradient(-45deg,transparent_75%,#e2e8f0_75%)] bg-size-[16px_16px] bg-position-[0_0,0_8px,8px_-8px,-8px_0] dark:border-slate-700 dark:bg-slate-900">
      <figcaption className="border-b border-slate-200 bg-white/90 px-3 py-2 text-xs font-semibold dark:border-slate-700 dark:bg-slate-950/90">
        {label}
      </figcaption>
      <div className="flex min-h-48 items-center justify-center p-3">
        {url ? (
          <img
            src={url}
            alt={`${label} BMP preview`}
            data-ocs-cipher-image-preview={hook}
            className="max-h-96 max-w-full object-contain [image-rendering:pixelated]"
          />
        ) : (
          <span className="text-xs text-slate-500">Waiting for a valid BMP result.</span>
        )}
      </div>
    </figure>
  );
}
