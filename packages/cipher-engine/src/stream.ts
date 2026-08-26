import type { ToolResult, ToolStream } from "./tool-definition";

/** 1 MiB. Large enough that per-chunk overhead vanishes, small enough to keep progress smooth. */
export const DEFAULT_CHUNK_SIZE = 1024 * 1024;

export interface StreamProgress {
  bytesProcessed: number;
  /** Absent when the source length is unknown (a stream rather than a File). */
  totalBytes?: number;
}

export interface RunStreamOptions {
  totalBytes?: number;
  onProgress?: (progress: StreamProgress) => void;
  /** Throttle progress callbacks to at most one per this many bytes. */
  progressInterval?: number;
  signal?: AbortSignal;
}

/**
 * Drive a `ToolStream` over an async source of chunks.
 *
 * This is the whole file-hashing pipeline, and it is host-agnostic on purpose:
 * the caller supplies `File.stream()` in the browser and the Electron renderer,
 * or an array of buffers in a test. Nothing here knows what a `File` is, which
 * is what lets the streaming-equals-one-shot invariant be tested without any
 * DOM at all.
 *
 * The chunks arriving here are whatever size the source produced — `File.stream()`
 * does not honour a requested size — so tools must not assume a block-aligned
 * `update`. Every `ToolStream` implementation buffers internally as needed.
 */
export async function runStream(
  stream: ToolStream,
  chunks: AsyncIterable<Uint8Array>,
  options: RunStreamOptions = {},
): Promise<ToolResult> {
  const { totalBytes, onProgress, progressInterval = DEFAULT_CHUNK_SIZE, signal } = options;

  let processed = 0;
  let lastReported = 0;

  onProgress?.({ bytesProcessed: 0, totalBytes });

  for await (const chunk of chunks) {
    if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
    stream.update(chunk);
    processed += chunk.length;
    if (processed - lastReported >= progressInterval) {
      lastReported = processed;
      onProgress?.({ bytesProcessed: processed, totalBytes });
    }
  }

  // Always report the final figure, even if the last chunk fell inside the
  // throttle window — otherwise a progress bar sticks at 99% on every file whose
  // size is not a clean multiple of the interval.
  onProgress?.({ bytesProcessed: processed, totalBytes });

  return stream.finish();
}

/**
 * Drive many `ToolStream`s over a single pass of the same chunks.
 *
 * This is the answer to "what happens if I point the variants panel at a hundred gigabytes". The
 * alternative -- one `runStream` per variant -- reads the file once per variant, so twenty CRC-8
 * models means twenty passes and twenty times the I/O. Here the bytes are read once and handed to
 * every engine, so the cost of a second variant is CPU only: a table lookup per byte, which is
 * nothing next to the disk.
 *
 * It follows that they finish together and share one progress figure. There is no per-variant
 * position to report, because there is one read head.
 *
 * Implemented as a fan-out `ToolStream` over the existing `runStream` rather than a second copy of
 * that loop, so the progress throttling, the final-figure guarantee and the abort check are the same
 * code in both paths. `runStream`'s own return value is discarded -- the fan-out has no digest of its
 * own -- and each real stream is finished afterwards, in order.
 */
export async function runStreams(
  streams: readonly ToolStream[],
  chunks: AsyncIterable<Uint8Array>,
  options: RunStreamOptions = {},
): Promise<ToolResult[]> {
  const fanOut: ToolStream = {
    update(chunk) {
      for (const stream of streams) stream.update(chunk);
    },
    finish: () => ({}),
  };
  await runStream(fanOut, chunks, options);
  return streams.map((stream) => stream.finish());
}

/**
 * Adapt a web `ReadableStream` to the `AsyncIterable` `runStream` wants.
 *
 * Chromium has supported async iteration on `ReadableStream` directly since 124,
 * but Firefox still does not, and this same bundle is served to a browser we do
 * not control. Ten lines here beats a polyfill.
 */
export async function* iterateStream(
  stream: ReadableStream<Uint8Array>,
): AsyncGenerator<Uint8Array> {
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      if (value) yield value;
    }
  } finally {
    reader.releaseLock();
  }
}

/** Re-chunk an async source to a fixed size. Used by the streaming-equivalence tests. */
export async function* rechunk(
  chunks: AsyncIterable<Uint8Array>,
  size: number,
): AsyncGenerator<Uint8Array> {
  let pending: Uint8Array[] = [];
  let pendingLength = 0;

  for await (const chunk of chunks) {
    pending.push(chunk);
    pendingLength += chunk.length;

    while (pendingLength >= size) {
      const merged = merge(pending, pendingLength);
      yield merged.subarray(0, size);
      const rest = merged.subarray(size);
      pending = rest.length > 0 ? [rest] : [];
      pendingLength = rest.length;
    }
  }

  if (pendingLength > 0) yield merge(pending, pendingLength);
}

function merge(parts: readonly Uint8Array[], total: number): Uint8Array {
  if (parts.length === 1) return parts[0]!;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
