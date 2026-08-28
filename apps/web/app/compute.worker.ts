/// <reference lib="webworker" />

import { iterateStream, runStream, runStreams, type ToolResult } from "@ocs/engine";
import { loadTool } from "@ocs/registry";

/**
 * Streams a file through a tool off the main thread.
 *
 * Hashing a few gigabytes is tens of seconds of solid CPU work. On the main
 * thread that means the progress bar it is meant to be driving cannot repaint,
 * which is the one case where a progress bar has to work. So the file goes to a
 * worker, and only progress counts and the final result come back.
 *
 * The `File` handle itself is what gets posted — not its bytes. A `File` is
 * structured-cloneable, and `file.stream()` inside the worker reads from disk
 * lazily, so a 40 GB file never needs 40 GB of memory on either side.
 */

export type ComputeRequest =
  | { kind?: "single"; jobId: number; toolId: string; spec: unknown; file: File; chunkSize?: number }
  | { kind: "variants"; jobId: number; toolId: string; spec: unknown; file: File; chunkSize?: number };

export type ComputeResponse =
  | { jobId: number; type: "progress"; bytesProcessed: number; totalBytes?: number }
  | { jobId: number; type: "done"; result: ToolResult }
  | { jobId: number; type: "variants-done"; results: Array<{ id: string; bytes?: Uint8Array }> }
  | { jobId: number; type: "error"; message: string };

const post = (message: ComputeResponse) => self.postMessage(message);

self.addEventListener("message", (event: MessageEvent<ComputeRequest>) => {
  void handle(event.data);
});

async function handle(req: ComputeRequest): Promise<void> {
  const { jobId, toolId, spec, file, chunkSize } = req;
  try {
    const tool = await loadTool(toolId);

    if (req.kind === "variants") {
      if (!tool.variants) {
        post({ jobId, type: "error", message: `Tool ${toolId} has no variants.` });
        return;
      }
      const table = tool.variants(spec as never);
      await Promise.all(table.rows.map((row) => row.prepare?.()));

      const results = await runStreams(
        table.rows.map((row) => row.stream()),
        iterateStream(file.stream()),
        {
          totalBytes: file.size,
          ...(chunkSize === undefined ? {} : { progressInterval: chunkSize }),
          onProgress: ({ bytesProcessed, totalBytes }) =>
            post({ jobId, type: "progress", bytesProcessed, totalBytes }),
        },
      );

      const variantResults: Array<{ id: string; bytes?: Uint8Array }> = [];
      results.forEach((result, index) => {
        const row = table.rows[index];
        if (row && result.bytes) {
          variantResults.push({ id: row.id, bytes: result.bytes });
        }
      });

      post({ jobId, type: "variants-done", results: variantResults });
      return;
    }

    if (!tool.createStream) {
      // A tool that cannot stream reads the whole file instead. AEAD ciphers are
      // in this category by nature: there is no authenticated output to emit
      // until every byte has been seen.
      const bytes = new Uint8Array(await file.arrayBuffer());
      post({ jobId, type: "done", result: await tool.compute(spec as never, bytes) });
      return;
    }

    const result = await runStream(
      tool.createStream(spec as never),
      iterateStream(file.stream()),
      {
        totalBytes: file.size,
        ...(chunkSize === undefined ? {} : { progressInterval: chunkSize }),
        onProgress: ({ bytesProcessed, totalBytes }) =>
          post({ jobId, type: "progress", bytesProcessed, totalBytes }),
      },
    );

    post({ jobId, type: "done", result });
  } catch (error) {
    post({
      jobId,
      type: "error",
      message: error instanceof Error ? error.message : String(error),
    });
  }
}
