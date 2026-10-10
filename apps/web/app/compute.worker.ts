/// <reference lib="webworker" />

import {
  fileProcessingModeForSpec,
  iterateStream,
  runStream,
  runStreams,
  type ToolResult,
} from "@ocs/engine";
import { loadTool } from "@ocs/registry";

/**
 * Streams a file through a tool off the main thread.
 *
 * Hashing a few gigabytes is tens of seconds of solid CPU work. On the main
 * thread that means the progress bar it is meant to be driving cannot repaint,
 * which is the one case where a progress bar has to work. So the file goes to a
 * worker, and only progress counts and the final result come back.
 *
 * The `File` handle itself is what gets posted, not its bytes. A `File` is
 * structured-cloneable, so input is read lazily. Transform tools can still retain
 * output bytes in the renderer because Result and Export require the exact output.
 */

export type ComputeRequest =
  | {
      kind?: "single";
      jobId: number;
      toolId: string;
      spec: unknown;
      file: File;
      chunkSize?: number;
    }
  | {
      kind: "variants";
      jobId: number;
      toolId: string;
      spec: unknown;
      file: File;
      chunkSize?: number;
    }
  | { kind: "output-ack"; jobId: number; sequence: number };

export type ComputeResponse =
  | { jobId: number; type: "progress"; bytesProcessed: number; totalBytes?: number }
  | { jobId: number; type: "done"; result: ToolResult }
  | { jobId: number; type: "output"; sequence: number; chunk: Uint8Array }
  | { jobId: number; type: "variants-done"; results: Array<{ id: string; bytes?: Uint8Array }> }
  | { jobId: number; type: "error"; message: string };

function transferableBuffers(message: ComputeResponse): Transferable[] {
  const buffers = new Set<ArrayBuffer>();
  const add = (bytes: Uint8Array | undefined) => {
    if (bytes?.buffer instanceof ArrayBuffer) buffers.add(bytes.buffer);
  };
  if (message.type === "done") {
    add(message.result.bytes);
    for (const file of message.result.files ?? []) {
      if (typeof file.content !== "string") add(file.content);
    }
  } else if (message.type === "variants-done") {
    for (const result of message.results) add(result.bytes);
  } else if (message.type === "output") {
    add(message.chunk);
  }
  return [...buffers];
}

const post = (message: ComputeResponse) =>
  self.postMessage(message, transferableBuffers(message));

const outputAcknowledgements = new Map<string, () => void>();

self.addEventListener("message", (event: MessageEvent<ComputeRequest>) => {
  if (event.data.kind === "output-ack") {
    const key = `${event.data.jobId}:${event.data.sequence}`;
    outputAcknowledgements.get(key)?.();
    outputAcknowledgements.delete(key);
    return;
  }
  void handle(event.data);
});

async function handle(req: Exclude<ComputeRequest, { kind: "output-ack" }>): Promise<void> {
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

    const streamsCurrentSpec = fileProcessingModeForSpec(tool, spec as never) === "streaming";
    if (!tool.createStream || !streamsCurrentSpec) {
      // A tool that cannot stream reads the whole file instead. AEAD ciphers are
      // in this category by nature: there is no authenticated output to emit
      // until every byte has been seen.
      const bytes = new Uint8Array(await file.arrayBuffer());
      post({ jobId, type: "done", result: await tool.compute(spec as never, bytes) });
      return;
    }

    let outputSequence = 0;
    const result = await runStream(
      tool.createStream(spec as never),
      iterateStream(file.stream()),
      {
        totalBytes: file.size,
        ...(chunkSize === undefined ? {} : { progressInterval: chunkSize }),
        onProgress: ({ bytesProcessed, totalBytes }) =>
          post({ jobId, type: "progress", bytesProcessed, totalBytes }),
        onOutput: (source) => {
          const chunk =
            source.byteOffset === 0 && source.byteLength === source.buffer.byteLength
              ? source
              : Uint8Array.from(source);
          const sequence = outputSequence++;
          return new Promise<void>((resolve) => {
            outputAcknowledgements.set(`${jobId}:${sequence}`, resolve);
            post({ jobId, type: "output", sequence, chunk });
          });
        },
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
