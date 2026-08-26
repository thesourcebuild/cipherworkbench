import {
  iterateStream,
  runStream,
  type StreamProgress,
  type ToolDefinition,
  type ToolResult,
  type ToolSpecBase,
} from "@ocs/engine";
import type { ComputeRequest, ComputeResponse } from "./compute.worker";

export interface FileComputeOptions {
  onProgress?: (progress: StreamProgress) => void;
  signal?: AbortSignal;
}

/**
 * Runs a file through a tool, in a worker when one can be created and on the main
 * thread when it cannot.
 *
 * The fallback is not defensive padding. Bundling a worker through a Next static
 * export is the one part of this app whose behaviour depends on the bundler's
 * `new Worker(new URL(...))` handling, and it has to work identically when served
 * from a static host and from Electron's `app://` origin. If the worker fails to
 * construct or dies on load, hashing a file must still work — slower and with a
 * less responsive progress bar, but correct. Silent degradation is the right
 * trade here because the result is byte-identical either way: the same
 * `runStream` over the same `ToolStream`.
 */
let workerSupported = true;
let jobCounter = 0;

export async function computeFile(
  tool: ToolDefinition<ToolSpecBase>,
  spec: ToolSpecBase,
  file: File,
  options: FileComputeOptions = {},
): Promise<ToolResult> {
  if (workerSupported) {
    try {
      return await computeInWorker(tool.id, spec, file, options);
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      // One failure is enough to stop paying the construction cost on every file.
      workerSupported = false;
      console.warn(
        "Falling back to main-thread hashing; the compute worker is unavailable.",
        error,
      );
    }
  }
  return computeOnMainThread(tool, spec, file, options);
}

function computeInWorker(
  toolId: string,
  spec: ToolSpecBase,
  file: File,
  { onProgress, signal }: FileComputeOptions,
): Promise<ToolResult> {
  return new Promise<ToolResult>((resolve, reject) => {
    const worker = new Worker(new URL("./compute.worker.ts", import.meta.url), {
      type: "module",
    });
    const jobId = ++jobCounter;

    const cleanup = () => {
      worker.terminate();
      signal?.removeEventListener("abort", onAbort);
    };
    const onAbort = () => {
      cleanup();
      reject(new DOMException("Aborted", "AbortError"));
    };

    if (signal?.aborted) {
      onAbort();
      return;
    }
    signal?.addEventListener("abort", onAbort);

    worker.addEventListener("message", (event: MessageEvent<ComputeResponse>) => {
      const message = event.data;
      // Stale replies from a job the user has already moved past.
      if (message.jobId !== jobId) return;

      switch (message.type) {
        case "progress":
          onProgress?.({
            bytesProcessed: message.bytesProcessed,
            ...(message.totalBytes === undefined ? {} : { totalBytes: message.totalBytes }),
          });
          break;
        case "done":
          cleanup();
          resolve(message.result);
          break;
        case "error":
          cleanup();
          reject(new Error(message.message));
          break;
      }
    });

    // Fires when the worker script itself fails to load or parse — exactly the
    // case the main-thread fallback exists for.
    worker.addEventListener("error", (event) => {
      cleanup();
      reject(new Error(event.message || "The compute worker failed to start."));
    });

    const request: ComputeRequest = { jobId, toolId, spec, file };
    worker.postMessage(request);
  });
}

async function computeOnMainThread(
  tool: ToolDefinition<ToolSpecBase>,
  spec: ToolSpecBase,
  file: File,
  { onProgress, signal }: FileComputeOptions,
): Promise<ToolResult> {
  if (!tool.createStream) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    return tool.compute(spec, bytes);
  }

  return runStream(tool.createStream(spec), iterateStream(file.stream()), {
    totalBytes: file.size,
    ...(onProgress ? { onProgress } : {}),
    ...(signal ? { signal } : {}),
  });
}
