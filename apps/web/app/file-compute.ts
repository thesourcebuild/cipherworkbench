import {
  iterateStream,
  fileProcessingModeForSpec,
  runStream,
  runStreams,
  type StreamProgress,
  type ToolDefinition,
  type ToolResult,
  type ToolSpecBase,
} from "@ocs/engine";
import type { ComputeRequest, ComputeResponse } from "./compute.worker";
import { createBrowserFileSource } from "./browser-file-source";

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
export const MAX_MAIN_THREAD_FILE_BYTES = 16 * 1024 * 1024;

class WorkerUnavailableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "WorkerUnavailableError";
  }
}

class OutputAccumulator {
  private buffer: Uint8Array | undefined;
  private readonly chunks: Uint8Array[] = [];
  private length = 0;

  constructor(initialCapacity = 0) {
    if (initialCapacity > 0) this.buffer = new Uint8Array(initialCapacity);
  }

  append(chunk: Uint8Array): void {
    if (this.buffer) {
      if (this.length + chunk.length > this.buffer.length) {
        const grown = new Uint8Array(
          Math.max(this.length + chunk.length, this.buffer.length * 2),
        );
        grown.set(this.buffer.subarray(0, this.length));
        this.buffer = grown;
      }
      this.buffer.set(chunk, this.length);
    } else {
      this.chunks.push(chunk);
    }
    this.length += chunk.length;
  }

  finish(result: ToolResult): ToolResult {
    if (result.error) return result;
    if (this.length === 0 && !this.buffer) return result;
    if (result.bytes) this.append(result.bytes);
    if (this.length === 0) return result;
    if (this.buffer) return { ...result, bytes: this.buffer.subarray(0, this.length) };

    const bytes = new Uint8Array(this.length);
    let offset = 0;
    for (const chunk of this.chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return { ...result, bytes };
  }
}

function expectedCipherOutputCapacity(inputBytes: number): number {
  return inputBytes + Math.ceil(inputBytes / (16 * 1024)) * 32 + 1024;
}

function assertSafeMainThreadFallback(file: File, streamsCurrentSpec: boolean): void {
  if (streamsCurrentSpec || file.size <= MAX_MAIN_THREAD_FILE_BYTES) return;
  throw new Error(
    `The compute worker is unavailable, and this ${file.size}-byte file is too large to process safely on the main thread. Reload the app and try again.`,
  );
}

export async function computeFile(
  tool: ToolDefinition<ToolSpecBase>,
  spec: ToolSpecBase,
  file: File,
  options: FileComputeOptions = {},
): Promise<ToolResult> {
  const processingMode = fileProcessingModeForSpec(tool, spec);
  const streamsCurrentSpec = processingMode === "streaming";
  const maxFileBytes = tool.sourcePolicy?.maxFileBytes;
  if (maxFileBytes !== undefined && file.size > maxFileBytes) {
    throw new Error(
      `${tool.label} accepts files up to ${maxFileBytes.toLocaleString()} bytes; this file is ${file.size.toLocaleString()} bytes.`,
    );
  }
  if (workerSupported) {
    try {
      return await computeInWorker(
        tool.id,
        spec,
        file,
        options,
        tool.family === "cipher" && streamsCurrentSpec,
      );
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      if (!(error instanceof WorkerUnavailableError)) throw error;
      assertSafeMainThreadFallback(
        file,
        streamsCurrentSpec || processingMode === "random-access",
      );
      // One failure is enough to stop paying the construction cost on every file.
      workerSupported = false;
      console.warn(
        "Falling back to main-thread hashing; the compute worker is unavailable.",
        error,
      );
    }
  }
  assertSafeMainThreadFallback(file, streamsCurrentSpec || processingMode === "random-access");
  return computeOnMainThread(tool, spec, file, options);
}

export async function computeVariantsFile(
  tool: ToolDefinition<ToolSpecBase>,
  spec: ToolSpecBase,
  file: File,
  options: FileComputeOptions = {},
): Promise<Map<string, Uint8Array>> {
  const streamsCurrentSpec = Boolean(tool.variants);
  if (workerSupported) {
    try {
      return await computeVariantsInWorker(tool.id, spec, file, options);
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      if (!(error instanceof WorkerUnavailableError)) throw error;
      assertSafeMainThreadFallback(file, streamsCurrentSpec);
      workerSupported = false;
      console.warn(
        "Falling back to main-thread variants hashing; the compute worker is unavailable.",
        error,
      );
    }
  }
  assertSafeMainThreadFallback(file, streamsCurrentSpec);
  return computeVariantsOnMainThread(tool, spec, file, options);
}

function computeInWorker(
  toolId: string,
  spec: ToolSpecBase,
  file: File,
  { onProgress, signal }: FileComputeOptions,
  preallocateTransformOutput: boolean,
): Promise<ToolResult> {
  return new Promise<ToolResult>((resolve, reject) => {
    let worker: Worker;
    try {
      worker = new Worker(new URL("./compute.worker.ts", import.meta.url), {
        type: "module",
      });
    } catch (error) {
      reject(
        new WorkerUnavailableError("The compute worker failed to start.", { cause: error }),
      );
      return;
    }
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
    let output: OutputAccumulator;
    try {
      output = new OutputAccumulator(
        preallocateTransformOutput ? expectedCipherOutputCapacity(file.size) : 0,
      );
    } catch (error) {
      cleanup();
      reject(
        new Error("The transformed output is too large to retain for Result and Export.", {
          cause: error,
        }),
      );
      return;
    }

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
          resolve(output.finish(message.result));
          break;
        case "output":
          output.append(message.chunk);
          worker.postMessage({
            kind: "output-ack",
            jobId,
            sequence: message.sequence,
          } satisfies ComputeRequest);
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
      reject(
        new WorkerUnavailableError(event.message || "The compute worker failed to start."),
      );
    });

    const request: ComputeRequest = { kind: "single", jobId, toolId, spec, file };
    worker.postMessage(request);
  });
}

function computeVariantsInWorker(
  toolId: string,
  spec: ToolSpecBase,
  file: File,
  { onProgress, signal }: FileComputeOptions,
): Promise<Map<string, Uint8Array>> {
  return new Promise<Map<string, Uint8Array>>((resolve, reject) => {
    let worker: Worker;
    try {
      worker = new Worker(new URL("./compute.worker.ts", import.meta.url), {
        type: "module",
      });
    } catch (error) {
      reject(
        new WorkerUnavailableError("The compute worker failed to start.", { cause: error }),
      );
      return;
    }
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
      if (message.jobId !== jobId) return;

      switch (message.type) {
        case "progress":
          onProgress?.({
            bytesProcessed: message.bytesProcessed,
            ...(message.totalBytes === undefined ? {} : { totalBytes: message.totalBytes }),
          });
          break;
        case "variants-done": {
          cleanup();
          const map = new Map<string, Uint8Array>();
          for (const item of message.results) {
            if (item.bytes) map.set(item.id, item.bytes);
          }
          resolve(map);
          break;
        }
        case "output":
          worker.postMessage({
            kind: "output-ack",
            jobId,
            sequence: message.sequence,
          } satisfies ComputeRequest);
          break;
        case "error":
          cleanup();
          reject(new Error(message.message));
          break;
      }
    });

    worker.addEventListener("error", (event) => {
      cleanup();
      reject(
        new WorkerUnavailableError(event.message || "The compute worker failed to start."),
      );
    });

    const request: ComputeRequest = { kind: "variants", jobId, toolId, spec, file };
    worker.postMessage(request);
  });
}

async function computeOnMainThread(
  tool: ToolDefinition<ToolSpecBase>,
  spec: ToolSpecBase,
  file: File,
  { onProgress, signal }: FileComputeOptions,
): Promise<ToolResult> {
  const processingMode = fileProcessingModeForSpec(tool, spec);
  if (tool.computeFile && processingMode === "random-access") {
    return tool.computeFile(spec, createBrowserFileSource(file));
  }
  const streamsCurrentSpec = processingMode === "streaming";
  if (!tool.createStream || !streamsCurrentSpec) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    return tool.compute(spec, bytes, {
      filename: file.name,
      mimeType: file.type || undefined,
      inputSize: file.size,
      lastModified: file.lastModified,
    });
  }

  return runStream(tool.createStream(spec), iterateStream(file.stream()), {
    totalBytes: file.size,
    ...(onProgress ? { onProgress } : {}),
    ...(signal ? { signal } : {}),
  });
}

async function computeVariantsOnMainThread(
  tool: ToolDefinition<ToolSpecBase>,
  spec: ToolSpecBase,
  file: File,
  { onProgress, signal }: FileComputeOptions,
): Promise<Map<string, Uint8Array>> {
  if (!tool.variants) return new Map();
  const table = tool.variants(spec);
  await Promise.all(table.rows.map((row) => row.prepare?.()));
  const results = await runStreams(
    table.rows.map((row) => row.stream()),
    iterateStream(file.stream()),
    {
      totalBytes: file.size,
      ...(onProgress ? { onProgress } : {}),
      ...(signal ? { signal } : {}),
    },
  );
  const map = new Map<string, Uint8Array>();
  results.forEach((result, index) => {
    const row = table.rows[index];
    if (row && result.bytes) map.set(row.id, result.bytes);
  });
  return map;
}
