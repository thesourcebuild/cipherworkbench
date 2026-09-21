import fs from "node:fs";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { loadTool } from "../../packages/cipher-registry/src/index.ts";
import { collectExportFiles } from "../../apps/web/app/export-folder.ts";

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface TestCertPaths {
  testDir: string;
  caCert: string;
  caKey: string;
  serverCrt: string;
  serverKey: string;
  clientCrt: string;
  clientKey: string;
  clientP12: string;
}

/**
 * Generates fresh mTLS suite certificates and writes them to examples/certificates/<subDir>.
 */
export async function setupSuiteCerts(subDir: string): Promise<TestCertPaths> {
  const testDir = path.resolve("./examples/certificates", subDir);
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
  fs.mkdirSync(testDir, { recursive: true });

  const certTool = await loadTool("cert-creator");
  const spec = certTool.createSpec();
  spec.options = {
    creatorMode: "mtls-suite",
    commonName: "localhost",
    clientCommonName: "client-agent-1",
    san: "localhost, 127.0.0.1",
    keyType: "rsa2048",
    mtlsP12Password: "TestPassword123!",
  };

  const result = await certTool.compute(spec, new Uint8Array(0));
  if (result.error) throw new Error("Certificate suite generation failed: " + result.error);

  const files = collectExportFiles(result, undefined, spec);
  for (const f of files) {
    fs.writeFileSync(path.join(testDir, f.name), f.content);
  }

  return {
    testDir,
    caCert: path.join(testDir, "ca.crt"),
    caKey: path.join(testDir, "ca.key"),
    serverCrt: path.join(testDir, "server.crt"),
    serverKey: path.join(testDir, "server.key"),
    clientCrt: path.join(testDir, "client.crt"),
    clientKey: path.join(testDir, "client.key"),
    clientP12: path.join(testDir, "client.p12"),
  };
}

export interface ServerOptions {
  port: number;
  cert: string;
  key: string;
  ca?: string;
  verifyClient?: boolean;
}

/**
 * Spawns an OpenSSL s_server instance.
 */
export async function startOpenSslServer(opts: ServerOptions): Promise<{
  process: ChildProcess;
  stop: () => void;
  getStderr: () => string;
}> {
  const args = [
    "s_server",
    "-accept", String(opts.port),
    "-cert", opts.cert,
    "-key", opts.key,
    "-www",
  ];

  if (opts.ca) {
    args.push("-CAfile", opts.ca);
  }
  if (opts.verifyClient) {
    args.push("-Verify", "1");
  }

  const proc = spawn("openssl", args);
  let stderr = "";
  proc.stderr.on("data", (d) => (stderr += d.toString()));

  // Allow server socket to bind and start listening
  await sleep(1000);

  return {
    process: proc,
    stop: () => proc.kill(),
    getStderr: () => stderr,
  };
}

export interface ClientOptions {
  port: number;
  ca: string;
  cert?: string;
  key?: string;
}

/**
 * Runs an OpenSSL s_client connection attempt and returns full handshake output.
 */
export async function runOpenSslClient(opts: ClientOptions): Promise<string> {
  const args = [
    "s_client",
    "-connect", `127.0.0.1:${opts.port}`,
    "-CAfile", opts.ca,
  ];

  if (opts.cert && opts.key) {
    args.push("-cert", opts.cert, "-key", opts.key);
  }

  return new Promise<string>((resolve) => {
    const sClient = spawn("openssl", args);

    let output = "";
    sClient.stdout.on("data", (d) => (output += d.toString()));
    sClient.stderr.on("data", (d) => (output += d.toString()));

    sClient.stdin.write("GET / HTTP/1.0\r\n\r\n");
    setTimeout(() => {
      sClient.kill();
      resolve(output);
    }, 1500);
  });
}

/**
 * Cleans up temporary test directory.
 */
export function cleanupDir(dir: string): void {
  try {
    if (fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  } catch {
    // Ignore cleanup race conditions
  }
}
