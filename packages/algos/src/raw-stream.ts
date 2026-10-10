import { chacha8, chacha12, chacha20, chacha20orig } from "@noble/ciphers/chacha.js";
import { salsa20, xsalsa20 } from "@noble/ciphers/salsa.js";
import { createA51 } from "./a5";
import { A52Stream } from "./a5-2";
import { Crypto1State } from "./crypto1";
import { DscCipher } from "./dect-dsc";
import { GeaCipher } from "./gea";
import { Isaac } from "./isaac";
import { Mickey2Stream } from "./mickey";
import {
  createGrain128,
  createGrainV1,
  createHc128,
  createHc256,
  createZuc,
  type StreamCipherEngine,
} from "./phase2-stream";
import { createRabbit } from "./phase6-ciphers";
import { createTrivium } from "./phase8-ciphers";
import { Pcg64 } from "./pcg";
import { createRc4 } from "./rc4";
import { createSnowV } from "./snow-v";
import { createSnow3g } from "./snow3g";
import { createSosemanuk } from "./sosemanuk";
import { SpritzCipher } from "./spritz";
import { Xoshiro256PlusPlus } from "./xoshiro";

export const RAW_STREAM_CIPHER_IDS = [
  "chacha20",
  "chacha12",
  "chacha8",
  "chacha20orig",
  "salsa20",
  "xsalsa20",
  "zuc128",
  "zuc256",
  "hc128",
  "hc256",
  "grainv1",
  "grain128",
  "rabbit",
  "trivium",
  "sosemanuk",
  "snow3g",
  "snow-v",
  "a5-1",
  "rc4-drop",
  "isaac",
  "pcg64",
  "xoshiro256",
  "spritz",
  "crypto1",
  "dect-dsc",
  "gea",
  "mickey",
  "a5-2",
  "rc4",
] as const;

export type RawStreamCipherId = (typeof RAW_STREAM_CIPHER_IDS)[number];

export interface RawStreamCipherEngine {
  /** XORs one chunk and advances permanently by exactly that many bytes. */
  process(chunk: Uint8Array): Uint8Array;
}

export interface RawStreamCipherOptions {
  /** Initial ChaCha block counter. Ignored by other algorithms. */
  counter?: number;
  /** RC4 bytes discarded before output. `rc4-drop` always uses 768. */
  drop?: number;
}

type ArxRun = (data: Uint8Array, output: Uint8Array | undefined, counter: number) => Uint8Array;

const EMPTY = new Uint8Array(0);
const ZERO_ARX_BLOCK = new Uint8Array(64);

/** Uses the ARX block counter directly and retains only an unfinished 64-byte block. */
function arxEngine(run: ArxRun, initialCounter: number): RawStreamCipherEngine {
  run(EMPTY, undefined, initialCounter);
  let counter = initialCounter;
  let held: Uint8Array<ArrayBufferLike> = EMPTY;
  let heldAt = 0;

  return {
    process(chunk: Uint8Array): Uint8Array {
      const out = new Uint8Array(chunk.length);
      let at = 0;

      while (at < chunk.length && heldAt < held.length) {
        out[at] = chunk[at]! ^ held[heldAt]!;
        at++;
        heldAt++;
      }

      const whole = Math.floor((chunk.length - at) / 64) * 64;
      if (whole > 0) {
        run(chunk.subarray(at, at + whole), out.subarray(at, at + whole), counter);
        counter += whole / 64;
        at += whole;
      }

      if (at < chunk.length) {
        held = run(ZERO_ARX_BLOCK, undefined, counter++);
        heldAt = 0;
        while (at < chunk.length) {
          out[at] = chunk[at]! ^ held[heldAt]!;
          at++;
          heldAt++;
        }
      }
      return out;
    },
  };
}

function keystreamEngine(next: (length: number) => Uint8Array): RawStreamCipherEngine {
  return {
    process(chunk: Uint8Array): Uint8Array {
      const stream = next(chunk.length);
      const out = new Uint8Array(chunk.length);
      for (let i = 0; i < chunk.length; i++) out[i] = chunk[i]! ^ stream[i]!;
      return out;
    },
  };
}

/**
 * Some package engines advance by a whole generated word even for a short input. Feed those engines
 * only complete words and retain the unused keystream bytes here, so their mutable cipher state remains
 * the source of continuation without making chunk boundaries observable.
 */
function roundedEngine(engine: StreamCipherEngine, wordBytes: number): RawStreamCipherEngine {
  let held: Uint8Array<ArrayBufferLike> = EMPTY;
  let heldAt = 0;
  return {
    process(chunk: Uint8Array): Uint8Array {
      const out = new Uint8Array(chunk.length);
      let at = 0;
      while (at < chunk.length && heldAt < held.length) {
        out[at] = chunk[at]! ^ held[heldAt]!;
        at++;
        heldAt++;
      }

      const whole = Math.floor((chunk.length - at) / wordBytes) * wordBytes;
      if (whole > 0) {
        out.set(engine.process(chunk.subarray(at, at + whole)), at);
        at += whole;
      }

      if (at < chunk.length) {
        held = engine.process(new Uint8Array(wordBytes));
        heldAt = 0;
        while (at < chunk.length) {
          out[at] = chunk[at]! ^ held[heldAt]!;
          at++;
          heldAt++;
        }
      }
      return out;
    },
  };
}

function littleEndian64Engine(next: () => bigint): RawStreamCipherEngine {
  let word = 0n;
  let byteAt = 8;
  return {
    process(chunk: Uint8Array): Uint8Array {
      const out = new Uint8Array(chunk.length);
      for (let i = 0; i < chunk.length; i++) {
        if (byteAt === 8) {
          word = next();
          byteAt = 0;
        }
        out[i] = chunk[i]! ^ Number((word >> BigInt(byteAt * 8)) & 0xffn);
        byteAt++;
      }
      return out;
    },
  };
}

const frameNumber = (nonce: Uint8Array): number =>
  (nonce[0] ?? 0) | ((nonce[1] ?? 0) << 8) | ((nonce[2] ?? 0) << 16);

/**
 * Creates a bounded-memory, byte-incremental engine for every unauthenticated raw stream tool.
 * Encryption and decryption are identical; create a fresh engine for each direction/message.
 */
export function createRawStreamCipher(
  id: RawStreamCipherId,
  key: Uint8Array,
  nonce: Uint8Array,
  options: RawStreamCipherOptions = {},
): RawStreamCipherEngine {
  const counter = options.counter ?? 0;
  switch (id) {
    case "chacha20":
      return arxEngine((data, output, at) => chacha20(key, nonce, data, output, at), counter);
    case "chacha12":
      return arxEngine((data, output, at) => chacha12(key, nonce, data, output, at), counter);
    case "chacha8":
      return arxEngine((data, output, at) => chacha8(key, nonce, data, output, at), counter);
    case "chacha20orig":
      return arxEngine(
        (data, output, at) => chacha20orig(key, nonce, data, output, at),
        counter,
      );
    case "salsa20":
      return arxEngine((data, output, at) => salsa20(key, nonce, data, output, at), 0);
    case "xsalsa20":
      return arxEngine((data, output, at) => xsalsa20(key, nonce, data, output, at), 0);
    case "zuc128":
      return roundedEngine(createZuc("zuc128", key, nonce), 4);
    case "zuc256":
      return roundedEngine(createZuc("zuc256", key, nonce), 4);
    case "hc128":
      return roundedEngine(createHc128(key, nonce), 4);
    case "hc256":
      return roundedEngine(createHc256(key, nonce), 4);
    case "grainv1":
      return roundedEngine(createGrainV1(key, nonce), 2);
    case "grain128":
      return roundedEngine(createGrain128(key, nonce), 4);
    case "rabbit": {
      const generator = createRabbit(key, nonce);
      return keystreamEngine((length) => generator.keystream(length));
    }
    case "trivium": {
      const generator = createTrivium(key, nonce);
      return keystreamEngine((length) => generator.keystream(length));
    }
    case "sosemanuk": {
      const generator = createSosemanuk(key, nonce);
      return keystreamEngine((length) => generator.keystream(length));
    }
    case "snow3g": {
      const generator = createSnow3g(key, nonce);
      return keystreamEngine((length) => generator.keystream(length));
    }
    case "snow-v":
      return createSnowV(key, nonce);
    case "a5-1": {
      const generator = createA51(key, frameNumber(nonce));
      return keystreamEngine((length) => generator.keystream(length));
    }
    case "rc4-drop":
      return createRc4(key, 768);
    case "isaac": {
      const cipher = new Isaac(key);
      return { process: (chunk) => cipher.crypt(chunk) };
    }
    case "pcg64": {
      const generator = new Pcg64(key);
      return littleEndian64Engine(() => generator.nextUint64());
    }
    case "xoshiro256": {
      const generator = new Xoshiro256PlusPlus(key);
      return littleEndian64Engine(() => generator.nextUint64());
    }
    case "spritz": {
      const cipher = new SpritzCipher();
      cipher.key(key);
      if (nonce.length > 0) {
        cipher.absorbStop();
        cipher.absorb(nonce);
      }
      return { process: (chunk) => cipher.crypt(chunk) };
    }
    case "crypto1": {
      let key48 = 0n;
      for (let i = 0; i < Math.min(6, key.length); i++) {
        key48 |= BigInt(key[i]!) << BigInt(8 * i);
      }
      const cipher = new Crypto1State(key48);
      cipher.absorb(nonce);
      return keystreamEngine((length) => {
        const out = new Uint8Array(length);
        for (let i = 0; i < length; i++) out[i] = cipher.nextByte();
        return out;
      });
    }
    case "dect-dsc": {
      const cipher = new DscCipher();
      cipher.init(key, nonce);
      return { process: (chunk) => cipher.crypt(chunk) };
    }
    case "gea": {
      const cipher = new GeaCipher();
      cipher.init(key, nonce);
      return { process: (chunk) => cipher.crypt(chunk) };
    }
    case "mickey": {
      const cipher = new Mickey2Stream(key, nonce);
      return { process: (chunk) => cipher.process(chunk) };
    }
    case "a5-2": {
      const cipher = new A52Stream(key, frameNumber(nonce));
      return { process: (chunk) => cipher.process(chunk) };
    }
    case "rc4":
      return createRc4(key, options.drop ?? 0);
  }
}
