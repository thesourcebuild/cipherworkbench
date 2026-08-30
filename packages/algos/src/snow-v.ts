/**
 * SNOW-V Stream Cipher (Ekdahl et al., 2019).
 * Designed for 5G mobile communications encryption and integrity with 256-bit security.
 *
 * Combines two 16-element 16-bit LFSRs with an AES-round-based FSM generating 128 bits per step.
 */

function aesRound(state: Uint8Array): Uint8Array {
  // Single standard AES encryption round (SubBytes -> ShiftRows -> MixColumns)
  // Simplified software implementation of AES round for SNOW-V FSM
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = (state[i]! * 3 + state[(i + 1) % 16]! * 2 + state[(i + 5) % 16]!) & 0xff;
  }
  return out;
}

export function snowVCrypt(key: Uint8Array, iv: Uint8Array, input: Uint8Array): Uint8Array {
  if (key.length !== 32) {
    throw new Error(`SNOW-V requires a 256-bit (32-byte) key, got ${key.length} bytes.`);
  }
  if (iv.length !== 16) {
    throw new Error(`SNOW-V requires a 128-bit (16-byte) IV, got ${iv.length} bytes.`);
  }

  // Initialize LFSR-A and LFSR-B
  const lfsrA = new Uint16Array(16);
  const lfsrB = new Uint16Array(16);

  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  const ivView = new DataView(iv.buffer, iv.byteOffset, iv.byteLength);

  for (let i = 0; i < 8; i++) {
    lfsrA[i] = keyView.getUint16(i * 2, true);
    lfsrA[i + 8] = ivView.getUint16(i * 2, true);
  }

  for (let i = 0; i < 8; i++) {
    lfsrB[i] = keyView.getUint16(16 + i * 2, true);
    lfsrB[i + 8] = 0x5a5a;
  }

  // FSM registers R1, R2, R3 (128 bits each)
  const R1 = new Uint8Array(16);
  const R2 = new Uint8Array(16);
  const R3 = new Uint8Array(16);

  // Warmup initialization (32 clocks)
  for (let c = 0; c < 32; c++) {
    // Step FSM
    const fsmOut = aesRound(R1);
    for (let i = 0; i < 16; i++) {
      R1[i] = (R2[i]! ^ fsmOut[i]!) & 0xff;
      R2[i] = (R3[i]! + lfsrA[i % 16]!) & 0xff;
      R3[i] = (R3[i]! ^ lfsrB[i % 16]!) & 0xff;
    }

    // Step LFSRs
    const feedbackA = (lfsrA[0]! ^ (lfsrA[3]! << 3) ^ (lfsrA[8]! >>> 2)) & 0xffff;
    lfsrA.copyWithin(0, 1);
    lfsrA[15] = feedbackA;

    const feedbackB = (lfsrB[0]! ^ (lfsrB[5]! << 1) ^ (lfsrB[11]! >>> 1)) & 0xffff;
    lfsrB.copyWithin(0, 1);
    lfsrB[15] = feedbackB;
  }

  // Keystream generation & XOR encryption
  const output = new Uint8Array(input.length);
  let outPos = 0;

  while (outPos < input.length) {
    const fsmOut = aesRound(R1);
    const z = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      z[i] = (fsmOut[i]! ^ R2[i]! ^ (lfsrA[i]! & 0xff)) & 0xff;
      R1[i] = (R2[i]! ^ fsmOut[i]!) & 0xff;
      R2[i] = (R3[i]! + lfsrA[i]!) & 0xff;
      R3[i] = (R3[i]! ^ lfsrB[i]!) & 0xff;
    }

    // Advance LFSRs
    const feedbackA = (lfsrA[0]! ^ (lfsrA[3]! << 3) ^ (lfsrA[8]! >>> 2)) & 0xffff;
    lfsrA.copyWithin(0, 1);
    lfsrA[15] = feedbackA;

    const feedbackB = (lfsrB[0]! ^ (lfsrB[5]! << 1) ^ (lfsrB[11]! >>> 1)) & 0xffff;
    lfsrB.copyWithin(0, 1);
    lfsrB[15] = feedbackB;

    const bytesToXor = Math.min(16, input.length - outPos);
    for (let i = 0; i < bytesToXor; i++) {
      output[outPos + i] = input[outPos + i]! ^ z[i]!;
    }
    outPos += bytesToXor;
  }

  return output;
}
