/**
 * Pelican MAC -- High-speed 4-round AES-based message authentication code by Joan Daemen and Vincent Rijmen.
 */

import { aes128EncryptBlock, aes128KeySchedule, aesRound } from "./aes-round";

function stepAesRound(state: Uint8Array): void {
  const tmp = new Uint8Array(16);
  const zeroRk = new Uint8Array(16);
  aesRound(state, zeroRk, tmp);
  state.set(tmp, 0);
}

export function pelicanMac(key: Uint8Array, message: Uint8Array): Uint8Array {
  if (key.length !== 16) throw new Error(`Pelican MAC requires a 16-byte AES-128 key (got ${key.length}).`);

  const sched = aes128KeySchedule(key);
  const state = new Uint8Array(16);

  // Initialize state: AES_K(0)
  aes128EncryptBlock(sched, new Uint8Array(16), state);

  // Process message in 16-byte blocks
  let offset = 0;
  const block = new Uint8Array(16);

  while (offset + 16 <= message.length) {
    for (let i = 0; i < 16; i++) state[i] = state[i]! ^ message[offset + i]!;
    // 4 rounds of AES without key addition
    for (let r = 0; r < 4; r++) {
      stepAesRound(state);
    }
    offset += 16;
  }

  // Padding: 10* padding
  const remaining = message.length - offset;
  block.fill(0);
  block.set(message.subarray(offset), 0);
  block[remaining] = 0x80;

  for (let i = 0; i < 16; i++) state[i] = state[i]! ^ block[i]!;
  for (let r = 0; r < 4; r++) {
    stepAesRound(state);
  }

  // Finalization: AES_K(state)
  const tag = new Uint8Array(16);
  aes128EncryptBlock(sched, state, tag);
  return tag;
}
