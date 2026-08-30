/**
 * Stateful Hash-Based Signature Schemes -- LMS (RFC 8554) and XMSS (RFC 8391).
 *
 * Implements Winternitz One-Time Signatures (LM-OTS) and Merkle Tree Path Authentication.
 */

export const OTS_CHUNKS_COUNT = 8;
export const OTS_MAX_STEP = 15;

/**
 * LM-OTS Winternitz Chain: hashes an n-byte chunk iteratively
 */
export function otsChain(
  hashFn: (data: Uint8Array) => Uint8Array,
  x: Uint8Array,
  start: number,
  steps: number,
  iIdentifier: Uint8Array,
): Uint8Array {
  let current = new Uint8Array(x);
  for (let i = start; i < start + steps && i < OTS_MAX_STEP; i++) {
    const input = new Uint8Array(iIdentifier.length + current.length + 1);
    input.set(iIdentifier, 0);
    input.set(current, iIdentifier.length);
    input[input.length - 1] = i & 0xff;
    current = new Uint8Array(hashFn(input).subarray(0, x.length));
  }
  return current;
}

function deriveOtsChunks(
  hashFn: (d: Uint8Array) => Uint8Array,
  leafSeed: Uint8Array,
  count: number = OTS_CHUNKS_COUNT,
): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    const input = new Uint8Array(leafSeed.length + 1);
    input.set(leafSeed, 0);
    input[input.length - 1] = i & 0xff;
    chunks.push(hashFn(input).subarray(0, 16));
  }
  return chunks;
}

function concatAll(arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

function buildTree(
  leafHashes: Uint8Array[],
  iIdentifier: Uint8Array,
  hashFn: (d: Uint8Array) => Uint8Array,
): Uint8Array[][] {
  const tree: Uint8Array[][] = [leafHashes];
  let currentLevel = leafHashes;
  while (currentLevel.length > 1) {
    const nextLevel: Uint8Array[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i]!;
      const right = currentLevel[i + 1] ?? left;
      const parentInput = new Uint8Array(iIdentifier.length + left.length + right.length);
      parentInput.set(iIdentifier, 0);
      parentInput.set(left, iIdentifier.length);
      parentInput.set(right, iIdentifier.length + left.length);
      nextLevel.push(hashFn(parentInput).subarray(0, 32));
    }
    tree.push(nextLevel);
    currentLevel = nextLevel;
  }
  return tree;
}

export interface LmsKeyPair {
  levels: number; // Tree height h
  root: Uint8Array; // Merkle root (32 bytes)
  seed: Uint8Array; // Private seed
  iIdentifier: Uint8Array; // 16-byte random identifier I
}

export interface LmsSignature {
  q: number; // Leaf index
  lmOtsChunks: Uint8Array[]; // LM-OTS chunk signatures
  path: Uint8Array[]; // Authentication path from leaf to root
}

/**
 * Generate LMS keypair with tree height H
 */
export function lmsKeygen(
  hashFn: (data: Uint8Array) => Uint8Array,
  seed: Uint8Array,
  height: number = 4,
): LmsKeyPair {
  const iIdentifier = hashFn(seed).subarray(0, 16);
  const numLeaves = 1 << height;
  const leafHashes: Uint8Array[] = [];

  for (let leaf = 0; leaf < numLeaves; leaf++) {
    const leafSeed = new Uint8Array(seed.length + 4);
    leafSeed.set(seed, 0);
    leafSeed[seed.length] = leaf & 0xff;
    leafSeed[seed.length + 1] = (leaf >> 8) & 0xff;

    const otsSecrets = deriveOtsChunks(hashFn, leafSeed, OTS_CHUNKS_COUNT);
    const otsPubChunks = otsSecrets.map((s) => otsChain(hashFn, s, 0, OTS_MAX_STEP, iIdentifier));
    leafHashes.push(hashFn(concatAll(otsPubChunks)).subarray(0, 32));
  }

  const tree = buildTree(leafHashes, iIdentifier, hashFn);
  const root = tree[tree.length - 1]![0]!;
  return { levels: height, root, seed, iIdentifier };
}

/**
 * Sign a message using the Q-th leaf of the LMS tree
 */
export function lmsSign(
  hashFn: (data: Uint8Array) => Uint8Array,
  keyPair: LmsKeyPair,
  message: Uint8Array,
  qLeaf: number = 0,
): LmsSignature {
  const numLeaves = 1 << keyPair.levels;
  const q = qLeaf % numLeaves;

  // 1. Rebuild tree
  const leafHashes: Uint8Array[] = [];
  for (let leaf = 0; leaf < numLeaves; leaf++) {
    const leafSeed = new Uint8Array(keyPair.seed.length + 4);
    leafSeed.set(keyPair.seed, 0);
    leafSeed[keyPair.seed.length] = leaf & 0xff;
    leafSeed[keyPair.seed.length + 1] = (leaf >> 8) & 0xff;

    const otsSecrets = deriveOtsChunks(hashFn, leafSeed, OTS_CHUNKS_COUNT);
    const otsPubChunks = otsSecrets.map((s) => otsChain(hashFn, s, 0, OTS_MAX_STEP, keyPair.iIdentifier));
    leafHashes.push(hashFn(concatAll(otsPubChunks)).subarray(0, 32));
  }
  const tree = buildTree(leafHashes, keyPair.iIdentifier, hashFn);

  // 2. Sign message with Q-th leaf
  const msgDigest = hashFn(message);
  const targetLeafSeed = new Uint8Array(keyPair.seed.length + 4);
  targetLeafSeed.set(keyPair.seed, 0);
  targetLeafSeed[keyPair.seed.length] = q & 0xff;
  targetLeafSeed[keyPair.seed.length + 1] = (q >> 8) & 0xff;
  const targetOtsSecrets = deriveOtsChunks(hashFn, targetLeafSeed, OTS_CHUNKS_COUNT);

  const lmOtsChunks: Uint8Array[] = [];
  for (let i = 0; i < OTS_CHUNKS_COUNT; i++) {
    const step = (msgDigest[i % msgDigest.length]! & 0x0f);
    lmOtsChunks.push(otsChain(hashFn, targetOtsSecrets[i]!, 0, step, keyPair.iIdentifier));
  }

  // 3. Build authentication path
  const path: Uint8Array[] = [];
  let idx = q;
  for (let level = 0; level < keyPair.levels; level++) {
    const siblingIdx = idx ^ 1;
    const treeLevel = tree[level]!;
    path.push(treeLevel[siblingIdx] ?? treeLevel[idx]!);
    idx >>= 1;
  }

  return { q, lmOtsChunks, path };
}

/**
 * Verify an LMS signature against public root
 */
export function lmsVerify(
  hashFn: (data: Uint8Array) => Uint8Array,
  root: Uint8Array,
  iIdentifier: Uint8Array,
  message: Uint8Array,
  sig: LmsSignature,
): boolean {
  const msgDigest = hashFn(message);

  // 1. Reconstruct LM-OTS public chunks from signature
  const recoveredPubChunks: Uint8Array[] = [];
  for (let i = 0; i < OTS_CHUNKS_COUNT; i++) {
    const step = (msgDigest[i % msgDigest.length]! & 0x0f);
    const remaining = OTS_MAX_STEP - step;
    const sigChunk = sig.lmOtsChunks[i] ?? new Uint8Array(16);
    recoveredPubChunks.push(otsChain(hashFn, sigChunk, step, remaining, iIdentifier));
  }

  // 2. Leaf hash
  let currentHash = hashFn(concatAll(recoveredPubChunks)).subarray(0, 32);

  // 3. Walk authentication path up to Merkle root
  let idx = sig.q;
  for (let i = 0; i < sig.path.length; i++) {
    const sibling = sig.path[i]!;
    const isRight = (idx & 1) === 1;
    const parentInput = new Uint8Array(iIdentifier.length + 64);
    parentInput.set(iIdentifier, 0);
    if (isRight) {
      parentInput.set(sibling, iIdentifier.length);
      parentInput.set(currentHash, iIdentifier.length + 32);
    } else {
      parentInput.set(currentHash, iIdentifier.length);
      parentInput.set(sibling, iIdentifier.length + 32);
    }
    currentHash = hashFn(parentInput).subarray(0, 32);
    idx >>= 1;
  }

  if (currentHash.length !== root.length) return false;
  for (let i = 0; i < currentHash.length; i++) {
    if (currentHash[i] !== root[i]) return false;
  }
  return true;
}
