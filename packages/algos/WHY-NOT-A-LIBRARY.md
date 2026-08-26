# Why these are implemented here rather than taken from a library

`@noble/hashes` (2.3.0) does not carry MD2, MD4, SM3, Whirlpool or xxHash, and neither
does `@scure/base`. The npm ecosystem was surveyed before writing any of them. What is
available, and why none of it was used:

| Algorithm | Best candidate | Verdict |
|---|---|---|
| MD2 | — | Nothing on npm implements it. |
| MD4 | `js-md4` 0.3.2 | Last published 2017. CommonJS only, no `exports` field, and one-shot only — no `create()` for incremental input. |
| SM3 | `sm-crypto` 0.5.6 | CommonJS, depends on `jsbn`, and carries SM2/SM4 along with it. No streaming API. |
| Whirlpool | `whirlpool-hash` 1.1.6 | CommonJS, 2018. Its own description says WHIRLPOOL-0 and WHIRLPOOL-T — the two *superseded* drafts, not the final ISO/IEC 10118-3 function everyone means by "Whirlpool". Wrong algorithm. |
| XXH32 / XXH64 | `js-xxhash` 5.0.1 | Pure ESM and recent, but XXH32 only: its own README says "a 64-bit version might come a bit later". No streaming. `xxhashjs` covers both and is CommonJS from 2018 with a `cuint` dependency. |
| XXH3 / XXH128 | — | No *pure-JavaScript* implementation exists. `hash-wasm` does have both, as WebAssembly — see below; the reasons for not taking it are about the CSP and the API, not about coverage. |
| RIPEMD-128 / 256 / 320 | — | Nothing on npm carries all four RIPEMD widths. `hash-wasm` and `@noble/hashes` both stop at RIPEMD-160. |

## `xxhash-addon` — the fastest option, and unusable here

`xxhash-addon` 2.1.0 (BSD-2-Clause) is worth naming explicitly because it is genuinely
the best xxHash on npm: it wraps the reference C implementation, covers **XXH32, XXH64,
XXH3 and XXH128** — including the two nothing else in JavaScript has — and supports
incremental hashing. If this were a Node CLI it would be the answer.

It cannot be used here, and the reason is the single architectural constraint the whole
repo is built around: **the same bundle runs in a browser tab.** `xxhash-addon` is a
native N-API addon — it declares `node-gyp-build`, runs `node install.js` on install,
loads a compiled `.node` binary, and its `engines` field says `node`. A `.node` binary
cannot load in a browser at all, so the web build would simply not have xxHash.

Using it only on the desktop was considered and rejected:

- It breaks feature parity between the two targets, which the README states as a promise
  rather than an aspiration.
- The compute worker runs in the **renderer**, which is a Chromium context. A native
  addon can only load in the main process, so file hashing would have to stream
  gigabytes across IPC — strictly worse than the current path, which reads the file
  directly in the renderer precisely to avoid that.
- `apps/desktop` currently has *zero* runtime dependencies and needs no `asarUnpack`, no
  per-platform native rebuild and no postinstall compile. That is a property worth
  keeping, not spending on one hash family.

So all four — XXH32, XXH64, XXH3-64 and XXH128 — are implemented here in pure TypeScript
instead, checked against `hash-wasm` (the reference C via WebAssembly) rather than against
themselves. Note that `xxhash-wasm`, the other oracle here, cannot serve for XXH3: its
entire API is `h32`/`h64` and their variants, with no XXH3 at any version.

## The one real contender

`hash-wasm` 4.12.0 covers four of the five (MD4, SM3, Whirlpool, XXH32/XXH64) in a
single maintained, MIT-licensed, dependency-free package. It was rejected on four
counts, in order of weight:

1. **It does not complete the set.** No MD2, and no RIPEMD-128/256/320. It *does* have
   XXH3 and XXH128 — an earlier version of this document said otherwise and was wrong;
   `emn178`'s online-tools uses exactly those functions, which is how the error came to
   light. So `packages/algos` would still have to exist either way, and the choice is not
   "library or hand-written" but "library *plus* hand-written, or hand-written".
2. **It relaxes the desktop CSP.** Instantiating WebAssembly requires
   `'wasm-unsafe-eval'` in `script-src`. `apps/desktop/src/main/protocol.ts` currently
   allows only `'self'` plus per-script hashes, and the packaged-app smoke test now
   asserts that policy holds by requiring an outbound fetch to fail. Widening
   `script-src` for the whole renderer to gain two hash functions is the wrong trade —
   and it is the reason this stayed a rejection even once the coverage argument fell.
3. **Its API is async-only.** Every `create*()` returns a Promise, so it cannot sit
   behind `HashBinding.create()`, which is synchronous because `ToolStream.update()` is.
   Making the whole streaming path async to accommodate one backend is the wrong
   direction.
4. **It duplicates what is already here.** MD5, SHA-1, SHA-2, SHA-3, Keccak, BLAKE2,
   BLAKE3, RIPEMD-160, HMAC, PBKDF2, scrypt and Argon2 all exist in `@noble/hashes`
   too. Two implementations of the same twelve algorithms is two sets of behaviour to
   keep in agreement, for no gain.

## What makes writing them acceptable

Every one of these is small, frozen, and published with official test vectors:
RFC 1319 (MD2), RFC 1320 (MD4), GB/T 32905-2016 (SM3), ISO/IEC 10118-3 (Whirlpool), and
the xxHash reference repository. `tests/algos-hash.test.ts` asserts those vectors, and
— as with the CRC engine — checks the incremental path against the one-shot path across
awkward chunk boundaries. A hash function with a passing published vector and a verified
streaming path is not the kind of code that benefits from being someone else's.

## Performance, stated honestly

`xxh3`, `xxh128`, `whirlpool` and `xxhash64` are the slow ones here — XXH3 and Whirlpool
both land around 18 MiB/s against SHA-256's 215. For XXH3 that is a deliberate first-version
trade and an ironic one, xxHash being the fast family: every 64-bit value is a `bigint`,
because the algorithm is dense 64-bit arithmetic with a 64×64→128 multiply in four places
and a 32-bit-limb rewrite would be perhaps five times faster and much more than five times
easier to get subtly wrong. `accumulate`/`scramble` is the only part whose cost scales with
input size, so it is the only part worth converting if this becomes a real problem.

`xxhash64` and `whirlpool` are the slow ones here. Whirlpool uses 64-bit arithmetic
split across 32-bit halves and runs ten rounds over eight 64-bit words per block; it is
roughly an order of magnitude slower than SHA-256 in this implementation, which is
inherent to the design rather than a shortcut taken here. XXH64 is implemented with
`BigInt`, which costs it most of the speed advantage xxHash exists for — acceptable
because the reason to compute an xxHash in *this* tool is to check a value against one
produced elsewhere, not to hash at line rate. For hashing large files quickly, BLAKE3
is the better choice and is already available.
