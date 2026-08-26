import { getTextEncoding, needsTables } from "@ocs/contracts/encoding";
import type { InitialisedEncodings } from "./vendor/encoding";

/**
 * The lazy half: 635 KB of vendored WHATWG engine and tables, loaded the first time a legacy
 * encoding is actually selected.
 *
 * Structured exactly as emn178's online-tools structures it, and for the same reason. That site
 * marks each legacy option `data-load-encoding="2"` and fetches `encoding.min.js` plus
 * `encoding-indexes.min.js` on selection; here the equivalent is a dynamic `import()` that the
 * bundler turns into two chunks nothing else references. Someone who only ever hashes UTF-8
 * never downloads a byte of it.
 *
 * The API is deliberately split into an async `ensure` and a sync `encode`/`decode`, rather than
 * making encoding async. Input decoding is called from the options form, the input panel, three
 * lint rules and every tool's compute path, all synchronously — making it a promise would push
 * `await` into all of them for the sake of a load that happens at most once per session. So the
 * UI calls `ensureLegacyTables` when the selector changes and re-renders when it resolves,
 * which is the same sequence the reference site performs.
 */

let loaded: InitialisedEncodings | undefined;
let loading: Promise<InitialisedEncodings> | undefined;

/**
 * WHATWG treats these two labels as the same encoding, and the vendored engine does not.
 *
 * Its index lookup is keyed on the *name* it resolves a label to, and there is no
 * `iso-8859-8-i` entry in the tables — so encoding to it throws `Cannot read properties of
 * undefined`. The reference site has the same bug for the same reason. Normalising here fixes
 * it, and is correct rather than a workaround: ISO-8859-8-I differs from ISO-8859-8 only in
 * how a renderer orders the glyphs, never in the bytes.
 */
const LABEL_ALIASES: Readonly<Record<string, string>> = {
  "iso-8859-8-i": "iso-8859-8",
};

function canonical(id: string): string {
  return LABEL_ALIASES[id] ?? id;
}

/**
 * Loads the engine and the tables. Idempotent, and concurrent callers share one load.
 *
 * Two separate dynamic imports rather than one barrel, so the tables land in their own chunk:
 * the engine is 104 KB and the tables 531 KB, and there is no reason for a bundler to fuse them.
 */
export async function ensureLegacyTables(): Promise<void> {
  if (loaded) return;
  loading ??= (async () => {
    const [engine, indexes] = await Promise.all([
      import("./vendor/encoding.js"),
      import("./vendor/encoding-indexes.js"),
    ]);
    // The tables go in before the engine body runs, which is what `initEncodings` arranges.
    const result = engine.initEncodings(indexes.default);
    loaded = result;
    return result;
  })();
  await loading;
}

/** True once `ensureLegacyTables` has resolved. Lets a sync caller decide what to render. */
export function legacyTablesReady(): boolean {
  return loaded !== undefined;
}

/**
 * A failure, with `loading` set when the only thing wrong is that the tables have not arrived.
 * The UI shows that one as a pending state rather than as an error.
 */
export interface LegacyFailure {
  ok: false;
  error: string;
  loading?: boolean;
}

export type LegacyBytesResult = { ok: true; bytes: Uint8Array } | LegacyFailure;
export type LegacyTextResult = { ok: true; text: string } | LegacyFailure;

/**
 * Text to bytes in a legacy encoding.
 *
 * Returns a result rather than throwing, matching the rest of the codec layer: a character the
 * target encoding cannot represent is an ordinary thing for a user to type, and the message
 * naming that character is the useful response. The alternative — substituting `?` or a numeric
 * reference, which is what the WHATWG *encoder* actually specifies for HTML form submission —
 * would make this tool hash something other than what was entered.
 */
export function encodeLegacy(id: string, text: string): LegacyBytesResult {
  const meta = getTextEncoding(id);
  if (!meta) return { ok: false, error: `Unknown character encoding: ${id}` };
  if (!needsTables(id)) {
    return { ok: false, error: `${meta.label} does not use the legacy tables.` };
  }
  if (!loaded) {
    return {
      ok: false,
      loading: true,
      error: `Loading the ${meta.label} conversion tables\u2026`,
    };
  }

  let encoder: InstanceType<InitialisedEncodings["TextEncoderPolyfill"]>;
  try {
    encoder = new loaded.TextEncoderPolyfill(canonical(id), {
      NONSTANDARD_allowLegacyEncoding: true,
    });
  } catch (error) {
    return { ok: false, error: describe(error, meta.label) };
  }

  try {
    return { ok: true, bytes: encoder.encode(text) };
  } catch (error) {
    return { ok: false, error: describe(error, meta.label) };
  }
}

/** Bytes back to text. Present for completeness; the platform can do this one unaided. */
export function decodeLegacy(id: string, bytes: Uint8Array): LegacyTextResult {
  const meta = getTextEncoding(id);
  if (!meta) return { ok: false, error: `Unknown character encoding: ${id}` };
  if (!loaded) {
    return {
      ok: false,
      loading: true,
      error: `Loading the ${meta.label} conversion tables\u2026`,
    };
  }
  try {
    return { ok: true, text: new loaded.TextDecoderPolyfill(canonical(id)).decode(bytes) };
  } catch (error) {
    return { ok: false, error: describe(error, meta.label) };
  }
}

/**
 * Rewrites the engine's error into something a user can act on.
 *
 * Its message for an unencodable character is `The code point 8364 could not be encoded.` — a
 * decimal code point and no indication of which character that is or what to do. Naming the
 * character and pointing at the escape hatch is the difference between a dead end and a fix.
 */
function describe(error: unknown, label: string): string {
  const message = error instanceof Error ? error.message : String(error);
  const match = /code point (\d+)/.exec(message);
  if (match) {
    const code = Number(match[1]);
    const char = String.fromCodePoint(code);
    const hex = code.toString(16).toUpperCase().padStart(4, "0");
    return `"${char}" (U+${hex}) has no ${label} encoding. Use UTF-8, or switch the input mode to Hex if you already have the bytes.`;
  }
  return `${label}: ${message}`;
}
