/**
 * Types for the vendored `text-encoding` engine. Hand-written, because the upstream package
 * ships none and the surface this repo uses is two classes and one function.
 */

export interface TextEncoderOptions {
  /**
   * Upstream's escape hatch, and the reason this file exists: the WHATWG standard deliberately
   * forbids `TextEncoder` from emitting anything but UTF-8, so encoding *to* Shift_JIS or
   * windows-1251 means opting out of the standard on purpose.
   */
  NONSTANDARD_allowLegacyEncoding?: boolean;
}

export interface TextDecoderOptions {
  fatal?: boolean;
  ignoreBOM?: boolean;
}

export declare class TextEncoderPolyfillClass {
  constructor(label?: string, options?: TextEncoderOptions);
  readonly encoding: string;
  encode(input?: string): Uint8Array;
}

export declare class TextDecoderPolyfillClass {
  constructor(label?: string, options?: TextDecoderOptions);
  readonly encoding: string;
  decode(input?: ArrayBufferView | ArrayBuffer, options?: { stream?: boolean }): string;
}

export interface InitialisedEncodings {
  TextEncoderPolyfill: typeof TextEncoderPolyfillClass;
  TextDecoderPolyfill: typeof TextDecoderPolyfillClass;
}

/**
 * Evaluates the engine with the index tables in place. Idempotent.
 *
 * The tables have to be supplied here rather than afterwards: upstream registers its 28
 * single-byte encoders during module evaluation and skips them entirely if the tables are not
 * yet present.
 */
export declare function initEncodings(indexes: unknown): InitialisedEncodings;
