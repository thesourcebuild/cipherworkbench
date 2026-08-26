"use client";

import { Button, type ButtonProps } from "./button";
import { useCopy } from "./use-copy";

// `value` is omitted from the base props as well as overridden: a button element
// has its own `value` attribute (`string | number | readonly string[]`), and
// narrowing it to also accept a thunk is not a legal extension of it.
export interface CopyButtonProps extends Omit<ButtonProps, "onClick" | "children" | "value"> {
  /** Read lazily, so the button always copies the current value rather than the one at render time. */
  value: string | (() => string);
  label?: string;
  copiedLabel?: string;
  /**
   * Override the clipboard write. The app passes `platform().copyToClipboard`;
   * the default uses `navigator.clipboard` directly, which works unchanged in a
   * browser tab and in an Electron renderer served over a real origin.
   *
   * Not named `onCopy` — that is a real React clipboard event handler on every
   * element, and shadowing it here would make `<CopyButton onCopy={...}>` mean
   * something different from what it means everywhere else in the codebase.
   */
  writeClipboard?: (text: string) => Promise<void>;
}

export function CopyButton({
  value,
  label = "Copy",
  copiedLabel = "Copied",
  writeClipboard,
  size = "sm",
  variant = "secondary",
  ...props
}: CopyButtonProps) {
  // The timer handling lives in the hook, shared with `CopyIconButton`.
  const { copied, copy } = useCopy({ value, writeClipboard });

  return (
    <Button size={size} variant={variant} onClick={() => void copy()} {...props}>
      {copied ? copiedLabel : label}
    </Button>
  );
}
