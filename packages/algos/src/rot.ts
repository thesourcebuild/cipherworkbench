export const ROT_VARIANTS = ["rot5", "rot13", "rot18", "rot47"] as const;
export type RotVariant = (typeof ROT_VARIANTS)[number];

function rotateRange(character: string, first: number, size: number, shift: number): string {
  const code = character.codePointAt(0)!;
  return code >= first && code < first + size
    ? String.fromCharCode(first + ((code - first + shift) % size))
    : character;
}

/** Applies one of the conventional reciprocal ROT substitutions. */
export function rotTransform(text: string, variant: RotVariant): string {
  if (!ROT_VARIANTS.includes(variant)) throw new Error(`Unknown ROT variant: ${variant}`);

  let output = "";
  for (const character of text) {
    if (variant === "rot47") {
      output += rotateRange(character, 33, 94, 47);
      continue;
    }

    let transformed = character;
    if (variant === "rot13" || variant === "rot18") {
      transformed = rotateRange(transformed, 65, 26, 13);
      transformed = rotateRange(transformed, 97, 26, 13);
    }
    if (variant === "rot5" || variant === "rot18") {
      transformed = rotateRange(transformed, 48, 10, 5);
    }
    output += transformed;
  }
  return output;
}

export const rot5 = (text: string): string => rotTransform(text, "rot5");
export const rot13 = (text: string): string => rotTransform(text, "rot13");
export const rot18 = (text: string): string => rotTransform(text, "rot18");
export const rot47 = (text: string): string => rotTransform(text, "rot47");
