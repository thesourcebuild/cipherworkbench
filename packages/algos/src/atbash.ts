/** Reverses the ASCII alphabet (A <-> Z, B <-> Y) while preserving case. */
export function atbash(text: string): string {
  let output = "";
  for (const character of text) {
    const code = character.codePointAt(0)!;
    if (code >= 65 && code <= 90) output += String.fromCharCode(90 - (code - 65));
    else if (code >= 97 && code <= 122) output += String.fromCharCode(122 - (code - 97));
    else output += character;
  }
  return output;
}

export const atbashTransform = atbash;
