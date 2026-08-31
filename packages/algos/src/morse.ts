/**
 * International Morse Code Encoding and Decoding.
 * Maps alphanumeric characters and common punctuation to sequences of dots (.) and dashes (-).
 */

const MORSE_MAP: Record<string, string> = {
  A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".",
  F: "..-.", G: "--.", H: "....", I: "..", J: ".---",
  K: "-.-", L: ".-..", M: "--", N: "-.", O: "---",
  P: ".--.", Q: "--.-", R: ".-.", S: "...", T: "-",
  U: "..-", V: "...-", W: ".--", X: "-..-", Y: "-.--",
  Z: "--..",
  "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
  "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
  ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.",
  "!": "-.-.--", "/": "-..-.", "(": "-.--.", ")": "-.--.-",
  "&": ".-...", ":": "---...", ";": "-.-.-.", "=": "-...-",
  "+": ".-.-.", "-": "-....-", "_": "..--.-", "\"": ".-..-.",
  "$": "...-..-", "@": ".--.-.", " ": "/",
};

const REV_MORSE_MAP: Record<string, string> = {};
for (const [k, v] of Object.entries(MORSE_MAP)) {
  REV_MORSE_MAP[v] = k;
}

export function encodeMorse(text: string): string {
  const clean = text.toUpperCase();
  const tokens: string[] = [];

  for (const c of clean) {
    if (c === " ") {
      tokens.push("/");
    } else if (MORSE_MAP[c]) {
      tokens.push(MORSE_MAP[c]!);
    }
  }

  return tokens.join(" ");
}

export function decodeMorse(morse: string): string {
  const tokens = morse.trim().split(/\s+/);
  let result = "";

  for (const token of tokens) {
    if (token === "/" || token === "|") {
      result += " ";
    } else if (REV_MORSE_MAP[token]) {
      result += REV_MORSE_MAP[token]!;
    } else {
      result += "?";
    }
  }

  return result;
}
