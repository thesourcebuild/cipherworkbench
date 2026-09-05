/**
 * Fractionated Morse Cipher:
 * Polygraphic cipher converting Morse code into trigraphic substitutions using a 26-letter keyed alphabet.
 */

const MORSE_MAP: Record<string, string> = {
  A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".", F: "..-.", G: "--.",
  H: "....", I: "..", J: ".---", K: "-.-", L: ".-..", M: "--", N: "-.",
  O: "---", P: ".--.", Q: "--.-", R: ".-.", S: "...", T: "-", U: "..-",
  V: "...-", W: ".--", X: "-..-", Y: "-.--", Z: "--..",
  "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
  "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
};

const REV_MORSE: Record<string, string> = {};
for (const [ch, code] of Object.entries(MORSE_MAP)) {
  REV_MORSE[code] = ch;
}

// 26 trigraph combinations of {'.', '-', 'x'}
const TRIGRAPHS: string[] = [];
const SYM = [".", "-", "x"];
for (let i = 0; i < 3; i++) {
  for (let j = 0; j < 3; j++) {
    for (let k = 0; k < 3; k++) {
      if (TRIGRAPHS.length < 26) {
        TRIGRAPHS.push(SYM[i]! + SYM[j]! + SYM[k]!);
      }
    }
  }
}

function getKeyAlphabet(key: string): string {
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, "");
  let alpha = "";
  const seen = new Set<string>();

  for (const ch of cleanKey) {
    if (!seen.has(ch)) {
      seen.add(ch);
      alpha += ch;
    }
  }
  for (let i = 65; i <= 90; i++) {
    const ch = String.fromCharCode(i);
    if (!seen.has(ch)) {
      seen.add(ch);
      alpha += ch;
    }
  }
  return alpha;
}

export function fractionatedMorseEncrypt(text: string, key = "ROUNDTABLE"): string {
  const alpha = getKeyAlphabet(key);
  const words = text.toUpperCase().split(/\s+/);
  const morseWords: string[] = [];

  for (const word of words) {
    const chars: string[] = [];
    for (const ch of word) {
      if (MORSE_MAP[ch]) {
        chars.push(MORSE_MAP[ch]!);
      }
    }
    morseWords.push(chars.join("x"));
  }
  let morseStream = morseWords.join("xx");

  // Pad with 'x' to multiple of 3
  while (morseStream.length % 3 !== 0) {
    morseStream += "x";
  }

  let result = "";
  for (let i = 0; i < morseStream.length; i += 3) {
    const tri = morseStream.slice(i, i + 3);
    const idx = TRIGRAPHS.indexOf(tri);
    result += alpha[idx >= 0 ? idx : 0]!;
  }
  return result;
}

export function fractionatedMorseDecrypt(text: string, key = "ROUNDTABLE"): string {
  const alpha = getKeyAlphabet(key);
  let morseStream = "";

  for (const ch of text.toUpperCase().replace(/[^A-Z]/g, "")) {
    const idx = alpha.indexOf(ch);
    if (idx >= 0 && idx < TRIGRAPHS.length) {
      morseStream += TRIGRAPHS[idx]!;
    }
  }

  // Split by "xx" for words, then "x" for letters
  const morseWords = morseStream.split("xx");
  const words: string[] = [];

  for (const mw of morseWords) {
    const letterCodes = mw.split("x");
    let word = "";
    for (const code of letterCodes) {
      if (REV_MORSE[code]) {
        word += REV_MORSE[code]!;
      }
    }
    if (word) words.push(word);
  }
  return words.join(" ");
}
