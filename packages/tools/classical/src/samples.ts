import type { ToolSample } from "@ocs/engine";

const LOREM_IPSUM = `Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean eu varius leo, at iaculis orci. Nunc a risus fringilla, suscipit turpis ac, gravida sem. Ut at metus nec mi laoreet posuere et et nibh. Pellentesque sit amet eleifend velit. Sed egestas eu lacus id gravida. Duis quis placerat justo. Quisque tincidunt mollis mauris, sed ultricies dolor fermentum sed. Proin eget convallis orci. Integer augue diam, condimentum non dui porta, bibendum dictum tortor. Praesent enim mi, aliquet ut nunc sit amet, consectetur bibendum enim. Donec pretium erat et consequat efficitur. Pellentesque tempus pharetra dolor, eu sagittis ligula bibendum quis. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas.

Curabitur pharetra vestibulum dolor, sit amet suscipit risus aliquam quis. Nam ut nisl id libero mattis tempor quis in elit. Nullam auctor commodo mollis. Ut et euismod sapien, ac lobortis orci. Donec gravida enim id quam eleifend, quis venenatis lacus feugiat. Praesent gravida vitae nulla a vestibulum. Aliquam ex enim, aliquet vel massa eleifend, aliquet maximus ligula. Aenean eu dui ut diam facilisis varius. Maecenas suscipit odio at metus laoreet mollis. Sed at nisi rhoncus, scelerisque odio eget, convallis enim. Pellentesque sit amet sem id risus congue vulputate. Suspendisse mattis lectus sit amet libero pellentesque porttitor.

Donec placerat purus sed auctor bibendum. Suspendisse odio purus, tincidunt eget venenatis eget, efficitur eget ipsum. Vivamus id justo tempus, fermentum augue ac, aliquam est. Quisque ornare justo vitae metus vulputate, sit amet aliquam libero pulvinar. Maecenas non rutrum tellus, et sodales urna. Nullam ornare nulla in ipsum eleifend, in pharetra erat sollicitudin. Aenean odio erat, lacinia sed turpis nec, euismod posuere purus. Donec sed leo non nisl posuere pellentesque. Cras in eros leo. Ut ut congue augue. Quisque mattis leo ac metus iaculis, a tincidunt est bibendum. Interdum et malesuada fames ac ante ipsum primis in faucibus. Nam ante tellus, hendrerit a aliquet molestie, tincidunt eu diam. Aliquam pulvinar urna feugiat, ornare lacus ac, ultricies felis.

Morbi viverra neque nec dignissim laoreet. Praesent condimentum eget neque non imperdiet. Cras ex lectus, facilisis a dolor id, ornare porttitor orci. Nulla est justo, egestas eu interdum quis, posuere et nisi. Nunc ac maximus leo, sit amet tristique risus. Vestibulum ultricies ullamcorper justo, id vulputate orci ullamcorper iaculis. Nullam ipsum lorem, blandit at eleifend in, pellentesque eget odio. Vestibulum consequat blandit vehicula. Nulla dignissim nisl vel rhoncus lobortis. Sed quis fermentum arcu, in egestas eros. Sed mattis posuere lacus, non pharetra neque tincidunt eu. Nulla non mollis ligula, fringilla tempor enim. Duis rhoncus ex arcu, imperdiet aliquet odio vulputate id. Proin ultrices erat quam, eget pulvinar dui ultrices pellentesque. Nam pellentesque a libero a feugiat. Nam commodo lorem ut mauris lacinia sollicitudin.

Mauris elementum odio nec fermentum feugiat. Curabitur ornare sagittis quam, at pulvinar mauris convallis sit amet. Mauris sagittis, lacus vel commodo pharetra, nisi enim lacinia nunc, non aliquam augue nulla eget odio. Sed vitae scelerisque metus, nec vehicula nisl. Curabitur cursus vitae lorem et dictum. In ultrices orci nulla, vitae congue purus ultrices quis. Sed feugiat eros ut ante imperdiet, id ornare arcu pharetra. Maecenas efficitur arcu convallis justo tempus rhoncus. Phasellus eleifend elit in dolor commodo finibus. Vestibulum non odio tempus orci iaculis viverra id sed ligula. Sed in dolor eros. Nunc sed pretium metus, eget mollis mauris. Curabitur aliquet dignissim elit, vitae dictum nisi maximus sed. In blandit malesuada ligula, sit amet pulvinar neque vulputate nec. Vestibulum eget accumsan metus.`;

const SAMPLES_BY_TOOL: Record<string, readonly ToolSample[]> = {
  caesar: [
    {
      id: "hello",
      label: "HELLO",
      note: "The classical example. At the default shift of 3 this encrypts to KHOOR.",
      text: "HELLO",
    },
    {
      id: "khoor",
      label: "KHOOR",
      note: "The same example the other way: switch Direction to Decrypt and this gives HELLO back.",
      text: "KHOOR",
    },
    {
      id: "cryptogram",
      label: "A cryptogram to break",
      note: "Encrypted at shift 7. The brute force table under the result shows all 26 shifts.",
      text: "Aol xbpjr iyvdu mve qbtwz vcly 1 shgf kvn!",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  adfgvx: [
    {
      id: "attack",
      label: "ATTACK AT DAWN",
      note: "Classic WWI military field dispatch.",
      text: "ATTACK AT DAWN",
    },
    {
      id: "alphanumeric",
      label: "COVERT 1918",
      note: "Alphanumeric vector with 6x6 Polybius fractionating.",
      text: "COVERT OPERATION 1918",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  "vic-cipher": [
    {
      id: "strike",
      label: "STRIKE AT NOON",
      note: "Cold War KGB spy message with straddling checkerboard.",
      text: "STRIKE AT NOON",
    },
    {
      id: "agent",
      label: "SECRET AGENT",
      note: "Pencil and paper straddling checkerboard vector.",
      text: "SECRET AGENT 73521",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  "hill-cipher": [
    {
      id: "help",
      label: "HELP",
      note: "Classic 2x2 matrix textbook vector.",
      text: "HELP",
    },
    {
      id: "vector",
      label: "SECRET MESSAGE",
      note: "Polygraphic 2x2 matrix vector.",
      text: "SECRET MESSAGE",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  foursquare: [
    {
      id: "secret",
      label: "SECRET MEETING",
      note: "Delastelle 4-matrix digram pair substitution sample.",
      text: "SECRET MEETING",
    },
    {
      id: "attack",
      label: "ATTACK AT DAWN",
      note: "Digram encryption sample.",
      text: "ATTACK AT DAWN",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  chaocipher: [
    {
      id: "quote",
      label: "WELL DONE IS BETTER",
      note: "John F. Byrne's original 1918 Chaocipher test quote.",
      text: "WELL DONE IS BETTER THAN WELL SAID",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  enigma: [
    {
      id: "hello",
      label: "HELLOWORLD",
      note: "Standard Wehrmacht Enigma M3 plaintext.",
      text: "HELLOWORLD",
    },
    {
      id: "dispatch",
      label: "ANXBERLINX",
      note: "Historical military format (spaces replaced with X).",
      text: "ANXBERLINX",
    },
    {
      id: "numbers",
      label: "EINS ZWEI DREI",
      note: "Spelled out numbers per Wehrmacht protocol.",
      text: "EINS ZWEI DREI",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  vigenere: [
    {
      id: "attack",
      label: "ATTACK AT DAWN",
      note: "Polyalphabetic substitution with key LEMON.",
      text: "ATTACK AT DAWN",
    },
    {
      id: "sample",
      label: "MICHIGAN TECH",
      note: "Classical textbook polyalphabetic sample.",
      text: "MICHIGAN TECHNOLOGICAL UNIVERSITY",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  playfair: [
    {
      id: "gold",
      label: "HIDE THE GOLD",
      note: "Lord Peter Wimsey / classic Playfair example.",
      text: "HIDE THE GOLD IN THE TREE STUMP",
    },
    {
      id: "dispatch",
      label: "SECRET DISPATCH",
      note: "5x5 digraph key matrix vector.",
      text: "SECRET DISPATCH",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  bifid: [
    {
      id: "flee",
      label: "FLEE AT ONCE",
      note: "Delastelle 2-coordinate fractionating sample.",
      text: "FLEE AT ONCE",
    },
    {
      id: "midnight",
      label: "SECRET MEETING",
      note: "Polybius fractionating with period transposition.",
      text: "SECRET MEETING AT MIDNIGHT",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  trifid: [
    {
      id: "treaty",
      label: "TREATY NOT SIGNED",
      note: "Delastelle 3D 3x3x3 fractionating sample.",
      text: "TREATY NOT SIGNED",
    },
    {
      id: "covert",
      label: "COVERT MISSION",
      note: "3D trigram fractionating vector.",
      text: "COVERT MISSION",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  bacon: [
    {
      id: "knowledge",
      label: "KNOWLEDGE IS POWER",
      note: "Francis Bacon 5-bit binary steganographic cipher.",
      text: "KNOWLEDGE IS POWER",
    },
    {
      id: "strike",
      label: "STRIKE NOW",
      note: "5-bit A/B letter encoding vector.",
      text: "STRIKE NOW",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  railfence: [
    {
      id: "discovered",
      label: "WE ARE DISCOVERED",
      note: "Classic 3-rail geometric zig-zag transposition sample.",
      text: "WE ARE DISCOVERED FLEE AT ONCE",
    },
    {
      id: "defend",
      label: "DEFEND THE EAST WALL",
      note: "Multi-rail zig-zag transposition vector.",
      text: "DEFEND THE EAST WALL OF THE CASTLE",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  m209: [
    {
      id: "tactical",
      label: "TACTICAL DISPATCH",
      note: "US WWII Hagelin M-209 field transmission.",
      text: "TACTICAL AIR SUPPORT NEEDED AT COORDINATES",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  lorenz: [
    {
      id: "teleprinter",
      label: "HIGH COMMAND TELEPRINTER",
      note: "Lorenz SZ40/SZ42 strategic teleprinter ciphertext.",
      text: "GENERAL COMMUNIQUE SITUATION REPORT",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  solitaire: [
    {
      id: "cryptonomicon",
      label: "CRYPTONOMICON",
      note: "Bruce Schneier's Solitaire deck cipher example.",
      text: "DO NOT USE PC USE PENCIL AND DECK OF CARDS",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  adfgx: [
    {
      id: "field",
      label: "FIELD DISPATCH 1918",
      note: "WWI German ADFGX 5x5 fractionating cipher.",
      text: "ATTACK ENEMY FLANK AT DAWN",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  nihilist: [
    {
      id: "revolution",
      label: "SECRET DISPATCH",
      note: "Russian Nihilist fractionating coordinate addition cipher.",
      text: "MEET AT THE BRIDGE AT MIDNIGHT",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
  "straddling-checkerboard": [
    {
      id: "espionage",
      label: "ESPIONAGE TRANSMISSION",
      note: "Variable-length digit substitution without spaces.",
      text: "AGENT CONFIRMED OPERATION IN PROGRESS",
    },
    {
      id: "lorem",
      label: "Lorem Ipsum",
      note: "Full standard multi-paragraph Latin passage.",
      text: LOREM_IPSUM,
    },
  ],
};

export function samplesFor(toolId: string): readonly ToolSample[] | undefined {
  return SAMPLES_BY_TOOL[toolId];
}
