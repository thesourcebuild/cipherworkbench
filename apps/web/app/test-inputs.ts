/**
 * Canned inputs, for checking a tool against something known and for seeing how one behaves on more
 * than a handful of bytes.
 *
 * Its own module because the second one is nearly four kilobytes of prose, and `input-panel.tsx` is
 * a component rather than a place to keep a wall of Latin.
 *
 * Two entries, and each earns its place for a different reason:
 *
 *  - **`123456789`** is *the* check string. Every CRC in the RevEng catalogue publishes its check
 *    value over exactly these nine bytes, and so do the Tiger, Snefru and GOST vectors in this
 *    repo's own fixtures. Typing it by hand is the first thing anyone does with this app, which is
 *    reason enough to put it one click away.
 *  - **Lorem ipsum** is a multi-kilobyte input that spans several hash blocks -- 3,824 bytes is
 *    sixty 64-byte blocks, so it exercises the block loop, the buffer boundary and the length field
 *    rather than the single-block path nine bytes take. It also contains newlines, which is where
 *    someone comparing against a tool that trims trailing whitespace finds out that it does.
 *
 * The counts in the labels are derived from the strings, never written down beside them. A label
 * claiming 3,824 bytes over a string somebody has since edited is the sort of thing nothing catches.
 */
export interface TestInput {
  id: string;
  label: string;
  /** Tooltip: what it is for, rather than what it says. */
  note: string;
  text: string;
}

/**
 * Exported because it is also what a fresh session opens on -- see `DEFAULT_INPUT` in
 * `./input-state`. One string, so the box and the menu entry cannot drift apart.
 */
export const CHECK_STRING = "123456789";

/**
 * Exported for the tests, which run it through CRC, the hashes, HMAC and the ciphers.
 *
 * One home for the string rather than a copy in `tests/`. It is 3,824 bytes -- fifty-nine and three
 * quarter 64-byte blocks, and exactly 239 sixteen-byte blocks -- so it is the only input in the suite
 * that exercises a hash's block loop dozens of times over and lands a block cipher exactly on a
 * boundary, where PKCS#7 has to add a whole padding block rather than filling a partial one. A second
 * copy would drift from this one and the drift would be invisible: both would still hash to something.
 *
 * `tests/share-link.test.ts` already reaches into `apps/web/app` for the same reason.
 */
export const LOREM = [
  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean eu varius leo, at iaculis orci. Nunc a risus fringilla, suscipit turpis ac, gravida sem. Ut at metus nec mi laoreet posuere et et nibh. Pellentesque sit amet eleifend velit. Sed egestas eu lacus id gravida. Duis quis placerat justo. Quisque tincidunt mollis mauris, sed ultricies dolor fermentum sed. Proin eget convallis orci. Integer augue diam, condimentum non dui porta, bibendum dictum tortor. Praesent enim mi, aliquet ut nunc sit amet, consectetur bibendum enim. Donec pretium erat et consequat efficitur. Pellentesque tempus pharetra dolor, eu sagittis ligula bibendum quis. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas.",
  "Curabitur pharetra vestibulum dolor, sit amet suscipit risus aliquam quis. Nam ut nisl id libero mattis tempor quis in elit. Nullam auctor commodo mollis. Ut et euismod sapien, ac lobortis orci. Donec gravida enim id quam eleifend, quis venenatis lacus feugiat. Praesent gravida vitae nulla a vestibulum. Aliquam ex enim, aliquet vel massa eleifend, aliquet maximus ligula. Aenean eu dui ut diam facilisis varius. Maecenas suscipit odio at metus laoreet mollis. Sed at nisi rhoncus, scelerisque odio eget, convallis enim. Pellentesque sit amet sem id risus congue vulputate. Suspendisse mattis lectus sit amet libero pellentesque porttitor.",
  "Donec placerat purus sed auctor bibendum. Suspendisse odio purus, tincidunt eget venenatis eget, efficitur eget ipsum. Vivamus id justo tempus, fermentum augue ac, aliquam est. Quisque ornare justo vitae metus vulputate, sit amet aliquam libero pulvinar. Maecenas non rutrum tellus, et sodales urna. Nullam ornare nulla in ipsum eleifend, in pharetra erat sollicitudin. Aenean odio erat, lacinia sed turpis nec, euismod posuere purus. Donec sed leo non nisl posuere pellentesque. Cras in eros leo. Ut ut congue augue. Quisque mattis leo ac metus iaculis, a tincidunt est bibendum. Interdum et malesuada fames ac ante ipsum primis in faucibus. Nam ante tellus, hendrerit a aliquet molestie, tincidunt eu diam. Aliquam pulvinar urna feugiat, ornare lacus ac, ultricies felis.",
  "Morbi viverra neque nec dignissim laoreet. Praesent condimentum eget neque non imperdiet. Cras ex lectus, facilisis a dolor id, ornare porttitor orci. Nulla est justo, egestas eu interdum quis, posuere et nisi. Nunc ac maximus leo, sit amet tristique risus. Vestibulum ultricies ullamcorper justo, id vulputate orci ullamcorper iaculis. Nullam ipsum lorem, blandit at eleifend in, pellentesque eget odio. Vestibulum consequat blandit vehicula. Nulla dignissim nisl vel rhoncus lobortis. Sed quis fermentum arcu, in egestas eros. Sed mattis posuere lacus, non pharetra neque tincidunt eu. Nulla non mollis ligula, fringilla tempor enim. Duis rhoncus ex arcu, imperdiet aliquet odio vulputate id. Proin ultrices erat quam, eget pulvinar dui ultrices pellentesque. Nam pellentesque a libero a feugiat. Nam commodo lorem ut mauris lacinia sollicitudin.",
  "Mauris elementum odio nec fermentum feugiat. Curabitur ornare sagittis quam, at pulvinar mauris convallis sit amet. Mauris sagittis, lacus vel commodo pharetra, nisi enim lacinia nunc, non aliquam augue nulla eget odio. Sed vitae scelerisque metus, nec vehicula nisl. Curabitur cursus vitae lorem et dictum. In ultrices orci nulla, vitae congue purus ultrices quis. Sed feugiat eros ut ante imperdiet, id ornare arcu pharetra. Maecenas efficitur arcu convallis justo tempus rhoncus. Phasellus eleifend elit in dolor commodo finibus. Vestibulum non odio tempus orci iaculis viverra id sed ligula. Sed in dolor eros. Nunc sed pretium metus, eget mollis mauris. Curabitur aliquet dignissim elit, vitae dictum nisi maximus sed. In blandit malesuada ligula, sit amet pulvinar neque vulputate nec. Vestibulum eget accumsan metus.",
].join("\n\n");

/** Words, the way anyone counts them: runs of non-whitespace. */
function words(text: string): number {
  return text.trim().split(/\s+/).length;
}

/**
 * Character counts, not byte counts, and that is deliberate.
 *
 * Both strings are pure ASCII, so under UTF-8 the two numbers agree -- and under UTF-16LE, which
 * this app offers and people do pick, the byte count doubles while the character count does not. A
 * label that said "3,824 bytes" would be wrong for half the encodings in the dropdown beside it. The
 * Input panel's own header reports the real byte count for whatever encoding is selected, which is
 * the right place for a number that depends on one.
 */
export const TEST_INPUTS: readonly TestInput[] = [
  {
    id: "check",
    label: `123456789 (${CHECK_STRING.length} characters)`,
    note: "The standard check string. Every CRC model in the catalogue publishes its check value over these nine bytes, as do most published hash vectors.",
    text: CHECK_STRING,
  },
  {
    id: "lorem",
    label: `Lorem ipsum (${words(LOREM)} words, ${LOREM.length.toLocaleString()} characters)`,
    note: "Five paragraphs, separated by blank lines. Long enough to cross a hash's block boundary many times over, where nine bytes never leaves the first block.",
    text: LOREM,
  },
];
