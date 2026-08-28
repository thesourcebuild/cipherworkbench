import { Menu, app, clipboard, type BrowserWindow } from "electron";
import { appIcon } from "./window";

/**
 * Headless verification that the packaged renderer really loads over app://, that
 * React mounted, and that the crypto actually runs — the three things most likely
 * to break silently between a working `next build` and a working desktop app.
 *
 * Enabled with OCS_SMOKE=1; exits non-zero on failure so CI can gate on it.
 */

/** SHA-256("abc"), FIPS 180-4 §B.1. The check value the probe below demands. */
const SHA256_ABC = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";

/** CRC-32/ISO-HDLC of "123456789", from the RevEng catalogue. */
const CRC32_CHECK = "CBF43926";

/**
 * The 8-bit and 16-bit sum of "123456789" — 0xDD and 0x01DD.
 *
 * Two values from one probe, because the point is the option rather than the arithmetic: the second
 * only appears if changing the width selector re-ran the compute. The sum family's whole catalogue
 * is enum options, which nothing else here exercises in the packaged build.
 */
const SUM8_CHECK = "DD";
const SUM16_CHECK = "01DD";

/**
 * RFC 8032 section 7.1 TEST 2: the Ed25519 signature over the single byte 0x72 — "r" as
 * text — under the private key below.
 *
 * The public-key family is the only one whose result depends on an *option* rather than on
 * the input panel, so this probe is the only one that drives the options form in the packaged
 * build. It is also the only probe that exercises a masked secret control.
 */
/**
 * SHA-256 of the three characters 日本語 encoded as **Shift_JIS** -- 93 fa 96 7b 8c ea.
 *
 * The digest of the same characters as UTF-8 is
 * 77710aedc74ecfa33685e33a6c7df5cc83004da1bdcef7fb280f5c2b2e97e0a5, so this value can only
 * appear if the encoding selector really took effect. That matters more than it looks: those
 * bytes come from 530 KB of WHATWG conversion tables in a chunk nothing references statically,
 * fetched on demand -- and a lazy chunk that fails to resolve over the app:// protocol is
 * exactly the class of packaging fault this smoke test exists to catch.
 */
const SHIFT_JIS_SHA256 = "7FA11A31677814A9D558E8854002A5BB79BAC5B1ADBA7EBC992365A7F483B688";

/**
 * Streebog-256 of RFC 6986's example 1 message, the digit string "0123456789...012".
 *
 * The RFC prints its values most significant byte first; this is the byte order a program produces,
 * which is what `tests/algos-streebog.test.ts` explains at length.
 */
/** RFC 9562 appendix A's own v5: SHA-1 over the DNS namespace and "www.example.com". */
const UUID_V5_EXAMPLE = "2ed6657d-e927-568b-95e1-2665a8aea6a2";

const STREEBOG_256_RFC_EXAMPLE =
  "9D151EEFD8590B89DAA6BA6CB74AF9275DD051026BB149A452FD84E5E57B5500";
const ED25519_SECRET = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const ED25519_SIGNATURE =
  "92A009A9F0D4CAB8720E820B5F642540A2B27B5416503F8FB3762223EBDB69DA" +
  "085AC1E43E15996E458F3613D0F11D8C387B2EAEB4302AEEB00D291612BB0C00";

interface ComputeProbe {
  digest?: string;
  error?: string;
}

/**
 * Drops a file on the input panel and requires the same known digest back.
 *
 * This is the probe for the riskiest part of the build. File input goes through a
 * bundler-generated Web Worker, and whether that worker is emitted as a real chunk
 * or as an unusable raw asset depends on which bundler ran — Turbopack gets it
 * wrong under `output: "export"`, which is why the web build is pinned to webpack.
 * `file-compute.ts` falls back to the main thread when the worker fails to start,
 * so a broken worker produces a *correct answer* and no error: exactly the kind of
 * regression that never gets noticed. Hence the caller also asserts that the
 * fallback's console warning was absent.
 *
 * Getting SHA-256("abc") back from a 3-byte file additionally proves the streaming
 * path agrees with the one-shot path in the real build, not just in the unit tests.
 */
function checkFileCompute(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await new Promise((r) => setTimeout(r, 100));
         }
       };
       // A result that has finished computing. While the debounce is pending the panel still shows
       // the previous value, and reading that is how a probe passes for the wrong reason.
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';

       // The source control is a dropdown, so this sets the value and dispatches the event React
       // listens for. Clicking an <option> does nothing, which is how this probe would fail
       // silently if the tab row ever came back.
       const source = document.querySelector("[data-ocs-input-mode]");
       if (!source) return { error: "no input source selector" };
       const setSelectValue = Object.getOwnPropertyDescriptor(
         HTMLSelectElement.prototype,
         "value",
       ).set;
       setSelectValue.call(source, "file");
       source.dispatchEvent(new Event("change", { bubbles: true }));

       const dropzone = await waitFor("[data-ocs-dropzone]", 5000);
       if (!dropzone) return { error: "File mode did not render a drop zone" };

       // A real drop event: an <input type=file> cannot be populated
       // programmatically, but a synthetic DragEvent carrying a constructed
       // DataTransfer goes through the same React handler a user's drop does.
       const transfer = new DataTransfer();
       transfer.items.add(new File([new Uint8Array([0x61, 0x62, 0x63])], "probe.bin"));
       dropzone.dispatchEvent(
         new DragEvent("drop", { dataTransfer: transfer, bubbles: true, cancelable: true }),
       );

       const deadline = Date.now() + 10000;
       while (Date.now() < deadline) {
         await new Promise((r) => setTimeout(r, 100));
         const text = (document.querySelector(SETTLED)?.textContent ?? "")
           .replace(/[^0-9a-fA-F]/g, "");
         if (/^[0-9a-fA-F]{64}$/.test(text)) return { digest: text };
       }
       return { error: "no digest appeared within 10s of dropping a file" };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Types "abc" into the input and requires SHA-256("abc") to come out.
 *
 * This is the probe that matters, and it is deliberately a *known answer* rather
 * than "the output changed". Everything cheaper than this is satisfiable by
 * prerendered HTML: the markup renders, `<main>` exists, the bridge is present —
 * and the app can still be completely dead, which is exactly what happens when a
 * CSP blocks the inline hydration scripts. Demanding a specific digest proves
 * three things at once: React hydrated, the lazily-imported algorithm chunk was
 * fetched over app://, and it computed the right bytes in the packaged build.
 *
 * It waits for the workbench rather than asserting it is already there. The tool's
 * definition arrives through a dynamic `import()`, so at `did-finish-load` the page
 * is still showing the loading skeleton — checking for the textarea at that moment
 * fails on a perfectly healthy build.
 *
 * The value is set through the prototype's native setter rather than by assigning
 * `.value` directly. React tracks the last value it wrote on the DOM node, and a
 * direct assignment updates the node without updating that tracker, so React
 * dedupes the resulting `input` event as a no-op and the probe silently passes
 * nothing to the app.
 */
/**
 * Seeding, which only this probe can see, and only before anything has been typed.
 *
 * A fresh box holds 123456789 -- the check string every CRC model in the catalogue publishes its
 * value over -- and that string is not JSON, not XML and not a JWT. So a family may declare its own
 * samples, and switching to a tool that has one replaces the placeholder; switching to a tool with
 * none puts the check string back, which is what keeps "a fresh box holds 123456789" true everywhere
 * else instead of leaving whichever document was seeded last.
 *
 * Both directions are asserted, because only one of them is the interesting failure. Seeding forward
 * and never restoring would leave a JSON document in front of a CRC tool, which is the same defect
 * with the tools swapped.
 *
 * It runs **first**, ahead of every other probe, and that ordering is the whole reason it works: this
 * may only ever replace an input the app itself put there, so the moment any probe types, seeding is
 * correctly switched off for the rest of the session. Running this later would assert nothing and
 * pass.
 */
function checkSeededInput(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       /*
        * Polls for the value *wanted*, not for any non-empty one, and that is the whole correctness of
        * this probe. Seeding lands in an effect after the tool's lazy chunk resolves, so on a switch
        * the box briefly still holds the previous tool's text. An earlier version polled until the box
        * was non-empty, which is true immediately, and passed only because the workbench happened to
        * unmount the panel while loading -- a race it eventually lost. Waiting on the condition removes
        * the race instead of widening the window.
        */
       const openAndAwait = async (id, wanted, describe) => {
         /*
          * Re-queried per attempt, for the same reason as the poll below and as the open() helpers in
          * the later probes: the sidebar remounts on a tool switch, so a row found and then clicked
          * can be a node React already replaced -- the click reaches a detached element and silently
          * does nothing.
          */
         const selector = '[data-ocs-tool="' + id + '"]';
         const clickDeadline = Date.now() + 15000;
         let everSeen = false;
         let selected = false;
         while (!selected && Date.now() < clickDeadline) {
           const button = document.querySelector(selector);
           if (!button) {
             await sleep(100);
             continue;
           }
           everSeen = true;
           button.click();
           selected = Boolean(await waitFor(selector + '[aria-current="true"]', 2000));
         }
         if (!everSeen) return id + " is not listed in the sidebar";
         if (!selected) return "clicking " + id + " did not select it";
         const box = await waitFor("[data-ocs-input]", 10000);
         if (!box) return id + " rendered no input box";
         const deadline = Date.now() + 15000;
         let last = "";
         while (Date.now() < deadline) {
           last = box.value;
           if (wanted(last)) return null;
           await sleep(100);
         }
         return "on " + id + " the box " + describe + "; it held " + JSON.stringify(last);
       };

       const isCheckString = (text) => text === "123456789";
       /*
        * A document, not the check string. The exact text is the family's business, so this asks only
        * that it changed and that it parses -- which is what makes it a JSON sample rather than
        * whatever was in the box before.
        */
       const isJsonDocument = (text) => {
         if (text === "" || text === "123456789") return false;
         try {
           JSON.parse(text);
           return true;
         } catch (thrown) {
           return false;
         }
       };

       let problem = await openAndAwait("crc8", isCheckString, "never held the check string");
       if (problem) return { error: problem };

       problem = await openAndAwait("json", isJsonDocument, "never held a JSON document");
       if (problem) return { error: problem };
       const seeded = document.querySelector("[data-ocs-input]").value;

       problem = await openAndAwait("crc32", isCheckString, "did not get the check string back");
       if (problem) return { error: problem };

       return { digest: String(seeded.length) };
     })()`,
  ) as Promise<ComputeProbe>;
}

function checkCompute(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await new Promise((r) => setTimeout(r, 100));
         }
       };
       // A result that has finished computing. While the debounce is pending the panel still shows
       // the previous value, and reading that is how a probe passes for the wrong reason.
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';

       // Select SHA-256 explicitly rather than trusting the default. The run has its
       // own wiped userData directory so nothing should be restored, but this probe
       // asserts a specific known answer and must not depend on that holding.
       const sha256 = await waitFor('[data-ocs-tool="sha256"]', 10000);
       if (!sha256) return { error: "the sha256 tool is not listed in the sidebar" };
       sha256.click();

       // Wait for the *switch* to land, not merely for a textarea to exist. If another
       // tool was already open, its textarea is still in the DOM at this point, and
       // typing into it feeds the outgoing workbench — which is how this probe
       // previously reported a CRC-32 value while claiming to test SHA-256.
       const selected = await waitFor('[data-ocs-tool="sha256"][aria-current="true"]', 10000);
       if (!selected) return { error: "clicking sha256 did not select it" };

       // The tool definition is dynamically imported, so the workbench replaces a
       // skeleton some time after that. A missing textarea here means the import never
       // resolved — a chunk that failed to fetch over app://, most likely.
       const input = await waitFor("[data-ocs-input]", 10000);
       if (!input) return { error: "the workbench never rendered — [data-ocs-input] absent after 10s" };
       if (!document.querySelector("[data-ocs-result]")) {
         return { error: "the workbench rendered without a result panel" };
       }

       // The panel's two preferences are switches, and Auto update being on is what the poll below
       // depends on. Checked for state rather than existence: a switch stuck reporting the wrong
       // value would leave this probe waiting for a digest that was never going to be computed.
       const autoUpdate = document.querySelector('[data-ocs-toggle="auto-update"]');
       if (!autoUpdate) return { error: "no Auto update switch" };
       if (autoUpdate.getAttribute("role") !== "switch") {
         return { error: "Auto update is not exposed as a switch" };
       }
       if (autoUpdate.getAttribute("aria-checked") !== "true") {
         return { error: "Auto update is off in a fresh profile; nothing would recompute" };
       }

       const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
       setter.call(input, "abc");
       input.dispatchEvent(new Event("input", { bubbles: true }));

       // The compute hook debounces text input by INPUT_DEBOUNCE_MS; poll rather than guess a
       // delay, and leave enough budget that neither a slower machine nor a longer debounce turns
       // the wait into a failure.
       const deadline = Date.now() + 10000;
       while (Date.now() < deadline) {
         await new Promise((r) => setTimeout(r, 100));
         const text = (document.querySelector(SETTLED)?.textContent ?? "")
           .replace(/\\s+/g, "");
         if (text.length > 0) return { digest: text };
       }
       return { error: "no result appeared within 5s of entering input" };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Switches tools via the sidebar and computes a second algorithm from a different
 * family.
 *
 * The first probe proves one lazily-imported chunk loads. This proves the *registry*
 * works: picking a tool from the sidebar resolves a different family's dynamic import
 * and swaps the whole workbench — the options form, the compute path and the result
 * panel — without a reload. A packaging mistake that split the chunks wrongly shows up
 * here and nowhere earlier.
 */
function checkToolSwitch(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       // A result that has finished computing. While the debounce is pending the panel still shows
       // the previous value, and reading that is how a probe passes for the wrong reason.
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';

       // Back to Text mode first — the file probe left the panel on File.
       const source = document.querySelector("[data-ocs-input-mode]");
       if (source) {
         Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(
           source,
           "text",
         );
         source.dispatchEvent(new Event("change", { bubbles: true }));
       }
       await sleep(100);

       // Selected by id, not by label text: a category header can render the same
       // string as a tool inside it, so matching on text clicked the collapse toggle.
       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let button = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         button = document.querySelector('[data-ocs-tool="crc32"]') || button;
         if (document.querySelector('[data-ocs-tool="crc32"][aria-current="true"]')) break;
         if (button) button.click();
         await sleep(100);
       }
       if (!button) return { error: "the crc32 tool is not listed in the sidebar" };

       // Wait for the selection to land before touching the textarea. SHA-256's is
       // still mounted at this instant, and typing into it would test the outgoing
       // tool — the same race the first probe hit.
       //
       // Two independent budgets, too: sharing one deadline between the mount wait and
       // the compute wait left the second with whatever the first did not use.
       let input = null;
       const mountDeadline = Date.now() + 10000;
       while (Date.now() < mountDeadline) {
         await sleep(100);
         if (!document.querySelector('[data-ocs-tool="crc32"][aria-current="true"]')) continue;
         input = document.querySelector("[data-ocs-input]");
         if (input) break;
       }
       if (!input) return { error: "the CRC-32 workbench never rendered" };

       // What is on screen before typing. CRC-32 of the previous probe's "abc" is also eight hex
       // characters, so shape alone cannot tell them apart -- and switching tool computes it
       // immediately, before this probe types anything. Requiring a *different* settled value is what
       // makes this probe about CRC-32("123456789") rather than about any eight hex digits.
       const before = (document.querySelector(SETTLED)?.textContent ?? "").replace(/[^0-9a-fA-F]/g, "");

       const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
       setter.call(input, "123456789");
       input.dispatchEvent(new Event("input", { bubbles: true }));

       const computeDeadline = Date.now() + 10000;
       let last = "";
       while (Date.now() < computeDeadline) {
         await sleep(100);
         last = (document.querySelector(SETTLED)?.textContent ?? "").replace(/[^0-9a-fA-F]/g, "");
         if (last !== before && /^[0-9a-fA-F]{8}$/.test(last)) return { digest: last };
       }
       return { error: 'no CRC-32 value appeared; the result panel showed ' + JSON.stringify(last) };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Computes an 8-bit sum, widens it to 16 bits through the options form, and requires both values.
 *
 * The point is not the arithmetic — that has published vectors in the unit suite — but that
 * `@ocs/checksum` is a *separate lazy chunk*, reached by its own `case` in `loadTool()`. A chunk
 * that fails to resolve over app:// is the packaging fault this file exists to catch, and every
 * family added after the first is a new opportunity for it. Changing the width afterwards proves
 * the enum controls in that chunk's catalogue are live rather than merely rendered.
 */
function checkChecksumFamily(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       // A result that has finished computing. While the debounce is pending the panel still shows
       // the previous value, and reading that is how a probe passes for the wrong reason.
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';

       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let button = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         button = document.querySelector('[data-ocs-tool="sum"]') || button;
         if (document.querySelector('[data-ocs-tool="sum"][aria-current="true"]')) break;
         if (button) button.click();
         await sleep(100);
       }
       if (!button) return { error: "the sum tool is not listed in the sidebar" };

       let input = null;
       const mountDeadline = Date.now() + 10000;
       while (Date.now() < mountDeadline) {
         await sleep(100);
         if (!document.querySelector('[data-ocs-tool="sum"][aria-current="true"]')) continue;
         input = document.querySelector("[data-ocs-input]");
         if (input) break;
       }
       if (!input) return { error: "the sum workbench never rendered" };

       // Set the text explicitly rather than relying on what an earlier probe left behind.
       const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
       setter.call(input, "123456789");
       input.dispatchEvent(new Event("input", { bubbles: true }));

       const readResult = async (pattern) => {
         const deadline = Date.now() + 10000;
         let last = "";
         while (Date.now() < deadline) {
           await sleep(100);
           last = (document.querySelector(SETTLED)?.textContent ?? "").replace(/[^0-9a-fA-F]/g, "");
           if (pattern.test(last)) return last;
         }
         return { showed: last };
       };

       const narrow = await readResult(/^[0-9a-fA-F]{2}$/);
       if (typeof narrow !== "string") {
         return { error: 'no 8-bit sum appeared; the result panel showed ' + JSON.stringify(narrow.showed) };
       }

       // The width lives two components deep behind a masked-or-not control wrapper, hence the
       // data hook. A select element, because every option in this family is an enum.
       const width = document.querySelector('[data-ocs-option="width"] select');
       if (!width) return { error: "the sum tool rendered without a width selector" };
       const selectSetter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set;
       selectSetter.call(width, "16");
       width.dispatchEvent(new Event("change", { bubbles: true }));

       const wide = await readResult(/^[0-9a-fA-F]{4}$/);
       if (typeof wide !== "string") {
         return { error: 'widening to 16 bits changed nothing; the result panel showed ' + JSON.stringify(wide.showed) };
       }

       return { digest: narrow + "/" + wide };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Drives the Result panel's hex prefix selector and requires the value to change.
 *
 * A control that renders and does nothing is this repo's most-repeated bug: AEGIS's tag length was
 * inert in the app for a while with a green suite, and the "(not set)" placeholder sat in every
 * dropdown through two rounds of unit tests. Neither a typecheck nor the node suite can see a select
 * wired to nothing, so this drives it end to end in the packaged renderer.
 *
 * CRC-32 of "123456789" is 0xcbf43926, which is the value every other CRC check in this file uses.
 */
function checkHexPrefix(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const waitFor = async (selector, timeout) => {
         const until = Date.now() + timeout;
         while (Date.now() < until) {
           const found = document.querySelector(selector);
           if (found) return found;
           await sleep(50);
         }
         return null;
       };
       const setSelect = (element, value) => {
         Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(
           element,
           value,
         );
         element.dispatchEvent(new Event("change", { bubbles: true }));
       };
       const settled = async (pattern) => {
         const until = Date.now() + 10000;
         let last = "";
         while (Date.now() < until) {
           await sleep(60);
           last = (document.querySelector(SETTLED)?.textContent ?? "").replace(/\\s+/g, "");
           if (pattern.test(last)) return last;
         }
         return { showed: last };
       };

       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let link = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         link = document.querySelector('[data-ocs-tool="crc32"]') || link;
         if (document.querySelector('[data-ocs-tool="crc32"][aria-current="true"]')) break;
         if (link) link.click();
         await sleep(100);
       }
       if (!link) return { error: "the crc32 tool is not listed in the sidebar" };
       if (!(await waitFor('[data-ocs-tool="crc32"][aria-current="true"]', 10000))) {
         return { error: "clicking crc32 did not select it" };
       }

       const input = await waitFor("[data-ocs-input]", 10000);
       if (!input) return { error: "no input field" };
       const setValue = Object.getOwnPropertyDescriptor(
         HTMLTextAreaElement.prototype,
         "value",
       ).set;
       setValue.call(input, "123456789");
       input.dispatchEvent(new Event("input", { bubbles: true }));

       // Hex is the default, so the prefix selector must already be on screen.
       const encoding = document.querySelector('[aria-label="Output encoding"]');
       if (encoding) setSelect(encoding, "hex");

       const bare = await settled(/^cbf43926$/);
       if (typeof bare !== "string") {
         return { error: "no bare CRC-32 appeared; the panel showed " + JSON.stringify(bare) };
       }

       const prefix = await waitFor('[aria-label="Hex prefix"]', 10000);
       if (!prefix) return { error: "hex is selected but no prefix selector rendered" };

       setSelect(prefix, "0x");
       const lower = await settled(/^0xcbf43926$/);
       if (typeof lower !== "string") {
         return { error: "0x did not take; the panel showed " + JSON.stringify(lower) };
       }

       setSelect(prefix, "0X");
       const upper = await settled(/^0Xcbf43926$/);
       if (typeof upper !== "string") {
         return { error: "0X did not take; the panel showed " + JSON.stringify(upper) };
       }

       setSelect(prefix, "");
       const back = await settled(/^cbf43926$/);
       if (typeof back !== "string") {
         return { error: "clearing the prefix did not take; showed " + JSON.stringify(back) };
       }

       // And it is gone for an encoding a prefix means nothing for.
       if (encoding) {
         setSelect(encoding, "binary");
         await sleep(200);
         if (document.querySelector('[aria-label="Hex prefix"]')) {
           return { error: "the prefix selector is still shown for binary output" };
         }
         setSelect(encoding, "hex");
       }

       return { digest: lower + "/" + upper };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Opens the Table panel on CRC-32 and reads zlib's table out of it, then again on CRC-5.
 *
 * The panel is collapsed by default, which is why this exists: a fault in a 256-cell grid that
 * nobody expands is invisible to a typecheck, to the unit suite and to a build. And the values are
 * worth asserting rather than merely the presence of cells -- 0x77073096 is the second entry of the
 * most-copied array in computing, so if the grid renders the wrong orientation or a stale table this
 * catches it against something published rather than against our own output.
 *
 * The CRC-5 leg is here because that panel did not exist until the polynomial was left-justified
 * into a byte, and "the panel is simply absent for five of the tools" is a state the whole suite
 * was previously content with. It also pins the *width* of a cell, which is the visible half of the
 * justification: two hex digits, not eight and not one.
 */
function checkLookupTable(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
       const waitFor = async (selector, timeout) => {
         const until = Date.now() + timeout;
         while (Date.now() < until) {
           const found = document.querySelector(selector);
           if (found) return found;
           await sleep(50);
         }
         return null;
       };
       const setSelect = (element, value) => {
         Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(
           element,
           value,
         );
         element.dispatchEvent(new Event("change", { bubbles: true }));
       };

       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let link = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         link = document.querySelector('[data-ocs-tool="crc32"]') || link;
         if (document.querySelector('[data-ocs-tool="crc32"][aria-current="true"]')) break;
         if (link) link.click();
         await sleep(100);
       }
       if (!link) return { error: "the crc32 tool is not listed in the sidebar" };
       if (!(await waitFor('[data-ocs-tool="crc32"][aria-current="true"]', 10000))) {
         return { error: "clicking crc32 did not select it" };
       }

       const panel = await waitFor("[data-ocs-table]", 15000);
       if (!panel) return { error: "CRC-32 rendered no Table panel" };

       // Collapsed on open, by design. Expand it the way a user would.
       const toggle = panel.querySelector('button[aria-expanded]');
       if (!toggle) return { error: "the Table panel has no collapse toggle" };
       if (toggle.getAttribute("aria-expanded") !== "true") toggle.click();

       const select = await waitFor("[data-ocs-table-select]", 10000);
       if (!select) return { error: "the Table panel rendered no orientation selector" };
       setSelect(select, "reflected");

       const cellText = async (index) => {
         const cell = await waitFor('[data-ocs-table-cell="' + index + '"]', 10000);
         return cell ? cell.textContent.trim() : null;
       };

       // zlib's crc_table[0..3].
       const expected = ["0x00000000", "0x77073096", "0xEE0E612C", "0x990951BA"];
       const seen = [];
       for (let i = 0; i < expected.length; i++) seen.push(await cellText(i));
       if (seen.join(" ") !== expected.join(" ")) {
         return { error: "reflected CRC-32 table read " + seen.join(" ") };
       }

       // And the other orientation is the Ethernet table, so the selector is really switching.
       setSelect(select, "normal");
       await sleep(100);
       const normal1 = await cellText(1);
       if (normal1 !== "0x04C11DB7") {
         return { error: "normal CRC-32 table entry 1 read " + String(normal1) };
       }

       const count = document.querySelectorAll("[data-ocs-table-cell]").length;
       if (count !== 256) return { error: "the grid rendered " + count + " cells, expected 256" };

       // The heading's badge has to agree with the grid under it. Nothing else can see a count that
       // is merely plausible.
       const badge = document.querySelector("[data-ocs-table-count]");
       if (!badge) return { error: "the Table heading has no entry-count badge" };
       if (badge.textContent.trim() !== count + " entries") {
         return { error: "the badge reads " + JSON.stringify(badge.textContent.trim()) + " over " + count + " cells" };
       }

       // Now the same panel on a width narrower than the byte that indexes it.
       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let narrowLink = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         narrowLink = document.querySelector('[data-ocs-tool="crc5"]') || narrowLink;
         if (document.querySelector('[data-ocs-tool="crc5"][aria-current="true"]')) break;
         if (narrowLink) narrowLink.click();
         await sleep(100);
       }
       if (!narrowLink) return { error: "the crc5 tool is not listed in the sidebar" };
       if (!(await waitFor('[data-ocs-tool="crc5"][aria-current="true"]', 10000))) {
         return { error: "clicking crc5 did not select it" };
       }

       /**
        * A retry loop rather than a wait-then-act, because the CRC-32 panel is still mounted for a
        * frame or two after the sidebar selection changes -- so a single "find the toggle and click
        * it" can land on the outgoing panel and collapse it, after which nothing ever appears. The
        * loop expands whatever panel is current and stops when a cell is two hex digits wide, which
        * is a condition only the new panel can satisfy.
        */
       let narrowReady = false;
       const narrowUntil = Date.now() + 20000;
       while (Date.now() < narrowUntil) {
         const cell1 = document.querySelector('[data-ocs-table-cell="1"]');
         if (cell1 && cell1.textContent.trim().length === 4) { narrowReady = true; break; }
         const panelNow = document.querySelector("[data-ocs-table]");
         const toggleNow = panelNow && panelNow.querySelector('button[aria-expanded]');
         if (toggleNow && toggleNow.getAttribute("aria-expanded") !== "true") toggleNow.click();
         await sleep(100);
       }
       if (!narrowReady) return { error: "CRC-5 rendered no byte-wide lookup table" };

       /**
        * CRC-5/USB's polynomial is 0x05, shifted up three bits to sit at the top of a byte: 0x28.
        * Entry 1 of a normal table is always the polynomial itself, and entries 2 and 3 are the next
        * two remainders, so these four values fail if the justification, the orientation or the cell
        * padding is wrong.
        */
       const narrowCells = [];
       for (let i = 0; i < 4; i++) narrowCells.push(await cellText(i));
       if (narrowCells.join(" ") !== "0x00 0x28 0x50 0x78") {
         return { error: "CRC-5/USB table read " + narrowCells.join(" ") };
       }
       const narrowCount = document.querySelectorAll("[data-ocs-table-cell]").length;
       if (narrowCount !== 256) {
         return { error: "the CRC-5 grid rendered " + narrowCount + " cells, expected 256" };
       }

       return { digest: seen[1] + "/" + normal1 + "/" + narrowCells[1] };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * The Variants panel, and its own Run button.
 *
 * Three things it pins down, each of which has already been wrong once.
 *
 * The rows exist *before* any run: names, aliases and parameters come off the spec, so the table is
 * populated the moment the tool loads. Keyed on computed values instead, the panel did not exist at
 * all until something had run -- and with auto-update off on a fresh load, nothing had.
 *
 * Run fills the Result column, and nothing else does. Auto update is off here and the Result panel's
 * Compute is never pressed, so a value appearing without Run would mean the two had got coupled again.
 *
 * The values are three *published* check figures on rows whose polynomials differ. Reading the cells
 * off the selected model rather than off each row's own would put 0x07 on all twenty and look
 * completely normal, so one row proves nothing -- and a mis-paired table is worse than an empty one,
 * because someone identifying an unknown checksum walks away with the wrong model name.
 */
function checkVariants(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let link = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         link = document.querySelector('[data-ocs-tool="crc8"]') || link;
         if (document.querySelector('[data-ocs-tool="crc8"][aria-current="true"]')) break;
         if (link) link.click();
         await sleep(100);
       }
       if (!link) return { error: "the crc8 tool is not listed in the sidebar" };

       let panel = null;
       const mountDeadline = Date.now() + 15000;
       while (Date.now() < mountDeadline) {
         await sleep(100);
         if (!document.querySelector('[data-ocs-tool="crc8"][aria-current="true"]')) continue;
         panel = document.querySelector("[data-ocs-variants]");
         if (panel) break;
       }
       if (!panel) return { error: "CRC-8 rendered no Variants panel" };

       // Collapsed or not, expand it the way a user would.
       const toggle = panel.querySelector('button[aria-expanded]');
       if (!toggle) return { error: "the Variants panel has no collapse toggle" };
       if (toggle.getAttribute("aria-expanded") !== "true") toggle.click();
       await sleep(200);

       const heads = Array.from(panel.querySelectorAll("th")).map((th) => th.textContent.trim());
       if (heads.join(",") !== "Model,Result,Check,Poly,Init,RefIn,RefOut,XorOut") {
         return { error: "the columns read " + heads.join(",") };
       }

       const cells = (name) => {
         const row = panel.querySelector('[data-ocs-variant="' + name + '"]');
         return row ? Array.from(row.querySelectorAll("td")).map((td) => td.textContent.trim()) : [];
       };

       // The rows are there before Run, with their parameters, and no values.
       const before = cells("CRC-8/SMBUS");
       if (before.length !== 8) return { error: "SMBUS row has " + before.length + " cells" };
       if (before[3] !== "0x07") return { error: "SMBUS Poly read " + JSON.stringify(before[3]) };
       if (before[1] !== "\u2014") {
         return { error: "a value was shown before Run: " + JSON.stringify(before[1]) };
       }

       const run = panel.querySelector("[data-ocs-variants-run]");
       if (!run) return { error: "the Variants panel has no Run button" };
       if (run.textContent.trim() !== "Run") {
         return { error: "the button reads " + JSON.stringify(run.textContent.trim()) };
       }
       if (run.disabled) return { error: "Run is disabled with input in the box" };
       run.click();

       /*
        * Upper-case, which is this column's default and not the Result panel's.
        *
        * A check value is printed upper-case nearly everywhere it is printed -- the RevEng catalogue,
        * a peripheral datasheet -- and this table exists to be read against one of those. Asserting
        * the case rather than a case-insensitive match is the whole point: "f4" would satisfy a
        * lower-cased comparison and would mean the default had silently reverted.
        */
       let smbus = "";
       const runDeadline = Date.now() + 15000;
       while (Date.now() < runDeadline) {
         smbus = cells("CRC-8/SMBUS")[1] ?? "";
         if (smbus === "F4") break;
         await sleep(100);
       }
       if (smbus !== "F4") {
         return { error: "after Run, CRC-8/SMBUS read " + JSON.stringify(smbus) + ", expected F4" };
       }

       const dow = cells("CRC-8/MAXIM-DOW");
       const bluetooth = cells("CRC-8/BLUETOOTH");
       if (dow[1] !== "A1") return { error: "CRC-8/MAXIM-DOW read " + JSON.stringify(dow[1]) };
       // No letters in this one, so it says nothing about the case -- it is here for the value.
       if (bluetooth[1] !== "26") {
         return { error: "CRC-8/BLUETOOTH read " + JSON.stringify(bluetooth[1]) };
       }

       /*
        * And the selector actually changes it, which is what makes upper hex a *default* rather than
        * a hardcoding. Driven to lower hex and back: a control that renders and reaches nothing is
        * this repo's most-repeated defect, and one that had merely been hardcoded would show "F4"
        * here whatever was selected.
        */
       const encodingSelect = panel.querySelector("[data-ocs-variants-encoding]");
       if (!encodingSelect) return { error: "the Variants panel has no encoding selector" };
       if (encodingSelect.value !== "hex-upper") {
         return { error: "the selector opened on " + JSON.stringify(encodingSelect.value) };
       }
       const setEncoding = (value) => {
         Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(
           encodingSelect,
           value,
         );
         encodingSelect.dispatchEvent(new Event("change", { bubbles: true }));
       };
       setEncoding("hex");
       let lowered = "";
       const lowerDeadline = Date.now() + 8000;
       while (Date.now() < lowerDeadline) {
         lowered = cells("CRC-8/SMBUS")[1] ?? "";
         if (lowered === "f4") break;
         await sleep(100);
       }
       if (lowered !== "f4") {
         return { error: "switching to lower hex left " + JSON.stringify(lowered) };
       }
       // Back, because the probes share one window and the assertions below expect the default.
       setEncoding("hex-upper");
       const restoreDeadline = Date.now() + 8000;
       while (Date.now() < restoreDeadline) {
         if ((cells("CRC-8/SMBUS")[1] ?? "") === "F4") break;
         await sleep(100);
       }
       // Each row's own parameters, not the selected model's.
       if (dow[3] !== "0x31") return { error: "MAXIM-DOW Poly read " + JSON.stringify(dow[3]) };
       if (dow[5] !== "true") return { error: "MAXIM-DOW RefIn read " + JSON.stringify(dow[5]) };
       // The alias sits in the Model cell, which is what makes the row findable.
       if (!dow[0].includes("DOW-CRC")) {
         return { error: "MAXIM-DOW shows no aliases: " + JSON.stringify(dow[0]) };
       }

       const count = document.querySelectorAll("[data-ocs-variant]").length;
       const badge = document.querySelector("[data-ocs-variants-count]");
       if (!badge) return { error: "the Variants heading has no count badge" };
       if (badge.textContent.trim() !== count + " models") {
         return { error: "the badge reads " + JSON.stringify(badge.textContent.trim()) + " over " + count + " rows" };
       }

       /**
        * Identify: paste a value into Verify and the rows that produce it turn green.
        *
        * 0xA1 is the case that matters, because *two* CRC-8 models give it over 123456789 --
        * CRC-8/I-432-1 and CRC-8/MAXIM-DOW. A probe that accepted one marked row would pass on an
        * implementation that returned the first match and quietly hid the other, which is the one
        * output of this panel somebody writes down.
        *
        * No backticks in this comment: it sits inside a template literal, and one would close it.
        */
       const verifyPanel = document.querySelector("[data-ocs-verify]");
       if (!verifyPanel) return { error: "no Verify panel" };
       const verifyToggle = verifyPanel.querySelector('button[aria-expanded]');
       if (!verifyToggle) return { error: "the Verify panel has no collapse toggle" };
       if (verifyToggle.getAttribute("aria-expanded") !== "true") verifyToggle.click();
       await sleep(200);

       const verify = document.querySelector("[data-ocs-verify-expected]");
       if (!verify) return { error: "no Verify field to paste into" };
       const areaSetter = Object.getOwnPropertyDescriptor(
         HTMLTextAreaElement.prototype,
         "value",
       ).set;
       areaSetter.call(verify, "a1");
       verify.dispatchEvent(new Event("input", { bubbles: true }));

       let marks = [];
       const identifyDeadline = Date.now() + 10000;
       while (Date.now() < identifyDeadline) {
         marks = Array.from(document.querySelectorAll("[data-ocs-variant-match]")).map((row) =>
           row.getAttribute("data-ocs-variant"),
         );
         if (marks.length >= 2) break;
         await sleep(100);
       }
       marks.sort();
       if (marks.join(",") !== "CRC-8/I-432-1,CRC-8/MAXIM-DOW") {
         return { error: "0xA1 marked " + JSON.stringify(marks.join(",")) };
       }
       // And the verdict names both, rather than reporting one and stopping.
       const verdict = panel.querySelector("header p")?.textContent ?? "";
       if (!verdict.includes("I-432-1") || !verdict.includes("MAXIM-DOW")) {
         return { error: "the verdict reads " + JSON.stringify(verdict) };
       }

       // Cleared, so the probes after this one do not inherit a pasted value.
       areaSetter.call(verify, "");
       verify.dispatchEvent(new Event("input", { bubbles: true }));
       await sleep(200);

       return { digest: smbus + "/" + dow[1] + "/" + bluetooth[1] + "/" + count + "/" + marks.length };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * With Auto update off: the byte count is still shown, and nothing recomputes until Compute.
 *
 * Both halves are bugs that shipped, and neither is reachable from the unit suite -- they live in
 * the interaction between a switch, a debounce and a monotonic counter.
 *
 *  - The Input panel read "Nothing entered yet." over nine visible characters, because the byte
 *    count came off a *finished* computation and there had not been one.
 *  - The guard was `!autoUpdate && manualTrigger === 0`, which stops guarding the instant Compute is
 *    pressed: the counter never returns to 0, so from then on every keystroke recomputed and the
 *    switch might as well not have existed.
 *
 * The second is what the 1.6-second wait is for: it has to be longer than `INPUT_DEBOUNCE_MS`, or
 * the probe would pass simply by looking before the recompute it is trying to catch.
 *
 * Auto update is left back **on**, because an earlier probe asserts it is on in a fresh profile and
 * the probes share one window.
 */
function checkManualCompute(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
       const status = () => {
         const el = document.querySelector("[data-ocs-result]");
         return el ? el.getAttribute("data-ocs-status") : null;
       };
       // Whitespace and an optional 0x only. Stripping every non-hex character would silently
       // swallow the "x" of a prefix and turn 0xcbf43926 into a passing 0cbf43926.
       const shown = () =>
         (document.querySelector("[data-ocs-result]")?.textContent ?? "")
           .replace(/\\s+/g, "")
           .replace(/^0[xX]/, "")
           .toLowerCase();
       const sizeText = () =>
         (document.querySelector("[data-ocs-input-size]")?.textContent ?? "").trim();

       /**
        * Re-queried every time rather than held in a variable.
        *
        * The switch lives in the Input panel, which the workbench remounts on a tool change -- so a
        * reference taken before the click on crc32 is a detached node afterwards, and clicking it
        * does nothing at all. That is how the first version of this probe failed: every assertion
        * about the bugs passed and the cleanup silently did not happen.
        */
       const autoUpdate = () => document.querySelector('[data-ocs-toggle="auto-update"]');
       const setAutoUpdate = async (on) => {
         const el = autoUpdate();
         if (!el) return "no Auto update switch";
         if (el.getAttribute("aria-checked") !== String(on)) el.click();
         for (let i = 0; i < 20; i++) {
           if (autoUpdate()?.getAttribute("aria-checked") === String(on)) return null;
           await sleep(50);
         }
         return "Auto update would not turn " + (on ? "on" : "off");
       };

       const offProblem = await setAutoUpdate(false);
       if (offProblem) return { error: offProblem };

       // Selected *after* the switch, so the tool mounts with auto-update already off and computes
       // nothing on arrival.
       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let link = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         link = document.querySelector('[data-ocs-tool="crc32"]') || link;
         if (document.querySelector('[data-ocs-tool="crc32"][aria-current="true"]')) break;
         if (link) link.click();
         await sleep(100);
       }
       if (!link) return { error: "the crc32 tool is not listed in the sidebar" };
       let input = null;
       const mountDeadline = Date.now() + 10000;
       while (Date.now() < mountDeadline) {
         await sleep(100);
         if (!document.querySelector('[data-ocs-tool="crc32"][aria-current="true"]')) continue;
         input = document.querySelector("[data-ocs-input]");
         if (input) break;
       }
       if (!input) return { error: "the CRC-32 workbench never rendered" };

       /**
        * Re-queried on every use, like the Auto update switch above and for the same reason: File
        * mode replaces the textarea with a drop zone, so the element captured before that round trip
        * is a detached node afterwards. Writing to it succeeds and changes nothing, which is how the
        * first version of the Clear check below failed.
        */
       const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
       const box = () => document.querySelector("[data-ocs-input]");
       const type = (text) => {
         const el = box();
         if (!el) return false;
         setter.call(el, text);
         el.dispatchEvent(new Event("input", { bubbles: true }));
         return true;
       };

       type("123456789");
       await sleep(200);

       // Bug one. The count comes off a decode that happens either way, so it is there before any
       // computation -- and "Nothing entered yet." over visible text is the thing being ruled out.
       if (!/^9 bytes\\b/.test(sizeText())) {
         return { error: "the input size read " + JSON.stringify(sizeText()) + ", expected 9 bytes" };
       }

       /**
        * Nothing computes on arrival. The switch is off, so selecting a tool -- which is a change of
        * what you are asking, and was briefly treated as a reason to compute once -- must leave the
        * Result panel empty. 1.6s is longer than INPUT_DEBOUNCE_MS, so anything coming has arrived.
        */
       await sleep(1600);
       if (status() !== "blank") {
         return { error: "arriving on crc32 with the switch off gave status " + status() };
       }
       if (shown() !== "") {
         return { error: "a value appeared on arrival: " + JSON.stringify(shown()) };
       }

       // Compute is the only thing that produces one.
       const compute = document.querySelector("[data-ocs-compute]");
       if (!compute) return { error: "no Compute button while auto-update is off" };
       compute.click();
       let settled = "";
       const firstDeadline = Date.now() + 10000;
       while (Date.now() < firstDeadline) {
         if (status() === "done") { settled = shown(); break; }
         await sleep(50);
       }
       if (settled !== "cbf43926") {
         return { error: "Compute gave " + JSON.stringify(settled) + ", expected cbf43926" };
       }

       /**
        * And editing does not. Dropping the last character used to recompute after the debounce,
        * exactly as though the switch were on. The value has to stay put *and* be marked out of date
        * -- a digest of the previous text sitting there looking current would be a different bug.
        */
       type("12345678");
       await sleep(1600);
       if (status() !== "stale") {
         return { error: "editing the input with auto-update off left the status at " + status() };
       }
       if (shown() !== "cbf43926") {
         return { error: "the shown value moved to " + JSON.stringify(shown()) + " on its own" };
       }

       document.querySelector("[data-ocs-compute]").click();
       let recomputed = "";
       const computeDeadline = Date.now() + 10000;
       while (Date.now() < computeDeadline) {
         if (status() === "done" && shown() !== "cbf43926") { recomputed = shown(); break; }
         await sleep(50);
       }
       if (recomputed !== "9ae0daaf") {
         return { error: "Compute gave " + JSON.stringify(recomputed) + ", expected 9ae0daaf" };
       }

       /**
        * And the same switch against a *file*, which had no guard at all: autoUpdate was simply
        * never read on that path, so choosing a file always started a read. It is the worse half of
        * the two, because a file is where "do not compute until I ask" costs something -- gigabytes
        * go through the streaming worker before anyone can stop it.
        *
        * Note the absence of backticks in this comment. It sits inside a template literal, so one
        * would close the literal and the whole probe stops parsing -- which is exactly how the first
        * version of it failed.
        */
       const source = document.querySelector("[data-ocs-input-mode]");
       if (!source) return { error: "no input source selector" };
       const setSelectValue = Object.getOwnPropertyDescriptor(
         HTMLSelectElement.prototype,
         "value",
       ).set;
       setSelectValue.call(source, "file");
       source.dispatchEvent(new Event("change", { bubbles: true }));

       let dropzone = null;
       const zoneDeadline = Date.now() + 5000;
       while (Date.now() < zoneDeadline) {
         dropzone = document.querySelector("[data-ocs-dropzone]");
         if (dropzone) break;
         await sleep(50);
       }
       if (!dropzone) return { error: "File mode did not render a drop zone" };

       // An <input type=file> cannot be populated programmatically; a synthetic drop carrying a
       // constructed DataTransfer goes through the same React handler a real one does.
       const transfer = new DataTransfer();
       transfer.items.add(new File([new Uint8Array([0x61, 0x62, 0x63])], "probe.bin"));
       dropzone.dispatchEvent(
         new DragEvent("drop", { dataTransfer: transfer, bubbles: true, cancelable: true }),
       );

       await sleep(1600);
       if (status() === "done") {
         return { error: "importing a file computed on its own with auto-update off" };
       }

       const fileCompute = document.querySelector("[data-ocs-compute]");
       if (!fileCompute) return { error: "no Compute button in file mode" };
       fileCompute.click();

       let fileDigest = "";
       const fileDeadline = Date.now() + 10000;
       while (Date.now() < fileDeadline) {
         if (status() === "done") { fileDigest = shown(); break; }
         await sleep(50);
       }
       // CRC-32/ISO-HDLC of the three bytes "abc".
       if (fileDigest !== "352441c2") {
         return { error: "Compute on the dropped file produced " + JSON.stringify(fileDigest) };
       }

       /**
        * And Clear against the file, from the same corner of the controls row it occupies for typed
        * input. It used to be a second button inside the drop zone; there is one call site now, so
        * this is the branch of it that the text check below cannot reach.
        */
       /**
        * Scoped to the panel it belongs to. The Verify panel shares the same ClearButton component
        * now, so a bare document query would depend on which panel comes first in the column -- true
        * today, and not a thing to rest a probe on.
        *
        * No backticks in this comment: it sits inside a template literal, so one would close the
        * literal and stop the whole probe parsing. That has happened twice in this file.
        */
       const filePanel = document.querySelector("[data-ocs-dropzone]")?.closest("section");
       if (!filePanel) return { error: "the drop zone is not inside a panel" };
       const fileClear = filePanel.querySelector("[data-ocs-clear]");
       if (!fileClear) return { error: "no Clear button in file mode" };
       if (fileClear.disabled) return { error: "Clear is disabled with a file loaded" };
       fileClear.click();
       await sleep(300);
       if ((document.querySelector("[data-ocs-dropzone]")?.textContent ?? "").includes("probe.bin")) {
         return { error: "Clear left the file in the drop zone" };
       }
       if (!filePanel.querySelector("[data-ocs-clear]")?.disabled) {
         return { error: "Clear is still enabled with no file loaded" };
       }

       // Back to text, so the probes after this one find the panel the way they expect it.
       setSelectValue.call(source, "text");
       source.dispatchEvent(new Event("change", { bubbles: true }));
       await sleep(200);

       /**
        * Clear empties the box, and the panel notices.
        *
        * A button that renders and does nothing is this repo's most-repeated defect -- AEGIS's tag
        * length was inert with a green suite, and the "(not set)" placeholder survived two rounds of
        * unit tests -- so the assertion is on the textarea's value *and* on the size line above it,
        * which is what proves the change went through React rather than only into the DOM.
        *
        * Done while auto-update is still off, and the text is put back afterwards, because the
        * probes share one window and the ones after this expect an input that is not empty.
        */
       // The Input panel's own, not the Verify panel's -- see the note on filePanel above.
       const inputPanel = box()?.closest("section");
       if (!inputPanel) return { error: "the input textarea is not inside a panel" };
       const clear = inputPanel.querySelector("[data-ocs-clear]");
       if (!clear) return { error: "no Clear button in text mode" };
       if (clear.disabled) return { error: "Clear is disabled with text in the box" };
       clear.click();
       await sleep(200);
       if (box()?.value !== "") {
         return { error: "Clear left " + JSON.stringify(box()?.value) + " in the box" };
       }
       if (sizeText() !== "Nothing entered yet.") {
         return { error: "after Clear the size line read " + JSON.stringify(sizeText()) };
       }
       if (!inputPanel.querySelector("[data-ocs-clear]")?.disabled) {
         return { error: "Clear is still enabled with an empty box" };
       }
       /**
        * The Test input menu fills the box. A dropdown that renders and does nothing is this repo's
        * most-repeated defect, and this one is worth a probe for a second reason: it holds no value,
        * so nothing about its own state can show whether picking an entry did anything.
        */
       /*
        * It lives in the right rail's Settings tab, which is the tab the rail opens on -- so this no
        * longer needs to switch tabs. The click is kept anyway: the probes before this one may have
        * left another tab selected, and asserting the tab exists is worth a line now that Settings is
        * the only place the menu can be.
        */
       const settingsTab = document.querySelector('[data-ocs-tab="settings"]');
       if (!settingsTab) return { error: "no Settings tab in the rail" };
       settingsTab.click();
       let samples = null;
       const menuDeadline = Date.now() + 5000;
       while (Date.now() < menuDeadline) {
         samples = document.querySelector("[data-ocs-test-input]");
         if (samples) break;
         await sleep(50);
       }
       if (!samples) return { error: "no Test input menu in the Settings tab" };
       if (document.querySelector('[data-ocs-tab="presets"]')) {
         return { error: "the Presets tab is still in the rail" };
       }
       setSelectValue.call(samples, "check");
       samples.dispatchEvent(new Event("change", { bubbles: true }));
       await sleep(300);
       if (box()?.value !== "123456789") {
         return { error: "the check sample put " + JSON.stringify(box()?.value) + " in the box" };
       }
       if (!/^9 bytes/.test(sizeText())) {
         return { error: "after the check sample the size line read " + JSON.stringify(sizeText()) };
       }
       // Straight back to its label rather than resting on the entry just chosen.
       if (samples.value !== "") {
         return { error: "the Test input menu is resting on " + JSON.stringify(samples.value) };
       }

       /*
        * The rail's panel order, and that both of the top two fold.
        *
        * Neither is visible to a typecheck or to the node suite -- the panels render either way, and
        * the order is JSX sequence rather than data. Test input has to come first because it is the
        * one control here you reach for before computing anything, and Settings is unbounded (a block
        * cipher contributes a dozen rows), so anything under it starts below the fold.
        */
       const railPanels = Array.from(document.querySelectorAll("section")).filter((section) => {
         const heading = section.querySelector("h2");
         return heading && ["Test input", "Settings", "Info"].includes(heading.textContent.trim());
       });
       const railOrder = railPanels.map((section) => section.querySelector("h2").textContent.trim());
       if (railOrder.indexOf("Test input") !== 0) {
         return { error: "the Settings tab is ordered " + railOrder.join(",") };
       }
       if (railOrder.indexOf("Settings") !== 1) {
         return { error: "Settings is not directly under Test input: " + railOrder.join(",") };
       }
       /*
        * A chevron that renders and folds nothing is the same defect class as an inert dropdown, so
        * each toggle is driven and the content checked to have gone -- then restored, since the probes
        * after this one expect the menu and the option controls to be reachable.
        */
       /*
        * Exactly one scroll container in the content area, and it is <main> itself.
        *
        * This is the assertion three layouts were needed to arrive at. The rail was once sticky with
        * its own max-height and overflow, so two scrollbars sat a few pixels apart -- the inner one
        * moving the rail's panels, the outer one moving the rail itself, and which a drag reached
        * depended on which pixel was grabbed. Giving each column its own scroller removed that and
        * put the workbench column's scrollbar in the gutter between the panels and the rail, floating
        * in empty space. Neither is visible to a typecheck or the node suite: every element exists in
        * all three layouts, and the only difference is which of them has a scroll range.
        *
        * A panel's own capped body -- MonoBlock, the Table grid, the Variants table, all max-h-96 --
        * is excluded structurally rather than by height: every panel is a <section> and no column is
        * inside one. A height floor was tried first and picked up a 369px max-h-96 block, which is
        * the sort of threshold that works until content grows.
        */
       const mainEl = document.querySelector("main");
       if (!mainEl) return { error: "no <main> in the shell" };
       const mainOverflow = getComputedStyle(mainEl).overflowY;
       if (mainOverflow !== "auto" && mainOverflow !== "scroll") {
         return { error: "<main> does not scroll; the content area has no scrollbar" };
       }
       const innerScrollers = Array.from(mainEl.querySelectorAll("*")).filter((element) => {
         if (element.closest("section")) return false;
         const overflow = getComputedStyle(element).overflowY;
         return overflow === "auto" || overflow === "scroll";
       });
       if (innerScrollers.length !== 0) {
         const described = innerScrollers.map((element) => {
           const heading = element.querySelector("h2");
           return element.tagName + (heading ? ":" + heading.textContent.trim() : "");
         });
         return {
           error:
             "a second scrollbar is back inside <main>: " + described.join(",") +
             " -- the content area is meant to have exactly one",
         };
       }
       /*
        * And nothing is clipped sideways.
        *
        * A flex item defaults to min-width:auto, so the row holding the two columns refused to shrink
        * to its frame, sat 102px wider than it, and had the difference cut off -- taking the rail's
        * right edge with it. Nothing failed: every element was present and correctly sized, the frame
        * around them was simply too narrow, so the only symptom was a rail with its edge gone.
        */
       if (mainEl.scrollWidth - mainEl.clientWidth > 2) {
         return {
           error:
             "<main> overflows " +
             (mainEl.scrollWidth - mainEl.clientWidth) +
             "px horizontally; the column row is not shrinking to it",
         };
       }

       for (const heading of ["Test input", "Settings"]) {
         const section = railPanels[railOrder.indexOf(heading)];
         const toggle = section.querySelector("h2 button[aria-expanded]");
         if (!toggle) return { error: heading + " has no collapse toggle" };
         if (toggle.getAttribute("aria-expanded") !== "true") {
           return { error: heading + " did not start open" };
         }
         const bodyCount = section.querySelectorAll("select,input,label").length;
         if (bodyCount === 0) return { error: heading + " rendered no controls to fold" };
         toggle.click();
         await sleep(150);
         const collapsed = document.querySelectorAll("section").length;
         if (collapsed === 0) return { error: "the rail vanished when folding " + heading };
         const after = railPanels[railOrder.indexOf(heading)];
         if (after.querySelectorAll("select,input,label").length !== 0) {
           return { error: heading + " kept its controls after collapsing" };
         }
         if (after.querySelector("h2 button[aria-expanded]")?.getAttribute("aria-expanded") !== "false") {
           return { error: heading + " did not report itself collapsed" };
         }
         after.querySelector("h2 button[aria-expanded]").click();
         await sleep(150);
         if (after.querySelectorAll("select,input,label").length === 0) {
           return { error: heading + " did not come back when expanded" };
         }
       }

       // No need to switch back: the menu is in Settings, so we never left the tab the rail opens on.

       if (!type("12345678")) return { error: "no textarea to restore the input into" };
       await sleep(200);
       if (box()?.value !== "12345678") return { error: "could not restore the input after Clear" };

       // Back on, because an earlier probe asserts it is on and the probes share one window.
       const onProblem = await setAutoUpdate(true);
       if (onProblem) return { error: onProblem };

       return { digest: settled + "/" + fileDigest };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * AES's Key size control and the Generate buttons beside the key and the IV.
 *
 * Three things here are invisible to every other kind of test, and all three are about a control
 * reaching what it claims to.
 *
 * The Key size select has to *change what Generate makes* -- 16 bytes at AES-128, 32 at AES-256 -- and
 * a select wired to nothing would leave a perfectly plausible 32-byte key on screen either way. The IV
 * Generate has to produce the length the selected *mode* wants, which was the bug behind all of this:
 * the catalogue offered a static 12 bytes, so on CBC it filled the field with a value the very next
 * check refused, and a 12-byte IV looks exactly like a 12-byte IV somebody mistyped. And the control
 * must be *absent* under XTS, whose key is two AES keys, where offering AES-128 would offer something
 * the mode refuses.
 *
 * Lengths are read off the rendered field rather than from any internal state, which is the only way
 * to know the button and the resolver agree.
 */
function checkAesKeySize(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       const open = async (id) => {
         const selector = '[data-ocs-tool="' + id + '"]';
         const deadline = Date.now() + 15000;
         let everSeen = false;
         while (Date.now() < deadline) {
           const button = document.querySelector(selector);
           if (!button) { await sleep(100); continue; }
           everSeen = true;
           button.click();
           if (await waitFor(selector + '[aria-current="true"]', 2000)) return null;
         }
         return everSeen ? "clicking " + id + " did not select it" : id + " is not in the sidebar";
       };
       const control = (id, tag) => document.querySelector('[data-ocs-option="' + id + '"] ' + tag);
       const setSelect = (element, value) => {
         Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(element, value);
         element.dispatchEvent(new Event("change", { bubbles: true }));
       };
       /*
        * The field's byte count, read from the value the control holds. A secret is masked, so its
        * text is not readable -- the value attribute is.
        *
        * Decoded according to whichever encoding the field's own selector currently shows, not
        * assumed to be hex. It used to assume hex unconditionally -- true when this probe was
        * written, false since Key and IV/Nonce started defaulting to Text(UTF-8): Generate then
        * fills the field with random printable characters, this stripped every one of them that was
        * not also a hex digit, and halved whatever was left of a random string -- a number with no
        * relationship to the sixteen, twenty-four or thirty-two bytes actually produced, different
        * on every run because the characters that happen to look like hex digits are themselves
        * random. Two bytes one run, three the next, from a control that was never wrong.
        */
       const byteLength = (id) => {
         const field = control(id, "input") || control(id, "textarea");
         if (!field) return -1;
         const value = String(field.value);
         const encodingSelect = document.querySelector(
           '[data-ocs-option="' + id + '"] select[aria-label$="encoding"]',
         );
         const encoding = encodingSelect ? encodingSelect.value : "hex";
         if (encoding === "utf-8") return new TextEncoder().encode(value).length;
         if (encoding === "base64" || encoding === "base64url") {
           const padded = (encoding === "base64url" ? value.replace(/-/g, "+").replace(/_/g, "/") : value)
             .replace(/=+$/, "");
           const withPadding = padded + "=".repeat((4 - (padded.length % 4)) % 4);
           try {
             return atob(withPadding).length;
           } catch {
             return -1;
           }
         }
         const hex = value.replace(/[^0-9a-fA-F]/g, "");
         return hex.length % 2 === 0 ? hex.length / 2 : -1;
       };
       const pressGenerate = async (id) => {
         const wrapper = document.querySelector('[data-ocs-option="' + id + '"]');
         if (!wrapper) return "no " + id + " control";
         const button = Array.from(wrapper.querySelectorAll("button")).find(
           (b) => b.textContent.trim() === "Generate",
         );
         if (!button) return "no Generate button beside " + id;
         button.click();
         await sleep(250);
         return null;
       };

       let problem = await open("aes");
       if (problem) return { error: problem };

       const keySize = await waitFor('[data-ocs-option="keySize"] select', 10000);
       if (!keySize) return { error: "AES has no Key size control" };
       if (keySize.value === "") return { error: "the Key size select is resting on (not set)" };
       const offered = Array.from(keySize.options).map((o) => o.value).join(",");
       if (offered !== "128,192,256") return { error: "Key size offers " + offered };

       /*
        * Mode renders above Key size, which in turn renders above Key source. Asked for directly, and
        * it is a fact about the rendered page rather than about the data -- the form sorts by an order
        * field, so all three controls exist and work whichever number each carries.
        *
        * This used to check the opposite relation, from when Key size sat above Mode. options.ts's own
        * comment on OPTION_KEY_SIZE records that ordering was deliberately reversed --
        * "Mode comes first, then this, then Key source" -- and this probe was not updated with it, so
        * it kept asserting the superseded layout while the app had already moved on. Compared with
        * compareDocumentPosition rather than by reading the order values, because that is what
        * somebody looking at the rail sees; DOCUMENT_POSITION_FOLLOWING (4) means the argument comes
        * after the node.
        */
       const modeForOrder = document.querySelector('[data-ocs-option="mode"]');
       const keySizeWrapper = document.querySelector('[data-ocs-option="keySize"]');
       if (!modeForOrder || !keySizeWrapper) return { error: "Mode or Key size is missing a wrapper" };
       const relation = modeForOrder.compareDocumentPosition(keySizeWrapper);
       if (!(relation & Node.DOCUMENT_POSITION_FOLLOWING)) {
         return { error: "Key size renders above Mode" };
       }

       /*
        * Generate at each size, and the field must hold exactly that many bytes. Checked at all three
        * rather than one: a control read with the wrong accessor returns undefined and falls back to a
        * default, which would look right at whichever size happens to be the default.
        */
       const measured = [];
       for (const [bits, want] of [["128", 16], ["192", 24], ["256", 32]]) {
         setSelect(keySize, bits);
         await sleep(150);
         problem = await pressGenerate("key");
         if (problem) return { error: problem };
         const got = byteLength("key");
         if (got !== want) {
           return { error: "at AES-" + bits + " Generate produced " + got + " bytes, expected " + want };
         }
         measured.push(bits + ":" + got);
       }

       /*
        * The IV's Generate follows the mode, which is the half that was broken: 12 under GCM and 16
        * under CBC, from one static catalogue number that said 12 for both.
        */
       const mode = control("mode", "select");
       if (!mode) return { error: "AES has no Mode control" };
       const ivLengths = [];
       for (const [modeId, want] of [["gcm", 12], ["cbc", 16], ["ctr", 16]]) {
         setSelect(mode, modeId);
         await sleep(200);
         problem = await pressGenerate("nonce");
         if (problem) return { error: problem };
         const got = byteLength("nonce");
         if (got !== want) {
           return { error: "under " + modeId + " the IV Generate produced " + got + " bytes, expected " + want };
         }
         ivLengths.push(modeId + ":" + got);
       }

       /*
        * Under XTS the control stays and its *choices* change, which is the whole of choice-level
        * availability and is invisible to the unit suite: the catalogue holds every choice at once,
        * and only a rendered select shows which ones a mode leaves reachable.
        *
        * The labels are checked rather than only the count. A 32-byte key string is AES-256 under GCM
        * and XTS-AES-128 under XTS -- the same bytes under a different name -- and that name is the
        * reason this is a dropdown rather than a byte count.
        */
       setSelect(mode, "xts");
       await sleep(400);
       const xtsSelect = await waitFor('[data-ocs-option="keySize"] select', 5000);
       if (!xtsSelect) return { error: "the Key size control vanished under XTS" };
       const xtsLabels = Array.from(xtsSelect.options)
         .filter((o) => o.value !== "")
         .map((o) => o.textContent.trim() + "=" + o.value)
         .join(",");
       if (xtsLabels !== "XTS-AES-128=256,XTS-AES-256=512") {
         return { error: "under XTS the Key size offers " + xtsLabels };
       }
       if (xtsSelect.value === "") return { error: "the Key size select is (not set) under XTS" };

       /*
        * And the choice reaches Generate, which is what separates a dropdown from decoration. XTS-AES-256
        * is 64 bytes because the key string is two AES-256 keys.
        */
       const xtsSizes = [];
       for (const [bits, want] of [["256", 32], ["512", 64]]) {
         setSelect(xtsSelect, bits);
         await sleep(200);
         problem = await pressGenerate("key");
         if (problem) return { error: problem };
         const got = byteLength("key");
         if (got !== want) {
           return { error: "XTS at " + bits + " generated " + got + " bytes, expected " + want };
         }
         xtsSizes.push(bits + ":" + got);
       }

       // Back to the default, because the probes share one window.
       setSelect(mode, "gcm");
       await sleep(200);

       return {
         digest: measured.join("/") + " " + ivLengths.join("/") + " xts:" + xtsSizes.join("/"),
       };
     })()`,
  );
}

/**
 * The Padding control on ECB and CBC, and its absence everywhere else.
 *
 * Three things here that nothing else can see. The control has to *appear* under CBC and be *gone*
 * under GCM, which is choice-independent gating and therefore a rendered fact. Each scheme has to
 * change the ciphertext -- a select wired to nothing leaves four identical outputs, which look exactly
 * as much like AES-CBC as the right ones. And None has to refuse an unaligned input with a message
 * naming the way out, which is a compute-path refusal surfaced as a rendered error rather than a throw.
 *
 * The lengths matter as much as the bytes: over a block-aligned input PKCS#7 adds a whole further
 * block while None adds nothing, so 32 bytes in gives 48 out under PKCS#7 and 32 under None.
 */
function checkPadding(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       const open = async (id) => {
         const selector = '[data-ocs-tool="' + id + '"]';
         const deadline = Date.now() + 15000;
         let everSeen = false;
         while (Date.now() < deadline) {
           const button = document.querySelector(selector);
           if (!button) { await sleep(100); continue; }
           everSeen = true;
           button.click();
           if (await waitFor(selector + '[aria-current="true"]', 2000)) return null;
         }
         return everSeen ? "clicking " + id + " did not select it" : id + " is not in the sidebar";
       };
       const control = (id, tag) => document.querySelector('[data-ocs-option="' + id + '"] ' + tag);
       const setSelect = (element, value) => {
         Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(element, value);
         element.dispatchEvent(new Event("change", { bubbles: true }));
       };
       const setField = (element, value) => {
         const proto = element.tagName === "TEXTAREA" ? HTMLTextAreaElement : HTMLInputElement;
         Object.getOwnPropertyDescriptor(proto.prototype, "value").set.call(element, value);
         element.dispatchEvent(new Event("input", { bubbles: true }));
       };

       let problem = await open("aes");
       if (problem) return { error: problem };

       /*
        * Auto update is forced on, because checkManualCompute runs earlier in this list and leaves it
        * off -- the probes share one window deliberately. Re-queried on each attempt rather than held,
        * since the Input panel remounts on a tool change and a detached switch clicks into nothing,
        * which is how that probe's own cleanup once silently failed.
        */
       const autoUpdate = () => document.querySelector('[data-ocs-toggle="auto-update"]');
       for (let i = 0; i < 30; i++) {
         const el = autoUpdate();
         if (el && el.getAttribute("aria-checked") === "true") break;
         if (el && el.getAttribute("aria-checked") !== "true") el.click();
         await sleep(100);
       }
       if (autoUpdate()?.getAttribute("aria-checked") !== "true") {
         return { error: "could not turn Auto update on" };
       }

       const mode = await waitFor('[data-ocs-option="mode"] select', 10000);
       if (!mode) return { error: "AES has no Mode control" };

       // Under GCM there is nothing to pad, so the control must not be there at all.
       setSelect(mode, "gcm");
       await sleep(300);
       if (document.querySelector('[data-ocs-option="padding"] select')) {
         return { error: "the Padding control is shown under GCM, which never pads" };
       }

       setSelect(mode, "cbc");
       await sleep(400);
       const padding = await waitFor('[data-ocs-option="padding"] select', 5000);
       if (!padding) return { error: "the Padding control is missing under CBC" };
       if (padding.value !== "pkcs7") {
         return { error: "Padding opens on " + (padding.value || "(not set)") + " rather than pkcs7" };
       }
       const offered = Array.from(padding.options).filter((o) => o.value !== "").map((o) => o.value).join(",");
       if (offered !== "pkcs7,pkcs5,iso7816,x923,iso10126,zero,none") {
         return { error: "Padding offers " + offered };
       }

       /*
        * Key size, forced to 256. Ordinary AES modes accept exactly the declared size rather than any
        * of 16/24/32 -- resolveCipher narrows to it -- and this probe shares its window with
        * checkAesSizes, which runs immediately before it and leaves Key size wherever its own last
        * selection landed once switched from XTS's 256/512 back to an ordinary mode's list. The
        * thirty-two-byte key typed below was silently invalid against whatever that leftover
        * happened to be, which is what an empty result and an unmoving digest actually were.
        */
       const keySize = document.querySelector('[data-ocs-option="keySize"] select');
       if (keySize) setSelect(keySize, "256");

       /*
        * A block-aligned input, so None is legal and PKCS#7 adds a whole extra block. Both fields are
        * filled explicitly rather than generated, because a fixed key and IV make the four outputs
        * comparable with each other.
        *
        * Forced to hex first. Key and IV/Nonce default to Text(UTF-8), and "11" repeated thirty-two
        * times is a valid value under either encoding -- 32 bytes of 0x11 as hex, or 64 raw ASCII "1"
        * bytes as text. Only one of those is what this probe means, and nothing before this line
        * would have said which was used.
        */
       const setEncoding = (id, value) => {
         const select = document.querySelector('[data-ocs-option="' + id + '"] select[aria-label$="encoding"]');
         if (select) setSelect(select, value);
       };
       setEncoding("key", "hex");
       setEncoding("nonce", "hex");
       const key = control("key", "input") || control("key", "textarea");
       const iv = control("nonce", "input") || control("nonce", "textarea");
       if (!key || !iv) return { error: "no key or IV field under CBC" };
       setField(key, "11".repeat(32));
       setField(iv, "22".repeat(16));
       const input = await waitFor("[data-ocs-input]", 5000);
       if (!input) return { error: "no input panel" };
       setField(input, "abcdefghijklmnopqrstuvwxyz012345");
       /*
        * Waited for rather than slept past: this is the *first* compute this spec has ever run, key,
        * IV and input all just changed together, and a flat 400ms was sometimes shorter than that
        * first debounce-and-compute cycle actually took. Capturing the baseline while the panel was
        * still "pending" read as an empty result -- not wrong exactly, just too early to be one -- and
        * every later comparison against that empty baseline was vacuous rather than a real check.
        */
       if (!(await waitFor('[data-ocs-result][data-ocs-status="done"]', 5000))) {
         return { error: "the result panel never reached done for the initial pkcs7 computation" };
       }

       /*
        * Waits for the panel to settle *and* for the value to have moved, rather than for any value at
        * all: after switching the scheme the previous ciphertext is still on screen for a moment, and a
        * probe that accepted it would shift every reading by one and then hang on the last.
        *
        * "Changed" is a sound condition here rather than a heuristic, because consecutive schemes are
        * required to differ -- so a value that never changes is precisely the defect being looked for,
        * and it surfaces as this timeout with the scheme named.
        */
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const hexOf = (el) => (el ? el.textContent.replace(/[^0-9a-fA-F]/g, "") : "");
       const waitForChange = async (before) => {
         const deadline = Date.now() + 10000;
         for (;;) {
           const settled = document.querySelector(SETTLED);
           const text = hexOf(settled);
           if (settled && text.length > 0 && text !== before) return text;
           if (Date.now() > deadline) return "";
           await sleep(150);
         }
       };

       /*
        * PKCS#5 is deliberately identical to PKCS#7, so it is driven separately: waiting for the value
        * to *change* is exactly wrong for it, and requiring every scheme to differ would fail on the one
        * property both are listed for. Its check is that it settles on the same bytes.
        */
       /*
        * Re-queried on each attempt rather than held from the earlier capture -- the same discipline
        * the auto-update toggle above uses, and for the same reason: setting the key and nonce
        * encodings and the key/IV/input fields, all after padding was first captured, is enough
        * surrounding state change that the select can remount, and setSelect on a detached node
        * dispatches an event nobody is listening to. A scheme that silently never got selected looks
        * identical to a scheme that produced no change -- both leave waitForChange waiting for
        * something that was never coming -- which is why every scheme after the first was failing
        * the same way pkcs7 alone did before that was fixed.
        */
       const paddingSelect = () => document.querySelector('[data-ocs-option="padding"] select');

       const seen = {};
       let previous = hexOf(document.querySelector(SETTLED));
       /*
        * PKCS#7 is not entered here -- it is already the active scheme, confirmed above, and this
        * value is its ciphertext for the key/IV/input just set. Selecting it again is a no-op change
        * event: the panel recomputes the same bytes it already shows, waitForChange correctly never
        * sees anything different, and the wait ran out every time. The same reasoning that puts
        * PKCS#5 outside this loop applies to PKCS#7 itself -- it just was not applied to itself.
        */
       seen.pkcs7 = previous;
       for (const scheme of ["iso7816", "x923", "iso10126", "zero", "none"]) {
         setSelect(paddingSelect(), scheme);
         const hex = await waitForChange(previous);
         if (hex === "") {
           return { error: scheme + " did not produce a ciphertext of its own" };
         }
         if (Object.values(seen).indexOf(hex) !== -1) {
           return { error: scheme + " produced the same ciphertext as another scheme" };
         }
         seen[scheme] = hex;
         previous = hex;
       }

       // Back to PKCS#7, then PKCS#5, which must land on the same bytes rather than a different set.
       setSelect(paddingSelect(), "pkcs7");
       const backToPkcs7 = await waitForChange(previous);
       if (backToPkcs7 !== seen.pkcs7) {
         return { error: "returning to pkcs7 gave a different ciphertext than the first time" };
       }
       setSelect(paddingSelect(), "pkcs5");
       /*
        * Not waitForChange: PKCS#5 is required to land on the *same* bytes pkcs7 already shows, so
        * there may be nothing to see change even once the recompute has genuinely happened. A flat
        * sleep before reading risked the same mistake fixed above -- catching the panel mid-"pending"
        * and reading that as a wrong value rather than as not finished yet -- so status is checked
        * directly rather than assumed from a fixed delay.
        */
       if (!(await waitFor('[data-ocs-result][data-ocs-status="done"]', 5000))) {
         return { error: "the result panel never reached done after selecting pkcs5" };
       }
       const asPkcs5 = hexOf(document.querySelector(SETTLED));
       if (asPkcs5 !== seen.pkcs7) {
         return { error: "pkcs5 must be byte-for-byte pkcs7; got a different value" };
       }

       /*
        * And ISO 10126 is random, so the same settings twice must *not* agree -- the one place in this
        * app where a repeated computation is expected to differ. Driven by re-selecting it, which
        * recomputes with fresh filler.
        */
       setSelect(paddingSelect(), "iso10126");
       const firstRandom = await waitForChange(asPkcs5);
       setSelect(paddingSelect(), "zero");
       await waitForChange(firstRandom);
       setSelect(paddingSelect(), "iso10126");
       const secondRandom = await waitForChange(seen.zero);
       if (firstRandom === secondRandom) {
         return { error: "ISO 10126 gave identical ciphertext twice; its filler is not random" };
       }
       // 32 bytes in: a whole further block under every scheme that pads, nothing added under None.
       if (seen.pkcs7.length !== 96) return { error: "pkcs7 gave " + seen.pkcs7.length / 2 + " bytes, expected 48" };
       if (seen.zero.length !== 96) return { error: "zero gave " + seen.zero.length / 2 + " bytes, expected 48" };
       if (seen.none.length !== 64) return { error: "none gave " + seen.none.length / 2 + " bytes, expected 32" };

       /*
        * And None refuses an input that is not whole blocks. A rendered error, not a throw: the refusal
        * comes from the compute path, which the family wraps for exactly this.
        *
        * Padding is put back on None explicitly rather than assumed still there: the randomness check
        * just above leaves it on iso10126, from the second of its two selections, and nothing between
        * that block and this one ever touches the control again.
        */
       setSelect(paddingSelect(), "none");
       await waitForChange(secondRandom);
       setField(input, "abcdefghijklmnopq");
       const sawRefusal = await (async () => {
         const deadline = Date.now() + 5000;
         while (Date.now() < deadline) {
           if (/whole number of 16-byte blocks/.test(document.body.textContent)) return true;
           await sleep(150);
         }
         return false;
       })();
       if (!sawRefusal) {
         return { error: "None accepted a 17-byte input without saying why it cannot" };
       }

       // Back to a state the later probes expect.
       setSelect(paddingSelect(), "pkcs7");
       setSelect(mode, "gcm");
       await sleep(200);

       return { digest: "7 schemes pkcs5=pkcs7 iso10126-random pkcs7:48 none:32" };
     })()`,
  );
}

/**
 * Deriving a cipher key from a password, in the packaged renderer.
 *
 * Four things here that no unit test can see, and the first is the one that nearly shipped broken.
 *
 * Selecting a KDF has to *remove* the Key field and *add* Password and Salt. That is choice-level
 * gating on a tag, and the tag is emitted by variantTag -- which returned undefined for 45 tools
 * before this feature, so the gate would have deleted the key input for all of them while
 * typechecking and passing the suite. A rendered page is the only place a missing field shows.
 *
 * Note the three controls live in three places, which is deliberate rather than untidy: the source
 * select is in the rail with Mode and Key size, because those are the three choices that decide which
 * function runs; the password and salt are in the Input panel where the Key field was; and the cost
 * parameters have their own rail group that disappears under Custom. The probe drives them all by
 * option id, so it is indifferent to where each one is rendered -- which is what makes it survive a
 * placement change like this one.
 *
 * The IV field has to come back when Derives is switched to Key only, which is a conjunction encoded
 * as a tag and therefore worth checking rather than reasoning about.
 *
 * The value has to match OpenSSL. The probe types the same password, salt and iteration count the
 * unit tests use and requires the byte-for-byte answer openssl enc produced, so a wiring fault
 * between the form and the resolver -- an option id read from the wrong place, an encoding selector
 * defaulting differently in the app than in a spec literal -- fails here even though the unit tests,
 * which write option values straight into a spec, would pass.
 *
 * And the whole path runs through the compute worker over app://, including a dynamic import of the
 * KDF module. A chunk that failed to resolve there is invisible to every other kind of test.
 */
function checkKeySource(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       const open = async (id) => {
         const selector = '[data-ocs-tool="' + id + '"]';
         const deadline = Date.now() + 15000;
         let everSeen = false;
         while (Date.now() < deadline) {
           const button = document.querySelector(selector);
           if (!button) { await sleep(100); continue; }
           everSeen = true;
           button.click();
           if (await waitFor(selector + '[aria-current="true"]', 2000)) return null;
         }
         return everSeen ? "clicking " + id + " did not select it" : id + " is not in the sidebar";
       };
       const control = (id, tag) => document.querySelector('[data-ocs-option="' + id + '"] ' + tag);
       const setSelect = (element, value) => {
         Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(element, value);
         element.dispatchEvent(new Event("change", { bubbles: true }));
       };
       const setField = (element, value) => {
         const proto = element.tagName === "TEXTAREA" ? HTMLTextAreaElement : HTMLInputElement;
         Object.getOwnPropertyDescriptor(proto.prototype, "value").set.call(element, value);
         element.dispatchEvent(new Event("input", { bubbles: true }));
       };
       const fieldOf = (id) => control(id, "input") || control(id, "textarea");

       let problem = await open("aes");
       if (problem) return { error: problem };

       // Auto update is forced on: checkManualCompute runs earlier and the probes share one window.
       const autoUpdate = () => document.querySelector('[data-ocs-toggle="auto-update"]');
       for (let i = 0; i < 30; i++) {
         const el = autoUpdate();
         if (el && el.getAttribute("aria-checked") === "true") break;
         if (el) el.click();
         await sleep(100);
       }

       const mode = await waitFor('[data-ocs-option="mode"] select', 10000);
       if (!mode) return { error: "AES has no Mode control" };
       setSelect(mode, "cbc");
       await sleep(300);

       // Custom is the default, so the Key field is there and the password is not.
       if (!fieldOf("key")) return { error: "the Key field is missing under Custom" };
       if (fieldOf("password")) return { error: "a Password field is shown under Custom" };

       const source = await waitFor('[data-ocs-option="keySource"] select', 5000);
       if (!source) return { error: "there is no Key source control" };
       if (source.value !== "directinput") {
         return { error: "Key source opens on " + (source.value || "(not set)") + " rather than directinput" };
       }
       const offered = Array.from(source.options).filter((o) => o.value !== "").map((o) => o.value).join(",");
       if (offered !== "directinput,pbkdf2,evpkdf,hkdf,scrypt,argon2,bcryptpbkdf") {
         return { error: "Key source offers " + offered };
       }

       /*
        * The swap. This is the assertion that would have failed for 45 tools had variantTag kept
        * returning a bare mode, and it is invisible to the unit suite.
        */
       setSelect(source, "pbkdf2");
       await sleep(500);
       if (fieldOf("key")) return { error: "the Key field is still shown under PBKDF2" };
       const password = await waitFor('[data-ocs-option="password"] input, [data-ocs-option="password"] textarea', 5000);
       if (!password) return { error: "no Password field appeared under PBKDF2" };
       if (!fieldOf("kdfSalt")) return { error: "no Salt field appeared under PBKDF2" };
       // Key and IV is the default, so the IV field is gone.
       if (fieldOf("nonce")) return { error: "the IV field is shown while the IV is being derived" };

       /*
        * The same inputs the unit tests use, and the same expected value -- which came from
        * openssl enc -aes-256-cbc -pbkdf2 -iter 10000 -S 0011223344556677 -pass pass:hunter2.
        */
       setField(password, "hunter2");
       const saltSelect = control("kdfSalt", "select");
       if (saltSelect) setSelect(saltSelect, "hex");
       setField(fieldOf("kdfSalt"), "0011223344556677");
       const iterations = fieldOf("pbkdf2Iterations");
       if (!iterations) return { error: "no Iterations field under PBKDF2" };
       setField(iterations, "10000");
       const input = await waitFor("[data-ocs-input]", 5000);
       if (!input) return { error: "no input panel" };
       setField(input, "123456789");
       await sleep(600);

       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const hexOf = (el) => (el ? el.textContent.replace(/[^0-9a-fA-F]/g, "").toLowerCase() : "");
       const waitForValue = async (want) => {
         const deadline = Date.now() + 15000;
         for (;;) {
           const text = hexOf(document.querySelector(SETTLED));
           if (text === want) return text;
           if (Date.now() > deadline) return text;
           await sleep(200);
         }
       };
       const WANT = "2a36645fdc30bcee17351ec19106e5f6";
       const got = await waitForValue(WANT);
       if (got !== WANT) {
         return { error: "PBKDF2 gave " + (got || "(nothing)") + ", expected the openssl value " + WANT };
       }

       // The derived key is reported, so nobody has to run the KDF tool separately to see it.
       const body = document.body.textContent;
       if (body.indexOf("Derived key") === -1) {
         return { error: "the result does not report the derived key" };
       }

       /*
        * Key only brings the IV field back -- the other half of the conjunction tag. Checked by what
        * renders rather than by what computes, because a field that reappeared but was ignored, or was
        * ignored but reappeared, are different bugs and only one of them changes the bytes.
        */
       const derives = fieldOf("kdfDerives") || control("kdfDerives", "select");
       if (!derives) return { error: "no Derives control" };
       setSelect(derives, "key");
       await sleep(500);
       if (!fieldOf("nonce")) return { error: "the IV field did not come back under Key only" };

       // Back to a state the later probes expect.
       setSelect(source, "directinput");
       await sleep(300);
       if (!fieldOf("key")) return { error: "the Key field did not come back under Direct Input" };

       return { digest: "7 sources, key swapped for password, openssl value matched" };
     })()`,
  );
}

/**
 * The Caesar cipher in the packaged renderer, and specifically the two things only a rendered page can
 * show.
 *
 * The cipher itself is covered twenty ways in the node suite, so this is not about the arithmetic. It is
 * about the shift control reaching it -- an option that renders and does nothing is this repo\'s
 * most-repeated defect, and here it would be invisible, because a Caesar output at the wrong shift looks
 * exactly as much like a Caesar output as the right one. And it is about the brute-force table, which is
 * a `working` block: the newest member of the result contract, rendered by a panel no other probe drives.
 */
function checkCaesar(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       const open = async (id) => {
         const selector = '[data-ocs-tool="' + id + '"]';
         const deadline = Date.now() + 15000;
         let everSeen = false;
         while (Date.now() < deadline) {
           const button = document.querySelector(selector);
           if (!button) { await sleep(100); continue; }
           everSeen = true;
           button.click();
           if (await waitFor(selector + '[aria-current="true"]', 2000)) return null;
         }
         return everSeen ? "clicking " + id + " did not select it" : id + " is not in the sidebar";
       };
       const settle = async (test, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         let last = "";
         while (Date.now() < deadline) {
           await sleep(120);
           const block = document.querySelector(SETTLED);
           last = block ? block.textContent.trim() : "";
           if (last && test(last)) return { value: last };
         }
         return { last };
       };
       // data-ocs-option is on a wrapper div; the control is inside it.
       const control = (id, tag) =>
         document.querySelector('[data-ocs-option="' + id + '"] ' + tag);
       const setValue = (element, value) => {
         const proto = element.tagName === "SELECT" ? HTMLSelectElement : HTMLInputElement;
         Object.getOwnPropertyDescriptor(proto.prototype, "value").set.call(element, String(value));
         element.dispatchEvent(new Event(element.tagName === "SELECT" ? "change" : "input", { bubbles: true }));
       };

       const problem = await open("caesar");
       if (problem) return { error: problem };

       const box = await waitFor("[data-ocs-input]", 10000);
       if (!box) return { error: "the Caesar tool has no input box" };
       Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set.call(box, "HELLO");
       box.dispatchEvent(new Event("input", { bubbles: true }));

       // The default shift is 3, so this is the tool demonstrating itself on arrival.
       const three = await settle((t) => t === "KHOOR", 15000);
       if (!three.value) {
         return { error: 'HELLO at the default shift gave ' + JSON.stringify(three.last) + ', expected KHOOR' };
       }

       /*
        * A different shift must give a different answer, and the value is pinned rather than merely
        * compared: 5 is the second example in every description of this cipher, so MJQQT is a published
        * value and "something changed" would pass over a control wired to the wrong option.
        */
       const shift = control("shift", "input");
       if (!shift) return { error: "no shift control on the Caesar tool" };
       setValue(shift, 5);
       const five = await settle((t) => t === "MJQQT", 15000);
       if (!five.value) {
         return { error: 'shift 5 gave ' + JSON.stringify(five.last) + ', expected MJQQT' };
       }

       /*
        * The brute-force table, which is a ToolResult.working block. Read from the panel rather than
        * from the result: it is a separate element, and nothing else in this smoke test renders one.
        */
       const workingBlock = document.querySelector("[data-ocs-working]");
       if (!workingBlock) return { error: "the 26-shift table did not render" };
       const lines = workingBlock.textContent.trim().split("\\n");
       if (lines.length !== 27) {
         return { error: "the table has " + lines.length + " lines, expected a heading and 26 rows" };
       }
       const marked = lines.filter((line) => line.trim().startsWith(">"));
       if (marked.length !== 1) {
         return { error: marked.length + " rows are marked; exactly one should be" };
       }
       if (marked[0].indexOf("MJQQT") === -1) {
         return { error: "the marked row reads " + JSON.stringify(marked[0]) };
       }
       // And row 0 is the input unchanged, which is what makes it every shift rather than every useful one.
       if (lines[1].indexOf("HELLO") === -1) {
         return { error: "row 0 reads " + JSON.stringify(lines[1]) + ", expected the input" };
       }

       /*
        * Decrypting is the same shift the other way, and the marked row moves to 26 - k -- which is the
        * one place the modular arithmetic is visible on screen.
        */
       const direction = control("direction", "select");
       if (!direction) return { error: "no direction control on the Caesar tool" };
       setValue(direction, "decrypt");
       const back = await settle((t) => t === "CZGGJ", 15000);
       if (!back.value) {
         return { error: 'decrypting HELLO at 5 gave ' + JSON.stringify(back.last) + ', expected CZGGJ' };
       }
       const afterMark = document
         .querySelector("[data-ocs-working]")
         .textContent.trim()
         .split("\\n")
         .filter((line) => line.trim().startsWith(">"))[0];
       if (!/^>\\s*21\\s/.test(afterMark.trim())) {
         return { error: "after switching to decrypt the marked row is " + JSON.stringify(afterMark) };
       }

       return { digest: three.value + "/" + five.value + "/" + back.value + "/" + lines.length };
     })()`,
  );
}

/**
 * The two random tools, in the packaged renderer.
 *
 * These need a probe more than most, for a reason peculiar to randomness: **no output can be wrong.**
 * Every other probe here compares against a published value -- Streebog's RFC digest, RFC 9562's v5
 * UUID, three CRC check values -- and a random tool has nothing to compare against, so a control wired
 * to nothing produces output that looks exactly as correct as the real thing. A dropdown that renders
 * and reaches nothing is already this repo's most-repeated defect; here it is also invisible.
 *
 * So the assertions are on the things that *are* determined: the range is respected, the shape select
 * actually changes what comes out, the no-repeats box actually de-duplicates, an impossible request is
 * refused rather than fudged, and the byte tool's length reaches the output. Every one of those would
 * pass by accident if the tool ignored its options, which is why each is checked against a value the
 * default could not produce.
 */
function checkRandomTools(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       const open = async (id) => {
         const selector = '[data-ocs-tool="' + id + '"]';
         const deadline = Date.now() + 15000;
         let everSeen = false;
         while (Date.now() < deadline) {
           const button = document.querySelector(selector);
           if (!button) { await sleep(100); continue; }
           everSeen = true;
           button.click();
           if (await waitFor(selector + '[aria-current="true"]', 2000)) return null;
         }
         return everSeen ? "clicking " + id + " did not select it" : id + " is not in the sidebar";
       };
       const setValue = (element, value) => {
         const proto = element.tagName === "SELECT" ? HTMLSelectElement : HTMLInputElement;
         Object.getOwnPropertyDescriptor(proto.prototype, "value").set.call(element, String(value));
         element.dispatchEvent(new Event(element.tagName === "SELECT" ? "change" : "input", { bubbles: true }));
       };
       /*
        * The data-ocs-option attribute is on a wrapper div, not on the control -- every other probe
        * here appends a " select" or " input" suffix for that reason. Calling a value setter on the
        * wrapper throws "Illegal invocation", which is how this was found rather than reasoned about.
        */
       const option = (id) =>
         document.querySelector('[data-ocs-option="' + id + '"] input, [data-ocs-option="' + id + '"] select');
       /*
        * A boolean option is a Toggle -- a button with role="switch" and aria-checked -- not a
        * checkbox. Re-queried on each call rather than held, for the reason the Auto update probe
        * records: the rail remounts and a held node is detached.
        */
       const toggle = (id) =>
         document.querySelector('[data-ocs-option="' + id + '"] [role="switch"]');
       const setToggle = async (id, on) => {
         const el = toggle(id);
         if (!el) return "no " + id + " switch";
         if (el.getAttribute("aria-checked") !== String(on)) el.click();
         for (let i = 0; i < 20; i++) {
           if (toggle(id)?.getAttribute("aria-checked") === String(on)) return null;
           await sleep(50);
         }
         return id + " would not turn " + (on ? "on" : "off");
       };
       // The generators recompute on their own, so the value settles without pressing anything.
       const settle = async (test, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         let last = "";
         while (Date.now() < deadline) {
           await sleep(120);
           const block = document.querySelector('[data-ocs-result][data-ocs-status="done"]');
           last = block ? block.textContent.trim() : "";
           if (last && test(last)) return { value: last };
         }
         return { last };
       };

       let problem = await open("random");
       if (problem) return { error: problem };

       const shape = await waitFor('[data-ocs-option="randomShape"] select', 10000);
       if (!shape) return { error: "the random tool has no shape control" };
       if (shape.value === "") return { error: "the shape select is resting on (not set)" };

       /*
        * A range the default could not produce. The default is 1 to 100, so requiring every one of 40
        * values to be between 900 and 910 fails if the bounds are ignored -- which is the whole point:
        * an option that never reaches the sampler leaves output that is still perfectly random.
        */
       for (const [id, value] of [["randomMin", 900], ["randomMax", 910], ["count", 40]]) {
         const control = option(id);
         if (!control) return { error: "no " + id + " control on the random tool" };
         setValue(control, value);
       }
       const ranged = await settle((text) => {
         const lines = text.split("\\n");
         return lines.length === 40 && lines.every((line) => Number(line) >= 900 && Number(line) <= 910);
       }, 12000);
       if (!ranged.value) {
         return { error: "40 draws in 900..910 never appeared; the panel showed " + JSON.stringify(ranged.last) };
       }
       // And both endpoints are reachable: an exclusive bound is the likeliest arithmetic slip here.
       const seenAcrossRuns = new Set(ranged.value.split("\\n").map(Number));

       /*
        * No repeats, asked for over a range that makes the difference certain: 11 values from 11
        * possibilities must be all of them, and the independent draw would repeat with probability
        * about 1 - 11!/11^11, which is over 99.99%.
        */
       setValue(option("count"), 11);
       const distinctProblem = await setToggle("randomDistinct", true);
       if (distinctProblem) return { error: distinctProblem };
       const unique = await settle((text) => {
         const lines = text.split("\\n").map(Number);
         return lines.length === 11 && new Set(lines).size === 11;
       }, 12000);
       if (!unique.value) {
         return { error: "no-repeats produced " + JSON.stringify(unique.last) };
       }
       for (const value of unique.value.split("\\n").map(Number)) seenAcrossRuns.add(value);
       if (!seenAcrossRuns.has(900) || !seenAcrossRuns.has(910)) {
         return { error: "the range ends were never drawn: saw " + [...seenAcrossRuns].sort().join(",") };
       }

       /*
        * And an impossible request is refused with the numbers in it, rather than quietly returning
        * fewer values -- which is what a tool that clamped instead would do.
        */
       setValue(option("count"), 40);
       const refused = await (async () => {
         const deadline = Date.now() + 8000;
         while (Date.now() < deadline) {
           await sleep(120);
           const text = document.body.textContent;
           if (text.includes("needs a range of at least 40")) return true;
         }
         return false;
       })();
       if (!refused) return { error: "40 distinct values from 11 was not refused" };
       const offProblem = await setToggle("randomDistinct", false);
       if (offProblem) return { error: offProblem };
       setValue(option("count"), 3);

       // Decimals: a different shape must produce a different *form* of answer.
       setValue(shape, "decimal");
       const decimals = await settle((text) => {
         const lines = text.split("\\n");
         return lines.length === 3 && lines.every((line) => /^0\\.[0-9]+$/.test(line));
       }, 12000);
       if (!decimals.value) {
         return { error: "decimals produced " + JSON.stringify(decimals.last) };
       }

       /*
        * The byte tool, where the assertion is that the length control reaches the output *and* that
        * the encoding menu exists -- it is the only tool in this family that returns bytes, and that
        * menu appearing is the visible consequence.
        */
       problem = await open("randombytes");
       if (problem) return { error: problem };
       const lengthControl = await waitFor('[data-ocs-option="randomBytes"] input', 10000);
       if (!lengthControl) return { error: "the random-bytes tool has no length control" };
       setValue(lengthControl, 20);
       /*
        * Whitespace stripped before matching: the Result panel groups hex in blocks for readability,
        * so 20 bytes arrive as "528ea836 a85ea798 ...". Matching the raw text failed here and the
        * tool was right -- worth the note, because the same trap is waiting for the next probe that
        * asserts on a hex result.
        */
       const bare = (text) => text.replace(/\\s+/g, "");
       const hex = await settle((text) => /^[0-9a-fA-F]{40}$/.test(bare(text)), 12000);
       if (!hex.value) return { error: "20 bytes of hex never appeared, saw " + JSON.stringify(hex.last) };

       const encodingMenu = document.querySelector("[data-ocs-output-encoding]");
       if (!encodingMenu) {
         return { error: "the byte tool has no output-encoding menu, which is why it is its own tool" };
       }
       setValue(encodingMenu, "base64");
       const base64 = await settle(
         (text) => /^[A-Za-z0-9+/]+=*$/.test(bare(text)) && bare(text).length < 40,
         12000,
       );
       if (!base64.value) {
         return { error: "base64 never appeared, saw " + JSON.stringify(base64.last) };
       }
       // Back to default hex-upper, because the probes share one window.
       setValue(encodingMenu, "hex-upper");

       return { digest: bare(hex.value).length + "/" + decimals.value.split("\\n").length };
     })()`,
  );
}

/**
 * The Input panel's Copy button, checked against the *system* clipboard.
 *
 * A control that renders and does nothing is this repo's most-repeated defect -- AEGIS's tag length
 * was inert with a green suite, four MAC options were unreachable, the "(not set)" placeholder
 * survived two rounds of unit tests -- and a copy button is the shape of it that hides best: the
 * icon swaps to a tick, so it *looks* like it worked whether or not anything was written.
 *
 * So the assertion is `clipboard.readText()` in the main process rather than the button's own state.
 * That covers the whole path a click actually takes: `useCopy` reading the value lazily, the
 * `writeClipboard` override, `platform().copyToClipboard`, the preload bridge and the main process's
 * clipboard call. The tick is checked too, but second -- it is the part that can lie.
 *
 * The clipboard is emptied first, because a passing read of a value some earlier probe happened to
 * copy is indistinguishable from a passing read of this one.
 */
function checkInputCopy(window: BrowserWindow): Promise<ComputeProbe> {
  const WANTED = "copy-probe-9f3a";
  /**
   * Whether this host has a working clipboard at all, checked before anything is asserted through it.
   *
   * The clipboard is not part of the app: it is a shared OS resource that can be held by another
   * process, absent in a non-interactive session, or simply broken -- on the machine this was written
   * on it stopped round-tripping for `Set-Clipboard`/`Get-Clipboard` in PowerShell too, at which point
   * this probe failed five runs in a row for a button that was working perfectly.
   *
   * So the oracle's precondition is checked first, which is the same discipline the parity tests apply
   * to OpenSSL. When the clipboard works the assertion is the strong one -- the exact text, read in the
   * main process, covering the whole path a click takes. When it does not, the tick is still checked and
   * the skip is *stated* in the digest rather than passing quietly, because "the clipboard hop was not
   * verified" is information.
   */
  const sentinel = `clipboard-check-${Date.now()}`;
  clipboard.writeText(sentinel);
  const clipboardWorks = clipboard.readText() === sentinel;
  if (!clipboardWorks) {
    process.stdout.write(
      "SMOKE NOTE: this host has no working clipboard (a write did not read back), so the copy button's clipboard hop is unverified; its tick is still checked.\n",
    );
  }
  clipboard.writeText("");
  return window.webContents
    .executeJavaScript(
      `(async () => {
       const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
       const box = () => document.querySelector("[data-ocs-input]");
       /*
        * Opens a tool with an input rather than assuming one is selected.
        *
        * The probes share one window on purpose, so this used to inherit whatever the previous probe
        * left -- and it broke the moment a probe for a *generator* was added ahead of it, because a
        * generator has no textarea at all. Opening what this needs removes the ordering dependency
        * instead of making the probe list order-sensitive, which is the sort of coupling nobody
        * remembers when inserting the next one.
        */
       if (!box()) {
         const deadline = Date.now() + 15000;
         while (!box() && Date.now() < deadline) {
           const row = document.querySelector('[data-ocs-tool="crc32"]');
           if (row) row.click();
           await sleep(150);
         }
         if (!box()) return { error: "could not reach a tool with an input box" };
       }

       // Typed through the value setter and an input event, which is how React sees a change.
       const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
       setter.call(box(), ${JSON.stringify(WANTED)});
       box().dispatchEvent(new Event("input", { bubbles: true }));
       /*
        * Waited for through the *size line*, not the textarea's value.
        *
        * The DOM value is set by the line above and says nothing about whether React has committed
        * it -- and the copy button reads the value out of React state, so clicking before that commit
        * copies the previous text, or an empty string, and the probe fails with "never showed its
        * tick" for a button that is working. That is the same distinction checkManualCompute records:
        * the size line only moves when the state does.
        */
       const sizeLine = () => {
         const el = document.querySelector("[data-ocs-input-size]");
         return el ? el.textContent.trim() : "";
       };
       const typedDeadline = Date.now() + 10000;
       while (Date.now() < typedDeadline) {
         if (box()?.value === ${JSON.stringify(WANTED)} && /^${WANTED.length} bytes/.test(sizeLine())) break;
         await sleep(100);
       }
       if (box()?.value !== ${JSON.stringify(WANTED)}) {
         return { error: "could not type the probe value into the box" };
       }
       if (!/^${WANTED.length} bytes/.test(sizeLine())) {
         return { error: "the input never reached React state; the size line reads " + JSON.stringify(sizeLine()) };
       }

       const copy = document.querySelector("[data-ocs-copy-icon]");
       if (!copy) return { error: "no copy button in the input panel" };
       if (copy.disabled) return { error: "the copy button is disabled with text in the box" };

       /*
        * Its position is asserted, not just its presence: it was asked for *before* the Clear icon,
        * and a pair of round pills in the wrong order is the kind of thing that reads as fine until
        * somebody reaches for the one they expected. compareDocumentPosition beats comparing indices,
        * which would break the moment another control joined the row.
        */
       const clear = document.querySelector("[data-ocs-clear]");
       if (!clear) return { error: "no clear button to order against" };
       const following = copy.compareDocumentPosition(clear) & Node.DOCUMENT_POSITION_FOLLOWING;
       if (!following) return { error: "the copy button is after the clear button, not before it" };

       copy.click();
       /*
        * Polled for five seconds, not one, and the reason is where the tick comes from.
        *
        * useCopy awaits the clipboard write *before* it sets the copied flag, and on the desktop
        * that write is an IPC round trip through the preload bridge to the main process. So the tick
        * does not appear on click -- it appears whenever that returns, and under load that was
        * occasionally past the old one-second budget, failing about one run in five for a button that
        * was working. The 1.5-second window the tick stays up is unaffected by looking for longer:
        * this poll starts before the tick exists and stops the moment it finds it.
        */
       let ticked = false;
       for (let attempt = 0; attempt < 100; attempt++) {
         await sleep(50);
         if (copy.querySelector("polyline")) { ticked = true; break; }
       }
       /*
        * Reported rather than judged here, because the renderer cannot see the OS clipboard.
        *
        * The tick appears only after the clipboard write *resolves*, so on a host whose clipboard is
        * broken it legitimately never appears -- and this probe then blamed a button that was working.
        * The main process re-probes the clipboard when it sees this and decides, which is the only
        * place that distinction can be made.
        */

       /*
        * And in file mode there is nothing to copy, so it must be disabled rather than gone -- the
        * row would otherwise change shape depending on how the input arrived.
        */
       const modeSelect = document.querySelector("[data-ocs-input-mode]");
       if (!modeSelect) return { error: "no input-source select" };
       const setMode = (value) => {
         Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(
           modeSelect,
           value,
         );
         modeSelect.dispatchEvent(new Event("change", { bubbles: true }));
       };
       setMode("file");
       await sleep(250);
       const inFileMode = document.querySelector("[data-ocs-copy-icon]");
       if (!inFileMode) return { error: "the copy button vanished in file mode" };
       if (!inFileMode.disabled) return { error: "the copy button is enabled in file mode" };
       // Back to text, because the probes share one window and the ones after this expect a box.
       setMode("text");
       await sleep(250);
       if (!box()) return { error: "the textarea did not come back after file mode" };

       return {
         digest: (box() ? String(box().value.length) : "0") + (ticked ? "/ticked" : "/no-tick"),
       };
     })()`,
    )
    .then(async (probe: ComputeProbe) => {
      if (probe.error) return probe;
      /*
       * Polled rather than read once, because the clipboard is shared with the whole machine.
       *
       * The renderer's tick already proves the write resolved, so this is not waiting for the app --
       * it is waiting for the OS. On Windows the clipboard is a lock another process can hold for a
       * moment, and a read landing in that window comes back empty; that flaked once here, reporting
       * an empty clipboard for a copy that had plainly happened. Ten tries over a second is far longer
       * than propagation takes and costs nothing when the first read succeeds.
       */
      const digest = probe.digest ?? "";
      /**
       * The tick, judged against a *fresh* clipboard probe rather than the one taken at the start.
       *
       * The clipboard can change state mid-run -- it did on this machine, going from broken to working
       * between two consecutive smoke runs -- so a precondition checked once is not enough. If the tick
       * never appeared, the question is whether the clipboard is working *now*: if it is, the button is
       * genuinely broken and this fails; if it is not, the write had nothing to resolve into and there
       * is nothing to report about the button.
       */
      if (digest.endsWith("/no-tick")) {
        const stillWorks = (() => {
          const probeText = `clipboard-recheck-${Date.now()}`;
          clipboard.writeText(probeText);
          return clipboard.readText() === probeText;
        })();
        if (stillWorks) return { error: "the copy button never showed its tick" };
        process.stdout.write(
          "SMOKE NOTE: the clipboard stopped working mid-run, so the copy button's tick and clipboard hop are both unverified.\n",
        );
        return { digest: `${digest}/clipboard-unavailable` };
      }
      if (!clipboardWorks) {
        return { digest: `${digest}/clipboard-unavailable` };
      }
      let pasted = "";
      for (let attempt = 0; attempt < 10; attempt++) {
        pasted = clipboard.readText();
        if (pasted === WANTED) return probe;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      return {
        error: `the clipboard holds ${JSON.stringify(pasted)} rather than the input text`,
      };
    });
}

/**
 * Reads the footer, and requires every link in it to be one the app will actually open.
 *
 * The second half is the point. A clicked link reaches the system browser only if it matches
 * `EXTERNAL_ALLOWLIST` in `window.ts`, and a URL that does not match is not refused with a message --
 * `setWindowOpenHandler` returns `deny` and nothing happens at all. So a typo in the host, or a link
 * added later pointing somewhere else, produces three inert links in a shipped build with nothing in
 * the unit suite, the typecheck or the build able to see it. That is this repo's most-repeated defect
 * shape, and it is why this probe exists rather than a render check.
 *
 * The version is asserted against the About box's, because they read the same
 * `PlatformEnvironment.appVersion` and two places disagreeing about the version of one running
 * program is worse than either number on its own.
 */
function checkFooter(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

       const footer = document.querySelector("[data-ocs-footer]");
       if (!footer) return { error: "no footer rendered" };

       // The version arrives from an async platform call, so give it a moment.
       let version = "";
       for (let i = 0; i < 40; i++) {
         const cell = footer.querySelector("[data-ocs-footer-version]");
         version = cell ? cell.textContent.trim() : "";
         if (/^v\\d/.test(version)) break;
         await sleep(50);
       }
       if (!/^v\\d/.test(version)) {
         return { error: "the footer never showed a version, read " + JSON.stringify(version) };
       }

       const links = Array.from(footer.querySelectorAll("a[href]"));
       if (links.length !== 3) return { error: "the footer has " + links.length + " links, expected 3" };

       const offsite = links.map((a) => a.href).filter((href) => !href.startsWith("https://github.com/"));
       if (offsite.length > 0) {
         // Not on the main process allowlist, so clicking these would silently do nothing.
         return { error: "footer links the app cannot open: " + offsite.join(" ") };
       }

       if (!footer.textContent.includes("Cipher Workbench")) {
         return { error: "the footer does not name the app" };
       }

       return { digest: version + "/" + links.length };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Requires that no select offers "(not set)" as something a user could pick.
 *
 * Not unit-testable, and that is the whole reason this exists. The placeholder was rendered
 * unconditionally in the options form, so every dropdown in the app carried an entry that -- if
 * chosen -- removed the option from the spec and left compute running on a fallback the form no
 * longer displayed. A typecheck cannot see it, and the unit suite that asserts every enum is *seeded*
 * passed throughout, because seeding was never the problem: the entry was in the list either way.
 *
 * Driven on HAVAL, which is where it was reported and which renders two of these selects. The
 * assertion is per-option so a failure names the control.
 */
function checkNoUnsetChoice(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
       const waitFor = async (selector, timeout) => {
         const until = Date.now() + timeout;
         while (Date.now() < until) {
           const found = document.querySelector(selector);
           if (found) return found;
           await sleep(50);
         }
         return null;
       };

       // The data-ocs-tool hook, as every other probe here uses -- a text match would miss a
       // collapsed category and would break the moment a label changed.
       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let link = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         link = document.querySelector('[data-ocs-tool="haval"]') || link;
         if (document.querySelector('[data-ocs-tool="haval"][aria-current="true"]')) break;
         if (link) link.click();
         await sleep(100);
       }
       if (!link) return { error: "the haval tool is not listed in the sidebar" };
       if (!(await waitFor('[data-ocs-tool="haval"][aria-current="true"]', 10000))) {
         return { error: "clicking haval did not select it" };
       }

       const passes = await waitFor('[data-ocs-option="passes"] select', 15000);
       if (!passes) return { error: "HAVAL rendered without a Passes selector" };

       // Every select the tool renders, not only the two that are new.
       const selects = [...document.querySelectorAll("[data-ocs-option] select")];
       if (selects.length < 2) {
         return { error: \`expected at least two selects on HAVAL, saw \${selects.length}\` };
       }

       const offenders = [];
       for (const select of selects) {
         const id = select.closest("[data-ocs-option]").getAttribute("data-ocs-option");
         // An empty-valued option is only acceptable if it cannot be chosen.
         const pickable = [...select.options].filter((o) => o.value === "" && !o.disabled);
         if (pickable.length > 0) offenders.push(id);
         // And nothing may be sitting on the placeholder to begin with.
         if (select.value === "") offenders.push(id + " (unset)");
       }
       if (offenders.length > 0) {
         return { error: \`selects offering or resting on (not set): \${offenders.join(", ")}\` };
       }

       const passValue = passes.value;
       const lengthSelect = document.querySelector('[data-ocs-option="outputLength"] select');
       return {
         digest: passValue + "/" + (lengthSelect ? lengthSelect.value : "none"),
       };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Sends `menu:about` the way the Help menu does, and requires the About overlay to open.
 *
 * The probe exists because of how this shipped: the preload forwarded five menu channels, the bridge
 * declared them, and no renderer code ever subscribed -- so every File item and About were inert, and
 * nothing anywhere could tell. A menu item that does nothing is invisible to a typecheck, a unit test
 * and a build. It takes an end-to-end dispatch to see it.
 */
function checkAboutMenu(window: BrowserWindow): Promise<ComputeProbe> {
  window.webContents.send("menu:about");

  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

       let dialog = null;
       const deadline = Date.now() + 5000;
       while (Date.now() < deadline) {
         await sleep(100);
         dialog = document.querySelector('[role="dialog"][aria-label="Settings"]');
         if (dialog) break;
       }
       if (!dialog) return { error: "menu:about did not open the settings overlay" };

       // On About, not on whichever category was left selected: the menu item names one.
       const heading = dialog.querySelector("h1");
       if (heading?.textContent !== "About") {
         return { error: 'the overlay opened on "' + heading?.textContent + '" rather than About' };
       }
       if (!/Cipher Workbench/.test(dialog.textContent ?? "")) {
         return { error: "the About pane does not name the application" };
       }

       const close = dialog.querySelector('[aria-label="Close settings"]');
       if (close) close.click();
       await sleep(200);
       return { digest: "menu:about opened the About overlay" };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Opens Settings and requires its category sidebar to sit *beside* the content, not above it.
 *
 * A geometry check, which is unusual here and earns it: the shared `Dialog` wrapped its children in a
 * div, so making the card a flex row gave it one flex item holding both panes -- and the sidebar
 * rendered as a short box stacked on top. Nothing else could see that. Both elements existed, both
 * had their classes, the typecheck and every unit test passed, and the layout was simply wrong. So
 * this asserts the thing that was false: the sidebar's right edge is left of the content's left edge,
 * and the two overlap vertically.
 */
function checkSettingsLayout(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

       const trigger = document.querySelector('[aria-label="Settings"]');
       if (!trigger) return { error: "no Settings button in the shell" };
       trigger.click();

       let dialog = null;
       const deadline = Date.now() + 5000;
       while (Date.now() < deadline) {
         await sleep(100);
         dialog = document.querySelector('[role="dialog"][aria-label="Settings"]');
         if (dialog) break;
       }
       if (!dialog) return { error: "the settings dialog never opened" };

       const aside = dialog.querySelector("aside");
       const heading = dialog.querySelector("h1");
       if (!aside) return { error: "the settings dialog has no category sidebar" };
       if (!heading) return { error: "the settings dialog has no category heading" };

       const nav = aside.getBoundingClientRect();
       const pane = heading.getBoundingClientRect();
       if (nav.right > pane.left) {
         return {
           error:
             "the sidebar is not beside the content: sidebar right=" +
             Math.round(nav.right) +
             " pane left=" +
             Math.round(pane.left),
         };
       }
       if (nav.bottom <= pane.top) {
         return { error: "the sidebar sits above the content rather than alongside it" };
       }

       const categories = aside.querySelectorAll("nav button").length;
       if (categories < 3) return { error: "expected three categories, found " + categories };

       // Left as it was found, so later probes are not clicking through a modal.
       const close = dialog.querySelector('[aria-label="Close settings"]');
       if (close) close.click();
       await sleep(200);
       if (document.querySelector('[role="dialog"][aria-label="Settings"]')) {
         return { error: "closing the settings dialog did nothing" };
       }

       return { digest: categories + " categories, sidebar beside content" };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Signs one byte with Ed25519 and requires RFC 8032's published signature back.
 *
 * The three probes above all feed the tool through the input panel. This one has to set an
 * *option* — a private key — which is a different code path entirely: the options form reads
 * the catalogue, decodes the hex through the companion encoding selector, and hands the bytes
 * to a compute function that ignores none of it. It is also the first probe to touch a masked
 * secret control, which renders an `<input type="password">` rather than the textarea the
 * others drive.
 *
 * The message is "r" typed as text rather than an empty input, deliberately: the input panel's
 * contents survive a tool switch, so an earlier probe's "123456789" would otherwise be what
 * got signed. One ASCII "r" is 0x72, which is exactly TEST 2's message.
 */
function checkAsymmetric(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       // A result that has finished computing. While the debounce is pending the panel still shows
       // the previous value, and reading that is how a probe passes for the wrong reason.
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       const setValue = (element, value) => {
         const proto =
           element.tagName === "TEXTAREA"
             ? HTMLTextAreaElement.prototype
             : HTMLInputElement.prototype;
         Object.getOwnPropertyDescriptor(proto, "value").set.call(element, value);
         element.dispatchEvent(new Event("input", { bubbles: true }));
       };

       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let button = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         button = document.querySelector('[data-ocs-tool="ed25519"]') || button;
         if (document.querySelector('[data-ocs-tool="ed25519"][aria-current="true"]')) break;
         if (button) button.click();
         await sleep(100);
       }
       if (!button) return { error: "the ed25519 tool is not listed in the sidebar" };

       const selected = await waitFor('[data-ocs-tool="ed25519"][aria-current="true"]', 10000);
       if (!selected) return { error: "clicking ed25519 did not select it" };

       // The options form only exists once the family's chunk has loaded.
       const operation = await waitFor('[data-ocs-option="operation"] select', 10000);
       if (!operation) return { error: "the Ed25519 options form never rendered" };

       // Ed25519 opens on Generate keypair, which produces a different key every run.
       const setSelect = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set;
       setSelect.call(operation, "sign");
       operation.dispatchEvent(new Event("change", { bubbles: true }));

       // Switching operation is what makes the private-key field appear at all — it is gated
       // on availableOn: ["sign"] — so this also proves variantTag is wired up.
       const keyField = await waitFor('[data-ocs-option="privateKey"] input', 10000);
       if (!keyField) return { error: "switching to Sign did not reveal the private-key field" };

       // Where it is, as well as that it exists: keys, IVs and nonces belong beside the message,
       // not in the Settings rail. Nothing else would notice them moving back.
       if (!document.querySelector('[data-ocs-material] [data-ocs-option="privateKey"]')) {
         return { error: "the private-key field is not inside the input panel's material section" };
       }
       setValue(keyField, "${ED25519_SECRET}");

       const input = document.querySelector("[data-ocs-input]");
       if (!input) return { error: "no input panel while signing" };
       setValue(input, "r");

       const deadline = Date.now() + 10000;
       let last = "";
       while (Date.now() < deadline) {
         await sleep(100);
         // Strips to hex characters rather than stripping whitespace: the result panel groups
         // hex in fours with a thin space, and a character class needs no backslash escape —
         // which matters, because this string is a JS template literal inside a TS template
         // literal and a "\s" that loses one backslash on the way through matches nothing.
         last = (document.querySelector(SETTLED)?.textContent ?? "").replace(
           /[^0-9a-fA-F]/g,
           "",
         );
         if (/^[0-9a-fA-F]{128}$/.test(last)) return { digest: last };
       }
       return { error: 'no Ed25519 signature appeared; the result panel showed ' + JSON.stringify(last) };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Hashes text through a legacy character encoding, which no other probe touches.
 *
 * Two things are being proved. First, that selecting Shift_JIS actually loads and applies the
 * conversion tables -- the digest below is unreachable otherwise, since the UTF-8 reading of the
 * same characters gives a completely different value. Second, and the reason this is in the
 * *packaged* smoke test rather than only in the unit suite, that the dynamic `import()` holding
 * those tables resolves over `app://`. Nothing references that chunk statically, so a protocol
 * handler that mishandles it would fail here and nowhere else.
 */
function checkLegacyEncoding(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       // A result that has finished computing. While the debounce is pending the panel still shows
       // the previous value, and reading that is how a probe passes for the wrong reason.
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };

       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let button = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         button = document.querySelector('[data-ocs-tool="sha256"]') || button;
         if (document.querySelector('[data-ocs-tool="sha256"][aria-current="true"]')) break;
         if (button) button.click();
         await sleep(100);
       }
       if (!button) return { error: "the sha256 tool is not listed in the sidebar" };
       if (!(await waitFor('[data-ocs-tool="sha256"][aria-current="true"]', 10000))) {
         return { error: "clicking sha256 did not select it" };
       }

       // Back to Text mode: an earlier probe may have left the panel on File.
       const source = document.querySelector("[data-ocs-input-mode]");
       if (source) {
         Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(
           source,
           "text",
         );
         source.dispatchEvent(new Event("change", { bubbles: true }));
       }

       // Same hazard as the tool-switch probe: this arrives on SHA-256 with the previous probe's
       // "r" still typed, computes a perfectly good 64-character digest of it, and 64 characters is
       // exactly the shape this probe is looking for.
       const before = (document.querySelector(SETTLED)?.textContent ?? "").replace(/[^0-9a-fA-F]/g, "");

       const select = await waitFor("[data-ocs-input-encoding]", 10000);
       if (!select) return { error: "no input encoding selector" };
       const setSelect = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set;
       setSelect.call(select, "shift_jis");
       select.dispatchEvent(new Event("change", { bubbles: true }));

       const input = await waitFor("[data-ocs-input]", 10000);
       if (!input) return { error: "no input panel" };
       const setValue = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
       setValue.call(input, "\u65e5\u672c\u8a9e");
       input.dispatchEvent(new Event("input", { bubbles: true }));

       // A longer budget than the other probes get: this one waits on a 530 KB chunk being
       // fetched over app:// before anything can be computed at all.
       const deadline = Date.now() + 20000;
       let last = "";
       while (Date.now() < deadline) {
         await sleep(100);
         last = (document.querySelector(SETTLED)?.textContent ?? "").replace(
           /[^0-9a-fA-F]/g,
           "",
         );
         if (last !== before && /^[0-9a-fA-F]{64}$/.test(last)) return { digest: last };
       }
       return { error: 'no digest appeared; the result panel showed ' + JSON.stringify(last) };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Hashes a published vector with Streebog-256, which is the heaviest table-driven tool in the app.
 *
 * The point is not correctness -- `tests/algos-streebog.test.ts` owns that -- but that the *packaged*
 * renderer can build and use a table this size. Streebog derives 4096 64-bit lookup entries at module
 * load from the RFC's matrix, and it lives in the same lazily-imported chunk as Tiger's 8 KB S-boxes
 * and Skein's rotation tables. That chunk grew by an order of magnitude when those were added; nothing
 * references it statically, so a protocol handler or a bundler split that mishandled it would show up
 * here and in no unit test.
 *
 * The message and digest are RFC 6986's own example 1, so a wrong answer is a real failure rather than
 * a drift from a value this repo produced itself.
 */
function checkStreebog(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };

       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let button = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         button = document.querySelector('[data-ocs-tool="streebog256"]') || button;
         if (document.querySelector('[data-ocs-tool="streebog256"][aria-current="true"]')) break;
         if (button) button.click();
         await sleep(100);
       }
       if (!button) return { error: "the streebog256 tool is not listed in the sidebar" };
       if (!(await waitFor('[data-ocs-tool="streebog256"][aria-current="true"]', 10000))) {
         return { error: "clicking streebog256 did not select it" };
       }

       // The previous probe left the input encoding on Shift_JIS, which would change the bytes.
       const encoding = document.querySelector("[data-ocs-input-encoding]");
       if (encoding) {
         Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(
           encoding,
           "utf-8",
         );
         encoding.dispatchEvent(new Event("change", { bubbles: true }));
       }

       const input = await waitFor("[data-ocs-input]", 10000);
       if (!input) return { error: "no input panel" };
       const setValue = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
       setValue.call(
         input,
         "012345678901234567890123456789012345678901234567890123456789012",
       );
       input.dispatchEvent(new Event("input", { bubbles: true }));

       const deadline = Date.now() + 20000;
       let last = "";
       while (Date.now() < deadline) {
         await sleep(100);
         last = (document.querySelector(SETTLED)?.textContent ?? "").replace(/[^0-9a-fA-F]/g, "");
         if (/^[0-9a-fA-F]{64}$/.test(last)) return { digest: last };
       }
       return { error: 'no digest appeared; the result panel showed ' + JSON.stringify(last) };
     })()`,
  ) as Promise<ComputeProbe>;
}

/*
 * The parity family, and specifically the thing only a packaged probe can see.
 *
 * Two claims are checked. The UART tool returns a *diagram* rather than bytes, so its result panel
 * must render the frame verbatim and must offer no output-encoding menu -- a single-entry
 * outputEncodings list is what hides that selector, and nothing in the unit suite or a typecheck can
 * tell a hidden selector from a rendered one. And the Parity tool opens on **binary** rather than hex,
 * which is this family's one departure from every other in the app: the result is bits, and 01 says
 * what 0x01 makes you decode.
 *
 * The frame asserted is 'A' at 8N1: start 0, then 0x41 least significant bit first, then stop 1. It is
 * asymmetric on purpose -- 0x55 and 0xff read the same in both directions, so they cannot tell a
 * correct frame from one sent MSB-first.
 *
 * Note the plain comment and the absent backticks: this is inside a template literal, and one
 * backtick ends the whole probe.
 */
function checkParityFamily(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       const settle = async (test, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         let last = "";
         while (Date.now() < deadline) {
           await sleep(100);
           last = document.querySelector(SETTLED)?.textContent ?? "";
           if (test(last)) return { value: last };
         }
         return { last };
       };
       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered, so a tool switch remounts its rows. A probe that queries the
        * row, then clicks it, can hold a node React replaced in between -- the click goes to a
        * detached element and does nothing, which is the same defect the Auto update probe hit and is
        * recorded in CLAUDE.md. Both spellings of it flaked here: "parity is not listed in the
        * sidebar" when the query lost the race, and "clicking fsb did not select it" when the click
        * did. Retrying a fresh query removes the race instead of widening the window, and the two
        * failure messages stay distinct so a genuinely missing tool still reads as missing.
        */
       const open = async (id) => {
         const selector = '[data-ocs-tool="' + id + '"]';
         const deadline = Date.now() + 15000;
         let everSeen = false;
         while (Date.now() < deadline) {
           const button = document.querySelector(selector);
           if (!button) {
             await sleep(100);
             continue;
           }
           everSeen = true;
           button.click();
           if (await waitFor(selector + '[aria-current="true"]', 2000)) return null;
         }
         if (!everSeen) return id + " is not listed in the sidebar";
         return "clicking " + id + " did not select it";
       };
       const type = (value) => {
         const box = document.querySelector("[data-ocs-input]");
         if (!box) return false;
         Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set.call(box, value);
         box.dispatchEvent(new Event("input", { bubbles: true }));
         return true;
       };

       let problem = await open("uart");
       if (problem) return { error: problem };
       if (!(await waitFor("[data-ocs-input]", 10000))) return { error: "uart has no input box" };
       if (!type("A")) return { error: "could not type into the uart input" };

       /*
        * Three separate things, because the table is padded to its column widths and a single
        * substring can no longer stand for the row. The heading has to name the bit order -- 0x30 is
        * 0011_0000 and its frame shows 0000_1100, which reads as a bug without it -- the byte has to
        * be labelled, and the reversed data has to be there.
        */
       const frame = await settle(
         (t) =>
           t.indexOf("LSB first") !== -1 && t.indexOf("0x41") !== -1 && t.indexOf("10000010") !== -1,
         20000,
       );
       if (!frame.value) {
         return { error: 'the 8N1 frame for A did not appear; the panel showed "' + frame.last + '"' };
       }
       /*
        * The panel is bounded, which only a rendered page can show.
        *
        * The UART tool prints one row per input byte, so thirty bytes is thirty-one lines -- and before
        * MonoBlock capped its height the Result panel grew until the page did, pushing Verify, the
        * Table panel and the Variants table off the bottom of the screen. Neither a typecheck nor the
        * node suite can see a div that grows: the text is identical either way.
        */
       if (!type("012345678901234567890123456789")) {
         return { error: "could not type the long input" };
       }
       const tall = await settle((t) => t.split(String.fromCharCode(10)).length >= 31, 20000);
       if (!tall.value) return { error: "the 30-byte frame table did not appear" };
       const box = document.querySelector("[data-ocs-result]");
       const height = box.getBoundingClientRect().height;
       if (height > 520) {
         return { error: "the result panel grew to " + Math.round(height) + "px for 31 lines" };
       }
       // And it is genuinely scrolling rather than merely clipped, so nothing is unreachable.
       if (box.scrollHeight <= box.clientHeight) {
         return { error: "31 lines fit without scrolling, so the cap is not what is bounding it" };
       }

       /*
        * And every column is named. The report that prompted this table was a row reading 30 0 0
        * 00001100 1 under a header of start data(8) stop: the leading two columns had no headings at
        * all, so for the input "0" the digit appeared three times with nothing to say which was which.
        */
       for (const heading of ["Byte", "Char", "Start", "Stop"]) {
         if (frame.value.indexOf(heading) === -1) {
           return { error: "the frame table has no " + heading + " column" };
         }
       }
       /*
        * A diagram has no other spelling, so the encoding menu must be absent. This is the assertion
        * the unit suite cannot make: outputEncodings has one entry, and whether that hides the control
        * is a fact about the rendered panel.
        */
       if (document.querySelector("[data-ocs-output-encoding]")) {
         return { error: "the uart frame offers an output-encoding menu, which a diagram has no use for" };
       }

       problem = await open("parity");
       if (problem) return { error: problem };
       /*
        * The switch is still offered here, which is the assertion that stops the fix from becoming
        * "hide it everywhere". Parity reads a box, so not recomputing over half-typed input is a real
        * setting with a real meaning.
        */
       if (!document.querySelector('[data-ocs-toggle="auto-update"]')) {
         return { error: "the parity tool lost the Auto update switch" };
       }
       if (!(await waitFor("[data-ocs-input]", 10000))) return { error: "parity has no input box" };
       // Ten bytes, 0x30 to 0x39, whose even parity bits are 0110100110 -- the exact input from the
       // report, so the value asserted below is the one that was on screen when it was made.
       if (!type("0123456789")) return { error: "could not type into the parity input" };

       /*
        * Binary, not hex. Nine bytes in, nine parity bits out, each rendered as a byte: even parity of
        * 0x31 to 0x39 is 1,1,0,1,0,0,1,1,0, so the panel reads 00000001 00000001 00000000 ...
        */
       const bits = await settle((t) => t.replace(/[^01]/g, "").length >= 80, 20000);
       if (!bits.value) {
         return { error: 'no parity bits appeared; the panel showed "' + bits.last + '"' };
       }
       const packed = bits.value.replace(/[^01]/g, "");
       /*
        * Ten bytes as one byte each, in binary: the even parity of 0x30 to 0x39 is 0110100110, so the
        * panel reads 00000000 00000001 00000001 00000000 ... Eighty characters for ten bits, which is
        * the readability complaint the Parity bits row above answers -- and this still asserts the
        * value, because the bytes are what gets copied.
        */
       const expected =
         "00000000" + "00000001" + "00000001" + "00000000" + "00000001" +
         "00000000" + "00000000" + "00000001" + "00000001" + "00000000";
       if (packed !== expected) {
         return { error: "parity of 123456789 rendered as " + packed };
       }
       /*
        * And the bits are stated in words somewhere on the page.
        *
        * Eighty characters of binary carrying ten bits is what was reported, and the fix was a field
        * row reading "01101001 10". A field that renders and says nothing is this repo's most-repeated
        * defect, and the field table is rendered from ToolResult.fields by a component no unit test
        * exercises -- so the value being *on screen* is only checkable here.
        */
       /*
        * textContent, not innerText, and the difference bit once already.
        *
        * FieldTable renders its labels with CSS text-transform: uppercase, and innerText returns the
        * *rendered* text -- so searching it for "Parity bits" finds nothing while the row is plainly on
        * screen. textContent is the DOM text and is unaffected by styling, which is what a probe
        * asserting content rather than appearance wants.
        */
       const bodyText = document.body.textContent;
       if (bodyText.indexOf("Parity bits") === -1) {
         return { error: "no Parity bits row in the result panel" };
       }
       if (bodyText.indexOf("01101001 10") === -1) {
         return { error: "the Parity bits row does not spell out 01101001 10" };
       }

       /*
        * And the working, which is a second MonoBlock under the fields and its own contract member.
        *
        * A block that renders empty, or renders the value again, is invisible to a typecheck and to
        * the node suite -- the string is identical either way. So this reads the element and requires
        * the heading row and one worked row for the byte 0x30: two ones, so an even parity bit of 0.
        */
       const workingBox = document.querySelector("[data-ocs-working]");
       if (!workingBox) return { error: "the parity result shows no working" };
       const working = workingBox.textContent;
       if (working.indexOf("Even parity bit") === -1) {
         return { error: "the working has no parity-bit column" };
       }
       if (working.indexOf("0x30") === -1 || working.indexOf("0011 0000") === -1) {
         return { error: "the working does not show 0x30 as 0011 0000" };
       }
       // Eleven lines: a heading and one row per input byte.
       if (working.split(String.fromCharCode(10)).length !== 11) {
         return {
           error: "the working has " + working.split(String.fromCharCode(10)).length + " lines, not 11",
         };
       }

       /*
        * And the parity tool keeps it: its bits are a deterministic byte output somebody can hold a
        * copy of. This is the other half of the same assertion -- a flag that hid the panel everywhere
        * would pass the check above and be useless.
        */
       if (!document.querySelector("[data-ocs-verify]")) {
         return { error: "the parity tool offers no Verify panel" };
       }

       const menu = document.querySelector("[data-ocs-output-encoding]");
       if (!menu) return { error: "the parity result offers no output-encoding menu" };
       if (menu.value !== "binary") {
         return { error: "the parity tool opened on " + menu.value + " rather than binary" };
       }
       return { digest: menu.value + "/" + packed.length };
     })()`,
  ) as Promise<ComputeProbe>;
}

/*
 * MD6, and specifically its digest-length dropdown.
 *
 * Three things only a rendered page can show. That the control is a *select* with exactly three
 * options rather than a number field -- MD6 accepts any length from 1 to 512 bits, so a numeric field
 * would be honest and useless, and `outputLengths` is what turns it into a select. That picking one
 * changes the answer, which a control wired to nothing would not. And that MD6 computes at all in the
 * packaged renderer: it is the only tree hash in the app and the only algorithm whose leaf size is 512
 * bytes, so its chunk of the hash family is new ground for the app:// loader.
 *
 * MD6-512 of "abc" is the value in tests/vectors.ts, from Rivest's reference implementation. Note the
 * plain comment and the absent backticks: this is inside a template literal.
 */
function checkMd6(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       const settle = async (test, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         let last = "";
         while (Date.now() < deadline) {
           await sleep(100);
           last = (document.querySelector(SETTLED)?.textContent ?? "").replace(/[^0-9a-fA-F]/g, "").toLowerCase();
           if (test(last)) return { value: last };
         }
         return { last };
       };

       /*
        * The sidebar renders the catalogue in order, so MD6 has to come after MD5 rather than before
        * it. Reported once, because it was inserted ahead of the md5 entry: the tools were listed 2, 4,
        * 6, 5. Reading the rendered order is the only way to see that -- the unit suite checks the same
        * thing through the variants table, which is the same catalogue but not the same rendering.
        */
       const order = Array.from(document.querySelectorAll("[data-ocs-tool]"))
         .map((el) => el.getAttribute("data-ocs-tool"))
         .filter((id) => id === "md2" || id === "md4" || id === "md5" || id === "md6");
       if (order.join(",") !== "md2,md4,md5,md6") {
         return { error: "the MD tools are listed as " + order.join(",") };
       }

       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let button = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         button = document.querySelector('[data-ocs-tool="md6"]') || button;
         if (document.querySelector('[data-ocs-tool="md6"][aria-current="true"]')) break;
         if (button) button.click();
         await sleep(100);
       }
       if (!button) return { error: "md6 is not listed in the sidebar" };
       if (!(await waitFor('[data-ocs-tool="md6"][aria-current="true"]', 10000))) {
         return { error: "clicking md6 did not select it" };
       }

       const box = await waitFor("[data-ocs-input]", 10000);
       if (!box) return { error: "md6 has no input box" };
       Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set.call(box, "abc");
       box.dispatchEvent(new Event("input", { bubbles: true }));

       /*
        * A select with three options, not a number field. MD6 takes any d from 1 to 512 bits, so the
        * numeric control would accept 137 -- a value nothing has ever published a digest for.
        */
       const select = await waitFor('[data-ocs-option="outputLength"] select', 10000);
       if (!select) {
         const numeric = document.querySelector('[data-ocs-option="outputLength"] input');
         return {
           error: numeric
             ? "md6 offers a number field for the digest length, not a select"
             : "md6 offers no digest-length control",
         };
       }
       const offered = Array.from(select.options).map((o) => o.value).filter((v) => v !== "");
       if (offered.join(",") !== "16,32,64") {
         return { error: "the digest lengths offered are " + offered.join(",") + ", not 16,32,64" };
       }

       const setSelect = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set;
       setSelect.call(select, "64");
       select.dispatchEvent(new Event("change", { bubbles: true }));

       const long = await settle((t) => t.length === 128, 20000);
       if (!long.value) {
         return { error: 'MD6-512 of abc did not appear; the panel showed "' + long.last + '"' };
       }
       const expected =
         "00918245271e377a7ffb202b90f3bda5477d8feab12d8a3a8994ebc55fe6e74c" +
         "a8341520032eeea3fdef892f2882378f636212af4b2683ccf80bf025b7d9b457";
       if (long.value !== expected) {
         return { error: "MD6-512 of abc came back as " + long.value };
       }

       /*
        * And the control is load-bearing: 128 bits is a different function, not a prefix. If the
        * select were wired to nothing this would still be the 512-bit digest.
        */
       setSelect.call(select, "16");
       select.dispatchEvent(new Event("change", { bubbles: true }));
       const short = await settle((t) => t.length === 32, 20000);
       if (!short.value) {
         return { error: 'MD6-128 did not appear; the panel showed "' + short.last + '"' };
       }
       if (short.value !== "8db50d79cf42fe7d1807ebaa15329c61") {
         return { error: "MD6-128 of abc came back as " + short.value };
       }
       if (expected.slice(0, 32) === short.value) {
         return { error: "MD6-128 is a prefix of MD6-512, which it must not be" };
       }
       return { digest: short.value };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Drives Quark's instance select, which is the first control in the app whose value decides the
 * *digest width* rather than a parameter of one.
 *
 * `variantOutputLen` is a new mechanism, and "a control that renders and reaches nothing" is the
 * defect this repo has shipped most often -- AEGIS's 256-bit tag length was inert with a green suite,
 * the MAC family had four such controls at once, and the `(not set)` placeholder survived two rounds of
 * unit tests. None of those were visible to a typecheck, a build or the node suite, because every one
 * of them was reached by writing option values straight into a spec, which is a shape the form never
 * produces when the wiring is broken.
 *
 * What is asserted is the *width*, not a published digest, and that is deliberate: the only published
 * Quark values are for the empty message, and a hash tool with an empty input correctly computes
 * nothing at all -- so pinning them here would mean defeating that guard to test something the unit
 * suite already covers through `DIGEST_VECTORS`, which carries both u-Quark's and c-Quark's own
 * self-test values.
 *
 * Be precise about what this does and does not catch, because it was checked rather than assumed. It
 * catches a select that renders and reaches nothing -- remove the option from the catalogue, or stop
 * the resolver passing it to the binding, and the width never moves off 34. It does *not* catch
 * `variantOutputLen` returning undefined: the rendered digest is the binding's answer, and the binding
 * reads the variant itself, so the bytes stay right while the tool header's claimed length goes wrong.
 * That disagreement is what "resolveOutputLen agrees with compute under every named variant" in
 * `tests/hash.test.ts` is for; this probe was run against a broken `variantOutputLen` and passed, which
 * is how the gap was found and why that test exists.
 */
function checkQuarkVariant(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       const settle = async (test, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         let last = "";
         while (Date.now() < deadline) {
           await sleep(100);
           last = (document.querySelector(SETTLED)?.textContent ?? "").replace(/[^0-9a-fA-F]/g, "");
           if (test(last)) return { value: last };
         }
         return { last };
       };

       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let button = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         button = document.querySelector('[data-ocs-tool="quark"]') || button;
         if (document.querySelector('[data-ocs-tool="quark"][aria-current="true"]')) break;
         if (button) button.click();
         await sleep(100);
       }
       if (!button) return { error: "quark is not listed in the sidebar" };
       if (!(await waitFor('[data-ocs-tool="quark"][aria-current="true"]', 10000))) {
         return { error: "clicking quark did not select it" };
       }

       const box = await waitFor("[data-ocs-input]", 10000);
       if (!box) return { error: "quark has no input box" };
       Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set.call(box, "abc");
       box.dispatchEvent(new Event("input", { bubbles: true }));

       const select = await waitFor('[data-ocs-option="hashVariant"] select', 10000);
       if (!select) return { error: "quark offers no instance control" };
       const offered = Array.from(select.options).map((o) => o.value).filter((v) => v !== "");
       if (offered.join(",") !== "u-quark,d-quark,s-quark,c-quark") {
         return { error: "the instances offered are " + offered.join(",") };
       }
       /*
        * There must be no enabled empty option and the select must not be resting on one -- the same
        * condition checkNoUnsetChoice enforces app-wide, asserted here too because this select is
        * seeded from a new code path. Note a backtick may not appear in this comment: the whole body
        * is a template literal, so one would close it.
        */
       const unset = Array.from(select.options).find((o) => o.value === "" && !o.disabled);
       if (unset) return { error: "the instance select offers an enabled (not set) option" };
       if (select.value === "") return { error: "the instance select is resting on (not set)" };

       /* u-Quark: 17 bytes, so 34 hex characters. */
       const short = await settle((t) => t.length === 34, 30000);
       if (!short.value) {
         return { error: 'u-Quark did not settle at 17 bytes; the panel showed "' + short.last + '"' };
       }

       const setSelect = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set;
       setSelect.call(select, "c-quark");
       select.dispatchEvent(new Event("change", { bubbles: true }));

       /* c-Quark: 48 bytes, so 96. A select wired to nothing would still show 34. */
       const long = await settle((t) => t.length === 96, 30000);
       if (!long.value) {
         return { error: 'c-Quark did not settle at 48 bytes; the panel showed "' + long.last + '"' };
       }
       if (long.value.slice(0, 34) === short.value) {
         return { error: "c-Quark begins with u-Quark's digest, which it must not" };
       }
       return { digest: short.value + "/" + long.value.length };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Computes an FSB digest in the packaged renderer, which is really a test of its 266 KB pi table.
 *
 * FSB carries the only large committed data blob in `packages/algos` -- 363 KB of base64 that decodes to
 * the parity of pi's first 2,179,072 fractional digits -- and it is decoded by a hand-written base64
 * reader rather than `atob`, because that package is free of platform globals. None of that is visible to
 * the unit suite in a way that matters: vitest runs the same module under Node with no bundler in the
 * way, so a chunk that fails to resolve over `app://`, or a minifier that mangled a 2,838-entry array
 * literal, would pass every test and break the packaged app.
 *
 * The same reasoning already puts the Shift_JIS and Streebog probes in this file. This one is the
 * largest table of the three.
 *
 * The expected value is this repo's own -- FSB has no published digest, which its metadata says at
 * length. What the probe establishes is that the packaged renderer computes the *same* thing the unit
 * suite does, which is precisely the chunk-loading and minification question.
 */
function checkFsbTable(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       const settle = async (test, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         let last = "";
         while (Date.now() < deadline) {
           await sleep(100);
           last = (document.querySelector(SETTLED)?.textContent ?? "").replace(/[^0-9a-fA-F]/g, "").toLowerCase();
           if (test(last)) return { value: last };
         }
         return { last };
       };

       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let button = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         button = document.querySelector('[data-ocs-tool="fsb"]') || button;
         if (document.querySelector('[data-ocs-tool="fsb"][aria-current="true"]')) break;
         if (button) button.click();
         await sleep(100);
       }
       if (!button) return { error: "fsb is not listed in the sidebar" };
       if (!(await waitFor('[data-ocs-tool="fsb"][aria-current="true"]', 10000))) {
         return { error: "clicking fsb did not select it" };
       }

       const box = await waitFor("[data-ocs-input]", 10000);
       if (!box) return { error: "fsb has no input box" };
       Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set.call(box, "abc");
       box.dispatchEvent(new Event("input", { bubbles: true }));

       const select = await waitFor('[data-ocs-option="outputLength"] select', 10000);
       if (!select) return { error: "fsb offers no digest-length control" };
       const offered = Array.from(select.options).map((o) => o.value).filter((v) => v !== "");
       if (offered.join(",") !== "20,28,32,48,64") {
         return { error: "the digest lengths offered are " + offered.join(",") };
       }

       const setSelect = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set;
       setSelect.call(select, "20");
       select.dispatchEvent(new Event("change", { bubbles: true }));

       /* FSB-160 of "abc". Wrong by one bit anywhere in the table and this is unrecognisable. */
       const settled = await settle((t) => t.length === 40, 30000);
       if (!settled.value) {
         return { error: 'FSB-160 did not settle at 20 bytes; the panel showed ' + settled.last };
       }
       if (settled.value !== "c93c6cbd9f9a7d35fcd02d0e9822bd8589854aef") {
         return { error: "FSB-160 of abc came back as " + settled.value };
       }
       return { digest: settled.value };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Drives rapidhash's version dropdown, whose four entries are four different *functions*.
 *
 * The input is three bytes on purpose. rapidhash v2.0 and v2.2 differ in only three places, and at most
 * lengths they agree -- 1 to 3 bytes and 49 to 64 are the only ranges where all four versions disagree.
 * So a three-byte message is the shortest input for which four distinct digests prove the select
 * actually reaches the binding; at thirteen bytes two of the four would match on a control wired to
 * nothing.
 *
 * Unlike `checkQuarkVariant` this cannot be fooled by the binding reading the variant itself, because
 * the assertion is that the *values* differ rather than that a length changed.
 *
 * It also checks a second thing for free, and worth knowing before anyone "corrects" the expected
 * values. The seed field is left empty, so each version applies its *own* default -- and v1.0's is
 * `0xbdd89aa982704029` rather than zero. Its digest here is therefore `9c9e7860c5c4e179`, which is the
 * published value for that seed, not the `f8098dcbc713bb50` the unit tests assert at an explicit zero.
 * Both are correct; if this probe ever reports v1.0 agreeing with the unit test's value, the
 * empty-means-default path in `compute.ts` has broken.
 */
function checkRapidhashVersion(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       const settle = async (test, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         let last = "";
         while (Date.now() < deadline) {
           await sleep(100);
           last = (document.querySelector(SETTLED)?.textContent ?? "").replace(/[^0-9a-fA-F]/g, "").toLowerCase();
           if (test(last)) return { value: last };
         }
         return { last };
       };

       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let button = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         button = document.querySelector('[data-ocs-tool="rapidhash"]') || button;
         if (document.querySelector('[data-ocs-tool="rapidhash"][aria-current="true"]')) break;
         if (button) button.click();
         await sleep(100);
       }
       if (!button) return { error: "rapidhash is not listed in the sidebar" };
       if (!(await waitFor('[data-ocs-tool="rapidhash"][aria-current="true"]', 10000))) {
         return { error: "clicking rapidhash did not select it" };
       }

       const box = await waitFor("[data-ocs-input]", 10000);
       if (!box) return { error: "rapidhash has no input box" };
       Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set.call(box, "123");
       box.dispatchEvent(new Event("input", { bubbles: true }));

       const select = await waitFor('[data-ocs-option="hashVariant"] select', 10000);
       if (!select) return { error: "rapidhash offers no version control" };
       const offered = Array.from(select.options).map((o) => o.value).filter((v) => v !== "");
       if (offered.join(",") !== "v1.0,v2.0,v2.2,v3.0") {
         return { error: "the versions offered are " + offered.join(",") };
       }
       if (select.value === "") return { error: "the version select is resting on (not set)" };
       if (Array.from(select.options).some((o) => o.value === "" && !o.disabled)) {
         return { error: "the version select offers an enabled (not set) option" };
       }

       /*
        * Waits for each version's *exact* expected digest rather than for "a value different from the
        * last one", and that is a correction rather than a refinement.
        *
        * The difference-based version was racy and flaked: with the select starting on v3.0, the first
        * iteration could accept the stale v3.0 digest still on screen as v1.0's answer, shifting every
        * recorded value by one -- and then the final iteration waited forever for v3.0's digest to
        * differ from v3.0's digest. It passed or failed on timing. Pinning the values removes the race
        * and checks more: that each version computes the right answer, not merely a different one.
        *
        * These are the digests of "123" with the Seed field left **empty**, so each version applies its
        * own default seed. v1.0's default is 0xbdd89aa982704029, which is why its value here is not the
        * f8098dcbc713bb50 the unit tests assert at an explicit zero -- see the note above.
        */
       const EXPECTED = {
         "v1.0": "9c9e7860c5c4e179",
         "v2.0": "366cd8137a946e51",
         "v2.2": "4ff17d290a897c99",
         "v3.0": "bbb9e0e685c2bf69",
       };
       const setSelect = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set;
       const seen = {};
       for (const version of offered) {
         const want = EXPECTED[version];
         if (!want) return { error: "no expected digest recorded for " + version };
         setSelect.call(select, version);
         select.dispatchEvent(new Event("change", { bubbles: true }));
         const settled = await settle((t) => t === want, 20000);
         if (!settled.value) {
           return {
             /*
              * Says *why* it did not settle, not just what it showed.
              *
              * An empty value is ambiguous on its own: it means either that no result reached the
              * done status inside the budget, or that the text held nothing this probe's filter
              * keeps. Reporting the status attribute and the raw text separates the two, which is
              * what turned an intermittent failure here into something diagnosable rather than a
              * shrug.
              */
             error:
               version +
               " expected " +
               want +
               " but the panel showed " +
               JSON.stringify(settled.last) +
               " (status=" +
               JSON.stringify(
                 document.querySelector("[data-ocs-result]")?.getAttribute("data-ocs-status") ?? null,
               ) +
               ", raw=" +
               JSON.stringify(
                 (document.querySelector("[data-ocs-result]")?.textContent ?? "").slice(0, 60),
               ) +
               ", select=" +
               JSON.stringify(select.value) +
               ")",
           };
         }
         seen[version] = settled.value;
       }
       const values = offered.map((v) => seen[v]);
       if (new Set(values).size !== 4) {
         return { error: "the four versions produced " + new Set(values).size + " distinct digests: " + values.join(" ") };
       }
       return { digest: values.join("/") };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Formats a JSON document and then derives a UUIDv5, both in the packaged renderer.
 *
 * The format family is the only one in the app whose work is done by third-party libraries --
 * `jsonc-parser`, `@xmldom/xmldom`, `entities`, `uuid` and `change-case`, all in one lazily-imported
 * chunk. That is exactly the arrangement nothing else here can check: the unit suite runs those
 * libraries under Node's resolver with no bundler in the way, and a typecheck and a build would both
 * pass on a chunk that fails to resolve over `app://` or whose CommonJS interop broke in production.
 *
 * Two steps rather than one, because they fail differently. The JSON half reads the input panel and
 * proves the chunk loaded at all. The UUID half drives two option controls on a tool that reads *no*
 * input and pins RFC 9562's own v5 of `www.example.com` in the DNS namespace -- a published value, so
 * a wrong answer is a real failure rather than a drift from something this repo produced itself.
 */
function checkFormatFamily(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };
       const settle = async (test, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         let last = "";
         while (Date.now() < deadline) {
           await sleep(100);
           last = document.querySelector(SETTLED)?.textContent ?? "";
           if (test(last)) return { value: last };
         }
         return { last };
       };
       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered, so a tool switch remounts its rows. A probe that queries the
        * row, then clicks it, can hold a node React replaced in between -- the click goes to a
        * detached element and does nothing, which is the same defect the Auto update probe hit and is
        * recorded in CLAUDE.md. Both spellings of it flaked here: "parity is not listed in the
        * sidebar" when the query lost the race, and "clicking fsb did not select it" when the click
        * did. Retrying a fresh query removes the race instead of widening the window, and the two
        * failure messages stay distinct so a genuinely missing tool still reads as missing.
        */
       const open = async (id) => {
         const selector = '[data-ocs-tool="' + id + '"]';
         const deadline = Date.now() + 15000;
         let everSeen = false;
         while (Date.now() < deadline) {
           const button = document.querySelector(selector);
           if (!button) {
             await sleep(100);
             continue;
           }
           everSeen = true;
           button.click();
           if (await waitFor(selector + '[aria-current="true"]', 2000)) return null;
         }
         if (!everSeen) return id + " is not listed in the sidebar";
         return "clicking " + id + " did not select it";
       };
       // A double quote by code point, for the same reason as the note on the JSON assertion below.
       const quote = String.fromCharCode(34);
       const setSelect = (element, value) => {
         Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(
           element,
           value,
         );
         element.dispatchEvent(new Event("change", { bubbles: true }));
       };

       let problem = await open("json");
       if (problem) return { error: problem };

       // Earlier probes leave the input encoding wherever they left it, and a document read as
       // Shift_JIS would fail to parse for a reason that has nothing to do with this family.
       const encoding = document.querySelector("[data-ocs-input-encoding]");
       if (encoding) setSelect(encoding, "utf-8");

       const input = await waitFor("[data-ocs-input]", 10000);
       if (!input) return { error: "no input panel" };
       Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set.call(
         input,
         '{"b":1.0,"a":[1,2]}',
       );
       input.dispatchEvent(new Event("input", { bubbles: true }));

       // Whitespace-insensitive: this is checking that the library ran and that the scalar came back
       // verbatim, not the exact indentation, which the unit suite pins to the character.
       // No regex here on purpose: a backslash inside this template literal is dropped before it
       // reaches the renderer, so a character class becomes an unterminated expression at runtime --
       // while every typecheck and lint passes. The same hazard as the backticks warned about above.
       const formatted = await settle((text) => text.includes(quote + "a" + quote + ":"), 20000);
       if (!formatted.value) {
         return { error: 'JSON did not format; the panel showed "' + formatted.last + '"' };
       }
       // 1.0 rather than 1 is the whole reason this family uses a parse tree instead of JSON.parse.
       if (!formatted.value.includes("1.0")) {
         return { error: "the formatter rewrote 1.0; the panel showed " + formatted.value };
       }

       /*
        * No Verify panel on a format tool, which only a rendered page can show.
        *
        * VerifyPanel compares result.bytes, and every tool in this family returns text -- so before
        * supportsVerify existed it rendered a box asking for an expected digest that could never say
        * anything either way. The panel is collapsible, so the heading is what to look for.
        */
       if (document.querySelector("[data-ocs-verify]")) {
         return { error: "json offers a Verify panel, which cannot compare a document" };
       }

       problem = await open("uuid");
       if (problem) return { error: problem };

       /*
        * The generator has no input box, and nothing but a packaged probe can see that.
        *
        * uuidResult ignores its input argument entirely, so the textarea that used to sit above
        * these controls was read by nothing -- it invited someone to type and then discarded it,
        * which is indistinguishable from the tool being broken. readsInput:false on the manifest
        * removes the whole byte-source half of the panel; a typecheck and the unit suite both pass
        * either way, so the absence is asserted here. Note the plain comment and the absent
        * backticks: this is inside a template literal, and one backtick ends the whole probe.
        */
       if (document.querySelector("[data-ocs-input]")) {
         return { error: "uuid still renders an input box, which nothing reads" };
       }
       if (document.querySelector("[data-ocs-input-mode]")) {
         return { error: "uuid still renders a byte-source selector" };
       }
       /*
        * And no Auto update switch, whose hint reads "recompute after you stop typing" over a panel
        * with no box in it. The workbench forces the behaviour on for a generator rather than leaving a
        * hidden switch deciding whether a UUID appears -- so the Generate button has to be here
        * permanently, which is the other half of the same assertion. A flag that hid both would pass
        * the first check and leave the tool with no way to produce anything.
        */
       if (document.querySelector('[data-ocs-toggle="auto-update"]')) {
         return { error: "uuid still offers the Auto update switch" };
       }
       if (!document.querySelector("[data-ocs-compute]")) {
         return { error: "uuid offers no Generate button" };
       }

       const version = document.querySelector('[data-ocs-option="uuidVersion"] select');
       if (!version) return { error: "no UUID version control" };
       setSelect(version, "v5");

       const namespace = await waitFor('[data-ocs-option="uuidNamespace"] select', 10000);
       if (!namespace) return { error: "no UUID namespace control" };
       setSelect(namespace, "dns");

       // Revealed by the version being v3 or v5, which is the availableOn tag doing its job.
       const name = await waitFor('[data-ocs-option="uuidName"] textarea, [data-ocs-option="uuidName"] input', 10000);
       if (!name) return { error: "the name field did not appear for v5" };
       const prototype = name instanceof HTMLTextAreaElement ? HTMLTextAreaElement : HTMLInputElement;
       Object.getOwnPropertyDescriptor(prototype.prototype, "value").set.call(
         name,
         "www.example.com",
       );
       name.dispatchEvent(new Event("input", { bubbles: true }));

       const uuid = await settle(
         (text) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(text.trim()),
         20000,
       );
       if (!uuid.value) {
         return { error: 'no UUID appeared; the panel showed "' + uuid.last + '"' };
       }
       return { digest: uuid.value.trim() };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Generates an ML-DSA-65 keypair in the packaged renderer.
 *
 * `@noble/post-quantum` is the largest single dependency this app pulls in, and it lands in the
 * public-key family's lazily-imported chunk. The unit suite proves the algorithms are right --
 * `tests/postquantum-parity.test.ts` checks all eighteen parameter sets against OpenSSL 3.5 in both
 * directions -- so what is left, and what nothing else can see, is whether that chunk resolves over
 * `app://` and whether its module-level initialisation survives the production build.
 *
 * This asserts a *length* rather than a value, deliberately. Keygen is randomised, so there is no
 * fixed answer to compare; a 1952-byte public key means the parameter set was read, the keygen ran,
 * and the result reached the panel. Pinning a value would mean pasting a 4032-byte private key and a
 * 3309-byte signature into this string, which buys nothing the parity test has not already bought.
 */
function checkPostQuantum(window: BrowserWindow): Promise<ComputeProbe> {
  return window.webContents.executeJavaScript(
    `(async () => {
       const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
       const SETTLED = '[data-ocs-result][data-ocs-status="done"]';
       const waitFor = async (selector, budgetMs) => {
         const deadline = Date.now() + budgetMs;
         for (;;) {
           const found = document.querySelector(selector);
           if (found) return found;
           if (Date.now() > deadline) return null;
           await sleep(100);
         }
       };

       /*
        * Re-queried on every attempt rather than found once and clicked.
        *
        * The sidebar is client-rendered and a tool switch remounts its rows, so both halves of
        * query-then-click can lose the race: the query reports a tool missing from a list it is
        * plainly in, and the click reaches a node React already replaced and does nothing. Both
        * spellings flaked here, on parity, fsb and mldsa. The message below is unchanged, so a
        * genuinely absent tool still reads as absent.
        */
       let button = null;
       for (let attempt = 0; attempt < 60; attempt++) {
         // Assigned before the break test, not after: a tool an earlier probe left already
         // selected must still record its row here, or the check below reports it missing from a
         // sidebar it is sitting in. That shipped for one run and failed deterministically.
         button = document.querySelector('[data-ocs-tool="mldsa"]') || button;
         if (document.querySelector('[data-ocs-tool="mldsa"][aria-current="true"]')) break;
         if (button) button.click();
         await sleep(100);
       }
       if (!button) return { error: "the mldsa tool is not listed in the sidebar" };
       if (!(await waitFor('[data-ocs-tool="mldsa"][aria-current="true"]', 10000))) {
         return { error: "clicking mldsa did not select it" };
       }

       // The parameter-set control only exists once the family's chunk has loaded, so finding it is
       // half of what this probe is for.
       const paramSet = await waitFor('[data-ocs-option="paramSet"] select', 15000);
       if (!paramSet) return { error: "the ML-DSA options form never rendered" };
       Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(
         paramSet,
         "65",
       );
       paramSet.dispatchEvent(new Event("change", { bubbles: true }));

       const deadline = Date.now() + 20000;
       let last = 0;
       while (Date.now() < deadline) {
         await sleep(100);
         const hex = (document.querySelector(SETTLED)?.textContent ?? "").replace(
           /[^0-9a-fA-F]/g,
           "",
         );
         last = hex.length;
         // 1952 bytes, which is ML-DSA-65's public key and nothing else in this app's output.
         if (last === 3904) return { digest: String(last) };
       }
       return { error: 'no ML-DSA public key appeared; the panel showed ' + last + ' hex characters' };
     })()`,
  ) as Promise<ComputeProbe>;
}

/**
 * Requires an outbound request from the packaged renderer to fail.
 *
 * The app's headline claim is that nothing you type leaves the machine, and two independent
 * mechanisms back it: `connect-src 'self'` in the CSP, and the session-level block in `window.ts`.
 * Neither was tested until now -- which is how the block came to be scoped wrongly in the first
 * place, and it would be equally easy for the CSP header to go missing from a new response path in
 * `protocol.handle` without anything noticing.
 *
 * Deliberately a *reachable* host rather than a made-up one: a DNS failure would pass this test
 * for the wrong reason. If the block and the CSP were both removed, this fetch would succeed and
 * the probe would fail, which is exactly the coupling wanted.
 */
function checkNoOutbound(
  window: BrowserWindow,
): Promise<{ blocked?: boolean; detail?: string }> {
  return window.webContents.executeJavaScript(
    `(async () => {
       try {
         const response = await fetch("https://example.com/", { cache: "no-store" });
         return { blocked: false, detail: "fetch resolved with status " + response.status };
       } catch (error) {
         return { blocked: true, detail: String(error && error.message ? error.message : error) };
       }
     })()`,
  ) as Promise<{ blocked?: boolean; detail?: string }>;
}

export function runSmokeTest(window: BrowserWindow): void {
  const consoleErrors: string[] = [];
  window.webContents.on("console-message", (event) => {
    if (event.level === "error" || event.level === "warning") consoleErrors.push(event.message);
  });

  /*
   * Idempotent, because `app.exit()` does not stop the promise chain that called `fail()` -- every
   * `.then()` after the failing step still runs, against a window mid-teardown, and throws "Object has
   * been destroyed". That throw lands in a wrapping `.catch()` which calls `fail()` again with a
   * message about whatever step happened to be running when the window died, unrelated to the real
   * failure. The first call is the true one; every call after it is exactly that cascade and is
   * dropped rather than printed.
   */
  let failed = false;
  const fail = (reason: string): void => {
    if (failed) return;
    failed = true;
    process.stderr.write(`SMOKE FAIL: ${reason}\n`);
    if (consoleErrors.length > 0) {
      process.stderr.write(`SMOKE CONSOLE: ${JSON.stringify(consoleErrors, null, 2)}\n`);
    }
    app.exit(1);
  };

  const timeout = setTimeout(() => fail("renderer did not finish loading within 30s"), 30_000);

  window.webContents.on("did-fail-load", (_event, code, description, url) => {
    clearTimeout(timeout);
    fail(`did-fail-load ${code} ${description} for ${url}`);
  });

  window.webContents.on("did-finish-load", () => {
    void window.webContents
      .executeJavaScript(
        `(() => ({
           url: location.href,
           title: document.title,
           hasMain: !!document.querySelector("main"),
           hasSidebar: !!document.querySelector("nav"),
           bridge: typeof window.openCipherSuite === "object",
           nodeLeaked: typeof window.require !== "undefined" || typeof window.process !== "undefined",
           subtleCrypto: typeof crypto !== "undefined" && typeof crypto.subtle === "object",
           getRandomValues: typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function",
           textLength: document.body ? document.body.innerText.length : 0,
         }))()`,
      )
      .then((result: Record<string, unknown>) => {
        clearTimeout(timeout);

        const menu = Menu.getApplicationMenu();
        const shell = {
          appName: app.getName(),
          windowTitle: window.getTitle(),
          iconResolved: appIcon() ?? null,
          menuBarVisible: window.isMenuBarVisible(),
          menus: menu ? menu.items.map((i) => i.label).filter(Boolean) : [],
          // Named rather than counted: Help held two external links to third-party sites, which is
          // the only thing in this app that ever reached the internet.
          helpItems:
            menu?.items
              .find((i) => i.label === "&Help")
              ?.submenu?.items.map((i) => i.label)
              .filter(Boolean) ?? [],
          devToolsOpen: window.webContents.isDevToolsOpened(),
        };

        process.stdout.write(`SMOKE RESULT: ${JSON.stringify(result, null, 2)}\n`);
        process.stdout.write(`SMOKE SHELL: ${JSON.stringify(shell, null, 2)}\n`);

        if (shell.helpItems.length !== 1 || !shell.helpItems[0]?.startsWith("About")) {
          return fail(
            `Help should hold About and nothing else; it holds ${JSON.stringify(shell.helpItems)}`,
          );
        }

        // Only things that are genuinely true the moment the document finishes
        // loading. Anything behind a dynamic import is checked by `checkCompute`,
        // which waits for it.
        if (!result.hasMain) return fail("no <main> element — React did not mount");
        if (!result.hasSidebar) return fail("no tool list rendered");
        if (!result.bridge) return fail("window.openCipherSuite missing — preload did not run");
        if (result.nodeLeaked) return fail("node globals leaked into the renderer");
        // Both are gated on a secure context. If the renderer were ever served over
        // file:// instead of app://, these would be the first things to vanish — and
        // half the algorithms in this app would stop working.
        if (!result.getRandomValues) {
          return fail(
            "crypto.getRandomValues unavailable — the renderer is not a secure context",
          );
        }
        if (!result.subtleCrypto) {
          return fail("crypto.subtle unavailable — the renderer is not a secure context");
        }
        if (shell.devToolsOpen)
          return fail("DevTools opened by default — this is not a browser");
        if (shell.appName !== "Cipher Workbench") {
          return fail(`app name is "${shell.appName}", expected the product name`);
        }

        return checkSeededInput(window)
          .then((seedProbe) => {
            process.stdout.write(`SMOKE SEED: ${JSON.stringify(seedProbe, null, 2)}
`);
            if (seedProbe.error) return fail(`seeded input: ${seedProbe.error}`);
            return null;
          })
          .then(() => checkCompute(window))
          .then((probe) => {
            process.stdout.write(`SMOKE COMPUTE: ${JSON.stringify(probe, null, 2)}\n`);
            if (consoleErrors.length > 0) {
              process.stdout.write(
                `SMOKE CONSOLE: ${JSON.stringify(consoleErrors, null, 2)}\n`,
              );
            }

            if (probe.error) {
              const csp = consoleErrors.some((m) => /Content Security Policy/i.test(m));
              return fail(
                `compute probe failed: ${probe.error}` +
                  (csp ? " (CSP blocked a script — check protocol.ts's inline hashes)" : ""),
              );
            }
            if (probe.digest !== SHA256_ABC) {
              return fail(
                `SHA-256("abc") came back as ${probe.digest}, expected ${SHA256_ABC}`,
              );
            }

            return checkFileCompute(window)
              .then((fileProbe) => {
                process.stdout.write(`SMOKE FILE: ${JSON.stringify(fileProbe, null, 2)}\n`);

                if (fileProbe.error) return fail(`file probe failed: ${fileProbe.error}`);
                if (fileProbe.digest !== SHA256_ABC) {
                  return fail(
                    `hashing a 3-byte file gave ${fileProbe.digest}, expected ${SHA256_ABC} — the streaming path disagrees with the one-shot path`,
                  );
                }

                // The fallback is silent by design, so its warning is the only
                // evidence that the worker did not start. A correct digest alone
                // does not prove the worker ran.
                const fellBack = consoleErrors.some((m) =>
                  /Falling back to main-thread hashing/.test(m),
                );
                if (fellBack) {
                  return fail(
                    "the compute worker failed to start and hashing fell back to the main thread — check that the web build ran with --webpack (Turbopack emits the worker as an unusable raw .ts asset)",
                  );
                }

                return checkToolSwitch(window)
                  .then((switchProbe) => {
                    process.stdout.write(
                      `SMOKE SWITCH: ${JSON.stringify(switchProbe, null, 2)}\n`,
                    );

                    if (switchProbe.error)
                      return fail(`tool switch failed: ${switchProbe.error}`);
                    if (switchProbe.digest !== CRC32_CHECK) {
                      return fail(
                        `CRC-32 of "123456789" gave ${switchProbe.digest}, expected ${CRC32_CHECK}`,
                      );
                    }

                    return (
                      checkChecksumFamily(window)
                        .then((sumProbe) => {
                          process.stdout.write(
                            `SMOKE CHECKSUM: ${JSON.stringify(sumProbe, null, 2)}\n`,
                          );

                          if (sumProbe.error)
                            return fail(`checksum family probe failed: ${sumProbe.error}`);
                          const expected = `${SUM8_CHECK}/${SUM16_CHECK}`;
                          if (sumProbe.digest !== expected) {
                            return fail(
                              `the sum of "123456789" gave ${sumProbe.digest}, expected ${expected}`,
                            );
                          }
                        })
                        // A separate link rather than a nested chain: `fail` calls `app.exit(1)`, so
                        // a failed check above never reaches this, and keeping the Ed25519 block's
                        // shape untouched is worth more than symmetry with the older probes.
                        .then(() => checkSettingsLayout(window))
                        .then((settingsProbe) => {
                          process.stdout.write(
                            `SMOKE SETTINGS: ${JSON.stringify(settingsProbe, null, 2)}\n`,
                          );
                          if (settingsProbe.error)
                            return fail(`settings layout: ${settingsProbe.error}`);
                          return null;
                        })
                        .then(() => checkHexPrefix(window))
                        .then((prefixProbe) => {
                          process.stdout.write(
                            `SMOKE HEX PREFIX: ${JSON.stringify(prefixProbe, null, 2)}\n`,
                          );
                          if (prefixProbe.error)
                            return fail(`hex prefix: ${prefixProbe.error}`);
                          return null;
                        })
                        .then(() => checkLookupTable(window))
                        .then((tableProbe) => {
                          process.stdout.write(
                            `SMOKE TABLE: ${JSON.stringify(tableProbe, null, 2)}\n`,
                          );
                          if (tableProbe.error)
                            return fail(`lookup table: ${tableProbe.error}`);
                          return null;
                        })
                        .then(() => checkVariants(window))
                        .then((variantsProbe) => {
                          process.stdout.write(
                            `SMOKE VARIANTS: ${JSON.stringify(variantsProbe, null, 2)}
`,
                          );
                          if (variantsProbe.error)
                            return fail(`variants: ${variantsProbe.error}`);
                          return null;
                        })
                        .then(() => checkManualCompute(window))
                        .then((manualProbe) => {
                          process.stdout.write(
                            `SMOKE MANUAL: ${JSON.stringify(manualProbe, null, 2)}\n`,
                          );
                          if (manualProbe.error)
                            return fail(`manual compute: ${manualProbe.error}`);
                          return null;
                        })
                        .then(() => checkAesKeySize(window))
                        .then((aesProbe) => {
                          process.stdout.write(
                            `SMOKE AES SIZES: ${JSON.stringify(aesProbe, null, 2)}\n`,
                          );
                          if (aesProbe.error) return fail(`aes sizes: ${aesProbe.error}`);
                          return null;
                        })
                        .then(() => checkPadding(window))
                        .then((padProbe) => {
                          process.stdout.write(
                            `SMOKE PADDING: ${JSON.stringify(padProbe, null, 2)}
`,
                          );
                          if (padProbe.error) return fail(`padding: ${padProbe.error}`);
                          return null;
                        })
                        .then(() => checkKeySource(window))
                        .then((ksProbe) => {
                          process.stdout.write(
                            `SMOKE KEY SOURCE: ${JSON.stringify(ksProbe, null, 2)}
`,
                          );
                          if (ksProbe.error) return fail(`key source: ${ksProbe.error}`);
                          return null;
                        })
                        .then(() => checkCaesar(window))
                        .then((caesarProbe) => {
                          process.stdout.write(
                            `SMOKE CAESAR: ${JSON.stringify(caesarProbe, null, 2)}\n`,
                          );
                          if (caesarProbe.error) return fail(`caesar: ${caesarProbe.error}`);
                          return null;
                        })
                        .then(() => checkRandomTools(window))
                        .then((randomProbe) => {
                          process.stdout.write(
                            `SMOKE RANDOM: ${JSON.stringify(randomProbe, null, 2)}\n`,
                          );
                          if (randomProbe.error) return fail(`random: ${randomProbe.error}`);
                          return null;
                        })
                        .then(() => checkInputCopy(window))
                        .then((copyProbe) => {
                          process.stdout.write(
                            `SMOKE INPUT COPY: ${JSON.stringify(copyProbe, null, 2)}
`,
                          );
                          if (copyProbe.error) return fail(`input copy: ${copyProbe.error}`);
                          return null;
                        })
                        .then(() => checkFooter(window))
                        .then((footerProbe) => {
                          process.stdout.write(
                            `SMOKE FOOTER: ${JSON.stringify(footerProbe, null, 2)}\n`,
                          );
                          if (footerProbe.error) return fail(`footer: ${footerProbe.error}`);
                          return null;
                        })
                        .then(() => checkNoUnsetChoice(window))
                        .then((unsetProbe) => {
                          process.stdout.write(
                            `SMOKE ENUMS: ${JSON.stringify(unsetProbe, null, 2)}\n`,
                          );
                          if (unsetProbe.error)
                            return fail(`enum defaults: ${unsetProbe.error}`);
                          // HAVAL opens on three passes at 256 bits. Pinned because the pass count
                          // is a deliberate choice -- three is what every other implementation
                          // defaults to, even though five is the only unbroken one.
                          if (unsetProbe.digest !== "3/32") {
                            return fail(
                              `HAVAL opened on ${unsetProbe.digest}, expected 3 passes at 32 bytes`,
                            );
                          }
                          return null;
                        })
                        .then(() => checkAboutMenu(window))
                        .then((aboutProbe) => {
                          process.stdout.write(
                            `SMOKE ABOUT: ${JSON.stringify(aboutProbe, null, 2)}\n`,
                          );
                          if (aboutProbe.error)
                            return fail(`Help > About: ${aboutProbe.error}`);
                          return null;
                        })
                        .then(() => checkMd6(window))
                        .then((md6Probe) => {
                          process.stdout.write(`SMOKE MD6: ${JSON.stringify(md6Probe, null, 2)}
`);
                          if (md6Probe.error) return fail(`md6: ${md6Probe.error}`);
                          return null;
                        })
                        .then(() => checkQuarkVariant(window))
                        .then((quarkProbe) => {
                          process.stdout.write(
                            `SMOKE QUARK: ${JSON.stringify(quarkProbe, null, 2)}
`,
                          );
                          if (quarkProbe.error) return fail(`quark: ${quarkProbe.error}`);
                          return null;
                        })
                        .then(() => checkFsbTable(window))
                        .then((fsbProbe) => {
                          process.stdout.write(
                            `SMOKE FSB: ${JSON.stringify(fsbProbe, null, 2)}
`,
                          );
                          if (fsbProbe.error) return fail(`fsb: ${fsbProbe.error}`);
                          return null;
                        })
                        .then(() => checkRapidhashVersion(window))
                        .then((rapidProbe) => {
                          process.stdout.write(
                            `SMOKE RAPIDHASH: ${JSON.stringify(rapidProbe, null, 2)}
`,
                          );
                          if (rapidProbe.error) return fail(`rapidhash: ${rapidProbe.error}`);
                          return null;
                        })
                        .then(() => checkParityFamily(window))
                        .then((parityProbe) => {
                          process.stdout.write(
                            `SMOKE PARITY: ${JSON.stringify(parityProbe, null, 2)}
`,
                          );
                          if (parityProbe.error)
                            return fail(`parity family: ${parityProbe.error}`);
                          return null;
                        })
                        .then(() => checkFormatFamily(window))
                        .then((formatProbe) => {
                          process.stdout.write(
                            `SMOKE FORMAT: ${JSON.stringify(formatProbe, null, 2)}
`,
                          );
                          if (formatProbe.error)
                            return fail(`format family: ${formatProbe.error}`);
                          if (formatProbe.digest !== UUID_V5_EXAMPLE) {
                            return fail(
                              `UUIDv5 of www.example.com in the DNS namespace gave ${formatProbe.digest}, expected ${UUID_V5_EXAMPLE} -- the format family's lazy chunk did not load, or its libraries did not survive the production build`,
                            );
                          }
                          return null;
                        })
                        .then(() => checkAsymmetric(window))
                        .then((keyProbe) => {
                          process.stdout.write(
                            `SMOKE ASYMMETRIC: ${JSON.stringify(keyProbe, null, 2)}\n`,
                          );

                          if (keyProbe.error)
                            return fail(`Ed25519 probe failed: ${keyProbe.error}`);
                          if (keyProbe.digest !== ED25519_SIGNATURE) {
                            return fail(
                              `Ed25519 signed RFC 8032 TEST 2 as ${keyProbe.digest}, expected ${ED25519_SIGNATURE}`,
                            );
                          }

                          return checkLegacyEncoding(window)
                            .then((encProbe) => {
                              process.stdout.write(
                                `SMOKE ENCODING: ${JSON.stringify(encProbe, null, 2)}\n`,
                              );

                              if (encProbe.error) {
                                return fail(`Shift_JIS probe failed: ${encProbe.error}`);
                              }
                              if (encProbe.digest !== SHIFT_JIS_SHA256) {
                                return fail(
                                  `SHA-256 of Shift_JIS 日本語 gave ${encProbe.digest}, expected ${SHIFT_JIS_SHA256} — the encoding tables did not load, or did not apply`,
                                );
                              }

                              return checkStreebog(window)
                                .then((streebogProbe) => {
                                  process.stdout.write(
                                    `SMOKE STREEBOG: ${JSON.stringify(streebogProbe, null, 2)}\n`,
                                  );
                                  if (streebogProbe.error) {
                                    return fail(
                                      `Streebog probe failed: ${streebogProbe.error}`,
                                    );
                                  }
                                  if (streebogProbe.digest !== STREEBOG_256_RFC_EXAMPLE) {
                                    return fail(
                                      `Streebog-256 of RFC 6986's example 1 gave ${streebogProbe.digest}, expected ${STREEBOG_256_RFC_EXAMPLE} — the hash family's lazy chunk did not load, or its derived tables are wrong in the packaged build`,
                                    );
                                  }
                                  return checkPostQuantum(window)
                                    .then((pqProbe) => {
                                      process.stdout.write(
                                        `SMOKE POSTQUANTUM: ${JSON.stringify(pqProbe, null, 2)}\n`,
                                      );
                                      if (pqProbe.error) {
                                        return fail(`ML-DSA probe failed: ${pqProbe.error}`);
                                      }
                                      return chainNetwork();
                                    })
                                    .catch((error: unknown) =>
                                      fail(`ML-DSA probe threw: ${String(error)}`),
                                    );
                                })
                                .catch((error: unknown) =>
                                  fail(`Streebog probe threw: ${String(error)}`),
                                );

                              function chainNetwork() {
                                return checkNoOutbound(window)
                                  .then((netProbe) => {
                                    process.stdout.write(
                                      `SMOKE NETWORK: ${JSON.stringify(netProbe, null, 2)}\n`,
                                    );
                                    if (!netProbe.blocked) {
                                      return fail(
                                        `the renderer reached the network -- ${netProbe.detail}. Both the CSP's connect-src and the session block in window.ts would have to be broken for this.`,
                                      );
                                    }

                                    process.stdout.write("SMOKE PASS\n");
                                    app.exit(0);
                                  })
                                  .catch((error: unknown) =>
                                    fail(`network probe threw: ${String(error)}`),
                                  );
                              }
                            })
                            .catch((error: unknown) =>
                              fail(`Shift_JIS probe threw: ${String(error)}`),
                            );
                        })
                        .catch((error: unknown) =>
                          fail(`checksum or Ed25519 probe threw: ${String(error)}`),
                        )
                    );
                  })
                  .catch((error: unknown) => fail(`tool switch threw: ${String(error)}`));
              })
              .catch((error: unknown) => fail(`file probe threw: ${String(error)}`));
          })
          .catch((error: unknown) => fail(`compute probe threw: ${String(error)}`));
      })
      .catch((error: unknown) => {
        clearTimeout(timeout);
        fail(`executeJavaScript threw: ${String(error)}`);
      });
  });
}
