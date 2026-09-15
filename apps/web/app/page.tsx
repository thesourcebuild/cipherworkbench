import { AppShell } from "./app-shell";
import { ALL_TOOLS, SITE_DESCRIPTION, SITE_NAME } from "./site";

export default function Page() {
  return (
    <>
      <div className="sr-only">
        <h1>{SITE_NAME} — hash, checksum, MAC and cipher calculator</h1>
        <p>{SITE_DESCRIPTION}</p>
        <p>
          Offline cryptographic suite with {ALL_TOOLS.length} algorithms running client-side in your browser.
        </p>
      </div>
      <AppShell />
    </>
  );
}
