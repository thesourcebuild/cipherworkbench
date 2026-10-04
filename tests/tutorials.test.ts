import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { loadTutorialContent } from "../apps/web/app/tutorials/tutorial-loader";
import { ALL_TUTORIALS_META, getTutorialMeta } from "../apps/web/app/tutorials/tutorials-meta";
import type {
  DtlsTutorialVersion,
  TlsTutorialVersion,
} from "../apps/web/app/tutorials/tutorial-types";

const TLS_TUTORIAL_ID = "5.1-the-complete-tls-handshake";
const DTLS_TUTORIAL_ID = "5.3-the-dtls-handshake";
const SSL_TUTORIAL_ID = "5.1-ssl-3.0-handshake";
const TRANSPORT_VISUAL_SOURCE = readFileSync(
  path.join(__dirname, "../apps/web/app/tutorials/transport-handshake-visual.tsx"),
  "utf8",
);

const EXPECTED_TLS_VERSIONS: Readonly<Record<string, TlsTutorialVersion>> = {
  "5.1-the-complete-tls-handshake": "1.3",
  "5.1-tls-1.2-handshake": "1.2",
  "5.1-tls-1.1-handshake": "1.1",
};

const EXPECTED_DTLS_VERSIONS: Readonly<Record<string, DtlsTutorialVersion>> = {
  "5.3-the-dtls-handshake": "1.3",
  "5.3-dtls-1.2-handshake": "1.2",
  "5.3-dtls-1.0-handshake": "1.0",
};

describe("TLS handshake tutorial variants", () => {
  const tutorial = getTutorialMeta(TLS_TUTORIAL_ID);

  it("keeps all versions under one sidebar and progress item", () => {
    expect(tutorial).toBeDefined();
    expect(tutorial?.variants).toHaveLength(3);
    expect(
      ALL_TUTORIALS_META.filter((item) => Object.hasOwn(EXPECTED_TLS_VERSIONS, item.id)).map(
        (item) => item.id,
      ),
    ).toEqual([TLS_TUTORIAL_ID]);
  });

  it("uses unique variant IDs and defaults to TLS 1.3", () => {
    const ids = tutorial?.variants?.map((variant) => variant.id) ?? [];
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids[0]).toBe(TLS_TUTORIAL_ID);
  });

  it.each(Object.entries(EXPECTED_TLS_VERSIONS))(
    "loads %s with the shared six-step teaching flow",
    async (id, version) => {
      const content = await loadTutorialContent(id);

      expect(content?.visualization).toEqual({ kind: "tls-handshake", version });
      expect(content?.steps).toHaveLength(6);
      expect(content?.steps[0]?.title).toBe("Step 1: Alice sends ClientHello in plaintext");
      expect(content?.steps[1]?.title).toMatch(/^Step 2: Bob selects parameters/);
      expect(content?.steps[2]?.title).toMatch(/^Step 3: Bob authenticates/);
      expect(content?.steps[3]?.title).toMatch(/^Step 4: Alice verifies Bob/);
      expect(content?.steps[4]?.title).toMatch(/^Step 5: Alice/);
      expect(content?.steps[5]?.title).toMatch(/^Step 6: Session tickets/);
    },
  );

  it("distinguishes TLS version capabilities and its endpoint-security boundary", async () => {
    const tls11 = await loadTutorialContent("5.1-tls-1.1-handshake");
    const tls12 = await loadTutorialContent("5.1-tls-1.2-handshake");
    const tls13 = await loadTutorialContent(TLS_TUTORIAL_ID);

    expect(
      tls11?.steps.some((step) => step.callout?.text.includes("defines no AEAD cipher suites")),
    ).toBe(true);
    expect(tls12?.takeaways.join(" ")).toContain("has no standardized 0-RTT mode");
    expect(tls13?.takeaways.join(" ")).toContain("Only resumed sessions can offer 0-RTT");
    expect(tls13?.takeaways.join(" ")).toContain("early data remains replayable");
    expect(tls13?.takeaways.join(" ")).toContain(
      "not protection for plaintext on a compromised client or server",
    );
  });

  it("keeps protocol timelines independently numbered with their natural event counts", () => {
    const tls12Start = TRANSPORT_VISUAL_SOURCE.indexOf('  "1.2": {');
    const tls13Start = TRANSPORT_VISUAL_SOURCE.indexOf('  "1.3": {', tls12Start);
    const tls12Visual = TRANSPORT_VISUAL_SOURCE.slice(tls12Start, tls13Start);
    const dtlsStart = TRANSPORT_VISUAL_SOURCE.indexOf("const DTLS_VERSION_VISUALS");
    const tlsVisuals = TRANSPORT_VISUAL_SOURCE.slice(0, dtlsStart);
    const dtls13Start = TRANSPORT_VISUAL_SOURCE.indexOf('  "1.3": {', dtlsStart);
    const dtls13Visual = TRANSPORT_VISUAL_SOURCE.slice(dtls13Start);

    expect(tls12Visual.match(/step: /g)).toHaveLength(6);
    expect(tlsVisuals.match(/title: "HTTP request"/g)).toHaveLength(4);
    expect(tlsVisuals.match(/title: "HTTP response"/g)).toHaveLength(4);
    expect(dtls13Visual.match(/step: /g)).toHaveLength(7);
    expect(TRANSPORT_VISUAL_SOURCE).not.toContain("badge:");
    expect(TRANSPORT_VISUAL_SOURCE).toContain("{flight.step}");
    expect(TRANSPORT_VISUAL_SOURCE).toContain("Timeline event ${flight.step}");
  });
});

describe("DTLS handshake tutorial variants", () => {
  const tutorial = getTutorialMeta(DTLS_TUTORIAL_ID);

  it("keeps all versions under one sidebar and progress item", () => {
    expect(tutorial).toBeDefined();
    expect(tutorial?.variants).toHaveLength(3);
    expect(
      ALL_TUTORIALS_META.filter((item) => Object.hasOwn(EXPECTED_DTLS_VERSIONS, item.id)).map(
        (item) => item.id,
      ),
    ).toEqual([DTLS_TUTORIAL_ID]);
  });

  it("uses unique variant IDs and defaults to DTLS 1.3", () => {
    const ids = tutorial?.variants?.map((variant) => variant.id) ?? [];
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids[0]).toBe(DTLS_TUTORIAL_ID);
  });

  it.each(Object.entries(EXPECTED_DTLS_VERSIONS))(
    "loads %s with the shared six-step teaching flow",
    async (id, version) => {
      const content = await loadTutorialContent(id);

      expect(content?.visualization).toEqual({ kind: "dtls-handshake", version });
      expect(content?.steps).toHaveLength(6);
      expect(content?.steps.map((step) => step.title)).toEqual([
        "Step 1: Alice sends ClientHello in a UDP datagram",
        "Step 2: Bob optionally validates Alice's address",
        "Step 3: Bob selects parameters and authenticates",
        "Step 4: Alice verifies Bob and establishes shared keys",
        "Step 5: Alice and Bob finish, then application datagrams begin",
        "Step 6: DTLS recovers handshake loss and resumes sessions",
      ]);
      const walkthrough = content?.steps.map((step) => step.content).join("\n") ?? "";
      expect(walkthrough).toContain("`CertificateRequest`");
      expect(walkthrough).toContain("`Certificate`");
      expect(walkthrough).toContain("`CertificateVerify`");
    },
  );

  it("requires an ACK for the terminal DTLS 1.3 client flight", async () => {
    const content = await loadTutorialContent(DTLS_TUTORIAL_ID);

    expect(content?.steps[4]?.content).toContain("Bob sends an explicit `ACK`");
    expect(content?.steps[5]?.content).toContain("unacknowledged handshake records");
    expect(content?.steps[4]?.content).not.toContain("can explicitly acknowledge");
  });

  it.each(["5.3-dtls-1.0-handshake", "5.3-dtls-1.2-handshake"])(
    "marks the initial cookie flights as optional in %s",
    async (id) => {
      const content = await loadTutorialContent(id);
      const cookieStep = content?.steps[1]?.content ?? "";

      expect(cookieStep).toContain("flights 1–3 in the cookie-verified path");
      expect(cookieStep).toContain("present only when Bob enforces this DoS protection");
      expect(cookieStep).toContain(
        "Without them, Bob answers the original ClientHello directly",
      );
    },
  );

  it("keeps handshake recovery separate from reliable application delivery", async () => {
    const content = await loadTutorialContent(DTLS_TUTORIAL_ID);

    expect(content?.takeaways.join(" ")).toContain(
      "handshake reliability does not provide reliable application delivery",
    );
    expect(content?.analogy).toContain("does not make UDP reliable");
  });
});

describe("section 5 tutorial sequence", () => {
  const sectionTutorials = ALL_TUTORIALS_META.filter(
    (tutorial) => tutorial.conceptId === "putting-it-together",
  );

  it("starts with SSL 3.0, TLS, and DTLS", () => {
    expect(sectionTutorials.map((tutorial) => tutorial.number)).toEqual([
      "5.1",
      "5.2",
      "5.3",
      "5.4",
      "5.5",
      "5.6",
      "5.7",
    ]);
    expect(sectionTutorials[0]).toMatchObject({
      id: SSL_TUTORIAL_ID,
      title: "SSL 3.0: The Handshake Before TLS",
    });
    expect(sectionTutorials[1]).toMatchObject({
      id: TLS_TUTORIAL_ID,
      title: "The TLS Handshake: The Full Symphony",
    });
    expect(sectionTutorials[1]?.variants?.[0]?.title).toBe(
      "The TLS Handshake: The Full Symphony",
    );
    expect(sectionTutorials[2]).toMatchObject({
      id: DTLS_TUTORIAL_ID,
      title: "The DTLS Handshake: The Datagram Symphony",
    });
    expect(sectionTutorials[2]?.variants?.[0]?.title).toBe(
      "The DTLS Handshake: The Datagram Symphony",
    );
  });

  it("loads the SSL 3.0 lesson and its historical handshake visual", async () => {
    const content = await loadTutorialContent(SSL_TUTORIAL_ID);

    expect(content?.visualization).toEqual({ kind: "tls-handshake", version: "SSL 3.0" });
    expect(content?.steps).toHaveLength(6);
    expect(content?.takeaways).toContain(
      "RFC 7568 prohibits SSL 3.0. Study it to understand TLS history, never to configure a live service.",
    );
    expect(content?.takeaways.join(" ")).toContain(
      "security of stored or already-decrypted endpoint data remains a separate responsibility",
    );
  });
});
