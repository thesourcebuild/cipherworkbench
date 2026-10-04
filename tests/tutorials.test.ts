import { describe, expect, it } from "vitest";
import {
  DTLS_VERSION_VISUALS,
  TLS_VERSION_VISUALS,
  type VersionVisual,
} from "../apps/web/app/tutorials/transport-handshake-data";
import { loadTutorialContent } from "../apps/web/app/tutorials/tutorial-loader";
import { ALL_TUTORIALS_META, getTutorialMeta } from "../apps/web/app/tutorials/tutorials-meta";
import type {
  DtlsTutorialVersion,
  TlsTutorialVersion,
} from "../apps/web/app/tutorials/tutorial-types";

const TLS_TUTORIAL_ID = "5.1-the-complete-tls-handshake";
const DTLS_TUTORIAL_ID = "5.3-the-dtls-handshake";
const SSL_TUTORIAL_ID = "5.1-ssl-3.0-handshake";

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

const TRANSPORT_TUTORIAL_TIMELINES: readonly {
  id: string;
  visual: VersionVisual;
}[] = [
  { id: SSL_TUTORIAL_ID, visual: TLS_VERSION_VISUALS["SSL 3.0"] },
  ...Object.entries(EXPECTED_TLS_VERSIONS).map(([id, version]) => ({
    id,
    visual: TLS_VERSION_VISUALS[version],
  })),
  ...Object.entries(EXPECTED_DTLS_VERSIONS).map(([id, version]) => ({
    id,
    visual: DTLS_VERSION_VISUALS[version],
  })),
];

function expectedStepTitles(visual: VersionVisual) {
  return visual.flights.map((flight) => `Step ${flight.step}: ${flight.title}`);
}

describe("transport handshake timelines", () => {
  it.each(TRANSPORT_TUTORIAL_TIMELINES)(
    "keeps $id synchronized with its visual timeline",
    async ({ id, visual }) => {
      const content = await loadTutorialContent(id);

      expect(content?.steps).toHaveLength(visual.flights.length);
      expect(content?.steps.map((step) => step.title)).toEqual(expectedStepTitles(visual));
      expect(content?.afterTimeline).toBeDefined();

      const numberedSteps = content?.steps
        .map((step) => `${step.title}\n${step.content}`)
        .join("\n");
      expect(numberedSteps).not.toMatch(
        /NewSessionTicket|abbreviated handshake|\bresum(?:e|ed|es|ing|ption)\b/i,
      );
    },
  );
});

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
    "loads %s with its six-event visual timeline",
    async (id, version) => {
      const content = await loadTutorialContent(id);
      const visual = TLS_VERSION_VISUALS[version];

      expect(content?.visualization).toEqual({ kind: "tls-handshake", version });
      expect(content?.steps).toHaveLength(visual.flights.length);
      expect(content?.steps.map((step) => step.title)).toEqual(expectedStepTitles(visual));
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
    expect(Object.values(TLS_VERSION_VISUALS).map((visual) => visual.flights.length)).toEqual([
      6, 6, 6, 6,
    ]);
    expect(Object.values(DTLS_VERSION_VISUALS).map((visual) => visual.flights.length)).toEqual([
      6, 6, 7,
    ]);

    for (const visual of Object.values(TLS_VERSION_VISUALS)) {
      expect(visual.flights.map((flight) => flight.step)).toEqual([1, 2, 3, 4, 5, 6]);
      expect(visual.flights.map((flight) => flight.title)).toContain("HTTP request");
      expect(visual.flights.map((flight) => flight.title)).toContain("HTTP response");
      expect(visual.flights.every((flight) => !("badge" in flight))).toBe(true);
    }

    for (const visual of Object.values(DTLS_VERSION_VISUALS)) {
      expect(visual.flights.map((flight) => flight.step)).toEqual(
        Array.from({ length: visual.flights.length }, (_, index) => index + 1),
      );
      expect(visual.flights.every((flight) => !("badge" in flight))).toBe(true);
    }
  });

  it("shows the production-compatible TLS 1.2 path as ECDHE plus AEAD", () => {
    const visual = TLS_VERSION_VISUALS["1.2"];
    const applicationMessages = visual.flights
      .slice(4)
      .flatMap((flight) => flight.messages)
      .join(" ");

    expect(visual.eyebrow).toContain("Production-compatible ECDHE + AEAD");
    expect(applicationMessages).toMatch(/AES-GCM|ChaCha20-Poly1305/);
    expect(applicationMessages).not.toContain("CBC");
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
    "loads %s with its visual timeline",
    async (id, version) => {
      const content = await loadTutorialContent(id);
      const visual = DTLS_VERSION_VISUALS[version];

      expect(content?.visualization).toEqual({ kind: "dtls-handshake", version });
      expect(content?.steps).toHaveLength(visual.flights.length);
      expect(content?.steps.map((step) => step.title)).toEqual(expectedStepTitles(visual));
      const walkthrough = content?.steps.map((step) => step.content).join("\n") ?? "";
      expect(walkthrough).toContain("`CertificateRequest`");
      expect(walkthrough).toContain("`Certificate`");
      expect(walkthrough).toContain("`CertificateVerify`");
    },
  );

  it("requires an ACK for the terminal DTLS 1.3 client flight", async () => {
    const content = await loadTutorialContent(DTLS_TUTORIAL_ID);
    const visual = DTLS_VERSION_VISUALS["1.3"];
    const ackStep = content?.steps[6];

    expect(visual.rtt).toBe("1 RTT / 2 with HRR");
    expect(ackStep?.title).toBe("Step 7: Selective acknowledgement");
    expect(ackStep?.content).toContain("Bob sends an explicit `ACK`");
    expect(ackStep?.content).toContain("omit acknowledged handshake messages or fragments");
    expect(ackStep?.content).toContain("normally with epoch-3 application keys");
    expect(ackStep?.content).not.toContain("If a timer expires");
    expect(content?.afterTimeline?.content).toContain("If a timer expires");
    expect(
      content?.steps
        .slice(0, 6)
        .map((step) => step.content)
        .join("\n"),
    ).not.toContain("explicit `ACK`");
  });

  it.each(["5.3-dtls-1.0-handshake", "5.3-dtls-1.2-handshake"])(
    "marks the initial cookie flights as optional in %s",
    async (id) => {
      const content = await loadTutorialContent(id);
      const initialClientHello = content?.steps[0]?.content ?? "";
      const helloVerifyRequest = content?.steps[1]?.content ?? "";
      const retriedClientHello = content?.steps[2]?.content ?? "";

      expect(initialClientHello).toContain("optional cookie-verified path");
      expect(initialClientHello).toContain("does not enforce the cookie DoS check");
      expect(helloVerifyRequest).toContain("When Bob enforces stateless cookie DoS protection");
      expect(helloVerifyRequest).toContain("Without the cookie check");
      expect(retriedClientHello).toContain("Only after receiving HelloVerifyRequest");
      expect(retriedClientHello).toContain("flights 1–3 in the cookie-verified path");
      expect(content?.steps.map((step) => step.content).join("\n")).not.toMatch(/retransmi/i);
      expect(content?.afterTimeline?.content).toMatch(/retransmi/i);
      expect(content?.afterTimeline?.content).toMatch(/session|resum/i);
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
    const visual = TLS_VERSION_VISUALS["SSL 3.0"];

    expect(content?.visualization).toEqual({ kind: "tls-handshake", version: "SSL 3.0" });
    expect(content?.steps).toHaveLength(visual.flights.length);
    expect(content?.steps.map((step) => step.title)).toEqual(expectedStepTitles(visual));
    expect(content?.afterTimeline).toBeDefined();
    expect(content?.takeaways).toContain(
      "RFC 7568 prohibits SSL 3.0. Study it to understand TLS history, never to configure a live service.",
    );
    expect(content?.takeaways.join(" ")).toContain(
      "security of stored or already-decrypted endpoint data remains a separate responsibility",
    );
  });
});
