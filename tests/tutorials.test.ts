import { describe, expect, it } from "vitest";
import {
  DTLS_VERSION_VISUALS,
  TLS_VERSION_VISUALS,
  type VersionVisual,
} from "../apps/web/app/tutorials/transport-handshake-data";
import {
  CRYPTOGRAPHIC_FLOWS,
  type CryptographicFlow,
} from "../apps/web/app/tutorials/cryptographic-flow-data";
import { loadTutorialContent } from "../apps/web/app/tutorials/tutorial-loader";
import { ALL_TUTORIALS_META, getTutorialMeta } from "../apps/web/app/tutorials/tutorials-meta";
import type {
  DtlsTutorialVersion,
  CryptographicFlowId,
  MechanismDiagramId,
  TlsTutorialVersion,
} from "../apps/web/app/tutorials/tutorial-types";

const TLS_TUTORIAL_ID = "5.1-the-complete-tls-handshake";
const DTLS_TUTORIAL_ID = "5.3-the-dtls-handshake";
const SSL_TUTORIAL_ID = "5.1-ssl-3.0-handshake";

const CRYPTOGRAPHIC_FLOW_TUTORIALS: readonly {
  id: string;
  flowId: CryptographicFlowId;
}[] = [
  { id: "1.2-the-static-on-the-wire", flowId: "crc" },
  { id: "1.3-the-digital-fingerprint", flowId: "hash" },
  { id: "2.2-the-secret-handshake", flowId: "hmac" },
  { id: "3.1-the-locked-steel-box", flowId: "symmetric" },
  { id: "4.1-the-paint-mixing-trick", flowId: "ecdh" },
  { id: "4.2-the-open-padlock", flowId: "rsa" },
  { id: "5.2-the-imposter-in-the-middle", flowId: "certificate" },
];

const MECHANISM_DIAGRAM_TUTORIALS: readonly {
  id: string;
  diagramId: MechanismDiagramId;
}[] = [
  { id: "1.2-the-static-on-the-wire", diagramId: "crc" },
  { id: "1.3-the-digital-fingerprint", diagramId: "hash" },
  { id: "2.2-the-secret-handshake", diagramId: "hmac" },
  { id: "3.1-the-locked-steel-box", diagramId: "symmetric" },
  { id: "4.2-the-open-padlock", diagramId: "rsa" },
];

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

function expectedCryptographicStepTitles(flow: CryptographicFlow) {
  return flow.events.map((event) => `Step ${event.step}: ${event.title}`);
}

describe("cryptographic concept flows", () => {
  it.each(CRYPTOGRAPHIC_FLOW_TUTORIALS)(
    "keeps $id synchronized with its $flowId flow",
    async ({ id, flowId }) => {
      const content = await loadTutorialContent(id);
      const flow = CRYPTOGRAPHIC_FLOWS[flowId];

      expect(content?.visualization).toEqual({ kind: "cryptographic-flow", id: flowId });
      expect(content?.steps).toHaveLength(flow.events.length);
      expect(content?.steps.map((step) => step.title)).toEqual(
        expectedCryptographicStepTitles(flow),
      );
      expect(flow.events.map((event) => event.step)).toEqual(
        Array.from({ length: flow.events.length }, (_, index) => index + 1),
      );

      const participantIds = new Set(flow.participants.map((participant) => participant.id));
      for (const event of flow.events) {
        expect(event.actors.length).toBeGreaterThan(0);
        expect(event.actors.every((actorId) => participantIds.has(actorId))).toBe(true);
      }
    },
  );

  it("preserves each primitive's security boundary", async () => {
    const crc = await loadTutorialContent("1.2-the-static-on-the-wire");
    const hash = await loadTutorialContent("1.3-the-digital-fingerprint");
    const hmac = await loadTutorialContent("2.2-the-secret-handshake");
    const symmetric = await loadTutorialContent("3.1-the-locked-steel-box");
    const ecdh = await loadTutorialContent("4.1-the-paint-mixing-trick");
    const rsa = await loadTutorialContent("4.2-the-open-padlock");
    const certificate = await loadTutorialContent("5.2-the-imposter-in-the-middle");

    expect(crc?.takeaways.join(" ")).toMatch(/forge|forg/i);
    expect(hash?.afterTimeline?.content).toContain("trusted channel");
    expect(hmac?.afterTimeline?.content).toContain("not confidentiality");
    expect(symmetric?.afterTimeline?.content).toContain("not tamper detection");
    expect(ecdh?.afterTimeline?.content).toContain("man-in-the-middle");
    expect(rsa?.afterTimeline?.content).toContain("does not authenticate the sender");
    expect(certificate?.afterTimeline?.content).toContain("does **not encrypt");
    expect(certificate?.takeaways.join(" ")).toContain("SAN");
  });
});

describe("standalone mechanism diagrams", () => {
  it.each(MECHANISM_DIAGRAM_TUTORIALS)(
    "gives $id its own $diagramId mechanism diagram before the scenario flow",
    async ({ id, diagramId }) => {
      const content = await loadTutorialContent(id);

      expect(content?.mechanismDiagram).toBe(diagramId);
      expect(content?.visualization).toEqual({ kind: "cryptographic-flow", id: diagramId });
    },
  );
});

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

describe("section 5 (certificates) tutorial sequence", () => {
  const certTutorials = ALL_TUTORIALS_META.filter(
    (tutorial) => tutorial.conceptId === "certificates",
  );

  it("covers overview, identity, trust chains, CSRs, revocation, ACME, and key ceremonies", () => {
    expect(certTutorials.map((tutorial) => tutorial.id)).toEqual([
      "5.0-overview-certificates-pki",
      "5.2-the-imposter-in-the-middle",
      "5.2-the-chain-of-trust",
      "5.3-asking-for-permission-csr",
      "5.4-when-trust-breaks-revocation",
      "5.5-automated-trust-acme",
      "6.4-the-key-ceremony",
    ]);
    expect(certTutorials.map((tutorial) => tutorial.number)).toEqual([
      "5.0",
      "5.1",
      "5.2",
      "5.3",
      "5.4",
      "5.5",
      "5.6",
    ]);
  });

  it.each([
    "5.0-overview-certificates-pki",
    "5.2-the-chain-of-trust",
    "5.3-asking-for-permission-csr",
    "5.4-when-trust-breaks-revocation",
    "5.5-automated-trust-acme",
  ])("loads %s with valid tutorial content", async (id) => {
    const content = await loadTutorialContent(id);
    expect(content).toBeDefined();
    expect(content?.steps.length).toBeGreaterThan(0);
    expect(content?.takeaways.length).toBeGreaterThan(0);
    expect(content?.analogy).toBeDefined();
    expect(content?.problem).toBeDefined();
    expect(content?.seed.toolId).toBeDefined();
  });
});

describe("section 6 (transport protocols) tutorial sequence", () => {
  const sectionTutorials = ALL_TUTORIALS_META.filter(
    (tutorial) => tutorial.conceptId === "putting-it-together",
  );

  it("starts with overview, SSL 3.0, TLS, and DTLS", () => {
    expect(sectionTutorials.map((tutorial) => tutorial.id)).toEqual([
      "6.0-overview-secure-transport",
      SSL_TUTORIAL_ID,
      TLS_TUTORIAL_ID,
      DTLS_TUTORIAL_ID,
      "5.3-the-password-vault",
      "5.4-the-pirate-treasure-chest",
      "5.5-the-quantum-spy",
    ]);
    expect(sectionTutorials.map((tutorial) => tutorial.number)).toEqual([
      "6.0",
      "6.1",
      "6.2",
      "6.3",
      "6.4",
      "6.5",
      "6.6",
    ]);
    expect(sectionTutorials[0]).toMatchObject({
      id: "6.0-overview-secure-transport",
      title: "Overview: Secure Transport & Protocols",
    });
    expect(sectionTutorials[1]).toMatchObject({
      id: SSL_TUTORIAL_ID,
      title: "SSL 3.0: The Handshake Before TLS",
    });
    expect(sectionTutorials[2]).toMatchObject({
      id: TLS_TUTORIAL_ID,
      title: "The TLS Handshake: The Full Symphony",
    });
    expect(sectionTutorials[2]?.variants?.[0]?.title).toBe(
      "The TLS Handshake: The Full Symphony",
    );
    expect(sectionTutorials[3]).toMatchObject({
      id: DTLS_TUTORIAL_ID,
      title: "The DTLS Handshake: The Datagram Symphony",
    });
    expect(sectionTutorials[3]?.variants?.[0]?.title).toBe(
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

describe(".0 concept overview tutorials", () => {
  const OVERVIEW_TUTORIAL_IDS = [
    "1.0-overview-data-integrity",
    "2.0-overview-authenticity",
    "3.0-overview-confidentiality",
    "4.0-overview-asymmetric-crypto",
    "5.0-overview-certificates-pki",
    "6.0-overview-secure-transport",
    "7.0-overview-attacks-and-defences",
    "8.0-overview-encodings-and-advanced",
  ] as const;

  it("registers an overview tutorial with .0 number for each concept", () => {
    for (let i = 0; i < OVERVIEW_TUTORIAL_IDS.length; i++) {
      const id = OVERVIEW_TUTORIAL_IDS[i]!;
      const expectedNumber = `${i + 1}.0`;
      const meta = getTutorialMeta(id);

      expect(meta).toBeDefined();
      expect(meta?.number).toBe(expectedNumber);
      expect(meta?.title).toMatch(/^Overview:/);
    }
  });

  it.each(OVERVIEW_TUTORIAL_IDS)(
    "loads %s with all 4 required pillars (what it is, what it does, what it can do, what it does NOT do)",
    async (id) => {
      const content = await loadTutorialContent(id);
      expect(content).toBeDefined();
      expect(content?.steps).toHaveLength(4);

      const stepTitles = content?.steps.map((s) => s.title).join(" ") ?? "";
      expect(stepTitles).toMatch(/What It Is/i);
      expect(stepTitles).toMatch(/What It Does/i);
      expect(stepTitles).toMatch(/What It Can Do/i);
      expect(stepTitles).toMatch(/What It Does NOT Do/i);

      expect(content?.takeaways.length).toBeGreaterThan(0);
      expect(content?.analogy).toBeDefined();
      expect(content?.problem).toBeDefined();
      expect(content?.seed.toolId).toBeDefined();
    },
  );

  it("does not say 'zero computational' in 8.0 overview", async () => {
    const content = await loadTutorialContent("8.0-overview-encodings-and-advanced");
    const fullText = JSON.stringify(content);
    expect(fullText).not.toMatch(/zero computational/i);
  });
});

