import { cn } from "@ocs/ui";
import type { DtlsTutorialVersion, TlsTutorialVersion } from "./tutorial-types";

type Direction = "client-to-server" | "server-to-client";
type FlightProtection =
  | "plaintext"
  | "key transition"
  | "handshake to application"
  | "handshake keys"
  | "record keys"
  | "application keys";

interface HandshakeFlight {
  step: number;
  direction: Direction;
  title: string;
  messages: readonly string[];
  protection: FlightProtection;
  note: string;
}

interface VisualLegend {
  title: string;
  description: string;
  tone: "neutral" | "violet" | "cyan" | "emerald" | "amber";
}

interface VersionVisual {
  eyebrow: string;
  title: string;
  rtt: string;
  summary: string;
  flights: readonly HandshakeFlight[];
  legend: readonly [VisualLegend, VisualLegend, VisualLegend];
}

const VERSION_VISUALS: Record<TlsTutorialVersion, VersionVisual> = {
  "SSL 3.0": {
    eyebrow: "SSL 3.0 · Historical full handshake",
    title: "Two round trips to fragile legacy protection",
    rtt: "2-RTT",
    summary: "plaintext setup → ChangeCipherSpec → RC4/CBC records",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "ClientHello",
        messages: ["SSL 3.0", "client_random", "session ID", "cipher suites"],
        protection: "plaintext",
        note: "Alice offers bundled choices for key exchange, encryption, and the SSL MAC.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "Plaintext server flight",
        messages: ["ServerHello", "Certificate", "ServerKeyExchange?", "ServerHelloDone"],
        protection: "plaintext",
        note: "A common RSA suite sends Bob's certificate, while export or DH suites add key-exchange data.",
      },
      {
        step: 3,
        direction: "client-to-server",
        title: "Client key exchange and completion",
        messages: ["ClientKeyExchange", "ChangeCipherSpec", "Finished"],
        protection: "key transition",
        note: "Alice sends an RSA-encrypted pre-master secret, derives keys, then protects Finished.",
      },
      {
        step: 4,
        direction: "server-to-client",
        title: "Server completion",
        messages: ["ChangeCipherSpec", "Finished"],
        protection: "record keys",
        note: "Bob activates his pending state and proves that he observed the same handshake.",
      },
      {
        step: 5,
        direction: "client-to-server",
        title: "HTTP request",
        messages: ["GET / HTTP/1.1", "RC4 or CBC", "SSL MAC"],
        protection: "record keys",
        note: "Alice sends the request inside an SSL-protected application-data record.",
      },
      {
        step: 6,
        direction: "server-to-client",
        title: "HTTP response",
        messages: ["HTTP/1.1 200 OK", "RC4 or CBC", "chained CBC IV"],
        protection: "record keys",
        note: "Bob returns protected content using the separate server write state.",
      },
    ],
    legend: [
      {
        title: "Plaintext setup",
        description: "Hello, certificate, and key exchange cross the network visibly.",
        tone: "neutral",
      },
      {
        title: "ChangeCipherSpec",
        description: "Each peer promotes pending keys before sending Finished.",
        tone: "cyan",
      },
      {
        title: "Obsolete records",
        description: "RC4 and SSLv3 CBC are broken; RFC 7568 prohibits SSL 3.0.",
        tone: "amber",
      },
    ],
  },
  "1.1": {
    eyebrow: "TLS 1.1 · Historical full handshake",
    title: "Two round trips, then legacy record protection",
    rtt: "2-RTT",
    summary: "plaintext setup → ChangeCipherSpec → CBC/HMAC records",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "ClientHello",
        messages: ["TLS 1.1", "client_random", "bundled cipher suites", "SNI"],
        protection: "plaintext",
        note: "Alice offers legacy suites that bundle key exchange, cipher, and MAC choices.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "Plaintext server flight",
        messages: ["ServerHello", "Certificate", "ServerKeyExchange?", "ServerHelloDone"],
        protection: "plaintext",
        note: "DHE/ECDHE sends signed parameters; RSA key transport normally omits ServerKeyExchange.",
      },
      {
        step: 3,
        direction: "client-to-server",
        title: "Client key exchange and completion",
        messages: ["ClientKeyExchange", "ChangeCipherSpec", "Finished"],
        protection: "key transition",
        note: "The key exchange is visible; ChangeCipherSpec activates Alice's derived record keys.",
      },
      {
        step: 4,
        direction: "server-to-client",
        title: "Server completion",
        messages: ["ChangeCipherSpec", "Finished"],
        protection: "record keys",
        note: "Bob activates his write state and proves he saw the same transcript.",
      },
      {
        step: 5,
        direction: "client-to-server",
        title: "HTTP request",
        messages: ["GET / HTTP/1.1", "CBC encryption", "HMAC", "explicit IV"],
        protection: "record keys",
        note: "Alice sends the request in a protected TLS application-data record.",
      },
      {
        step: 6,
        direction: "server-to-client",
        title: "HTTP response",
        messages: ["HTTP/1.1 200 OK", "CBC encryption", "HMAC", "explicit IV"],
        protection: "record keys",
        note: "Bob returns protected content using his independent server write keys.",
      },
    ],
    legend: [
      {
        title: "Plaintext setup",
        description: "Hello, certificate, and key-exchange messages remain visible.",
        tone: "neutral",
      },
      {
        title: "ChangeCipherSpec",
        description: "Each peer separately activates its pending record keys.",
        tone: "cyan",
      },
      {
        title: "Legacy records",
        description: "CBC plus HMAC is fragile and TLS 1.1 is now deprecated.",
        tone: "amber",
      },
    ],
  },
  "1.2": {
    eyebrow: "TLS 1.2 · Representative ECDHE handshake",
    title: "Two round trips to modern record protection",
    rtt: "2-RTT",
    summary: "plaintext setup → ChangeCipherSpec → protected HTTP",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "ClientHello",
        messages: ["TLS 1.2", "client_random", "cipher suites", "signature_algorithms"],
        protection: "plaintext",
        note: "Alice offers suites such as ECDHE_RSA with AES-GCM and SHA-256.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "Plaintext server flight",
        messages: ["ServerHello", "Certificate", "ServerKeyExchange", "ServerHelloDone"],
        protection: "plaintext",
        note: "Bob signs his ephemeral ECDHE parameters with the certificate key.",
      },
      {
        step: 3,
        direction: "client-to-server",
        title: "Client key exchange and completion",
        messages: ["ClientKeyExchange", "ChangeCipherSpec", "Finished"],
        protection: "key transition",
        note: "Alice sends her ECDHE share, derives record keys, and authenticates the transcript.",
      },
      {
        step: 4,
        direction: "server-to-client",
        title: "Server completion",
        messages: ["ChangeCipherSpec", "Finished"],
        protection: "record keys",
        note: "Bob verifies Alice, activates his record keys, and returns his Finished proof.",
      },
      {
        step: 5,
        direction: "client-to-server",
        title: "HTTP request",
        messages: ["GET / HTTP/1.1", "AES-GCM / ChaCha20-Poly1305", "or legacy CBC"],
        protection: "record keys",
        note: "Alice sends the request using the selected TLS 1.2 record protection.",
      },
      {
        step: 6,
        direction: "server-to-client",
        title: "HTTP response",
        messages: ["HTTP/1.1 200 OK", "AES-GCM / ChaCha20-Poly1305", "or legacy CBC"],
        protection: "record keys",
        note: "Bob returns protected content using his independent server write keys.",
      },
    ],
    legend: [
      {
        title: "Plaintext setup",
        description: "Certificate and ephemeral key exchange remain network-visible.",
        tone: "neutral",
      },
      {
        title: "ChangeCipherSpec",
        description: "Finished is the first protected handshake message from each peer.",
        tone: "cyan",
      },
      {
        title: "Record keys",
        description: "AEAD is preferred, but protection depends on the selected suite.",
        tone: "emerald",
      },
    ],
  },
  "1.3": {
    eyebrow: "TLS 1.3 · Full certificate handshake",
    title: "One round trip to authenticated encryption",
    rtt: "1-RTT",
    summary: "public negotiation → encrypted authentication → protected HTTP",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "ClientHello",
        messages: [
          "TLS 1.3 + cipher suites",
          "signature algorithms",
          "X25519 key_share",
          "SNI + ALPN",
        ],
        protection: "plaintext",
        note: "Alice offers capabilities and a fresh ephemeral public key.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "ServerHello",
        messages: ["selected version + suite", "server key_share"],
        protection: "plaintext",
        note: "Both sides can now derive directional handshake keys.",
      },
      {
        step: 3,
        direction: "server-to-client",
        title: "Encrypted server authentication",
        messages: ["EncryptedExtensions", "Certificate", "CertificateVerify", "Finished"],
        protection: "handshake keys",
        note: "Bob proves his identity and authenticates the transcript.",
      },
      {
        step: 4,
        direction: "client-to-server",
        title: "Client completion",
        messages: ["Finished"],
        protection: "handshake keys",
        note: "Alice verifies Bob and confirms that she observed the same transcript.",
      },
      {
        step: 5,
        direction: "client-to-server",
        title: "HTTP request",
        messages: ["GET / HTTP/1.1", "AEAD-protected application data"],
        protection: "application keys",
        note: "Alice can send the request immediately after her Finished message.",
      },
      {
        step: 6,
        direction: "server-to-client",
        title: "HTTP response",
        messages: ["HTTP/1.1 200 OK", "AEAD-protected application data"],
        protection: "application keys",
        note: "Bob replies with a separate server application traffic key.",
      },
    ],
    legend: [
      {
        title: "Before ServerHello",
        description: "Negotiation is visible but later transcript-authenticated.",
        tone: "neutral",
      },
      {
        title: "Handshake keys",
        description: "Protect identity proof and Finished messages.",
        tone: "violet",
      },
      {
        title: "Application keys",
        description: "Separate client/server AEAD keys protect HTTP.",
        tone: "emerald",
      },
    ],
  },
};

const DTLS_VERSION_VISUALS: Record<DtlsTutorialVersion, VersionVisual> = {
  "1.0": {
    eyebrow: "DTLS 1.0 · Deprecated cookie-verified handshake",
    title: "Six-flight cookie path before legacy protection",
    rtt: "3-RTT*",
    summary: "optional DoS check → numbered fragments → protected Finished",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "Initial ClientHello (cookie path)",
        messages: ["DTLS 1.0", "client_random", "cipher suites", "empty cookie"],
        protection: "plaintext",
        note: "Flights 1–2 are used only when Bob enforces the stateless cookie DoS check.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "HelloVerifyRequest (optional DoS)",
        messages: ["stateless cookie"],
        protection: "plaintext",
        note: "Bob returns a cookie tied to Alice's apparent address; the exchange is recommended but optional.",
      },
      {
        step: 3,
        direction: "client-to-server",
        title: "ClientHello + cookie",
        messages: ["same offer", "echoed cookie"],
        protection: "plaintext",
        note: "Echoing the cookie proves Alice can receive datagrams at the claimed source address.",
      },
      {
        step: 4,
        direction: "server-to-client",
        title: "Plaintext server flight",
        messages: [
          "ServerHello",
          "Certificate",
          "ServerKeyExchange?",
          "CertificateRequest?",
          "ServerHelloDone",
        ],
        protection: "plaintext",
        note: "Bob optionally requests Alice's certificate for mutual authentication.",
      },
      {
        step: 5,
        direction: "client-to-server",
        title: "Client key exchange and completion",
        messages: [
          "Certificate?",
          "ClientKeyExchange",
          "CertificateVerify?",
          "ChangeCipherSpec",
          "Finished",
        ],
        protection: "key transition",
        note: "When requested, Alice proves possession of her certificate key before Finished.",
      },
      {
        step: 6,
        direction: "server-to-client",
        title: "Server completion",
        messages: ["ChangeCipherSpec", "Finished"],
        protection: "record keys",
        note: "Bob's Finished completes flight 6; protected application datagrams follow separately.",
      },
    ],
    legend: [
      {
        title: "Flights 1–2 optional",
        description:
          "Without the cookie DoS check, Bob answers the first ClientHello directly.",
        tone: "cyan",
      },
      {
        title: "Datagram recovery",
        description: "message_seq and fragment offsets rebuild reordered handshake messages.",
        tone: "violet",
      },
      {
        title: "Deprecated",
        description: "RFC 8996 says DTLS 1.0 must not be negotiated.",
        tone: "amber",
      },
    ],
  },
  "1.2": {
    eyebrow: "DTLS 1.2 · Representative ECDHE + AEAD handshake",
    title: "Six-flight cookie path over unreliable UDP",
    rtt: "3-RTT*",
    summary: "optional DoS check → ECDHE exchange → protected Finished",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "Initial ClientHello (cookie path)",
        messages: ["DTLS 1.2", "client_random", "cipher suites", "empty cookie"],
        protection: "plaintext",
        note: "Flights 1–2 are used only when Bob enforces the stateless cookie DoS check.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "HelloVerifyRequest (optional DoS)",
        messages: ["stateless cookie"],
        protection: "plaintext",
        note: "Bob can validate reachability without retaining handshake state.",
      },
      {
        step: 3,
        direction: "client-to-server",
        title: "ClientHello + cookie",
        messages: ["same offer", "echoed cookie"],
        protection: "plaintext",
        note: "The cookie round trip limits spoofed-source amplification before certificate data is sent.",
      },
      {
        step: 4,
        direction: "server-to-client",
        title: "Plaintext server flight",
        messages: [
          "ServerHello",
          "Certificate",
          "ServerKeyExchange",
          "CertificateRequest?",
          "ServerHelloDone",
        ],
        protection: "plaintext",
        note: "Bob signs an ECDHE share and may request Alice's certificate for mutual authentication.",
      },
      {
        step: 5,
        direction: "client-to-server",
        title: "Client key exchange and completion",
        messages: [
          "Certificate?",
          "ClientKeyExchange",
          "CertificateVerify?",
          "ChangeCipherSpec",
          "Finished",
        ],
        protection: "key transition",
        note: "Alice optionally proves her identity, derives keys, and advances to epoch 1.",
      },
      {
        step: 6,
        direction: "server-to-client",
        title: "Server completion",
        messages: ["ChangeCipherSpec", "Finished"],
        protection: "record keys",
        note: "Bob's Finished completes flight 6; AEAD-protected application datagrams follow separately.",
      },
    ],
    legend: [
      {
        title: "Flights 1–2 optional",
        description:
          "Without the cookie DoS check, Bob answers the first ClientHello directly.",
        tone: "cyan",
      },
      {
        title: "Reliable handshake",
        description: "Timers retransmit whole flights while application UDP stays unreliable.",
        tone: "violet",
      },
      {
        title: "Record protection",
        description: "Use ECDHE and AEAD; DTLS 1.2 still permits weaker legacy choices.",
        tone: "emerald",
      },
    ],
  },
  "1.3": {
    eyebrow: "DTLS 1.3 · Full certificate handshake",
    title: "One round trip with selective handshake recovery",
    rtt: "1-RTT*",
    summary: "ephemeral key share → encrypted identity → selective ACKs",
    flights: [
      {
        step: 1,
        direction: "client-to-server",
        title: "ClientHello",
        messages: ["DTLS 1.3", "X25519 key_share", "cipher suites", "signature algorithms"],
        protection: "plaintext",
        note: "Alice offers an ephemeral share in epoch 0; a normal path needs no cookie retry.",
      },
      {
        step: 2,
        direction: "server-to-client",
        title: "Optional HelloRetryRequest",
        messages: ["cookie", "selected group?"],
        protection: "plaintext",
        note: "Bob may request a cookie for address validation; this optional path adds one RTT.",
      },
      {
        step: 3,
        direction: "client-to-server",
        title: "Retried ClientHello",
        messages: ["cookie", "compatible key_share"],
        protection: "plaintext",
        note: "This flight appears only after HelloRetryRequest; otherwise the first ClientHello continues.",
      },
      {
        step: 4,
        direction: "server-to-client",
        title: "ServerHello",
        messages: ["selected version + suite", "server key_share"],
        protection: "plaintext",
        note: "Both sides derive epoch-2 handshake traffic keys from ephemeral (EC)DHE.",
      },
      {
        step: 5,
        direction: "server-to-client",
        title: "Encrypted server authentication",
        messages: [
          "EncryptedExtensions",
          "CertificateRequest?",
          "Certificate",
          "CertificateVerify",
          "Finished",
        ],
        protection: "handshake keys",
        note: "Bob proves his identity and may request Alice's certificate for mutual authentication.",
      },
      {
        step: 6,
        direction: "client-to-server",
        title: "Client completion",
        messages: ["Certificate?", "CertificateVerify?", "Finished", "application datagram"],
        protection: "handshake to application",
        note: "Alice optionally proves her identity, sends Finished, and can use epoch 3 immediately.",
      },
      {
        step: 7,
        direction: "server-to-client",
        title: "Selective acknowledgement",
        messages: ["ACK", "application datagram"],
        protection: "application keys",
        note: "ACK confirms the terminal handshake flight; only unacknowledged handshake records are resent.",
      },
    ],
    legend: [
      {
        title: "Cookie optional",
        description:
          "HelloRetryRequest validates reachability when amplification is a concern.",
        tone: "cyan",
      },
      {
        title: "Epoch keys",
        description: "Epoch 0 is plaintext, 2 is handshake, and 3 starts application traffic.",
        tone: "violet",
      },
      {
        title: "Selective recovery",
        description: "ACKs and encrypted record numbers improve datagram handshake handling.",
        tone: "emerald",
      },
    ],
  },
};

const PROTECTION_STYLES: Record<FlightProtection, string> = {
  plaintext: "border-slate-600 bg-slate-800 text-slate-300",
  "key transition": "border-cyan-400/40 bg-cyan-400/10 text-cyan-200",
  "handshake to application": "border-cyan-400/40 bg-cyan-400/10 text-cyan-200",
  "handshake keys": "border-violet-400/40 bg-violet-400/10 text-violet-200",
  "record keys": "border-emerald-400/40 bg-emerald-400/10 text-emerald-200",
  "application keys": "border-emerald-400/40 bg-emerald-400/10 text-emerald-200",
};

const PROTECTION_LABELS: Record<FlightProtection, string> = {
  plaintext: "plaintext",
  "key transition": "plaintext → protected",
  "handshake to application": "handshake → app keys",
  "handshake keys": "handshake keys",
  "record keys": "record keys",
  "application keys": "application keys",
};

const LEGEND_TITLE_STYLES: Record<VisualLegend["tone"], string> = {
  neutral: "text-slate-400",
  violet: "text-violet-300",
  cyan: "text-cyan-300",
  emerald: "text-emerald-300",
  amber: "text-amber-300",
};

function DirectionLine({ direction }: { direction: Direction }) {
  if (direction === "client-to-server") {
    return (
      <div className="flex items-center" aria-hidden="true">
        <div className="h-0.5 flex-1 bg-gradient-to-r from-orange-400 to-cyan-300" />
        <div className="border-y-[5px] border-l-[8px] border-y-transparent border-l-cyan-300" />
      </div>
    );
  }

  return (
    <div className="flex items-center" aria-hidden="true">
      <div className="border-y-[5px] border-r-[8px] border-y-transparent border-r-orange-400" />
      <div className="h-0.5 flex-1 bg-gradient-to-r from-orange-400 to-cyan-300" />
    </div>
  );
}

function HandshakeVisual({ visual }: { visual: VersionVisual }) {
  return (
    <figure className="overflow-hidden rounded-2xl border border-slate-700 bg-[#061d32] text-white shadow-xl shadow-slate-950/10">
      <div className="border-b border-white/10 bg-[#09243d] px-4 py-4 sm:px-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-cyan-300">
              {visual.eyebrow}
            </p>
            <h2 className="mt-1 text-lg font-bold tracking-tight sm:text-xl">{visual.title}</h2>
          </div>
          <span className="rounded-full border border-cyan-300/40 bg-cyan-300/10 px-3 py-1 font-mono text-xs font-bold text-cyan-200">
            {visual.rtt}
          </span>
        </div>
      </div>

      <div className="relative px-4 py-5">
        <div
          className="absolute bottom-5 left-[2.375rem] top-16 w-px bg-orange-400/50"
          aria-hidden="true"
        />
        <div
          className="absolute bottom-5 right-[2.375rem] top-16 w-px bg-cyan-300/50"
          aria-hidden="true"
        />

        <div className="relative grid grid-cols-[2.75rem_minmax(0,1fr)_2.75rem] items-start gap-2 pb-3 sm:gap-4">
          <div className="text-center">
            <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-full border-2 border-white bg-orange-500 text-lg shadow-lg shadow-orange-950/30">
              A
            </div>
            <span className="mt-1.5 block text-[10px] font-bold uppercase tracking-wider text-orange-200">
              Alice
            </span>
            <span className="block text-[9px] text-slate-400">Client</span>
          </div>
          <div className="pt-2 text-center text-xs leading-relaxed text-slate-400">
            <span className="hidden sm:inline">{visual.summary}</span>
            <span className="sm:hidden">Protocol timeline</span>
          </div>
          <div className="text-center">
            <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-full border-2 border-white bg-cyan-500 text-lg shadow-lg shadow-cyan-950/30">
              B
            </div>
            <span className="mt-1.5 block text-[10px] font-bold uppercase tracking-wider text-cyan-200">
              Bob
            </span>
            <span className="block text-[9px] text-slate-400">Server</span>
          </div>
        </div>

        <ol className="relative space-y-3">
          {visual.flights.map((flight) => {
            const fromClient = flight.direction === "client-to-server";
            return (
              <li
                key={flight.step}
                className="grid min-h-28 grid-cols-[2.75rem_minmax(0,1fr)_2.75rem] items-center gap-2 sm:gap-4"
              >
                <div className="relative z-10 flex justify-center">
                  {fromClient ? (
                    <span
                      aria-label={`Timeline event ${flight.step}`}
                      className="flex h-8 min-w-8 items-center justify-center rounded-full border-2 border-white bg-orange-500 px-1 text-[9px] font-bold shadow-md"
                    >
                      {flight.step}
                    </span>
                  ) : (
                    <span className="h-2.5 w-2.5 rounded-full border-2 border-[#061d32] bg-orange-400" />
                  )}
                </div>

                <div className="min-w-0 rounded-xl border border-white/10 bg-white/[0.045] px-3 py-2.5 sm:px-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-bold text-white">
                      {flight.title}
                    </span>
                    <span
                      className={cn(
                        "rounded-full border px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider",
                        PROTECTION_STYLES[flight.protection],
                      )}
                    >
                      {PROTECTION_LABELS[flight.protection]}
                    </span>
                  </div>
                  <div className="my-2">
                    <DirectionLine direction={flight.direction} />
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {flight.messages.map((message) => (
                      <code
                        key={message}
                        className="rounded border border-white/10 bg-slate-950/40 px-1.5 py-0.5 text-[9px] text-slate-200 sm:text-[10px]"
                      >
                        {message}
                      </code>
                    ))}
                  </div>
                  <p className="mt-1.5 text-[10px] leading-relaxed text-slate-400 sm:text-[11px]">
                    {flight.note}
                  </p>
                </div>

                <div className="relative z-10 flex justify-center">
                  {!fromClient ? (
                    <span
                      aria-label={`Timeline event ${flight.step}`}
                      className="flex h-8 min-w-8 items-center justify-center rounded-full border-2 border-white bg-cyan-500 px-1 text-[9px] font-bold shadow-md"
                    >
                      {flight.step}
                    </span>
                  ) : (
                    <span className="h-2.5 w-2.5 rounded-full border-2 border-[#061d32] bg-cyan-300" />
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      </div>

      <figcaption className="grid gap-px border-t border-white/10 bg-white/10 sm:grid-cols-3">
        {visual.legend.map((item) => (
          <div key={item.title} className="bg-[#09243d] px-4 py-3">
            <span
              className={cn(
                "text-[10px] font-bold uppercase tracking-wider",
                LEGEND_TITLE_STYLES[item.tone],
              )}
            >
              {item.title}
            </span>
            <p className="mt-1 text-xs text-slate-200">{item.description}</p>
          </div>
        ))}
      </figcaption>
    </figure>
  );
}

export function TlsHandshakeVisual({ version }: { version: TlsTutorialVersion }) {
  return <HandshakeVisual visual={VERSION_VISUALS[version]} />;
}

export function DtlsHandshakeVisual({ version }: { version: DtlsTutorialVersion }) {
  return <HandshakeVisual visual={DTLS_VERSION_VISUALS[version]} />;
}
