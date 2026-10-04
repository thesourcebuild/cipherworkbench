import { cn } from "@ocs/ui";

type Direction = "client-to-server" | "server-to-client";

interface HandshakeFlight {
  step: number;
  direction: Direction;
  title: string;
  messages: readonly string[];
  protection: "plaintext" | "handshake keys" | "key transition" | "application keys";
  note: string;
}

const FLIGHTS: readonly HandshakeFlight[] = [
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
    messages: ["Finished", "HTTP request"],
    protection: "key transition",
    note: "Alice verifies Bob, confirms the transcript, and can send data immediately.",
  },
  {
    step: 5,
    direction: "server-to-client",
    title: "HTTP response",
    messages: ["AEAD-protected application data"],
    protection: "application keys",
    note: "Bob replies with a separate server application traffic key.",
  },
];

const PROTECTION_STYLES: Record<HandshakeFlight["protection"], string> = {
  plaintext: "border-slate-600 bg-slate-800 text-slate-300",
  "handshake keys": "border-violet-400/40 bg-violet-400/10 text-violet-200",
  "key transition": "border-cyan-400/40 bg-cyan-400/10 text-cyan-200",
  "application keys": "border-emerald-400/40 bg-emerald-400/10 text-emerald-200",
};

const PROTECTION_LABELS: Record<HandshakeFlight["protection"], string> = {
  plaintext: "plaintext",
  "handshake keys": "handshake keys",
  "key transition": "handshake → app keys",
  "application keys": "application keys",
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

export function Tls13HandshakeVisual() {
  return (
    <figure className="overflow-hidden rounded-2xl border border-slate-700 bg-[#061d32] text-white shadow-xl shadow-slate-950/10">
      <div className="border-b border-white/10 bg-[#09243d] px-4 py-4 sm:px-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-cyan-300">
              TLS 1.3 · Full certificate handshake
            </p>
            <h2 className="mt-1 text-lg font-bold tracking-tight sm:text-xl">
              One round trip to authenticated encryption
            </h2>
          </div>
          <span className="rounded-full border border-cyan-300/40 bg-cyan-300/10 px-3 py-1 font-mono text-xs font-bold text-cyan-200">
            1-RTT
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
            <span className="hidden sm:inline">
              Public negotiation → encrypted authentication → protected HTTP
            </span>
            <span className="sm:hidden">Handshake flights</span>
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
          {FLIGHTS.map((flight) => {
            const fromClient = flight.direction === "client-to-server";
            return (
              <li
                key={flight.step}
                className="grid min-h-28 grid-cols-[2.75rem_minmax(0,1fr)_2.75rem] items-center gap-2 sm:gap-4"
              >
                <div className="relative z-10 flex justify-center">
                  {fromClient ? (
                    <span className="flex h-8 w-8 items-center justify-center rounded-full border-2 border-white bg-orange-500 text-xs font-bold shadow-md">
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
                    <span className="flex h-8 w-8 items-center justify-center rounded-full border-2 border-white bg-cyan-500 text-xs font-bold shadow-md">
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
        <div className="bg-[#09243d] px-4 py-3">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
            Before ServerHello
          </span>
          <p className="mt-1 text-xs text-slate-200">
            Negotiation is visible but later transcript-authenticated.
          </p>
        </div>
        <div className="bg-[#09243d] px-4 py-3">
          <span className="text-[10px] font-bold uppercase tracking-wider text-violet-300">
            Handshake keys
          </span>
          <p className="mt-1 text-xs text-slate-200">
            Protect identity proof and Finished messages.
          </p>
        </div>
        <div className="bg-[#09243d] px-4 py-3">
          <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-300">
            Application keys
          </span>
          <p className="mt-1 text-xs text-slate-200">
            Separate client/server AEAD keys protect HTTP.
          </p>
        </div>
      </figcaption>
    </figure>
  );
}
