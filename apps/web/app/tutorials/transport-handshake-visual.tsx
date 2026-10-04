import { cn } from "@ocs/ui";
import {
  DTLS_VERSION_VISUALS,
  TLS_VERSION_VISUALS,
  type Direction,
  type FlightProtection,
  type VersionVisual,
  type VisualLegend,
} from "./transport-handshake-data";
import type { DtlsTutorialVersion, TlsTutorialVersion } from "./tutorial-types";

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
  return <HandshakeVisual visual={TLS_VERSION_VISUALS[version]} />;
}

export function DtlsHandshakeVisual({ version }: { version: DtlsTutorialVersion }) {
  return <HandshakeVisual visual={DTLS_VERSION_VISUALS[version]} />;
}
