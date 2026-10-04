import { cn } from "@ocs/ui";
import {
  CRYPTOGRAPHIC_FLOWS,
  type CryptographicFlowParticipant,
  type CryptographicFlowTone,
} from "./cryptographic-flow-data";
import type { CryptographicFlowId } from "./tutorial-types";

const TONE_STYLES: Record<CryptographicFlowTone, string> = {
  neutral: "border-slate-500/50 bg-slate-500/10 text-slate-300",
  cyan: "border-cyan-400/40 bg-cyan-400/10 text-cyan-200",
  violet: "border-violet-400/40 bg-violet-400/10 text-violet-200",
  emerald: "border-emerald-400/40 bg-emerald-400/10 text-emerald-200",
  amber: "border-amber-400/40 bg-amber-400/10 text-amber-200",
  rose: "border-rose-400/40 bg-rose-400/10 text-rose-200",
};

const PARTICIPANT_STYLES: Record<CryptographicFlowTone, string> = {
  neutral: "border-slate-400 bg-slate-700 text-slate-100",
  cyan: "border-cyan-200 bg-cyan-500 text-slate-950",
  violet: "border-violet-200 bg-violet-500 text-white",
  emerald: "border-emerald-200 bg-emerald-500 text-slate-950",
  amber: "border-amber-200 bg-amber-500 text-slate-950",
  rose: "border-rose-200 bg-rose-500 text-white",
};

function ParticipantBadge({ participant }: { participant: CryptographicFlowParticipant }) {
  return (
    <div className="flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.045] py-1 pl-1 pr-3">
      <span
        className={cn(
          "flex h-7 w-7 items-center justify-center rounded-full border text-[10px] font-black",
          PARTICIPANT_STYLES[participant.tone],
        )}
      >
        {participant.initial}
      </span>
      <span className="min-w-0">
        <span className="block text-[10px] font-bold leading-tight text-white">
          {participant.name}
        </span>
        <span className="block text-[9px] leading-tight text-slate-400">
          {participant.role}
        </span>
      </span>
    </div>
  );
}

export function CryptographicFlowVisual({ id }: { id: CryptographicFlowId }) {
  const flow = CRYPTOGRAPHIC_FLOWS[id];
  const participants = new Map(
    flow.participants.map((participant) => [participant.id, participant]),
  );

  return (
    <figure className="overflow-hidden rounded-2xl border border-slate-700 bg-[#061d32] text-white shadow-xl shadow-slate-950/10">
      <div className="border-b border-white/10 bg-[#09243d] px-4 py-4 sm:px-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-cyan-300">
              {flow.eyebrow}
            </p>
            <h2 className="mt-1 text-lg font-bold tracking-tight sm:text-xl">{flow.title}</h2>
          </div>
          <span className="rounded-full border border-cyan-300/40 bg-cyan-300/10 px-3 py-1 text-xs font-bold text-cyan-200">
            {flow.property}
          </span>
        </div>
        <p className="mt-2 text-xs leading-relaxed text-slate-400">{flow.summary}</p>
      </div>

      <div className="border-b border-white/10 px-4 py-3 sm:px-6">
        <div className="flex flex-wrap gap-2">
          {flow.participants.map((participant) => (
            <ParticipantBadge key={participant.id} participant={participant} />
          ))}
        </div>
      </div>

      <div className="px-4 py-5 sm:px-6">
        <ol className="relative space-y-3 before:absolute before:bottom-4 before:left-4 before:top-4 before:w-px before:bg-cyan-300/25">
          {flow.events.map((event) => (
            <li key={event.step} className="relative grid grid-cols-[2rem_minmax(0,1fr)] gap-3">
              <span
                aria-label={`Flow event ${event.step}`}
                className={cn(
                  "relative z-10 flex h-8 w-8 items-center justify-center rounded-full border-2 border-white text-[10px] font-black shadow-md",
                  PARTICIPANT_STYLES[event.tone],
                )}
              >
                {event.step}
              </span>

              <div className="min-w-0 rounded-xl border border-white/10 bg-white/[0.045] px-3 py-3 sm:px-4">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="text-[9px] font-bold uppercase tracking-[0.16em] text-slate-400">
                      {event.route}
                    </p>
                    <h3 className="mt-0.5 text-xs font-bold text-white sm:text-sm">
                      {event.title}
                    </h3>
                  </div>
                  <span
                    className={cn(
                      "rounded-full border px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider",
                      TONE_STYLES[event.tone],
                    )}
                  >
                    {event.status}
                  </span>
                </div>

                <div className="mt-2 flex flex-wrap gap-1">
                  {event.actors.map((actorId) => {
                    const actor = participants.get(actorId);
                    return actor ? (
                      <span
                        key={actorId}
                        className={cn(
                          "rounded border px-1.5 py-0.5 text-[9px] font-bold",
                          TONE_STYLES[actor.tone],
                        )}
                      >
                        {actor.name}
                      </span>
                    ) : null;
                  })}
                  {event.artifacts.map((artifact) => (
                    <code
                      key={artifact}
                      className="rounded border border-white/10 bg-slate-950/40 px-1.5 py-0.5 text-[9px] text-slate-200 sm:text-[10px]"
                    >
                      {artifact}
                    </code>
                  ))}
                </div>

                <p className="mt-2 text-[10px] leading-relaxed text-slate-400 sm:text-[11px]">
                  {event.note}
                </p>
              </div>
            </li>
          ))}
        </ol>
      </div>

      <figcaption className="grid gap-px border-t border-white/10 bg-white/10 sm:grid-cols-3">
        {flow.legend.map((item) => (
          <div key={item.title} className="bg-[#09243d] px-4 py-3">
            <span
              className={cn(
                "text-[10px] font-bold uppercase tracking-wider",
                TONE_STYLES[item.tone],
                "border-0 bg-transparent p-0",
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
