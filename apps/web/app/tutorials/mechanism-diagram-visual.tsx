import type { ReactNode } from "react";
import { cn } from "@ocs/ui";
import type { MechanismDiagramId } from "./tutorial-types";

type DiagramTone = "sky" | "violet" | "emerald" | "amber" | "rose";
type DiagramIconName =
  "document" | "processor" | "packet" | "verify" | "digest" | "key" | "tag" | "lock";

const FRAME_STYLES: Record<
  DiagramTone,
  { border: string; eyebrow: string; badge: string; line: string }
> = {
  sky: {
    border: "border-sky-300/80 dark:border-sky-800",
    eyebrow: "text-sky-700 dark:text-sky-300",
    badge:
      "border-sky-300 bg-sky-100 text-sky-800 dark:border-sky-700 dark:bg-sky-950 dark:text-sky-200",
    line: "stroke-sky-500 dark:stroke-sky-300",
  },
  violet: {
    border: "border-violet-300/80 dark:border-violet-800",
    eyebrow: "text-violet-700 dark:text-violet-300",
    badge:
      "border-violet-300 bg-violet-100 text-violet-800 dark:border-violet-700 dark:bg-violet-950 dark:text-violet-200",
    line: "stroke-violet-500 dark:stroke-violet-300",
  },
  emerald: {
    border: "border-emerald-300/80 dark:border-emerald-800",
    eyebrow: "text-emerald-700 dark:text-emerald-300",
    badge:
      "border-emerald-300 bg-emerald-100 text-emerald-800 dark:border-emerald-700 dark:bg-emerald-950 dark:text-emerald-200",
    line: "stroke-emerald-500 dark:stroke-emerald-300",
  },
  amber: {
    border: "border-amber-300/80 dark:border-amber-800",
    eyebrow: "text-amber-700 dark:text-amber-300",
    badge:
      "border-amber-300 bg-amber-100 text-amber-800 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200",
    line: "stroke-amber-500 dark:stroke-amber-300",
  },
  rose: {
    border: "border-rose-300/80 dark:border-rose-800",
    eyebrow: "text-rose-700 dark:text-rose-300",
    badge:
      "border-rose-300 bg-rose-100 text-rose-800 dark:border-rose-700 dark:bg-rose-950 dark:text-rose-200",
    line: "stroke-rose-500 dark:stroke-rose-300",
  },
};

const NODE_STYLES: Record<DiagramTone, string> = {
  sky: "border-sky-300 bg-sky-50 dark:border-sky-800 dark:bg-sky-950/55",
  violet: "border-violet-300 bg-violet-50 dark:border-violet-800 dark:bg-violet-950/55",
  emerald: "border-emerald-300 bg-emerald-50 dark:border-emerald-800 dark:bg-emerald-950/55",
  amber: "border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/55",
  rose: "border-rose-300 bg-rose-50 dark:border-rose-800 dark:bg-rose-950/55",
};

const ICON_STYLES: Record<DiagramTone, string> = {
  sky: "bg-sky-500 text-white",
  violet: "bg-violet-500 text-white",
  emerald: "bg-emerald-500 text-white",
  amber: "bg-amber-400 text-slate-950",
  rose: "bg-rose-500 text-white",
};

function DiagramIcon({ name }: { name: DiagramIconName }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 32 32"
      className="h-8 w-8"
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="2"
    >
      {name === "document" ? (
        <>
          <path d="M8 3h11l5 5v21H8z" />
          <path d="M19 3v6h5M12 15h8M12 20h8M12 25h6" />
        </>
      ) : name === "processor" ? (
        <>
          <rect x="8" y="8" width="16" height="16" rx="3" />
          <path d="M12 2v6M20 2v6M12 24v6M20 24v6M2 12h6M2 20h6M24 12h6M24 20h6" />
          <path d="M12 16h8M16 12v8" />
        </>
      ) : name === "packet" ? (
        <>
          <path d="M4 9l12-6 12 6-12 6zM4 9v14l12 6 12-6V9M16 15v14" />
          <path d="M9 18l4 2" />
        </>
      ) : name === "verify" ? (
        <>
          <circle cx="16" cy="16" r="12" />
          <path d="M10 16l4 4 8-9" />
        </>
      ) : name === "digest" ? (
        <>
          <path d="M11 4L8 28M22 4l-3 24M4 12h24M3 21h24" />
        </>
      ) : name === "key" ? (
        <>
          <circle cx="11" cy="12" r="6" />
          <path d="M15 16l12 12M21 22l3-3M24 25l3-3" />
        </>
      ) : name === "tag" ? (
        <>
          <path d="M4 5h12l12 12-11 11L4 15z" />
          <circle cx="11" cy="12" r="2" />
        </>
      ) : (
        <>
          <rect x="6" y="13" width="20" height="16" rx="3" />
          <path d="M10 13V9a6 6 0 0112 0v4M16 19v5" />
        </>
      )}
    </svg>
  );
}

function MechanismNode({
  icon,
  title,
  detail,
  tone,
}: {
  icon: DiagramIconName;
  title: string;
  detail: string;
  tone: DiagramTone;
}) {
  return (
    <div
      className={cn(
        "flex w-full min-w-0 flex-1 flex-col items-center rounded-xl border px-3 py-4 text-center shadow-xs",
        NODE_STYLES[tone],
      )}
    >
      <span
        className={cn(
          "flex h-12 w-12 items-center justify-center rounded-xl shadow-sm",
          ICON_STYLES[tone],
        )}
      >
        <DiagramIcon name={icon} />
      </span>
      <strong className="mt-2 text-xs text-slate-950 dark:text-white">{title}</strong>
      <span className="mt-1 text-[10px] leading-relaxed text-slate-600 dark:text-slate-300">
        {detail}
      </span>
    </div>
  );
}

function FlowArrow({
  label,
  tone,
  breakpoint = "sm",
}: {
  label: string;
  tone: DiagramTone;
  breakpoint?: "sm" | "lg";
}) {
  const styles = FRAME_STYLES[tone];

  return (
    <div
      className={cn(
        "flex w-full shrink-0 flex-col items-center justify-center py-1",
        breakpoint === "sm" ? "sm:w-16 sm:py-0" : "lg:w-16 lg:py-0",
      )}
    >
      <span className="mb-0.5 text-center text-[9px] font-bold uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </span>
      <svg
        aria-hidden="true"
        viewBox="0 0 48 24"
        className={cn(
          "h-9 w-6 rotate-90",
          breakpoint === "sm" ? "sm:h-6 sm:w-12 sm:rotate-0" : "lg:h-6 lg:w-12 lg:rotate-0",
          styles.line,
        )}
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2.5"
      >
        <path d="M2 12h42M36 5l8 7-8 7" />
      </svg>
    </div>
  );
}

function DiagramFrame({
  id,
  eyebrow,
  title,
  property,
  tone,
  children,
  caption,
}: {
  id: MechanismDiagramId;
  eyebrow: string;
  title: string;
  property: string;
  tone: DiagramTone;
  children: ReactNode;
  caption: ReactNode;
}) {
  const styles = FRAME_STYLES[tone];

  return (
    <figure
      aria-labelledby={`mechanism-${id}-title`}
      className={cn(
        "overflow-hidden rounded-2xl border bg-white shadow-sm dark:bg-[#071b2d]",
        styles.border,
      )}
    >
      <div className="border-b border-slate-200 bg-slate-50/80 px-4 py-4 sm:px-6 dark:border-white/10 dark:bg-white/[0.035]">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className={cn("text-[10px] font-bold uppercase tracking-[0.2em]", styles.eyebrow)}>
            {eyebrow}
          </p>
          <span
            className={cn(
              "max-w-full rounded-full border px-3 py-1 text-center text-[10px] font-bold uppercase tracking-wider",
              styles.badge,
            )}
          >
            {property}
          </span>
        </div>
        <h2
          id={`mechanism-${id}-title`}
          className="mt-1 text-lg font-bold tracking-tight text-slate-950 sm:text-xl dark:text-white"
        >
          {title}
        </h2>
      </div>

      <div className="p-4 sm:p-6">{children}</div>

      <figcaption className="border-t border-slate-200 bg-slate-50/80 px-4 py-3 text-xs leading-relaxed text-slate-600 sm:px-6 dark:border-white/10 dark:bg-white/[0.035] dark:text-slate-300">
        {caption}
      </figcaption>
    </figure>
  );
}

function SharedSecretBanner({ children }: { children: ReactNode }) {
  return (
    <div className="mx-auto mb-4 flex w-fit items-center gap-2 rounded-full border border-violet-300 bg-violet-50 px-3 py-1.5 text-[10px] font-bold text-violet-800 dark:border-violet-700 dark:bg-violet-950/70 dark:text-violet-200">
      <DiagramIcon name="key" />
      <span>{children}</span>
    </div>
  );
}

function CrcDiagram() {
  return (
    <DiagramFrame
      id="crc"
      eyebrow="CRC-32 mechanism"
      title="The frame carries a CRC-32 check value for verification"
      property="Error detection + integrity"
      tone="sky"
      caption={
        <>
          A matching FCS indicates that the frame probably survived accidental transmission
          errors. Because CRC has no secret key, an attacker can alter the data and calculate a
          matching FCS.
        </>
      }
    >
      <div className="flex flex-col items-stretch lg:flex-row lg:items-center">
        <MechanismNode
          icon="document"
          title="Payload bits"
          detail="The Ethernet frame Alice wants to transmit"
          tone="sky"
        />
        <FlowArrow label="input" tone="sky" breakpoint="lg" />
        <MechanismNode
          icon="processor"
          title="CRC-32 calculation"
          detail="A public generator polynomial produces the 32-bit check value"
          tone="violet"
        />
        <FlowArrow label="append" tone="sky" breakpoint="lg" />
        <MechanismNode
          icon="packet"
          title="Payload + FCS"
          detail="The frame crosses a channel where noise may flip bits"
          tone="amber"
        />
        <FlowArrow label="recompute" tone="sky" breakpoint="lg" />
        <MechanismNode
          icon="verify"
          title="Receiver check"
          detail="Matching values accept; a mismatch drops the damaged frame"
          tone="emerald"
        />
      </div>

      <div className="mt-4 grid gap-2 sm:grid-cols-2">
        <div className="rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-xs text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200">
          <strong>Match:</strong> payload and FCS are passed to the next layer.
        </div>
        <div className="rounded-lg border border-rose-300 bg-rose-50 px-3 py-2 text-xs text-rose-900 dark:border-rose-800 dark:bg-rose-950/50 dark:text-rose-200">
          <strong>Mismatch:</strong> the corrupted frame is discarded.
        </div>
      </div>
    </DiagramFrame>
  );
}

function HashPath({
  label,
  input,
  digest,
  digestDetail,
  tone,
}: {
  label: string;
  input: string;
  digest: string;
  digestDetail: string;
  tone: "sky" | "rose";
}) {
  return (
    <div className={cn("rounded-xl border p-3", NODE_STYLES[tone])}>
      <p className="mb-3 text-[10px] font-bold uppercase tracking-wider text-slate-600 dark:text-slate-300">
        {label}
      </p>
      <div className="flex flex-col items-stretch sm:flex-row sm:items-center">
        <MechanismNode
          icon="document"
          title={input}
          detail="Arbitrary-length file bytes"
          tone={tone}
        />
        <FlowArrow label="hash" tone="violet" />
        <MechanismNode
          icon="digest"
          title="SHA-256"
          detail="The public hash function processes every input byte; no secret key is used"
          tone="violet"
        />
        <FlowArrow label="output" tone="violet" />
        <MechanismNode icon="tag" title={digest} detail={digestDetail} tone={tone} />
      </div>
    </div>
  );
}

function HashDiagram() {
  return (
    <DiagramFrame
      id="hash"
      eyebrow="SHA-256 mechanism"
      title="A trusted SHA-256 digest helps verify payload integrity"
      property="Error detection + integrity"
      tone="violet"
      caption={
        <>
          Bob must obtain the expected digest through an authenticated source. If Mallory can
          replace both the file and its digest, hashing alone cannot establish authenticity.
        </>
      }
    >
      <div className="mb-4 flex flex-col items-stretch lg:flex-row lg:items-center">
        <MechanismNode
          icon="document"
          title="Payload bytes"
          detail="The exact payload Alice wants Bob to verify"
          tone="sky"
        />
        <FlowArrow label="input" tone="violet" breakpoint="lg" />
        <MechanismNode
          icon="processor"
          title="SHA-256 calculation"
          detail="The public hash function processes every input byte"
          tone="violet"
        />
        <FlowArrow label="output" tone="violet" breakpoint="lg" />
        <MechanismNode
          icon="digest"
          title="SHA-256 digest"
          detail="A fixed-length 256-bit digest is computed from the payload"
          tone="amber"
        />
        <FlowArrow label="compare" tone="violet" breakpoint="lg" />
        <MechanismNode
          icon="verify"
          title="Integrity check"
          detail="Bob compares the computed digest with a trusted expected digest"
          tone="emerald"
        />
      </div>

      <div className="grid gap-3">
        <HashPath
          label="Official file"
          input="Installer v1"
          digest="474c60ba..."
          digestDetail="Matches the trusted digest, so Bob accepts the file as intact"
          tone="sky"
        />
        <HashPath
          label="One bit changed"
          input="Tampered file"
          digest="d9f3a1c2..."
          digestDetail="Different digest reveals tampering, so Bob rejects the file"
          tone="rose"
        />
      </div>

      <div className="mt-4 rounded-lg border border-violet-300 bg-violet-50 px-3 py-2 text-center text-xs text-violet-900 dark:border-violet-800 dark:bg-violet-950/50 dark:text-violet-200">
        Bob accepts only when the downloaded file's digest matches Alice's authenticated
        reference.
      </div>
    </DiagramFrame>
  );
}

function HmacDiagram() {
  return (
    <DiagramFrame
      id="hmac"
      eyebrow="HMAC-SHA-256 mechanism"
      title="The message and shared secret produce an authentication tag"
      property="Error detection + integrity + authenticity"
      tone="emerald"
      caption={
        <>
          The secret key is never transmitted with the request. The plaintext message is still
          visible, so HMAC authenticates data but does not encrypt it.
        </>
      }
    >
      <SharedSecretBanner>Same shared secret stored by Alice and Bob</SharedSecretBanner>

      <div className="flex flex-col items-stretch lg:flex-row lg:items-center">
        <MechanismNode
          icon="document"
          title="Plaintext request"
          detail="Exact bytes Alice wants Bob to authenticate"
          tone="sky"
        />
        <FlowArrow label="message + key" tone="emerald" breakpoint="lg" />
        <MechanismNode
          icon="processor"
          title="Alice computes HMAC"
          detail="HMAC-SHA-256 mixes the secret with the message"
          tone="emerald"
        />
        <FlowArrow label="send" tone="emerald" breakpoint="lg" />
        <MechanismNode
          icon="tag"
          title="Message + tag"
          detail="The message stays readable; the tag travels beside it"
          tone="amber"
        />
        <FlowArrow label="recompute" tone="emerald" breakpoint="lg" />
        <MechanismNode
          icon="verify"
          title="Bob verifies"
          detail="Bob uses his secret copy and compares tags in constant time"
          tone="violet"
        />
      </div>

      <div className="mt-4 flex flex-wrap justify-center gap-2 text-[10px] font-bold uppercase tracking-wide">
        <span className="rounded-full bg-emerald-100 px-3 py-1 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200">
          Match: accept authentic message
        </span>
        <span className="rounded-full bg-rose-100 px-3 py-1 text-rose-800 dark:bg-rose-950 dark:text-rose-200">
          Mismatch: reject modification
        </span>
      </div>
    </DiagramFrame>
  );
}

function SymmetricDiagram() {
  return (
    <DiagramFrame
      id="symmetric"
      eyebrow="Symmetric encryption mechanism"
      title="One shared secret key encrypts and decrypts"
      property="Confidentiality"
      tone="sky"
      caption={
        <>
          The nonce or IV is normally public and travels with the ciphertext. Authentication
          depends on the selected mode; production systems should prefer an AEAD mode such as
          AES-GCM.
        </>
      }
    >
      <SharedSecretBanner>Secret key K is held by both Alice and Bob</SharedSecretBanner>

      <div className="flex flex-col items-stretch lg:flex-row lg:items-center">
        <MechanismNode icon="document" title="Plaintext" detail="Meet me at noon" tone="sky" />
        <FlowArrow label="input" tone="sky" breakpoint="lg" />
        <MechanismNode
          icon="lock"
          title="Encrypt"
          detail="Cipher mode receives key K and a unique nonce or IV"
          tone="violet"
        />
        <FlowArrow label="public channel" tone="sky" breakpoint="lg" />
        <MechanismNode
          icon="packet"
          title="Ciphertext + nonce"
          detail="Eve can observe the package but not its plaintext"
          tone="amber"
        />
        <FlowArrow label="input" tone="sky" breakpoint="lg" />
        <MechanismNode
          icon="key"
          title="Decrypt"
          detail="Bob supplies the same key K and transmitted nonce"
          tone="violet"
        />
        <FlowArrow label="output" tone="sky" breakpoint="lg" />
        <MechanismNode
          icon="document"
          title="Recovered plaintext"
          detail="Meet me at noon"
          tone="emerald"
        />
      </div>
    </DiagramFrame>
  );
}

function RsaDiagram() {
  return (
    <DiagramFrame
      id="rsa"
      eyebrow="RSA-OAEP encryption mechanism"
      title="Bob's public key locks; Bob's private key unlocks"
      property="Recipient confidentiality"
      tone="violet"
      caption={
        <>
          Alice must authenticate Bob's public key before using it. RSA encryption protects a
          small secret for Bob, but it does not prove who created the ciphertext.
        </>
      }
    >
      <div className="mb-4 grid gap-2 sm:grid-cols-2">
        <div className="flex items-center gap-2 rounded-lg border border-sky-300 bg-sky-50 px-3 py-2 text-xs text-sky-900 dark:border-sky-800 dark:bg-sky-950/50 dark:text-sky-200">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-sky-500 text-white">
            <DiagramIcon name="key" />
          </span>
          <span>
            <strong>Public key:</strong> distributed openly after authentication
          </span>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-violet-300 bg-violet-50 px-3 py-2 text-xs text-violet-900 dark:border-violet-800 dark:bg-violet-950/50 dark:text-violet-200">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-violet-500 text-white">
            <DiagramIcon name="key" />
          </span>
          <span>
            <strong>Private key:</strong> remains protected by Bob
          </span>
        </div>
      </div>

      <div className="flex flex-col items-stretch lg:flex-row lg:items-center">
        <MechanismNode
          icon="document"
          title="Small plaintext"
          detail="Usually a random symmetric session key"
          tone="sky"
        />
        <FlowArrow label="Bob's public key" tone="violet" breakpoint="lg" />
        <MechanismNode
          icon="lock"
          title="RSA-OAEP encrypt"
          detail="Alice applies randomized OAEP padding and RSA"
          tone="sky"
        />
        <FlowArrow label="send" tone="violet" breakpoint="lg" />
        <MechanismNode
          icon="packet"
          title="RSA ciphertext"
          detail="The encrypted value may cross an untrusted network"
          tone="amber"
        />
        <FlowArrow label="Bob's private key" tone="violet" breakpoint="lg" />
        <MechanismNode
          icon="key"
          title="RSA-OAEP decrypt"
          detail="Only the matching private key can recover the value"
          tone="violet"
        />
        <FlowArrow label="output" tone="violet" breakpoint="lg" />
        <MechanismNode
          icon="document"
          title="Recovered secret"
          detail="Bob obtains the original session key"
          tone="emerald"
        />
      </div>
    </DiagramFrame>
  );
}

export function MechanismDiagramVisual({ id }: { id: MechanismDiagramId }) {
  switch (id) {
    case "crc":
      return <CrcDiagram />;
    case "hash":
      return <HashDiagram />;
    case "hmac":
      return <HmacDiagram />;
    case "symmetric":
      return <SymmetricDiagram />;
    case "rsa":
      return <RsaDiagram />;
  }
}
