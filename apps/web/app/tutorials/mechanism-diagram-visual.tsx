"use client";

import { useState, type ReactNode } from "react";
import { cn } from "@ocs/ui";
import type { MechanismDiagramId } from "./tutorial-types";

type DiagramTone = "sky" | "violet" | "emerald" | "amber" | "rose";
type DiagramIconName =
  | "document"
  | "processor"
  | "packet"
  | "verify"
  | "digest"
  | "key"
  | "tag"
  | "lock"
  | "shield"
  | "certificate"
  | "server";

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
      ) : name === "shield" ? (
        <>
          <path d="M16 3l10 4.5v7.5c0 6.5-4.5 12-10 14-5.5-2-10-7.5-10-14V7.5z" />
          <path d="M12 16l3 3 6-6" />
        </>
      ) : name === "certificate" ? (
        <>
          <rect x="5" y="4" width="22" height="18" rx="2" />
          <path d="M9 9h14M9 13h10" />
          <circle cx="16" cy="22" r="4" />
          <path d="M14 26l-2 3 4-1 4 1-2-3" />
        </>
      ) : name === "server" ? (
        <>
          <rect x="4" y="5" width="24" height="8" rx="2" />
          <rect x="4" y="19" width="24" height="8" rx="2" />
          <circle cx="8" cy="9" r="1.5" />
          <circle cx="8" cy="23" r="1.5" />
          <path d="M14 9h10M14 23h10" />
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

type CertificatePathFilter = "all" | "refer" | "verify" | "sign";

function CertificateFieldVerificationVisual({
  filter,
}: {
  filter: CertificatePathFilter;
}) {
  const isReferActive = filter === "all" || filter === "refer";
  const isVerifyActive = filter === "all" || filter === "verify";
  const isSignActive = filter === "all" || filter === "sign";

  return (
    <div className="relative w-full overflow-x-auto pb-2">
      <svg
        viewBox="0 0 1040 550"
        className="mx-auto block h-auto w-full min-w-[880px] max-w-[1040px] select-none"
        fill="none"
        aria-label="X.509 Certificate Chain Field Anatomy, Reference, and Verification Diagram"
      >
        <defs>
          {/* Arrow markers */}
          <marker
            id="cert-arrow-refer"
            viewBox="0 0 10 10"
            refX="8"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto"
          >
            <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#16a34a" />
          </marker>

          <marker
            id="cert-arrow-verify"
            viewBox="0 0 10 10"
            refX="8"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto"
          >
            <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#dc2626" />
          </marker>

          <marker
            id="cert-arrow-sign"
            viewBox="0 0 10 10"
            refX="8"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto"
          >
            <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#9333ea" />
          </marker>

          {/* Key badge symbol */}
          <g id="cert-pubkey-icon">
            <circle cx="0" cy="0" r="10" fill="#fef08a" stroke="#d97706" strokeWidth="1.2" />
            <circle cx="-2" cy="-2" r="3.2" fill="none" stroke="#b45309" strokeWidth="1.3" />
            <path
              d="M0.5 0.5 L5.5 5.5 M3 3 L4.5 1.5 M4.5 4.5 L6 3"
              stroke="#b45309"
              strokeWidth="1.3"
              strokeLinecap="round"
            />
          </g>

          {/* Wax seal / ribbon badge symbol */}
          <g id="cert-seal-icon">
            <path d="M-4 5 L-7 14 L-2 11.5 L3 14 L0 5" fill="#ea580c" />
            <circle cx="0" cy="0" r="9.5" fill="#f97316" stroke="#c2410c" strokeWidth="1.3" />
            <circle
              cx="0"
              cy="0"
              r="6.5"
              fill="none"
              stroke="#fed7aa"
              strokeWidth="0.9"
              strokeDasharray="2,1.5"
            />
            <path
              d="M-2.5 0 L-0.5 2.5 L3 -2"
              stroke="#ffffff"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </g>

          {/* Private key badge symbol */}
          <g id="cert-privkey-icon">
            <circle cx="0" cy="0" r="8" fill="#fca5a5" stroke="#dc2626" strokeWidth="1.2" />
            <circle cx="-1.5" cy="-1.5" r="2.5" fill="none" stroke="#991b1b" strokeWidth="1.2" />
            <path
              d="M0.5 0.5 L4.5 4.5 M2.5 2.5 L3.5 1.5 M3.5 3.5 L4.5 2.5"
              stroke="#991b1b"
              strokeWidth="1.2"
              strokeLinecap="round"
            />
          </g>
        </defs>

        {/* =========================================================================
            CARD 1: Website Certificate (Left, x=24..234)
           ========================================================================= */}
        <g id="card-website-cert">
          {/* Card Frame */}
          <rect
            x="24"
            y="20"
            width="210"
            height="265"
            rx="10"
            className="fill-white stroke-slate-300 dark:fill-slate-900 dark:stroke-slate-700"
            strokeWidth="1.5"
          />
          {/* Header Title */}
          <text
            x="129"
            y="45"
            textAnchor="middle"
            className="fill-slate-900 font-sans text-[15px] font-bold dark:fill-white"
          >
            Website Certificate
          </text>
          <text
            x="129"
            y="60"
            textAnchor="middle"
            className="fill-slate-500 font-sans text-[10px] font-medium dark:fill-slate-400"
          >
            End-Entity / Leaf · CA: FALSE
          </text>

          {/* Field 1: Website Distinguished Name (Green) */}
          <g className={cn("transition-opacity duration-300", isReferActive ? "opacity-100" : "opacity-35")}>
            <rect
              x="34"
              y="74"
              width="190"
              height="44"
              rx="6"
              fill="#dcfce7"
              stroke="#86efac"
              strokeWidth={filter === "refer" ? 2.5 : 1.2}
              className="dark:fill-emerald-950/60 dark:stroke-emerald-600"
            />
            <text
              x="129"
              y="93"
              textAnchor="middle"
              className="fill-emerald-950 font-sans text-[11px] font-bold dark:fill-emerald-200"
            >
              Website
            </text>
            <text
              x="129"
              y="107"
              textAnchor="middle"
              className="fill-emerald-800 font-sans text-[10px] font-semibold dark:fill-emerald-300"
            >
              Distinguished Name
            </text>
          </g>

          {/* Field 2: Website Public Key (Amber/Yellow) */}
          <g className={cn("transition-opacity duration-300", isVerifyActive ? "opacity-100" : "opacity-35")}>
            <rect
              x="34"
              y="126"
              width="190"
              height="40"
              rx="6"
              fill="#fef3c7"
              stroke="#fcd34d"
              strokeWidth="1.2"
              className="dark:fill-amber-950/60 dark:stroke-amber-600"
            />
            <text
              x="118"
              y="151"
              textAnchor="middle"
              className="fill-amber-950 font-sans text-[11px] font-bold dark:fill-amber-200"
            >
              Website Public Key
            </text>
            <use href="#cert-pubkey-icon" x="208" y="146" />
          </g>

          {/* Field 3: Issuer's (CA) Distinguished Name (Sky Blue) */}
          <g className={cn("transition-opacity duration-300", isReferActive ? "opacity-100" : "opacity-35")}>
            <rect
              x="34"
              y="174"
              width="190"
              height="46"
              rx="6"
              fill="#e0f2fe"
              stroke="#7dd3fc"
              strokeWidth={filter === "refer" ? 2.5 : 1.2}
              className="dark:fill-sky-950/60 dark:stroke-sky-600"
            />
            <text
              x="129"
              y="193"
              textAnchor="middle"
              className="fill-sky-950 font-sans text-[11px] font-bold dark:fill-sky-200"
            >
              Issuer&apos;s (CA)
            </text>
            <text
              x="129"
              y="207"
              textAnchor="middle"
              className="fill-sky-800 font-sans text-[10px] font-semibold dark:fill-sky-300"
            >
              Distinguished Name
            </text>
          </g>

          {/* Field 4: Issuer's Signature (Rose / Coral) */}
          <g className={cn("transition-opacity duration-300", isVerifyActive || isSignActive ? "opacity-100" : "opacity-35")}>
            <rect
              x="34"
              y="228"
              width="190"
              height="44"
              rx="6"
              fill="#ffe4e6"
              stroke="#fda4af"
              strokeWidth={filter === "verify" || filter === "sign" ? 2.5 : 1.2}
              className="dark:fill-rose-950/60 dark:stroke-rose-600"
            />
            <text
              x="118"
              y="255"
              textAnchor="middle"
              className="fill-rose-950 font-sans text-[11px] font-bold dark:fill-rose-200"
            >
              Issuer&apos;s Signature
            </text>
            <use href="#cert-seal-icon" x="208" y="250" />
          </g>
        </g>

        {/* =========================================================================
            CARD 2: Intermediate Certificate (Middle, x=414..624)
           ========================================================================= */}
        <g id="card-intermediate-cert">
          {/* Card Frame */}
          <rect
            x="414"
            y="126"
            width="210"
            height="265"
            rx="10"
            className="fill-white stroke-slate-300 dark:fill-slate-900 dark:stroke-slate-700"
            strokeWidth="1.5"
          />
          {/* Header Title */}
          <text
            x="519"
            y="151"
            textAnchor="middle"
            className="fill-slate-900 font-sans text-[15px] font-bold dark:fill-white"
          >
            Intermediate Certificate
          </text>
          <text
            x="519"
            y="166"
            textAnchor="middle"
            className="fill-slate-500 font-sans text-[10px] font-medium dark:fill-slate-400"
          >
            Subordinate CA · CA: TRUE
          </text>

          {/* Field 1: Issuer's Distinguished Name (Green) - Aligned with Website Field 3 */}
          <g className={cn("transition-opacity duration-300", isReferActive ? "opacity-100" : "opacity-35")}>
            <rect
              x="424"
              y="174"
              width="190"
              height="46"
              rx="6"
              fill="#dcfce7"
              stroke="#86efac"
              strokeWidth={filter === "refer" ? 2.5 : 1.2}
              className="dark:fill-emerald-950/60 dark:stroke-emerald-600"
            />
            <text
              x="519"
              y="193"
              textAnchor="middle"
              className="fill-emerald-950 font-sans text-[11px] font-bold dark:fill-emerald-200"
            >
              Issuer&apos;s
            </text>
            <text
              x="519"
              y="207"
              textAnchor="middle"
              className="fill-emerald-800 font-sans text-[10px] font-semibold dark:fill-emerald-300"
            >
              Distinguished Name
            </text>
          </g>

          {/* Field 2: Issuer's Public Key (Amber/Yellow) - Aligned with Website Field 4 */}
          <g className={cn("transition-opacity duration-300", isVerifyActive ? "opacity-100" : "opacity-35")}>
            <rect
              x="424"
              y="228"
              width="190"
              height="44"
              rx="6"
              fill="#fef3c7"
              stroke="#fcd34d"
              strokeWidth={filter === "verify" ? 2.5 : 1.2}
              className="dark:fill-amber-950/60 dark:stroke-amber-600"
            />
            <text
              x="508"
              y="255"
              textAnchor="middle"
              className="fill-amber-950 font-sans text-[11px] font-bold dark:fill-amber-200"
            >
              Issuer&apos;s Public Key
            </text>
            <use href="#cert-pubkey-icon" x="598" y="250" />
          </g>

          {/* Field 3: Root CA Distinguished Name (Sky Blue) */}
          <g className={cn("transition-opacity duration-300", isReferActive ? "opacity-100" : "opacity-35")}>
            <rect
              x="424"
              y="280"
              width="190"
              height="46"
              rx="6"
              fill="#e0f2fe"
              stroke="#7dd3fc"
              strokeWidth={filter === "refer" ? 2.5 : 1.2}
              className="dark:fill-sky-950/60 dark:stroke-sky-600"
            />
            <text
              x="519"
              y="299"
              textAnchor="middle"
              className="fill-sky-950 font-sans text-[11px] font-bold dark:fill-sky-200"
            >
              Root CA
            </text>
            <text
              x="519"
              y="313"
              textAnchor="middle"
              className="fill-sky-800 font-sans text-[10px] font-semibold dark:fill-sky-300"
            >
              Distinguished Name
            </text>
          </g>

          {/* Field 4: Root CA Signature (Rose / Coral) */}
          <g className={cn("transition-opacity duration-300", isVerifyActive || isSignActive ? "opacity-100" : "opacity-35")}>
            <rect
              x="424"
              y="334"
              width="190"
              height="44"
              rx="6"
              fill="#ffe4e6"
              stroke="#fda4af"
              strokeWidth={filter === "verify" || filter === "sign" ? 2.5 : 1.2}
              className="dark:fill-rose-950/60 dark:stroke-rose-600"
            />
            <text
              x="508"
              y="361"
              textAnchor="middle"
              className="fill-rose-950 font-sans text-[11px] font-bold dark:fill-rose-200"
            >
              Root CA Signature
            </text>
            <use href="#cert-seal-icon" x="598" y="356" />
          </g>
        </g>

        {/* =========================================================================
            CARD 3: Root Certificate (Right, x=804..1014)
           ========================================================================= */}
        <g id="card-root-cert">
          {/* Card Frame */}
          <rect
            x="804"
            y="232"
            width="210"
            height="212"
            rx="10"
            className="fill-white stroke-slate-300 dark:fill-slate-900 dark:stroke-slate-700"
            strokeWidth="1.5"
          />
          {/* Header Title */}
          <text
            x="909"
            y="257"
            textAnchor="middle"
            className="fill-slate-900 font-sans text-[15px] font-bold dark:fill-white"
          >
            Root Certificate
          </text>
          <text
            x="909"
            y="272"
            textAnchor="middle"
            className="fill-slate-500 font-sans text-[10px] font-medium dark:fill-slate-400"
          >
            Trust Anchor · Self-Signed
          </text>

          {/* Field 1: Root CA Distinguished Name (Green) - Aligned with Intermediate Field 3 */}
          <g className={cn("transition-opacity duration-300", isReferActive ? "opacity-100" : "opacity-35")}>
            <rect
              x="814"
              y="280"
              width="190"
              height="46"
              rx="6"
              fill="#dcfce7"
              stroke="#86efac"
              strokeWidth={filter === "refer" ? 2.5 : 1.2}
              className="dark:fill-emerald-950/60 dark:stroke-emerald-600"
            />
            <text
              x="909"
              y="299"
              textAnchor="middle"
              className="fill-emerald-950 font-sans text-[11px] font-bold dark:fill-emerald-200"
            >
              Root CA
            </text>
            <text
              x="909"
              y="313"
              textAnchor="middle"
              className="fill-emerald-800 font-sans text-[10px] font-semibold dark:fill-emerald-300"
            >
              Distinguished Name
            </text>
          </g>

          {/* Field 2: Root CA Public Key (Amber/Yellow) - Aligned with Intermediate Field 4 */}
          <g className={cn("transition-opacity duration-300", isVerifyActive ? "opacity-100" : "opacity-35")}>
            <rect
              x="814"
              y="334"
              width="190"
              height="44"
              rx="6"
              fill="#fef3c7"
              stroke="#fcd34d"
              strokeWidth={filter === "verify" ? 2.5 : 1.2}
              className="dark:fill-amber-950/60 dark:stroke-amber-600"
            />
            <text
              x="898"
              y="361"
              textAnchor="middle"
              className="fill-amber-950 font-sans text-[11px] font-bold dark:fill-amber-200"
            >
              Root CA Public Key
            </text>
            <use href="#cert-pubkey-icon" x="988" y="356" />
          </g>

          {/* Field 3: Root CA Signature (Rose / Coral) */}
          <g className={cn("transition-opacity duration-300", isVerifyActive || isSignActive ? "opacity-100" : "opacity-35")}>
            <rect
              x="814"
              y="386"
              width="190"
              height="44"
              rx="6"
              fill="#ffe4e6"
              stroke="#fda4af"
              strokeWidth={filter === "verify" || filter === "sign" ? 2.5 : 1.2}
              className="dark:fill-rose-950/60 dark:stroke-rose-600"
            />
            <text
              x="898"
              y="413"
              textAnchor="middle"
              className="fill-rose-950 font-sans text-[11px] font-bold dark:fill-rose-200"
            >
              Root CA Signature
            </text>
            <use href="#cert-seal-icon" x="988" y="408" />
          </g>
        </g>

        {/* =========================================================================
            PRIVATE KEY PILLS (Generously positioned inside the gaps with 0 overlap)
           ========================================================================= */}
        {/* Issuer's Private Key (in Gap 1 between x=234 and x=414; placed at x=249..399) */}
        <g
          id="pill-issuer-privkey"
          className={cn("transition-opacity duration-300", isSignActive ? "opacity-100" : "opacity-35")}
        >
          <rect
            x="249"
            y="362"
            width="150"
            height="32"
            rx="6"
            fill="#ede9fe"
            stroke="#a855f7"
            strokeWidth="1.3"
            className="dark:fill-purple-950/70 dark:stroke-purple-600"
          />
          <text
            x="314"
            y="382"
            textAnchor="middle"
            className="fill-purple-950 font-sans text-[10.5px] font-bold dark:fill-purple-200"
          >
            Issuer&apos;s Private Key
          </text>
          <use href="#cert-privkey-icon" x="385" y="378" />
        </g>

        {/* Root CA Private Key (in Gap 2 between x=624 and x=804; placed at x=639..789) */}
        <g
          id="pill-root-privkey"
          className={cn("transition-opacity duration-300", isSignActive ? "opacity-100" : "opacity-35")}
        >
          <rect
            x="639"
            y="485"
            width="150"
            height="32"
            rx="6"
            fill="#ede9fe"
            stroke="#a855f7"
            strokeWidth="1.3"
            className="dark:fill-purple-950/70 dark:stroke-purple-600"
          />
          <text
            x="704"
            y="505"
            textAnchor="middle"
            className="fill-purple-950 font-sans text-[10.5px] font-bold dark:fill-purple-200"
          >
            Root CA Private Key
          </text>
          <use href="#cert-privkey-icon" x="775" y="501" />
        </g>

        {/* =========================================================================
            CONNECTOR PATHS
           ========================================================================= */}

        {/* 1. GREEN "REFER" PATHS (Issuer DN -> Subject DN) */}
        <g
          id="paths-refer"
          className={cn("transition-opacity duration-300", isReferActive ? "opacity-100" : "opacity-20")}
        >
          {/* Website Issuer DN -> Intermediate Issuer DN */}
          <line
            x1="234"
            y1="197"
            x2="404"
            y2="197"
            stroke="#16a34a"
            strokeWidth="2.5"
            markerEnd="url(#cert-arrow-refer)"
          />
          {/* Label Badge 1 */}
          <rect
            x="295"
            y="185"
            width="58"
            height="24"
            rx="12"
            fill="#dcfce7"
            stroke="#16a34a"
            strokeWidth="1"
            className="dark:fill-emerald-950 dark:stroke-emerald-500"
          />
          <text
            x="324"
            y="201"
            textAnchor="middle"
            fontSize="12"
            fontWeight="bold"
            fill="#15803d"
            className="dark:fill-emerald-300"
          >
            Refer
          </text>

          {/* Intermediate Root CA DN -> Root Root CA DN */}
          <line
            x1="624"
            y1="303"
            x2="794"
            y2="303"
            stroke="#16a34a"
            strokeWidth="2.5"
            markerEnd="url(#cert-arrow-refer)"
          />
          {/* Label Badge 2 */}
          <rect
            x="685"
            y="291"
            width="58"
            height="24"
            rx="12"
            fill="#dcfce7"
            stroke="#16a34a"
            strokeWidth="1"
            className="dark:fill-emerald-950 dark:stroke-emerald-500"
          />
          <text
            x="714"
            y="307"
            textAnchor="middle"
            fontSize="12"
            fontWeight="bold"
            fill="#15803d"
            className="dark:fill-emerald-300"
          >
            Refer
          </text>
        </g>

        {/* 2. RED "VERIFY" PATHS (Parent Public Key -> Child Signature) */}
        <g
          id="paths-verify"
          className={cn("transition-opacity duration-300", isVerifyActive ? "opacity-100" : "opacity-20")}
        >
          {/* Intermediate Public Key -> Website Issuer Signature */}
          <line
            x1="414"
            y1="250"
            x2="244"
            y2="250"
            stroke="#dc2626"
            strokeWidth="2.5"
            markerEnd="url(#cert-arrow-verify)"
          />
          {/* Label Badge 1 */}
          <rect
            x="295"
            y="238"
            width="58"
            height="24"
            rx="12"
            fill="#ffe4e6"
            stroke="#dc2626"
            strokeWidth="1"
            className="dark:fill-rose-950 dark:stroke-rose-500"
          />
          <text
            x="324"
            y="254"
            textAnchor="middle"
            fontSize="12"
            fontWeight="bold"
            fill="#be123c"
            className="dark:fill-rose-300"
          >
            Verify
          </text>

          {/* Root Root CA Public Key -> Intermediate Root CA Signature */}
          <line
            x1="804"
            y1="356"
            x2="634"
            y2="356"
            stroke="#dc2626"
            strokeWidth="2.5"
            markerEnd="url(#cert-arrow-verify)"
          />
          {/* Label Badge 2 */}
          <rect
            x="685"
            y="344"
            width="58"
            height="24"
            rx="12"
            fill="#ffe4e6"
            stroke="#dc2626"
            strokeWidth="1"
            className="dark:fill-rose-950 dark:stroke-rose-500"
          />
          <text
            x="714"
            y="360"
            textAnchor="middle"
            fontSize="12"
            fontWeight="bold"
            fill="#be123c"
            className="dark:fill-rose-300"
          >
            Verify
          </text>
        </g>

        {/* 3. PURPLE "SIGN" & "SELF-SIGN" PATHS (Parent Private Key -> Child Signature) */}
        <g
          id="paths-sign"
          className={cn("transition-opacity duration-300", isSignActive ? "opacity-100" : "opacity-20")}
        >
          {/* Sign 1: Issuer Private Key -> Website Signature */}
          <path
            d="M 249 378 L 129 378 L 129 278"
            stroke="#9333ea"
            strokeWidth="2.2"
            strokeDasharray="5,4"
            markerEnd="url(#cert-arrow-sign)"
          />
          {/* Shielded badge pill for Sign 1 */}
          <rect
            x="106"
            y="317"
            width="46"
            height="22"
            rx="11"
            fill="white"
            stroke="#9333ea"
            strokeWidth="1.2"
            className="dark:fill-slate-900 dark:stroke-purple-500"
          />
          <text
            x="129"
            y="332"
            textAnchor="middle"
            className="fill-purple-900 font-sans text-[11px] font-bold dark:fill-purple-300"
          >
            Sign
          </text>

          {/* Sign 2: Root CA Private Key -> Intermediate Signature */}
          <path
            d="M 639 501 L 519 501 L 519 384"
            stroke="#9333ea"
            strokeWidth="2.2"
            strokeDasharray="5,4"
            markerEnd="url(#cert-arrow-sign)"
          />
          {/* Shielded badge pill for Sign 2 */}
          <rect
            x="496"
            y="427"
            width="46"
            height="22"
            rx="11"
            fill="white"
            stroke="#9333ea"
            strokeWidth="1.2"
            className="dark:fill-slate-900 dark:stroke-purple-500"
          />
          <text
            x="519"
            y="442"
            textAnchor="middle"
            className="fill-purple-900 font-sans text-[11px] font-bold dark:fill-purple-300"
          >
            Sign
          </text>

          {/* Self-sign 3: Root CA Private Key -> Root CA Signature */}
          <path
            d="M 789 501 L 909 501 L 909 438"
            stroke="#9333ea"
            strokeWidth="2.2"
            strokeDasharray="5,4"
            markerEnd="url(#cert-arrow-sign)"
          />
          {/* Shielded badge pill for Self-sign 3 */}
          <rect
            x="877"
            y="457"
            width="64"
            height="22"
            rx="11"
            fill="white"
            stroke="#9333ea"
            strokeWidth="1.2"
            className="dark:fill-slate-900 dark:stroke-purple-500"
          />
          <text
            x="909"
            y="472"
            textAnchor="middle"
            className="fill-purple-900 font-sans text-[11px] font-bold dark:fill-purple-300"
          >
            Self-sign
          </text>
        </g>
      </svg>
    </div>
  );
}

function CertificateHierarchyTierVisual() {
  return (
    <div className="flex flex-col space-y-3 py-2">
      {/* Tier 1: Root Certificate */}
      <div className="flex flex-col items-start">
        <div className="w-full max-w-md rounded-2xl border border-teal-600/40 bg-gradient-to-br from-[#1d5b6a] to-[#144450] p-4 text-white shadow-md shadow-teal-950/20 sm:p-5">
          <div className="flex items-center justify-between gap-2 border-b border-white/15 pb-2.5">
            <div className="flex items-center gap-2">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-teal-500/30 text-teal-200 ring-1 ring-white/20">
                <DiagramIcon name="shield" />
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wider text-teal-200">
                Tier 1 · Offline Trust Anchor
              </span>
            </div>
            <span className="rounded-full bg-teal-400/20 px-2.5 py-0.5 text-[10px] font-bold tracking-wide text-teal-100 ring-1 ring-teal-400/30">
              Self-Signed
            </span>
          </div>

          <div className="mt-3">
            <h3 className="text-base font-extrabold tracking-tight sm:text-lg">
              Root Certificate
            </h3>
            <p className="mt-1 text-xs leading-relaxed text-teal-100/90">
              Pre-installed in OS and browser trust stores (e.g. Chrome Root Store, Mozilla NSS, Apple Keychain). Private key is locked offline inside an air-gapped HSM vault.
            </p>
          </div>

          <div className="mt-3 flex flex-wrap gap-1.5 border-t border-white/10 pt-2 text-[10px]">
            <span className="rounded-md bg-black/20 px-2 py-0.5 font-mono text-teal-200">
              Subject = Issuer
            </span>
            <span className="rounded-md bg-black/20 px-2 py-0.5 font-mono text-teal-200">
              BasicConstraints: CA:TRUE
            </span>
          </div>
        </div>
      </div>

      {/* Connector 1: Root -> Intermediate */}
      <div className="flex items-center gap-3 py-1 pl-6 sm:pl-10 md:pl-16">
        <svg
          className="h-14 w-12 shrink-0 text-slate-500 dark:text-slate-400"
          viewBox="0 0 48 56"
          fill="none"
          aria-hidden="true"
        >
          <path
            d="M12 0 v36 h24"
            stroke="currentColor"
            strokeWidth="5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path d="M32 26 l12 10 -12 10 z" fill="currentColor" />
        </svg>
        <div className="rounded-xl border border-slate-200 bg-slate-100/90 px-3.5 py-2 text-xs font-medium text-slate-800 shadow-xs dark:border-slate-700/80 dark:bg-slate-800/90 dark:text-slate-200">
          <span className="font-bold text-slate-900 dark:text-white">
            (The root CA certificate&apos;s private key signs the intermediate certificate).
          </span>
          <span className="mt-0.5 block text-[10px] text-slate-600 dark:text-slate-400">
            Binds parent AKI (Authority Key ID) to child SKI (Subject Key ID)
          </span>
        </div>
      </div>

      {/* Tier 2: Intermediate Certificate */}
      <div className="flex flex-col items-center md:items-start md:pl-20 lg:pl-32">
        <div className="w-full max-w-md rounded-2xl border border-orange-500/40 bg-gradient-to-br from-[#f26532] to-[#c74c1f] p-4 text-white shadow-md shadow-orange-950/20 sm:p-5">
          <div className="flex items-center justify-between gap-2 border-b border-white/15 pb-2.5">
            <div className="flex items-center gap-2">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-white/20 text-white ring-1 ring-white/20">
                <DiagramIcon name="certificate" />
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wider text-orange-100">
                Tier 2 · Online Sub-CA
              </span>
            </div>
            <span className="rounded-full bg-white/20 px-2.5 py-0.5 text-[10px] font-bold tracking-wide text-white ring-1 ring-white/30">
              CA: TRUE
            </span>
          </div>

          <div className="mt-3">
            <h3 className="text-base font-extrabold tracking-tight sm:text-lg">
              Intermediate Certificate
            </h3>
            <p className="mt-1 text-xs leading-relaxed text-orange-100/95">
              Online operational CA that issues day-to-day web certificates. Protects the Root by isolating risk: if compromised, only this intermediate is revoked.
            </p>
          </div>

          <div className="mt-3 flex flex-wrap gap-1.5 border-t border-white/10 pt-2 text-[10px]">
            <span className="rounded-md bg-black/20 px-2 py-0.5 font-mono text-orange-200">
              Issuer: Root CA
            </span>
            <span className="rounded-md bg-black/20 px-2 py-0.5 font-mono text-orange-200">
              Sent by server in TLS
            </span>
          </div>
        </div>
      </div>

      {/* Connector 2: Intermediate -> Server Leaf */}
      <div className="flex items-center gap-3 py-1 pl-12 sm:pl-20 md:pl-36 lg:pl-48">
        <svg
          className="h-14 w-12 shrink-0 text-slate-500 dark:text-slate-400"
          viewBox="0 0 48 56"
          fill="none"
          aria-hidden="true"
        >
          <path
            d="M12 0 v36 h24"
            stroke="currentColor"
            strokeWidth="5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path d="M32 26 l12 10 -12 10 z" fill="currentColor" />
        </svg>
        <div className="rounded-xl border border-slate-200 bg-slate-100/90 px-3.5 py-2 text-xs font-medium text-slate-800 shadow-xs dark:border-slate-700/80 dark:bg-slate-800/90 dark:text-slate-200">
          <span className="font-bold text-slate-900 dark:text-white">
            (The intermediate CA certificate&apos;s private key signs the server certificate).
          </span>
          <span className="mt-0.5 block text-[10px] text-slate-600 dark:text-slate-400">
            Binds server public key to domain Subject Alternative Names (SANs)
          </span>
        </div>
      </div>

      {/* Tier 3: Leaf (SSL/TLS) Certificate */}
      <div className="flex flex-col items-end">
        <div className="w-full max-w-md rounded-2xl border border-cyan-500/40 bg-gradient-to-br from-[#5da7b3] to-[#397883] p-4 text-white shadow-md shadow-cyan-950/20 sm:p-5">
          <div className="flex items-center justify-between gap-2 border-b border-white/15 pb-2.5">
            <div className="flex items-center gap-2">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-white/20 text-white ring-1 ring-white/20">
                <DiagramIcon name="server" />
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-100">
                Tier 3 · Leaf / End-Entity
              </span>
            </div>
            <span className="rounded-full bg-white/20 px-2.5 py-0.5 text-[10px] font-bold tracking-wide text-white ring-1 ring-white/30">
              CA: FALSE
            </span>
          </div>

          <div className="mt-3">
            <h3 className="text-base font-extrabold tracking-tight sm:text-lg">
              (SSL/TLS) Certificate
            </h3>
            <p className="mt-1 text-xs leading-relaxed text-cyan-100/95">
              Installed directly on Bob&apos;s web server. Binds the server&apos;s public key to verified hostnames (SANs). Presented to Alice&apos;s browser upon connection.
            </p>
          </div>

          <div className="mt-3 flex flex-wrap gap-1.5 border-t border-white/10 pt-2 text-[10px]">
            <span className="rounded-md bg-black/20 px-2 py-0.5 font-mono text-cyan-100">
              Issuer: Intermediate CA
            </span>
            <span className="rounded-md bg-black/20 px-2 py-0.5 font-mono text-cyan-100">
              SAN: bank.example
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

function RootStoreDistributionVisual() {
  const [selectedOS, setSelectedOS] = useState<string>("all");

  const OS_STORES = [
    {
      id: "windows",
      name: "Microsoft Windows",
      shortName: "Windows",
      storeType: "Crypt32",
      icon: "🪟",
      desc: "Windows Root Certificate Program (stored in Crypt32 registry & certmgr.msc).",
      updater: "Updated via Windows Update automatically as Microsoft adds/removes trusted CAs.",
    },
    {
      id: "apple",
      name: "Apple (macOS / iOS)",
      shortName: "Apple",
      storeType: "Keychain",
      icon: "🍎",
      desc: "Apple Trust Store (managed by System Security Framework and Keychain Access).",
      updater: "Bundled directly into iOS and macOS system security updates.",
    },
    {
      id: "linux",
      name: "Linux Distributions",
      shortName: "Linux",
      storeType: "ca-certificates",
      icon: "🐧",
      desc: "Managed via ca-certificates package (located at /etc/ssl/certs / OpenSSL anchors).",
      updater: "Debian, Ubuntu, Fedora package managers update the bundle via apt/dnf.",
    },
    {
      id: "chrome",
      name: "Google Chrome",
      shortName: "Chrome",
      storeType: "Chrome Store",
      icon: "🌐",
      desc: "Chrome Root Store (CRS), independently curated across desktop & Android.",
      updater: "Updated dynamically via Chrome component updates without requiring OS reboots.",
    },
    {
      id: "firefox",
      name: "Mozilla Firefox",
      shortName: "Firefox",
      storeType: "Mozilla NSS",
      icon: "🦊",
      desc: "Mozilla Network Security Services (NSS) — the most open, community-audited store.",
      updater: "Maintains its own independent root list; powers Firefox, Thunderbird, and Tor Browser.",
    },
    {
      id: "android",
      name: "Google Android",
      shortName: "Android",
      storeType: "System CA",
      icon: "🤖",
      desc: "Android System CA Store (/system/etc/security/cacerts).",
      updater: "Updated via Google Play System Updates (Project Mainline) on Android 10+.",
    },
  ];

  return (
    <div className="space-y-4">
      {/* Top Banner & Context */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-violet-200 bg-violet-50/60 p-3 text-xs dark:border-violet-900/60 dark:bg-violet-950/30">
        <div className="flex items-center gap-2">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-violet-600 text-sm font-bold text-white shadow-xs">
            🔐
          </span>
          <div>
            <h4 className="font-bold text-violet-950 dark:text-violet-200">
              How Root Certificates Are Born &amp; Distributed
            </h4>
            <p className="text-[11px] text-violet-800/90 dark:text-violet-300/90">
              Root CAs have no parent authority. They self-sign their own keys and are shipped inside operating system software.
            </p>
          </div>
        </div>

        <span className="rounded-full bg-violet-200/80 px-2.5 py-0.5 text-[10px] font-bold text-violet-900 dark:bg-violet-900/80 dark:text-violet-200">
          The Ultimate Trust Anchor
        </span>
      </div>

      {/* Main Visual Canvas: 3-Stage Balanced Pipeline */}
      <div className="rounded-2xl border border-slate-200 bg-slate-50/50 p-4 sm:p-5 dark:border-white/10 dark:bg-slate-900/40">
        <div className="grid gap-4 lg:grid-cols-3 items-stretch">
          {/* Column 1: CA Data Center & Vault (Creation) */}
          <div className="flex flex-col justify-between rounded-xl border border-purple-200 bg-white p-4 shadow-xs dark:border-purple-900/60 dark:bg-slate-900">
            <div>
              <div className="flex items-center gap-3 border-b border-purple-100 pb-3 dark:border-purple-900/40">
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-purple-100 text-xl dark:bg-purple-950">
                  🏛️
                </span>
                <div>
                  <span className="inline-block rounded bg-purple-100 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-purple-800 dark:bg-purple-950 dark:text-purple-300">
                    Stage 1 · Offline Vault
                  </span>
                  <h4 className="mt-0.5 text-sm font-bold text-slate-900 dark:text-white">
                    VeriSign CA Data Center
                  </h4>
                </div>
              </div>

              {/* Private Key Box */}
              <div className="mt-4 rounded-xl border-2 border-purple-300 bg-purple-50/70 p-3.5 dark:border-purple-700 dark:bg-purple-950/40">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-purple-950 dark:text-purple-200">
                    Root CA Private Key
                  </span>
                  <span className="text-base">🗝️</span>
                </div>
                <p className="mt-1 text-xs leading-relaxed text-purple-900/90 dark:text-purple-300/90">
                  Generated inside an air-gapped Hardware Security Module (HSM). Never touches any network.
                </p>
                <div className="mt-2.5 flex items-center justify-between text-[10px] font-semibold text-purple-800 dark:text-purple-300">
                  <span className="rounded bg-purple-200/80 px-2 py-0.5 dark:bg-purple-900 dark:text-purple-200">
                    FIPS 140-2 Level 3/4
                  </span>
                  <span>M-of-N Shamir Cards</span>
                </div>
              </div>

              {/* Self-sign Action indicator */}
              <div className="mt-4 flex items-center justify-center gap-2 rounded-xl border border-dashed border-purple-400 bg-purple-50/60 p-2.5 text-xs font-bold text-purple-800 dark:border-purple-700 dark:bg-purple-950/40 dark:text-purple-300">
                <span>✍️ Self-signs certificate</span>
                <span className="text-sm">➔</span>
              </div>
            </div>

            <p className="mt-4 border-t border-slate-100 pt-3 text-[11px] leading-relaxed text-slate-500 dark:border-slate-800 dark:text-slate-400">
              The master key remains permanently locked inside an offline vault, awakened only during formal audited Key Ceremonies.
            </p>
          </div>

          {/* Column 2: The Self-Signed Root Certificate Card */}
          <div className="flex flex-col justify-between rounded-xl border-2 border-purple-300/80 bg-white p-4 shadow-xs ring-1 ring-purple-400/20 dark:border-purple-700/80 dark:bg-slate-900">
            <div>
              <div className="flex items-center gap-3 border-b border-slate-100 pb-3 dark:border-slate-800">
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-amber-100 text-xl dark:bg-amber-950">
                  📜
                </span>
                <div>
                  <span className="inline-block rounded bg-amber-100 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-amber-900 dark:bg-amber-950 dark:text-amber-300">
                    Stage 2 · Trust Anchor
                  </span>
                  <h4 className="mt-0.5 text-sm font-bold text-slate-900 dark:text-white">
                    VeriSign Root Certificate
                  </h4>
                </div>
              </div>

              {/* 3 Structured Sections matching the diagram */}
              <div className="mt-3 space-y-2">
                {/* 1. Distinguished Name (Green) */}
                <div className="rounded-xl border border-emerald-300 bg-emerald-50/80 p-2.5 dark:border-emerald-800 dark:bg-emerald-950/40">
                  <span className="block text-[10px] font-bold uppercase tracking-wider text-emerald-800 dark:text-emerald-300">
                    VeriSign Distinguished Name
                  </span>
                  <p className="mt-0.5 font-mono text-xs font-bold text-emerald-950 dark:text-emerald-200">
                    CN=VeriSign Class 3 Root CA
                  </p>
                  <p className="text-[10px] text-emerald-700 dark:text-emerald-400">
                    Issuer: CN=VeriSign Class 3 Root CA (Self)
                  </p>
                </div>

                {/* 2. Public Key (Yellow/Amber) */}
                <div className="rounded-xl border border-amber-300 bg-amber-50/80 p-2.5 dark:border-amber-800 dark:bg-amber-950/40">
                  <div className="flex items-center justify-between">
                    <span className="block text-[10px] font-bold uppercase tracking-wider text-amber-800 dark:text-amber-300">
                      Root CA Public Key
                    </span>
                    <span className="text-sm">🔑</span>
                  </div>
                  <p className="mt-0.5 font-mono text-xs font-bold text-amber-950 dark:text-amber-200">
                    RSA 4096-bit (e=65537)
                  </p>
                  <p className="text-[10px] text-amber-700 dark:text-amber-400">
                    Distributed to verify Intermediate CA signatures
                  </p>
                </div>

                {/* 3. Signature (Red/Rose) */}
                <div className="rounded-xl border border-rose-300 bg-rose-50/80 p-2.5 dark:border-rose-800 dark:bg-rose-950/40">
                  <div className="flex items-center justify-between">
                    <span className="block text-[10px] font-bold uppercase tracking-wider text-rose-800 dark:text-rose-300">
                      Root CA Signature
                    </span>
                    <span className="text-sm">🏷️</span>
                  </div>
                  <p className="mt-0.5 font-mono text-xs font-bold text-rose-950 dark:text-rose-200">
                    SHA-256 with RSA Signature
                  </p>
                  <p className="text-[10px] text-rose-700 dark:text-rose-400">
                    Signed with Root CA&apos;s <strong>OWN</strong> private key
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-3 flex items-center justify-center gap-1.5 rounded-lg border border-purple-200 bg-purple-50/60 p-2 text-center text-[10px] font-bold text-purple-900 dark:border-purple-900/60 dark:bg-purple-950/40 dark:text-purple-300">
              <span>⚓</span> Definition of Root: Issuer == Subject
            </div>
          </div>

          {/* Column 3: OS & Browser Trust Stores (Distribution) */}
          <div className="flex flex-col justify-between rounded-xl border border-sky-200 bg-white p-4 shadow-xs dark:border-sky-900/60 dark:bg-slate-900">
            <div>
              <div className="flex items-center gap-3 border-b border-sky-100 pb-3 dark:border-sky-900/40">
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-sky-100 text-xl dark:bg-sky-950">
                  💻
                </span>
                <div>
                  <span className="inline-block rounded bg-sky-100 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-sky-800 dark:bg-sky-950 dark:text-sky-300">
                    Stage 3 · Factory Pre-Installed
                  </span>
                  <h4 className="mt-0.5 text-sm font-bold text-slate-900 dark:text-white">
                    OS &amp; Browser Trust Stores
                  </h4>
                </div>
              </div>

              <p className="mt-3 text-[11px] leading-relaxed text-slate-600 dark:text-slate-400">
                Operating systems and browsers ship with a <strong>pre-installed list</strong> of trusted root certificates before leaving the factory.
              </p>

              {/* Ecosystem Grid */}
              <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">
                {OS_STORES.map((os) => (
                  <button
                    key={os.id}
                    type="button"
                    onClick={() => setSelectedOS(selectedOS === os.id ? "all" : os.id)}
                    className={cn(
                      "flex flex-col items-center justify-center rounded-lg border p-2 text-center transition-all",
                      selectedOS === os.id
                        ? "border-sky-500 bg-sky-50 shadow-xs ring-2 ring-sky-500/20 dark:border-sky-500 dark:bg-sky-950/60"
                        : "border-slate-200 bg-slate-50/70 hover:bg-slate-100 dark:border-slate-800 dark:bg-slate-800/40 dark:hover:bg-slate-800",
                    )}
                  >
                    <span className="text-xl">{os.icon}</span>
                    <span className="mt-1 text-xs font-bold text-slate-800 dark:text-slate-200">
                      {os.shortName}
                    </span>
                    <span className="text-[10px] text-slate-500 dark:text-slate-400">
                      {os.storeType}
                    </span>
                  </button>
                ))}
              </div>

              {/* OS detail tooltip */}
              {selectedOS !== "all" && (
                <div className="mt-3 rounded-lg border border-sky-300 bg-sky-50 p-2.5 text-[11px] text-sky-950 dark:border-sky-800 dark:bg-sky-950/70 dark:text-sky-200">
                  {(() => {
                    const os = OS_STORES.find((o) => o.id === selectedOS);
                    if (!os) return null;
                    return (
                      <>
                        <div className="flex items-center gap-1.5 font-bold">
                          <span>{os.icon}</span> {os.name} Store:
                        </div>
                        <p className="mt-1 text-slate-700 dark:text-slate-300">{os.desc}</p>
                        <p className="mt-1 text-[10px] font-semibold text-sky-700 dark:text-sky-300">
                          🔄 {os.updater}
                        </p>
                      </>
                    );
                  })()}
                </div>
              )}
            </div>

            <div className="mt-3 rounded-lg bg-slate-50 p-2 text-[10px] leading-relaxed text-slate-600 dark:bg-slate-800/60 dark:text-slate-300 border-t border-slate-100 dark:border-slate-800">
              <strong className="text-slate-900 dark:text-white">Why servers omit root certs: </strong>
              Clients never trust a Root CA sent over the network—only roots already in this local database are trusted.
            </div>
          </div>
        </div>

        {/* Bottom Takeaway Card: Answering the user's core question */}
        <div className="mt-4 rounded-xl border border-amber-300/80 bg-amber-50/70 p-3.5 text-xs text-amber-950 dark:border-amber-800/80 dark:bg-amber-950/30 dark:text-amber-200">
          <div className="flex items-start gap-2">
            <span className="mt-0.5 text-base">💡</span>
            <div className="space-y-1">
              <strong className="block text-amber-900 dark:text-amber-100 font-bold">
                Why does self-signing work for a Root CA?
              </strong>
              <p className="leading-relaxed">
                If anyone can create a self-signed certificate on their laptop claiming to be &quot;VeriSign&quot;, why doesn&apos;t that break security? Because your computer does <strong>NOT</strong> trust the signature itself—your computer trusts the <strong>pre-installed public key</strong> that was audited and shipped inside Windows, macOS, Linux, Chrome, and Firefox before the computer ever connected to the internet!
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function CertificateChainDiagram() {
  const [activeTab, setActiveTab] = useState<"fields" | "hierarchy" | "root-store">("fields");
  const [pathFilter, setPathFilter] = useState<CertificatePathFilter>("all");

  return (
    <DiagramFrame
      id="certificate-chain"
      eyebrow="X.509 PKI · Hierarchical Trust Model"
      title="Certificate Chain of Trust: Signing & Path Verification"
      property="Hierarchical Authentication"
      tone="emerald"
      caption={
        <>
          Root CAs sign intermediate certificates and remain offline in secure vaults.
          Intermediate CAs sign leaf certificates for web servers. When Alice connects over HTTPS,
          her client validates the signatures in reverse—building an unbroken path back to an installed Root anchor.
        </>
      }
    >
      {/* Top View Mode Switcher */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-3 dark:border-white/10">
        <div className="flex items-center gap-1.5 rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80">
          <button
            type="button"
            onClick={() => setActiveTab("fields")}
            className={cn(
              "rounded-md px-3 py-1.5 text-xs font-semibold transition-all",
              activeTab === "fields"
                ? "bg-white text-emerald-800 shadow-xs dark:bg-slate-700 dark:text-emerald-300"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            🔬 Field Anatomy &amp; Verification Map
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("hierarchy")}
            className={cn(
              "rounded-md px-3 py-1.5 text-xs font-semibold transition-all",
              activeTab === "hierarchy"
                ? "bg-white text-teal-800 shadow-xs dark:bg-slate-700 dark:text-teal-300"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            🏛️ Trust Tiers &amp; Blast Radius
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("root-store")}
            className={cn(
              "rounded-md px-3 py-1.5 text-xs font-semibold transition-all",
              activeTab === "root-store"
                ? "bg-white text-purple-800 shadow-xs dark:bg-slate-700 dark:text-purple-300"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            💾 Root Store Distribution (OS &amp; Browsers)
          </button>
        </div>

        {activeTab === "fields" && (
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Highlight:
            </span>
            <button
              type="button"
              onClick={() => setPathFilter("all")}
              className={cn(
                "rounded-md px-2.5 py-1 text-[11px] font-semibold transition-all",
                pathFilter === "all"
                  ? "bg-slate-900 text-white dark:bg-white dark:text-slate-900 shadow-xs"
                  : "bg-slate-100 text-slate-700 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700",
              )}
            >
              All Pathways
            </button>
            <button
              type="button"
              onClick={() => setPathFilter("refer")}
              className={cn(
                "rounded-md px-2.5 py-1 text-[11px] font-semibold transition-all",
                pathFilter === "refer"
                  ? "bg-emerald-600 text-white shadow-xs"
                  : "bg-emerald-50 text-emerald-800 hover:bg-emerald-100 dark:bg-emerald-950/60 dark:text-emerald-300",
              )}
            >
              🟢 Refer (Names)
            </button>
            <button
              type="button"
              onClick={() => setPathFilter("verify")}
              className={cn(
                "rounded-md px-2.5 py-1 text-[11px] font-semibold transition-all",
                pathFilter === "verify"
                  ? "bg-rose-600 text-white shadow-xs"
                  : "bg-rose-50 text-rose-800 hover:bg-rose-100 dark:bg-rose-950/60 dark:text-rose-300",
              )}
            >
              🔴 Verify (Public Keys)
            </button>
            <button
              type="button"
              onClick={() => setPathFilter("sign")}
              className={cn(
                "rounded-md px-2.5 py-1 text-[11px] font-semibold transition-all",
                pathFilter === "sign"
                  ? "bg-purple-600 text-white shadow-xs"
                  : "bg-purple-50 text-purple-800 hover:bg-purple-100 dark:bg-purple-950/60 dark:text-purple-300",
              )}
            >
              🟣 Sign (Private Keys)
            </button>
          </div>
        )}
      </div>

      {activeTab === "fields" ? (
        <>
          <CertificateFieldVerificationVisual filter={pathFilter} />

          {/* Interactive Legend / Explanatory Guide */}
          <div className="mt-4 grid gap-2.5 sm:grid-cols-3">
            <div className="rounded-xl border border-emerald-300/80 bg-emerald-50/70 p-3 text-xs text-emerald-950 dark:border-emerald-800/80 dark:bg-emerald-950/40 dark:text-emerald-200">
              <div className="flex items-center gap-1.5 font-bold uppercase tracking-wide text-emerald-800 dark:text-emerald-300">
                <span className="inline-block h-2.5 w-2.5 rounded-full bg-emerald-500" />
                1. Refer (Name Binding)
              </div>
              <p className="mt-1 text-[11px] leading-relaxed text-emerald-900/90 dark:text-emerald-300/90">
                The child certificate carries the parent&apos;s identity in its <strong>Issuer Distinguished Name</strong> field (and AKI extension) to specify which certificate issued it.
              </p>
            </div>

            <div className="rounded-xl border border-rose-300/80 bg-rose-50/70 p-3 text-xs text-rose-950 dark:border-rose-800/80 dark:bg-rose-950/40 dark:text-rose-200">
              <div className="flex items-center gap-1.5 font-bold uppercase tracking-wide text-rose-800 dark:text-rose-300">
                <span className="inline-block h-2.5 w-2.5 rounded-full bg-rose-500" />
                2. Verify (Public Key)
              </div>
              <p className="mt-1 text-[11px] leading-relaxed text-rose-900/90 dark:text-rose-300/90">
                The client extracts the parent&apos;s <strong>Public Key</strong> and cryptographically validates the child&apos;s digital signature over its payload bytes.
              </p>
            </div>

            <div className="rounded-xl border border-purple-300/80 bg-purple-50/70 p-3 text-xs text-purple-950 dark:border-purple-800/80 dark:bg-purple-950/40 dark:text-purple-200">
              <div className="flex items-center gap-1.5 font-bold uppercase tracking-wide text-purple-800 dark:text-purple-300">
                <span className="inline-block h-2.5 w-2.5 rounded-full bg-purple-500" />
                3. Sign &amp; Self-Sign
              </div>
              <p className="mt-1 text-[11px] leading-relaxed text-purple-900/90 dark:text-purple-300/90">
                Only the parent CA holds the <strong>Private Key</strong> needed to issue signatures. The Root CA self-signs its own anchor certificate.
              </p>
            </div>
          </div>
        </>
      ) : activeTab === "hierarchy" ? (
        <CertificateHierarchyTierVisual />
      ) : (
        <RootStoreDistributionVisual />
      )}
    </DiagramFrame>
  );
}

function MtlsDiagram() {
  const [mode, setMode] = useState<"mtls" | "oneway">("mtls");

  return (
    <DiagramFrame
      id="mtls"
      eyebrow="Mutual Transport Layer Security · RFC 8446"
      title="mTLS: Two-Way Cryptographic Handshake"
      property="Mutual Authentication"
      tone="violet"
      caption={
        <>
          In standard HTTPS, only the server presents a certificate. In mutual TLS (mTLS),
          both client and server exchange certificates and cryptographically prove private key ownership,
          establishing two-way trust before any application data is sent.
        </>
      }
    >
      {/* Mode Switcher */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-3 dark:border-white/10">
        <div className="flex items-center gap-1.5 rounded-xl bg-slate-100 p-1 dark:bg-slate-800/80">
          <button
            type="button"
            onClick={() => setMode("mtls")}
            className={cn(
              "rounded-lg px-3.5 py-1.5 text-xs font-bold transition-all",
              mode === "mtls"
                ? "bg-purple-600 text-white shadow-xs"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            🔄 Mutual TLS (Two-Way Auth)
          </button>
          <button
            type="button"
            onClick={() => setMode("oneway")}
            className={cn(
              "rounded-lg px-3.5 py-1.5 text-xs font-bold transition-all",
              mode === "oneway"
                ? "bg-slate-800 text-white shadow-xs dark:bg-slate-700"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            🔒 Standard TLS (One-Way Server Auth)
          </button>
        </div>

        <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
          {mode === "mtls" ? "Both parties verify each other" : "Only the server proves its identity"}
        </span>
      </div>

      {/* Main Diagram Canvas */}
      <div className="rounded-2xl border border-slate-200 bg-slate-50/50 p-4 sm:p-5 dark:border-white/10 dark:bg-slate-900/40">
        <div className="grid gap-4 lg:grid-cols-12 items-stretch">
          {/* Entity 1: Alice (Client) */}
          <div className="lg:col-span-3 flex flex-col items-center text-center justify-between rounded-2xl border border-sky-300/80 bg-white p-4 shadow-xs dark:border-sky-800 dark:bg-slate-900">
            <div>
              <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-sky-100 text-2xl dark:bg-sky-950/80">
                👩‍💻
              </span>
              <h4 className="mt-2 text-sm font-bold text-slate-900 dark:text-white">
                Alice (Client)
              </h4>
              <p className="text-[11px] text-sky-700 dark:text-sky-300 font-medium">
                Browser / Microservice / IoT Device
              </p>
            </div>

            <div className="mt-3 w-full space-y-2 border-t border-slate-100 pt-3 dark:border-slate-800 text-left text-xs">
              <div className="rounded-lg bg-slate-50 p-2 dark:bg-slate-800/60">
                <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Holds Credential:
                </span>
                <p className="font-semibold text-slate-800 dark:text-slate-200 text-xs">
                  {mode === "mtls" ? "📜 Client Certificate" : "❌ No Certificate"}
                </p>
                {mode === "mtls" && (
                  <span className="text-[10px] text-purple-700 dark:text-purple-300 font-mono font-semibold">
                    EKU: clientAuth
                  </span>
                )}
              </div>

              <div className="rounded-lg bg-emerald-50 p-2 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/60">
                <span className="block text-[10px] font-bold uppercase tracking-wider text-emerald-800 dark:text-emerald-300">
                  Verification Status:
                </span>
                <p className="text-xs font-bold text-emerald-700 dark:text-emerald-300">
                  ✅ Server Verified
                </p>
              </div>
            </div>
          </div>

          {/* Center: The Handshake Channels */}
          <div className="lg:col-span-6 flex flex-col justify-center space-y-3">
            {/* Flow 1: Server Authentication (Bob -> Alice) */}
            <div className="rounded-xl border border-emerald-300 bg-white p-3.5 shadow-xs dark:border-emerald-800 dark:bg-slate-900">
              <div className="flex items-center justify-between text-xs font-bold text-emerald-800 dark:text-emerald-300">
                <span>◀ 1. Server Certificate</span>
                <span className="rounded bg-emerald-100 px-2 py-0.5 text-[10px] uppercase font-bold text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300">
                  Bob ➔ Alice
                </span>
              </div>
              <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                Bob sends his <strong>Server Certificate</strong> and proves ownership with his private key. Alice checks his identity against her Root CA store.
              </p>
              <div className="mt-2 flex items-start gap-1.5 text-xs font-semibold text-emerald-700 dark:text-emerald-300">
                <span className="mt-1 inline-block h-2 w-2 shrink-0 rounded-full bg-emerald-500" />
                <p className="leading-snug">
                  Alice confirms: &quot;I am connected to Bob&apos;s real server.&quot;
                </p>
              </div>
            </div>

            {/* Flow 2: Client Authentication (Alice -> Bob) */}
            {mode === "mtls" ? (
              <div className="rounded-xl border border-purple-300 bg-white p-3.5 shadow-xs dark:border-purple-800 dark:bg-slate-900">
                <div className="flex items-center justify-between text-xs font-bold text-purple-800 dark:text-purple-300">
                  <span>2. Client Certificate + Proof ▶</span>
                  <span className="rounded bg-purple-100 px-2 py-0.5 text-[10px] uppercase font-bold text-purple-800 dark:bg-purple-950 dark:text-purple-300">
                    Alice ➔ Bob
                  </span>
                </div>
                <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                  Bob asks <code>CertificateRequest</code>. Alice returns her <strong>Client Certificate</strong> and signs the session transcript in <code>CertificateVerify</code>.
                </p>
                <div className="mt-2 flex items-start gap-1.5 text-xs font-semibold text-purple-700 dark:text-purple-300">
                  <span className="mt-1 inline-block h-2 w-2 shrink-0 rounded-full bg-purple-500" />
                  <p className="leading-snug">
                    Bob confirms: &quot;Alice holds the authorized client key.&quot;
                  </p>
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-dashed border-rose-300 bg-rose-50/50 p-3.5 dark:border-rose-800/80 dark:bg-rose-950/20">
                <div className="flex items-center justify-between text-xs font-bold text-rose-800 dark:text-rose-300">
                  <span>❌ No Client Certificate (Standard HTTPS)</span>
                  <span className="rounded bg-rose-100 px-2 py-0.5 text-[10px] uppercase font-bold text-rose-800 dark:bg-rose-900 dark:text-rose-200">
                    Anonymous
                  </span>
                </div>
                <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                  The client sends no certificate. Bob has <strong>no cryptographic proof</strong> of who Alice is at the connection layer.
                </p>
                <div className="mt-2 flex items-start gap-1.5 text-xs font-semibold text-rose-700 dark:text-rose-400">
                  <span className="mt-1 inline-block h-2 w-2 shrink-0 rounded-full bg-rose-500" />
                  <p className="leading-snug">
                    Bob must ask for passwords, cookies, or API keys in HTTP.
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Entity 2: Bob (Server) */}
          <div className="lg:col-span-3 flex flex-col items-center text-center justify-between rounded-2xl border border-emerald-300/80 bg-white p-4 shadow-xs dark:border-emerald-800 dark:bg-slate-900">
            <div>
              <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-100 text-2xl dark:bg-emerald-950/80">
                👨‍💻
              </span>
              <h4 className="mt-2 text-base font-bold text-slate-900 dark:text-white">
                Bob (Server)
              </h4>
              <p className="text-[11px] text-emerald-700 dark:text-emerald-300 font-medium">
                Web Server / API Gateway
              </p>
            </div>

            <div className="mt-3 w-full space-y-2 border-t border-slate-100 pt-3 dark:border-slate-800 text-left text-xs">
              <div className="rounded-lg bg-slate-50 p-2 dark:bg-slate-800/60">
                <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Holds Credential:
                </span>
                <p className="font-semibold text-slate-800 dark:text-slate-200 text-xs">
                  📜 Server Certificate
                </p>
                <span className="text-[10px] text-emerald-700 dark:text-emerald-400 font-mono font-semibold">
                  EKU: serverAuth
                </span>
              </div>

              <div
                className={cn(
                  "rounded-lg p-2 border text-xs font-bold transition-all",
                  mode === "mtls"
                    ? "bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800/60 text-emerald-700 dark:text-emerald-300"
                    : "bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800/60 text-amber-700 dark:text-amber-300",
                )}
              >
                <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Verification Status:
                </span>
                {mode === "mtls" ? "✅ Client Verified" : "⚠️ Client Anonymous"}
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Summary Bar */}
        <div
          className={cn(
            "mt-4 rounded-xl border p-3 text-xs text-center font-medium transition-all",
            mode === "mtls"
              ? "border-purple-300/80 bg-purple-50/80 text-purple-950 dark:border-purple-800/80 dark:bg-purple-950/40 dark:text-purple-200"
              : "border-amber-300/80 bg-amber-50/80 text-amber-950 dark:border-amber-800/80 dark:bg-amber-950/40 dark:text-amber-200",
          )}
        >
          {mode === "mtls" ? (
            <p>
              🤝 <strong>Two-Way Cryptographic Handshake:</strong> Both Alice and Bob hold verified identities. Neither party relies on passwords or static API keys.
            </p>
          ) : (
            <p>
              🔒 <strong>One-Way Authentication:</strong> Alice knows she is connected to Bob, but Bob must trust application passwords or cookies to identify Alice.
            </p>
          )}
        </div>
      </div>
    </DiagramFrame>
  );
}

type AnalogyRole = "all" | "subject" | "credential" | "verifier" | "trust-anchor" | "verification";

function PassportAnalogyDiagram() {
  const [activeTab, setActiveTab] = useState<"both" | "physical" | "digital">("both");
  const [highlightedRole, setHighlightedRole] = useState<AnalogyRole>("all");

  const isRoleActive = (role: AnalogyRole) => highlightedRole === "all" || highlightedRole === role;

  return (
    <DiagramFrame
      id="passport-analogy"
      eyebrow="Real-World Mental Model · X.509 Identity Binding"
      title="Passports vs. Digital Certificates: How Identity is Proven"
      property="Third-Party Trust & Signature Verification"
      tone="sky"
      caption={
        <>
          You never trust an unknown stranger or an arbitrary web server on their word alone.
          In both worlds, a neutral authority (a government or a Certificate Authority) signs the credential.
          The verifier checks that signature using a pre-installed, trusted master key.
        </>
      }
    >
      {/* View Filter & Role Highlighter Tabs */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-3 dark:border-white/10">
        <div className="flex items-center gap-1.5 rounded-xl bg-slate-100 p-1 dark:bg-slate-800/80">
          <button
            type="button"
            onClick={() => setActiveTab("both")}
            className={cn(
              "rounded-lg px-3 py-1.5 text-xs font-bold transition-all",
              activeTab === "both"
                ? "bg-sky-600 text-white shadow-xs"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            👥 Side-by-Side View
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("physical")}
            className={cn(
              "rounded-lg px-3 py-1.5 text-xs font-bold transition-all",
              activeTab === "physical"
                ? "bg-sky-600 text-white shadow-xs"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            🛂 1. Physical World (Passport)
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("digital")}
            className={cn(
              "rounded-lg px-3 py-1.5 text-xs font-bold transition-all",
              activeTab === "digital"
                ? "bg-sky-600 text-white shadow-xs"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            🔒 2. Digital Web (SSL Handshake)
          </button>
        </div>

        <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
          Click any role below to highlight the 1-to-1 parallel
        </span>
      </div>

      <div className="space-y-6">
        {/* ROW 1: Physical World (Passport Check) */}
        {(activeTab === "both" || activeTab === "physical") && (
          <div className="relative rounded-2xl border border-sky-200 bg-sky-50/30 p-4 sm:p-5 dark:border-sky-900/60 dark:bg-sky-950/20">
            <div className="mb-3 flex items-center justify-between">
              <span className="inline-flex items-center gap-1.5 rounded-md bg-sky-100 px-2.5 py-1 text-xs font-bold text-sky-800 dark:bg-sky-900/80 dark:text-sky-300">
                <span>🛂</span> PHYSICAL WORLD: Border Control Checkpoint
              </span>
              <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400">
                Sovereign Trust Model
              </span>
            </div>

            <div className="grid gap-4 lg:grid-cols-12 items-stretch">
              {/* Left: Bob (Traveler) */}
              <div
                className={cn(
                  "lg:col-span-3 flex flex-col items-center justify-between rounded-xl border bg-white p-3.5 text-center shadow-xs transition-all dark:bg-slate-900",
                  isRoleActive("subject")
                    ? "border-sky-400 ring-2 ring-sky-400/40 dark:border-sky-500"
                    : "border-slate-200 dark:border-slate-800 opacity-80",
                )}
              >
                {/* Speech Bubble */}
                <div className="relative mb-2 w-full rounded-lg border border-sky-300 bg-sky-50 px-2.5 py-2 text-xs font-semibold text-sky-900 dark:border-sky-800 dark:bg-sky-950/70 dark:text-sky-200">
                  &ldquo;Here is my passport that proves my identity&rdquo;
                  <div className="absolute -bottom-1 left-1/2 -translate-x-1/2 h-2 w-2 rotate-45 border-b border-r border-sky-300 bg-sky-50 dark:border-sky-800 dark:bg-sky-950" />
                </div>

                <div className="my-2 flex flex-col items-center">
                  <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-sky-100 text-2xl dark:bg-sky-950">
                    🧑‍💼
                  </span>
                  <h4 className="mt-2 text-sm font-bold text-slate-900 dark:text-white">
                    Bob
                  </h4>
                  <p className="text-[11px] font-semibold text-sky-700 dark:text-sky-300">
                    Traveler / Citizen
                  </p>
                </div>

                <div className="w-full rounded-md bg-slate-50 p-2 text-[10px] text-slate-600 dark:bg-slate-800/60 dark:text-slate-300">
                  <span className="font-bold uppercase tracking-wider text-slate-400">Role:</span> Subject (Holder)
                </div>
              </div>

              {/* Center: Transmission & Verification Loop */}
              <div className="lg:col-span-6 flex flex-col justify-between space-y-3">
                {/* Step 1: Presentation */}
                <div
                  className={cn(
                    "rounded-xl border bg-white p-3.5 shadow-xs transition-all dark:bg-slate-900",
                    isRoleActive("credential")
                      ? "border-sky-400 ring-2 ring-sky-400/40 dark:border-sky-500"
                      : "border-slate-200 dark:border-slate-800",
                  )}
                >
                  <div className="flex items-center justify-between text-xs font-bold text-sky-800 dark:text-sky-300">
                    <span className="flex items-center gap-1.5">
                      <span className="flex h-5 w-5 items-center justify-center rounded-full bg-sky-100 text-xs font-bold dark:bg-sky-950">1</span>
                      Bob&apos;s Passport with Embedded Data Chip
                    </span>
                    <span className="rounded bg-sky-100 px-2 py-0.5 text-[10px] font-bold text-sky-800 dark:bg-sky-950 dark:text-sky-300">
                      Presents ➔
                    </span>
                  </div>
                  <div className="mt-2 flex items-center gap-3">
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-amber-100 text-xl dark:bg-amber-950">
                      🛂
                    </span>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      Contains Bob&apos;s photo, biometric data, and an official digital signature sealed by the issuing nation&apos;s government.
                    </p>
                  </div>
                </div>

                {/* Step 2: Verification Loop */}
                <div
                  className={cn(
                    "rounded-xl border bg-rose-50/40 p-3.5 shadow-xs transition-all dark:bg-rose-950/20",
                    isRoleActive("verification")
                      ? "border-rose-400 ring-2 ring-rose-400/40 dark:border-rose-500"
                      : "border-rose-200 dark:border-rose-900/50",
                  )}
                >
                  <div className="flex items-center justify-between text-xs font-bold text-rose-800 dark:text-rose-300">
                    <span className="flex items-center gap-1.5">
                      <span className="flex h-5 w-5 items-center justify-center rounded-full bg-rose-100 text-xs font-bold dark:bg-rose-950">2</span>
                      Verification Loop
                    </span>
                    <span className="rounded bg-rose-100 px-2 py-0.5 text-[10px] font-bold text-rose-800 dark:bg-rose-950 dark:text-rose-300">
                      ◀ verify
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs text-slate-600 dark:text-slate-300">
                    The border computer reads the passport chip and verifies the cryptographic signature against the recognized nation&apos;s public keys.
                  </p>
                  <div className="mt-2 flex items-start gap-1.5 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
                    <span className="mt-1 inline-block h-2 w-2 shrink-0 rounded-full bg-emerald-500" />
                    <p className="leading-snug">
                      Signature authentic: Border officer confirms Bob&apos;s identity is genuine.
                    </p>
                  </div>
                </div>
              </div>

              {/* Right: Border Control Officer */}
              <div
                className={cn(
                  "lg:col-span-3 flex flex-col items-center justify-between rounded-xl border bg-white p-3.5 text-center shadow-xs transition-all dark:bg-slate-900",
                  isRoleActive("verifier") || isRoleActive("trust-anchor")
                    ? "border-sky-400 ring-2 ring-sky-400/40 dark:border-sky-500"
                    : "border-slate-200 dark:border-slate-800 opacity-80",
                )}
              >
                {/* Speech Bubble */}
                <div className="relative mb-2 w-full rounded-lg border border-sky-300 bg-sky-50 px-2.5 py-2 text-xs font-semibold text-sky-900 dark:border-sky-800 dark:bg-sky-950/70 dark:text-sky-200">
                  &ldquo;We accept your country&apos;s passports and can verify your identity&rdquo;
                  <div className="absolute -bottom-1 left-1/2 -translate-x-1/2 h-2 w-2 rotate-45 border-b border-r border-sky-300 bg-sky-50 dark:border-sky-800 dark:bg-sky-950" />
                </div>

                <div className="my-2 flex flex-col items-center">
                  <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-sky-100 text-2xl dark:bg-sky-950">
                    👮‍♂️
                  </span>
                  <h4 className="mt-2 text-sm font-bold text-slate-900 dark:text-white">
                    Border Officer
                  </h4>
                  <p className="text-[11px] font-semibold text-sky-700 dark:text-sky-300">
                    Customs / Passport Control
                  </p>
                </div>

                <div
                  className={cn(
                    "w-full rounded-lg p-2 text-left text-xs transition-all",
                    isRoleActive("trust-anchor")
                      ? "border border-sky-300 bg-sky-50 dark:border-sky-800 dark:bg-sky-950/50"
                      : "bg-slate-50 dark:bg-slate-800/60",
                  )}
                >
                  <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Trust Anchor:
                  </span>
                  <p className="font-semibold text-slate-800 dark:text-slate-200 text-xs">
                    Sovereign Trust Registry
                  </p>
                  <p className="text-[10px] text-slate-500 dark:text-slate-400">
                    Database of recognized issuing governments
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ROW 2: Digital Web (SSL/TLS Certificate Check) */}
        {(activeTab === "both" || activeTab === "digital") && (
          <div className="relative rounded-2xl border border-emerald-200 bg-emerald-50/30 p-4 sm:p-5 dark:border-emerald-900/60 dark:bg-emerald-950/20">
            <div className="mb-3 flex items-center justify-between">
              <span className="inline-flex items-center gap-1.5 rounded-md bg-emerald-100 px-2.5 py-1 text-xs font-bold text-emerald-800 dark:bg-emerald-900/80 dark:text-emerald-300">
                <span>🔒</span> DIGITAL WEB: SSL/TLS Handshake
              </span>
              <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400">
                Public Key Infrastructure (PKI)
              </span>
            </div>

            <div className="grid gap-4 lg:grid-cols-12 items-stretch">
              {/* Left: abcd.com (Server) */}
              <div
                className={cn(
                  "lg:col-span-3 flex flex-col items-center justify-between rounded-xl border bg-white p-3.5 text-center shadow-xs transition-all dark:bg-slate-900",
                  isRoleActive("subject")
                    ? "border-emerald-400 ring-2 ring-emerald-400/40 dark:border-emerald-500"
                    : "border-slate-200 dark:border-slate-800 opacity-80",
                )}
              >
                {/* Speech Bubble */}
                <div className="relative mb-2 w-full rounded-lg border border-emerald-300 bg-emerald-50 px-2.5 py-2 text-xs font-semibold text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-200">
                  &ldquo;Here is my SSL certificate that proves my identity&rdquo;
                  <div className="absolute -bottom-1 left-1/2 -translate-x-1/2 h-2 w-2 rotate-45 border-b border-r border-emerald-300 bg-emerald-50 dark:border-emerald-800 dark:bg-emerald-950" />
                </div>

                <div className="my-2 flex flex-col items-center">
                  <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-100 text-2xl dark:bg-emerald-950">
                    🖥️
                  </span>
                  <h4 className="mt-2 text-sm font-bold text-slate-900 dark:text-white">
                    abcd.com
                  </h4>
                  <p className="text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
                    Website / API Host
                  </p>
                </div>

                <div className="w-full rounded-md bg-slate-50 p-2 text-[10px] text-slate-600 dark:bg-slate-800/60 dark:text-slate-300">
                  <span className="font-bold uppercase tracking-wider text-slate-400">Role:</span> Subject (Server)
                </div>
              </div>

              {/* Center: Transmission & Verification Loop */}
              <div className="lg:col-span-6 flex flex-col justify-between space-y-3">
                {/* Step 1: Presentation */}
                <div
                  className={cn(
                    "rounded-xl border bg-white p-3.5 shadow-xs transition-all dark:bg-slate-900",
                    isRoleActive("credential")
                      ? "border-emerald-400 ring-2 ring-emerald-400/40 dark:border-emerald-500"
                      : "border-slate-200 dark:border-slate-800",
                  )}
                >
                  <div className="flex items-center justify-between text-xs font-bold text-emerald-800 dark:text-emerald-300">
                    <span className="flex items-center gap-1.5">
                      <span className="flex h-5 w-5 items-center justify-center rounded-full bg-emerald-100 text-xs font-bold dark:bg-emerald-950">1</span>
                      Website&apos;s SSL Certificate issued by VeriSign / CA
                    </span>
                    <span className="rounded bg-emerald-100 px-2 py-0.5 text-[10px] font-bold text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300">
                      TLS Handshake ➔
                    </span>
                  </div>
                  <div className="mt-2 flex items-center gap-3">
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-100 text-xl dark:bg-emerald-950">
                      📜
                    </span>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      Contains the server&apos;s public key, domain name (<code>abcd.com</code>), and a cryptographic digital signature signed by the CA.
                    </p>
                  </div>
                </div>

                {/* Step 2: Verification Loop */}
                <div
                  className={cn(
                    "rounded-xl border bg-rose-50/40 p-3.5 shadow-xs transition-all dark:bg-rose-950/20",
                    isRoleActive("verification")
                      ? "border-rose-400 ring-2 ring-rose-400/40 dark:border-rose-500"
                      : "border-rose-200 dark:border-rose-900/50",
                  )}
                >
                  <div className="flex items-center justify-between text-xs font-bold text-rose-800 dark:text-rose-300">
                    <span className="flex items-center gap-1.5">
                      <span className="flex h-5 w-5 items-center justify-center rounded-full bg-rose-100 text-xs font-bold dark:bg-rose-950">2</span>
                      Verification Loop
                    </span>
                    <span className="rounded bg-rose-100 px-2 py-0.5 text-[10px] font-bold text-rose-800 dark:bg-rose-950 dark:text-rose-300">
                      ◀ verify
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs text-slate-600 dark:text-slate-300">
                    The browser extracts the CA signature and verifies it against the CA&apos;s public key located in the operating system&apos;s Root CA store.
                  </p>
                  <div className="mt-2 flex items-start gap-1.5 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
                    <span className="mt-1 inline-block h-2 w-2 shrink-0 rounded-full bg-emerald-500" />
                    <p className="leading-snug">
                      Signature authentic: Browser confirms it is safely connected to real <code>abcd.com</code>.
                    </p>
                  </div>
                </div>
              </div>

              {/* Right: Client Browser (Alice) */}
              <div
                className={cn(
                  "lg:col-span-3 flex flex-col items-center justify-between rounded-xl border bg-white p-3.5 text-center shadow-xs transition-all dark:bg-slate-900",
                  isRoleActive("verifier") || isRoleActive("trust-anchor")
                    ? "border-emerald-400 ring-2 ring-emerald-400/40 dark:border-emerald-500"
                    : "border-slate-200 dark:border-slate-800 opacity-80",
                )}
              >
                {/* Speech Bubble */}
                <div className="relative mb-2 w-full rounded-lg border border-emerald-300 bg-emerald-50 px-2.5 py-2 text-xs font-semibold text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-200">
                  &ldquo;I have your issuer&apos;s public key and can verify your identity&rdquo;
                  <div className="absolute -bottom-1 left-1/2 -translate-x-1/2 h-2 w-2 rotate-45 border-b border-r border-emerald-300 bg-emerald-50 dark:border-emerald-800 dark:bg-emerald-950" />
                </div>

                <div className="my-2 flex flex-col items-center">
                  <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-100 text-2xl dark:bg-emerald-950">
                    💻
                  </span>
                  <h4 className="mt-2 text-sm font-bold text-slate-900 dark:text-white">
                    Client Browser
                  </h4>
                  <p className="text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
                    Chrome / Safari / Firefox
                  </p>
                </div>

                <div
                  className={cn(
                    "w-full rounded-lg p-2 text-left text-xs transition-all",
                    isRoleActive("trust-anchor")
                      ? "border border-emerald-300 bg-emerald-50 dark:border-emerald-800 dark:bg-emerald-950/50"
                      : "bg-slate-50 dark:bg-slate-800/60",
                  )}
                >
                  <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Trust Anchor:
                  </span>
                  <p className="font-semibold text-slate-800 dark:text-slate-200 text-xs">
                    Root Certificate Store
                  </p>
                  <p className="text-[10px] text-slate-500 dark:text-slate-400">
                    Pre-installed CA public keys (VeriSign, DigiCert, etc.)
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Interactive 1-to-1 Mapping Matrix */}
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-white/10 dark:bg-slate-900">
          <h4 className="mb-3 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Interactive Concept Mapping (Click to Highlight in Diagram)
          </h4>

          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
            {[
              {
                id: "subject" as AnalogyRole,
                label: "1. The Subject",
                phys: "Traveler (Bob)",
                dig: "Web Server (abcd.com)",
              },
              {
                id: "credential" as AnalogyRole,
                label: "2. The Credential",
                phys: "Biometric Passport",
                dig: "X.509 SSL Certificate",
              },
              {
                id: "verifier" as AnalogyRole,
                label: "3. The Verifier",
                phys: "Border Control Officer",
                dig: "Client Browser (Alice)",
              },
              {
                id: "trust-anchor" as AnalogyRole,
                label: "4. Trust Anchor",
                phys: "Treaty Government Keys",
                dig: "OS/Browser Root Store",
              },
              {
                id: "verification" as AnalogyRole,
                label: "5. Signature Check",
                phys: "Chip Signature Verified",
                dig: "RSA/ECDSA Signature Valid",
              },
            ].map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setHighlightedRole(highlightedRole === item.id ? "all" : item.id)}
                className={cn(
                  "rounded-lg border p-2.5 text-left text-xs transition-all",
                  highlightedRole === item.id
                    ? "border-sky-500 bg-sky-50 shadow-xs ring-2 ring-sky-500/20 dark:border-sky-500 dark:bg-sky-950/60"
                    : "border-slate-200 bg-slate-50/60 hover:bg-slate-100 dark:border-slate-800 dark:bg-slate-800/40 dark:hover:bg-slate-800",
                )}
              >
                <span className="block font-bold text-slate-900 dark:text-white">
                  {item.label}
                </span>
                <div className="mt-1 space-y-0.5 text-[11px]">
                  <p className="text-sky-700 dark:text-sky-300">
                    <span className="font-medium text-slate-400">🛂 </span>{item.phys}
                  </p>
                  <p className="text-emerald-700 dark:text-emerald-300">
                    <span className="font-medium text-slate-400">🔒 </span>{item.dig}
                  </p>
                </div>
              </button>
            ))}
          </div>

          <div className="mt-3 flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
            <span>
              💡 <strong>Core Takeaway:</strong> You never need to have met the subject in advance. You only need to trust the <em>authority that signed their credential</em>.
            </span>
            {highlightedRole !== "all" && (
              <button
                type="button"
                onClick={() => setHighlightedRole("all")}
                className="text-xs font-semibold text-sky-600 hover:underline dark:text-sky-400"
              >
                Reset highlights
              </button>
            )}
          </div>
        </div>
      </div>
    </DiagramFrame>
  );
}

function RootStoreDiagram() {
  return (
    <DiagramFrame
      id="root-store"
      eyebrow="X.509 PKI · The Ultimate Trust Anchor"
      title="Root CA Creation & Operating System Trust Stores"
      property="Pre-Distributed Trust Anchor"
      tone="violet"
      caption={
        <>
          Root CAs have no parent authority to vouch for them—they self-sign their own certificates.
          Client devices trust a Root CA not because of its signature, but because its public certificate
          was vetted and pre-installed directly into the operating system or browser trust store.
        </>
      }
    >
      <RootStoreDistributionVisual />
    </DiagramFrame>
  );
}

function TrustTriangleDiagram() {
  const [activeMode, setActiveMode] = useState<"both" | "triangle" | "crypto">("both");
  const [activeParty, setActiveParty] = useState<"all" | "ca" | "browser" | "server">("all");

  const isPartyActive = (party: "ca" | "browser" | "server") =>
    activeParty === "all" || activeParty === party;

  return (
    <DiagramFrame
      id="trust-triangle"
      eyebrow="X.509 PKI · Transitive Trust Architecture"
      title="The Triangle of Trust: How Browsers Trust Unknown Websites"
      property="Transitive Authentication via Neutral Authority"
      tone="sky"
      caption={
        <>
          Alice&apos;s browser has never communicated with Bob&apos;s server before. Encryption alone cannot
          defeat an imposter like Mallory. Public Key Infrastructure introduces a trusted third party
          (Trent, the Root CA): because Alice directly trusts Trent, and Trent directly certifies Bob,
          Alice can mathematically trust Bob!
        </>
      }
    >
      {/* View Switcher & Interactive Controls */}
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-2.5 dark:border-white/10">
        <div className="flex items-center gap-1 rounded-xl bg-slate-100 p-1 dark:bg-slate-800/80">
          <button
            type="button"
            onClick={() => setActiveMode("both")}
            className={cn(
              "rounded-lg px-2.5 py-1 text-xs font-bold transition-all",
              activeMode === "both"
                ? "bg-sky-600 text-white shadow-xs"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            👥 Full Architecture
          </button>
          <button
            type="button"
            onClick={() => setActiveMode("triangle")}
            className={cn(
              "rounded-lg px-2.5 py-1 text-xs font-bold transition-all",
              activeMode === "triangle"
                ? "bg-sky-600 text-white shadow-xs"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            🔺 1. The Trust Triangle
          </button>
          <button
            type="button"
            onClick={() => setActiveMode("crypto")}
            className={cn(
              "rounded-lg px-2.5 py-1 text-xs font-bold transition-all",
              activeMode === "crypto"
                ? "bg-sky-600 text-white shadow-xs"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            🔐 2. Cryptographic Mechanism
          </button>
        </div>

        {/* Entity Highlight Filter */}
        <div className="flex items-center gap-1 text-xs">
          <span className="text-slate-500 dark:text-slate-400 mr-1 text-[11px] font-semibold">
            Highlight:
          </span>
          <button
            type="button"
            onClick={() => setActiveParty("all")}
            className={cn(
              "rounded-md px-2 py-0.5 text-[11px] font-semibold transition-all",
              activeParty === "all"
                ? "bg-slate-900 text-white dark:bg-white dark:text-slate-900"
                : "bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300",
            )}
          >
            All
          </button>
          <button
            type="button"
            onClick={() => setActiveParty(activeParty === "ca" ? "all" : "ca")}
            className={cn(
              "rounded-md px-2 py-0.5 text-[11px] font-semibold transition-all",
              activeParty === "ca"
                ? "bg-sky-600 text-white"
                : "bg-sky-50 text-sky-700 hover:bg-sky-100 dark:bg-sky-950/60 dark:text-sky-300",
            )}
          >
            🛡️ Root CA
          </button>
          <button
            type="button"
            onClick={() => setActiveParty(activeParty === "browser" ? "all" : "browser")}
            className={cn(
              "rounded-md px-2 py-0.5 text-[11px] font-semibold transition-all",
              activeParty === "browser"
                ? "bg-sky-600 text-white"
                : "bg-sky-50 text-sky-700 hover:bg-sky-100 dark:bg-sky-950/60 dark:text-sky-300",
            )}
          >
            💻 Browser
          </button>
          <button
            type="button"
            onClick={() => setActiveParty(activeParty === "server" ? "all" : "server")}
            className={cn(
              "rounded-md px-2 py-0.5 text-[11px] font-semibold transition-all",
              activeParty === "server"
                ? "bg-sky-600 text-white"
                : "bg-sky-50 text-sky-700 hover:bg-sky-100 dark:bg-sky-950/60 dark:text-sky-300",
            )}
          >
            🖥️ Website
          </button>
        </div>
      </div>

      {/* Spacious, Balanced High-Fidelity Vector SVG Diagram */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white p-2.5 sm:p-4 shadow-xs dark:border-slate-800 dark:bg-slate-950">
        <svg
          viewBox="0 0 1080 430"
          className="w-full h-auto select-none font-sans"
          aria-label="The Triangle of Trust and PKI Key Architecture"
        >
          <defs>
            {/* Gradients */}
            <linearGradient id="tt-shield-grad" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#38bdf8" />
              <stop offset="100%" stopColor="#0284c7" />
            </linearGradient>

            {/* Black Arrowheads */}
            <marker
              id="tt-arrow-black-end"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" className="fill-slate-900 dark:fill-white" />
            </marker>

            <marker
              id="tt-arrow-black-start"
              viewBox="0 0 10 10"
              refX="2"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M 8 1.5 L 0 5 L 8 8.5 z" className="fill-slate-900 dark:fill-white" />
            </marker>

            {/* Blue Distribution Arrowhead */}
            <marker
              id="tt-arrow-blue-end"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#0284c7" />
            </marker>

            {/* Red Self-Sign Arrowhead */}
            <marker
              id="tt-arrow-red-end"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#dc2626" />
            </marker>

            {/* Gray Dashed Arrowheads */}
            <marker
              id="tt-arrow-gray-end"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#94a3b8" />
            </marker>

            <marker
              id="tt-arrow-gray-start"
              viewBox="0 0 10 10"
              refX="2"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M 8 1.5 L 0 5 L 8 8.5 z" fill="#94a3b8" />
            </marker>
          </defs>

          {/* =========================================================================
              LEFT HALF: THE TRIANGLE OF TRUST (CONCEPT)
              Center axis: x = 220
              ========================================================================= */}
          <g opacity={activeMode === "crypto" ? 0.2 : 1} className="transition-opacity duration-200">
            {/* Top Explanatory Text */}
            <text x="220" y="32" textAnchor="middle" className="text-[13px] font-normal fill-slate-700 dark:fill-slate-300">
              The browser trusts the web page,
            </text>
            <text x="220" y="50" textAnchor="middle" className="text-[13px] font-normal fill-slate-700 dark:fill-slate-300">
              because each <tspan className="font-bold fill-slate-950 dark:fill-white">trusts</tspan> the same root
            </text>
            <text x="220" y="68" textAnchor="middle" className="text-[13px] font-normal fill-slate-700 dark:fill-slate-300">
              Certification Authority (CA)
            </text>

            {/* Diagonal Double-Headed Arrow 1: Root CA <--> Browser */}
            <line
              x1="192"
              y1="165"
              x2="122"
              y2="305"
              className="stroke-slate-900 dark:stroke-white"
              strokeWidth="2.2"
              markerStart="url(#tt-arrow-black-start)"
              markerEnd="url(#tt-arrow-black-end)"
            />
            {/* Rotated Direct Trust label along Left Diagonal */}
            <g transform="translate(150, 235) rotate(-63)">
              <text x="0" y="-6" textAnchor="middle" className="text-[12px] font-bold fill-slate-900 dark:fill-white">
                Direct
              </text>
              <text x="0" y="8" textAnchor="middle" className="text-[12px] font-bold fill-slate-900 dark:fill-white">
                Trust
              </text>
            </g>

            {/* Diagonal Double-Headed Arrow 2: Root CA <--> Website */}
            <line
              x1="248"
              y1="165"
              x2="318"
              y2="305"
              className="stroke-slate-900 dark:stroke-white"
              strokeWidth="2.2"
              markerStart="url(#tt-arrow-black-start)"
              markerEnd="url(#tt-arrow-black-end)"
            />
            {/* Rotated Direct Trust label along Right Diagonal */}
            <g transform="translate(290, 235) rotate(63)">
              <text x="0" y="-6" textAnchor="middle" className="text-[12px] font-bold fill-slate-900 dark:fill-white">
                Direct
              </text>
              <text x="0" y="8" textAnchor="middle" className="text-[12px] font-bold fill-slate-900 dark:fill-white">
                Trust
              </text>
            </g>

            {/* Horizontal Dashed Double-Headed Arrow 3: Browser <--> Website */}
            <line
              x1="140"
              y1="345"
              x2="300"
              y2="345"
              className="stroke-slate-900 dark:stroke-white"
              strokeWidth="2.2"
              strokeDasharray="5 4"
              markerStart="url(#tt-arrow-black-start)"
              markerEnd="url(#tt-arrow-black-end)"
            />
            {/* Third-party Trust text centered cleanly above the dashed arrow */}
            <text x="220" y="322" textAnchor="middle" className="text-[12.5px] font-bold fill-slate-900 dark:fill-white">
              Third-party
            </text>
            <text x="220" y="338" textAnchor="middle" className="text-[12.5px] font-bold fill-slate-900 dark:fill-white">
              Trust
            </text>

            {/* TOP APEX: Root CA */}
            <g
              transform="translate(220, 142)"
              className="cursor-pointer transition-transform hover:scale-105"
              onClick={() => setActiveParty(activeParty === "ca" ? "all" : "ca")}
              opacity={isPartyActive("ca") ? 1 : 0.3}
            >
              {activeParty === "ca" && (
                <circle cx="0" cy="0" r="44" fill="none" stroke="#0284c7" strokeWidth="2" strokeDasharray="3 3" />
              )}
              <text x="0" y="-38" textAnchor="middle" className="text-[14px] font-bold fill-slate-900 dark:fill-white">
                Root CA
              </text>
              {/* Blue Shield */}
              <path
                d="M 0,-28 C 22,-28 28,-20 28,-6 C 28,16 14,32 0,38 C -14,32 -28,16 -28,-6 C -28,-20 -22,-28 0,-28 Z"
                fill="url(#tt-shield-grad)"
                stroke="#0369a1"
                strokeWidth="1.8"
              />
              {/* Padlock */}
              <path
                d="M -6,-4 V -10 C -6,-13 6,-13 6,-10 V -4"
                fill="none"
                stroke="#ffffff"
                strokeWidth="2.8"
                strokeLinecap="round"
              />
              <rect x="-9" y="-4" width="18" height="14" rx="2.5" fill="#ffffff" />
              <circle cx="0" cy="2" r="1.8" fill="#0284c7" />
              <path d="M 0,2 V 5.5" stroke="#0284c7" strokeWidth="1.6" strokeLinecap="round" />
            </g>

            {/* BOTTOM LEFT: Browser (Alice) */}
            <g
              transform="translate(95, 340)"
              className="cursor-pointer transition-transform hover:scale-105"
              onClick={() => setActiveParty(activeParty === "browser" ? "all" : "browser")}
              opacity={isPartyActive("browser") ? 1 : 0.3}
            >
              {activeParty === "browser" && (
                <circle cx="0" cy="0" r="40" fill="none" stroke="#0284c7" strokeWidth="2" strokeDasharray="3 3" />
              )}
              <circle cx="-14" cy="-20" r="12" fill="#0284c7" />
              <path d="M -30,16 C -30,-6 2,-6 2,16 Z" fill="#0284c7" />
              {/* Laptop */}
              <path d="M -8,16 L 1,-6 L 19,-6 L 10,16 Z" fill="#0369a1" stroke="#38bdf8" strokeWidth="1.2" />
              <circle cx="10" cy="5" r="2.5" fill="#ffffff" opacity="0.9" />
              <path d="M -12,16 L 24,16 L 21,18.5 L -14,18.5 Z" fill="#94a3b8" />
              <text x="-4" y="42" textAnchor="middle" className="text-[14px] font-bold fill-slate-900 dark:fill-white">
                Browser
              </text>
            </g>

            {/* BOTTOM RIGHT: Website (Bob) */}
            <g
              transform="translate(345, 340)"
              className="cursor-pointer transition-transform hover:scale-105"
              onClick={() => setActiveParty(activeParty === "server" ? "all" : "server")}
              opacity={isPartyActive("server") ? 1 : 0.3}
            >
              {activeParty === "server" && (
                <circle cx="0" cy="0" r="40" fill="none" stroke="#0284c7" strokeWidth="2" strokeDasharray="3 3" />
              )}
              {/* 3D Server Tower */}
              <path d="M -19,-22 L 5,-32 L 22,-22 L -2,-12 Z" fill="#38bdf8" stroke="#0284c7" strokeWidth="1.2" />
              <path d="M 22,-22 L 22,16 L -2,26 L -2,-12 Z" fill="#0284c7" stroke="#0369a1" strokeWidth="1.2" />
              <path d="M -19,-22 L -2,-12 L -2,26 L -19,16 Z" fill="#0369a1" stroke="#0284c7" strokeWidth="1.2" />
              <rect x="-16" y="-7" width="11" height="6" rx="1" fill="#0f172a" opacity="0.7" />
              <circle cx="-7" cy="-4" r="1.2" fill="#4ade80" />
              <rect x="-16" y="4" width="11" height="6" rx="1" fill="#0f172a" opacity="0.7" />
              <circle cx="-7" cy="7" r="1.2" fill="#38bdf8" />
              <text x="2" y="42" textAnchor="middle" className="text-[14px] font-bold fill-slate-900 dark:fill-white">
                Website
              </text>
            </g>
          </g>

          {/* =========================================================================
              CENTER VERTICAL DIVIDER LINE
              ========================================================================= */}
          <line
            x1="450"
            y1="20"
            x2="450"
            y2="410"
            className="stroke-slate-200 dark:stroke-slate-800"
            strokeWidth="1.5"
          />

          {/* =========================================================================
              RIGHT HALF: CRYPTOGRAPHIC ARCHITECTURE (KEYS & CERTS)
              Central axis: x = 730
              Browser: x = 540 (dx = -190)
              Website: x = 920 (dx = +190)
              Private key: centered at x = 960
              ========================================================================= */}
          <g opacity={activeMode === "triangle" ? 0.2 : 1} className="transition-opacity duration-200">
            {/* Top Center: Root CA Certificate 3-Band Card (Centered at x = 730) */}
            <g transform="translate(730, 110)">
              {/* Outer Card Frame */}
              <rect
                x="-115"
                y="-75"
                width="230"
                height="152"
                rx="7"
                className="fill-white stroke-slate-300 dark:fill-slate-900 dark:stroke-slate-700"
                strokeWidth="1.5"
              />
              <text x="0" y="-52" textAnchor="middle" className="text-[14px] font-bold fill-slate-900 dark:fill-white">
                Root CA Certificate
              </text>

              {/* Band 1: Distinguished Name (Green, centered at y = -26) */}
              <g transform="translate(0, -26)">
                <rect
                  x="-105"
                  y="-13"
                  width="210"
                  height="26"
                  rx="4"
                  fill="#dcfce7"
                  stroke="#86efac"
                  strokeWidth="1.2"
                />
                <text x="0" y="5" textAnchor="middle" className="text-[11px] font-semibold fill-emerald-950">
                  Root CA Distinguished Name
                </text>
              </g>

              {/* Band 2: Public Key (Yellow, centered at y = 8) */}
              <g transform="translate(0, 8)">
                <rect
                  x="-105"
                  y="-13"
                  width="210"
                  height="26"
                  rx="4"
                  fill="#fef9c3"
                  stroke="#fde047"
                  strokeWidth="1.2"
                />
                <text x="-15" y="5" textAnchor="middle" className="text-[11.5px] font-semibold fill-amber-950">
                  Root CA Public Key
                </text>
                {/* Golden Key Icon - cleanly inside yellow band */}
                <g transform="translate(75, 0)">
                  <circle cx="-5" cy="0" r="4.5" fill="#fef08a" stroke="#b45309" strokeWidth="1.2" />
                  <circle cx="-5" cy="0" r="1.8" fill="none" stroke="#b45309" strokeWidth="1.1" />
                  <path d="M -0.5,0 H 9 M 5,0 V 3 M 8,0 V 3" stroke="#b45309" strokeWidth="1.3" strokeLinecap="round" />
                </g>
              </g>

              {/* Band 3: Signature (Salmon/Red, centered at y = 42, absolute y = 110 + 42 = 152) */}
              <g transform="translate(0, 42)">
                <rect
                  x="-105"
                  y="-13"
                  width="210"
                  height="26"
                  rx="4"
                  fill="#fee2e2"
                  stroke="#fca5a5"
                  strokeWidth="1.2"
                />
                <text x="-15" y="5" textAnchor="middle" className="text-[11.5px] font-semibold fill-rose-950">
                  Root CA Signature
                </text>
                {/* Red Wax Ribbon Seal - cleanly inside salmon band */}
                <g transform="translate(75, 0)">
                  <path d="M -3,3 L -5,9 L 0,7.5 L 5,9 L 3,3 Z" fill="#dc2626" stroke="#991b1b" strokeWidth="0.8" />
                  <circle cx="0" cy="-1.5" r="6.5" fill="#ef4444" stroke="#b91c1c" strokeWidth="1.1" />
                  <circle cx="0" cy="-1.5" r="3.5" fill="none" stroke="#fecaca" strokeWidth="0.8" strokeDasharray="1.5 1" />
                </g>
              </g>
            </g>

            {/* Top Right: Root CA Private Key Box & Warning (Centered at x = 960) */}
            <g transform="translate(960, 42)">
              <text x="0" y="0" textAnchor="middle" className="text-[11.5px] font-bold fill-rose-800 dark:fill-rose-300">
                The private key
              </text>
              <text x="0" y="14" textAnchor="middle" className="text-[11.5px] font-bold fill-rose-800 dark:fill-rose-300">
                never leaves the
              </text>
              <text x="0" y="28" textAnchor="middle" className="text-[11.5px] font-bold fill-rose-800 dark:fill-rose-300">
                Root CA
              </text>

              {/* Pink Key Box (width = 144, height = 36, y = 46..82, center y = 64, absolute y = 42 + 64 = 106) */}
              <g transform="translate(0, 64)">
                <rect
                  x="-72"
                  y="-18"
                  width="144"
                  height="36"
                  rx="6"
                  fill="#ffe4e6"
                  stroke="#fb7185"
                  strokeWidth="1.4"
                />
                {/* Pink Key Icon */}
                <g transform="translate(-48, 0)">
                  <circle cx="-4" cy="0" r="4.5" fill="#fecdd3" stroke="#e11d48" strokeWidth="1.2" />
                  <circle cx="-4" cy="0" r="1.8" fill="none" stroke="#e11d48" strokeWidth="1.1" />
                  <path d="M 0.5,0 H 9 M 5,0 V 3 M 8,0 V 3" stroke="#e11d48" strokeWidth="1.3" strokeLinecap="round" />
                </g>
                <text x="12" y="-1" textAnchor="middle" className="text-[10.5px] font-bold fill-rose-950">
                  Root CA
                </text>
                <text x="12" y="11" textAnchor="middle" className="text-[10.5px] font-bold fill-rose-950">
                  Private Key
                </text>
              </g>

              {/* Self-Sign Arrow:
                  Starts at bottom center of pink box: (0, 82) -> absolute (960, 124).
                  Drops to y = 110 -> absolute y = 152 (EXACT vertical center of Signature band!).
                  Turns left to x = -118 -> absolute x = 842 (penetrates outer border right into the Signature band!).
                  Marker points directly into the Signature band! */}
              <path
                d="M 0,82 V 110 H -118"
                fill="none"
                stroke="#dc2626"
                strokeWidth="2.2"
                markerEnd="url(#tt-arrow-red-end)"
              />
              <text x="-56" y="128" textAnchor="middle" className="text-[12px] font-bold fill-rose-700 dark:fill-rose-400">
                Self-Sign
              </text>
            </g>

            {/* Center Shield under Certificate (Centered at x = 730, y = 195) */}
            <g
              transform="translate(730, 195)"
              className="cursor-pointer transition-transform hover:scale-105"
              onClick={() => setActiveParty(activeParty === "ca" ? "all" : "ca")}
              opacity={isPartyActive("ca") ? 1 : 0.3}
            >
              <path
                d="M 0,-28 C 22,-28 28,-20 28,-6 C 28,16 14,32 0,38 C -14,32 -28,16 -28,-6 C -28,-20 -22,-28 0,-28 Z"
                fill="url(#tt-shield-grad)"
                stroke="#0369a1"
                strokeWidth="1.8"
              />
              <path
                d="M -5,-3 V -9 C -5,-12 5,-12 5,-9 V -3"
                fill="none"
                stroke="#ffffff"
                strokeWidth="2.6"
                strokeLinecap="round"
              />
              <rect x="-8" y="-3" width="16" height="13" rx="2" fill="#ffffff" />
              <circle cx="0" cy="2" r="1.6" fill="#0284c7" />
              <path d="M 0,2 V 5" stroke="#0284c7" strokeWidth="1.4" strokeLinecap="round" />
            </g>

            {/* Symmetrical Blue Distribution Arrows from Shield to Browser & Website Certificates */}
            {/* Left arrow: from (704, 206) to (540, 246) -> dx = 164, dy = 40 */}
            <line
              x1="704"
              y1="206"
              x2="540"
              y2="246"
              stroke="#0284c7"
              strokeWidth="2.2"
              markerEnd="url(#tt-arrow-blue-end)"
            />
            {/* Right arrow: from (756, 206) to (920, 246) -> dx = 164, dy = 40 */}
            <line
              x1="756"
              y1="206"
              x2="920"
              y2="246"
              stroke="#0284c7"
              strokeWidth="2.2"
              markerEnd="url(#tt-arrow-blue-end)"
            />

            {/* BROWSER'S CERTIFICATE (Seated directly above Browser at x = 540, y = 275) */}
            <g transform="translate(540, 275)">
              {/* Green document with folded corner */}
              <rect x="-18" y="-22" width="36" height="44" rx="3" fill="#ffffff" stroke="#22c55e" strokeWidth="1.8" />
              <path d="M 6,-22 L 18,-10 L 6,-10 Z" fill="#bbf7d0" stroke="#22c55e" strokeWidth="1" />
              {/* Red seal ribbon */}
              <g transform="translate(-5, 8)">
                <path d="M -2,2 L -3.5,6 L 0,5 L 3.5,6 L 2,2 Z" fill="#dc2626" stroke="#991b1b" strokeWidth="0.6" />
                <circle cx="0" cy="-1" r="5" fill="#ef4444" stroke="#b91c1c" strokeWidth="0.8" />
              </g>
              {/* Gold key icon */}
              <g transform="translate(7, 6)">
                <circle cx="-3" cy="0" r="3" fill="#fef08a" stroke="#ca8a04" strokeWidth="1" />
                <path d="M 0,0 H 6 M 3.5,0 V 2.5 M 5.5,0 V 2.5" stroke="#ca8a04" strokeWidth="1.1" strokeLinecap="round" />
              </g>
            </g>

            {/* WEBSITE'S CERTIFICATE (Seated directly above Website at x = 920, y = 275) */}
            <g transform="translate(920, 275)">
              {/* Green document with folded corner */}
              <rect x="-18" y="-22" width="36" height="44" rx="3" fill="#ffffff" stroke="#22c55e" strokeWidth="1.8" />
              <path d="M 6,-22 L 18,-10 L 6,-10 Z" fill="#bbf7d0" stroke="#22c55e" strokeWidth="1" />
              {/* Red seal ribbon */}
              <g transform="translate(-5, 8)">
                <path d="M -2,2 L -3.5,6 L 0,5 L 3.5,6 L 2,2 Z" fill="#dc2626" stroke="#991b1b" strokeWidth="0.6" />
                <circle cx="0" cy="-1" r="5" fill="#ef4444" stroke="#b91c1c" strokeWidth="0.8" />
              </g>
              {/* Gold key icon */}
              <g transform="translate(7, 6)">
                <circle cx="-3" cy="0" r="3" fill="#fef08a" stroke="#ca8a04" strokeWidth="1" />
                <path d="M 0,0 H 6 M 3.5,0 V 2.5 M 5.5,0 V 2.5" stroke="#ca8a04" strokeWidth="1.1" strokeLinecap="round" />
              </g>
            </g>

            {/* Horizontal Dashed Connection directly connecting Browser & Website Certificates at y = 275 */}
            {/* Left dashed arrow: from x = 638 to x = 566 */}
            <line
              x1="638"
              y1="275"
              x2="566"
              y2="275"
              stroke="#94a3b8"
              strokeWidth="2"
              strokeDasharray="4 3"
              markerEnd="url(#tt-arrow-gray-end)"
            />
            {/* Clean Pill Background for Text (Centered at x = 730, y = 275) */}
            <g transform="translate(730, 275)">
              <rect
                x="-88"
                y="-25"
                width="176"
                height="50"
                rx="7"
                className="fill-slate-50 stroke-slate-200 dark:fill-slate-900 dark:stroke-slate-800"
                strokeWidth="1.2"
              />
              <text x="0" y="-8" textAnchor="middle" className="text-[11px] font-bold fill-slate-900 dark:fill-white">
                Root CA Certificate
              </text>
              <text x="0" y="5" textAnchor="middle" className="text-[9.5px] fill-slate-500 dark:text-slate-400">
                that includes the
              </text>
              <text x="0" y="17" textAnchor="middle" className="text-[10px] font-semibold fill-slate-800 dark:fill-slate-200">
                Root CA public key
              </text>
            </g>
            {/* Right dashed arrow: from x = 822 to x = 894 */}
            <line
              x1="822"
              y1="275"
              x2="894"
              y2="275"
              stroke="#94a3b8"
              strokeWidth="2"
              strokeDasharray="4 3"
              markerEnd="url(#tt-arrow-gray-end)"
            />

            {/* Bottom Left: Browser (Placed directly under Certificate at x = 540, y = 340) */}
            <g
              transform="translate(540, 340)"
              className="cursor-pointer transition-transform hover:scale-105"
              onClick={() => setActiveParty(activeParty === "browser" ? "all" : "browser")}
              opacity={isPartyActive("browser") ? 1 : 0.3}
            >
              <circle cx="-14" cy="-20" r="12" fill="#0284c7" />
              <path d="M -30,16 C -30,-6 2,-6 2,16 Z" fill="#0284c7" />
              <path d="M -8,16 L 1,-6 L 19,-6 L 10,16 Z" fill="#0369a1" stroke="#38bdf8" strokeWidth="1.2" />
              <circle cx="10" cy="5" r="2.5" fill="#ffffff" opacity="0.9" />
              <path d="M -12,16 L 24,16 L 21,18.5 L -14,18.5 Z" fill="#94a3b8" />
              <text x="-4" y="42" textAnchor="middle" className="text-[14px] font-bold fill-slate-900 dark:fill-white">
                Browser
              </text>
            </g>

            {/* Bottom Right: Website (Placed directly under Certificate at x = 920, y = 340) */}
            <g
              transform="translate(920, 340)"
              className="cursor-pointer transition-transform hover:scale-105"
              onClick={() => setActiveParty(activeParty === "server" ? "all" : "server")}
              opacity={isPartyActive("server") ? 1 : 0.3}
            >
              <path d="M -19,-22 L 5,-32 L 22,-22 L -2,-12 Z" fill="#38bdf8" stroke="#0284c7" strokeWidth="1.2" />
              <path d="M 22,-22 L 22,16 L -2,26 L -2,-12 Z" fill="#0284c7" stroke="#0369a1" strokeWidth="1.2" />
              <path d="M -19,-22 L -2,-12 L -2,26 L -19,16 Z" fill="#0369a1" stroke="#0284c7" strokeWidth="1.2" />
              <rect x="-16" y="-7" width="11" height="6" rx="1" fill="#0f172a" opacity="0.7" />
              <circle cx="-7" cy="-4" r="1.2" fill="#4ade80" />
              <rect x="-16" y="4" width="11" height="6" rx="1" fill="#0f172a" opacity="0.7" />
              <circle cx="-7" cy="7" r="1.2" fill="#38bdf8" />
              <text x="2" y="42" textAnchor="middle" className="text-[14px] font-bold fill-slate-900 dark:fill-white">
                Website
              </text>
            </g>
          </g>
        </svg>
      </div>

      {/* Explanatory 3-Pillar Breakdown */}
      <div className="mt-3 grid gap-2.5 sm:grid-cols-3">
        <div className="rounded-xl border border-sky-200 bg-sky-50/50 p-3 text-xs dark:border-sky-900/60 dark:bg-sky-950/30">
          <div className="flex items-center gap-1.5 font-bold text-sky-900 dark:text-sky-200">
            <span>🛡️</span> 1. Direct Trust (Diagonals)
          </div>
          <p className="mt-1 text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">
            <strong>Alice</strong> directly trusts Trent because his Root Certificate is pre-installed in her OS root store. <strong>Bob</strong> directly trusts Trent by applying for and receiving a certified badge.
          </p>
        </div>

        <div className="rounded-xl border border-amber-200 bg-amber-50/50 p-3 text-xs dark:border-amber-900/60 dark:bg-amber-950/30">
          <div className="flex items-center gap-1.5 font-bold text-amber-900 dark:text-amber-200">
            <span>🤝</span> 2. Third-Party Trust (Horizontal)
          </div>
          <p className="mt-1 text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">
            Alice and Bob have never met. By introducing Trent as an impartial intermediary, Alice derives <strong>transitive trust</strong>: if Trent vouchsafes Bob, Alice safely accepts Bob&apos;s identity.
          </p>
        </div>

        <div className="rounded-xl border border-rose-200 bg-rose-50/50 p-3 text-xs dark:border-rose-900/60 dark:bg-rose-950/30">
          <div className="flex items-center gap-1.5 font-bold text-rose-900 dark:text-rose-200">
            <span>🗝️</span> 3. Cryptographic Grounding
          </div>
          <p className="mt-1 text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">
            Trent&apos;s private key never leaves the secure vault and signs certificates. During the TLS handshake, Alice decrypts Bob&apos;s signature using Trent&apos;s public key, preventing any imposter from spoofing Bob.
          </p>
        </div>
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
    case "certificate-chain":
      return <CertificateChainDiagram />;
    case "mtls":
      return <MtlsDiagram />;
    case "passport-analogy":
      return <PassportAnalogyDiagram />;
    case "root-store":
      return <RootStoreDiagram />;
    case "trust-triangle":
      return <TrustTriangleDiagram />;
  }
}
