import type { CryptographicFlowId } from "./tutorial-types";

export type CryptographicFlowTone =
  "neutral" | "cyan" | "violet" | "emerald" | "amber" | "rose";

export interface CryptographicFlowParticipant {
  id: string;
  name: string;
  role: string;
  initial: string;
  tone: CryptographicFlowTone;
}

export interface CryptographicFlowEvent {
  step: number;
  title: string;
  actors: readonly string[];
  route: string;
  artifacts: readonly string[];
  status: string;
  tone: CryptographicFlowTone;
  note: string;
}

export interface CryptographicFlowLegend {
  title: string;
  description: string;
  tone: CryptographicFlowTone;
}

export interface CryptographicFlow {
  eyebrow: string;
  title: string;
  property: string;
  summary: string;
  participants: readonly CryptographicFlowParticipant[];
  events: readonly CryptographicFlowEvent[];
  legend: readonly CryptographicFlowLegend[];
}

const ALICE: CryptographicFlowParticipant = {
  id: "alice",
  name: "Alice",
  role: "Sender",
  initial: "A",
  tone: "amber",
};

const BOB: CryptographicFlowParticipant = {
  id: "bob",
  name: "Bob",
  role: "Receiver",
  initial: "B",
  tone: "cyan",
};

const EVE: CryptographicFlowParticipant = {
  id: "eve",
  name: "Eve",
  role: "Eavesdropper",
  initial: "E",
  tone: "violet",
};

const MALLORY: CryptographicFlowParticipant = {
  id: "mallory",
  name: "Mallory",
  role: "Active attacker",
  initial: "M",
  tone: "rose",
};

const NETWORK: CryptographicFlowParticipant = {
  id: "network",
  name: "Network",
  role: "Untrusted channel",
  initial: "N",
  tone: "neutral",
};

const TRENT: CryptographicFlowParticipant = {
  id: "trent",
  name: "Trent",
  role: "Certificate Authority",
  initial: "T",
  tone: "emerald",
};

export const CRYPTOGRAPHIC_FLOWS: Record<CryptographicFlowId, CryptographicFlow> = {
  crc: {
    eyebrow: "CRC-32 · Accidental corruption detection",
    title: "A frame check catches noise, not an attacker",
    property: "Integrity check",
    summary: "compute FCS → compare clean frame → corrupt second frame → reject",
    participants: [ALICE, NETWORK, BOB],
    events: [
      {
        step: 1,
        title: "Alice computes and appends the CRC-32",
        actors: ["alice"],
        route: "Local calculation",
        artifacts: ["payload", "CRC-32", "FCS: 0x7E060C31"],
        status: "checksum created",
        tone: "cyan",
        note: "Alice's NIC appends a four-byte remainder calculated over the frame.",
      },
      {
        step: 2,
        title: "The Valid Scenario — Bob verifies a clean packet",
        actors: ["alice", "bob"],
        route: "Alice → Bob · clean transmission",
        artifacts: ["payload unchanged", "matching FCS"],
        status: "accepted",
        tone: "emerald",
        note: "Bob recomputes the CRC and accepts the frame because both values match.",
      },
      {
        step: 3,
        title: "The Invalid Scenario — Lightning causes burst line noise",
        actors: ["network"],
        route: "Second transmission · network fault",
        artifacts: ["three adjacent bits flip", "payload corrupted"],
        status: "accidental damage",
        tone: "amber",
        note: "A burst error changes the polynomial remainder carried by the received frame.",
      },
      {
        step: 4,
        title: "Bob catches the corruption and drops the frame",
        actors: ["bob"],
        route: "Local verification",
        artifacts: ["received FCS", "recomputed CRC", "mismatch"],
        status: "rejected",
        tone: "rose",
        note: "Bob discards the damaged frame; a higher layer may arrange retransmission.",
      },
    ],
    legend: [
      {
        title: "Detects noise",
        description: "Strong burst-error detection makes CRC useful for storage and networks.",
        tone: "emerald",
      },
      {
        title: "No secret",
        description: "Everyone can calculate the same CRC from the visible data.",
        tone: "neutral",
      },
      {
        title: "Forgeable",
        description: "An attacker can alter data and deliberately calculate a matching CRC.",
        tone: "rose",
      },
    ],
  },
  hash: {
    eyebrow: "SHA-256 · Integrity against deliberate modification",
    title: "A trusted fingerprint exposes a tampered download",
    property: "Integrity",
    summary: "publish trusted digest → tamper with file → recompute locally → reject",
    participants: [ALICE, MALLORY, BOB],
    events: [
      {
        step: 1,
        title: "Alice publishes the Official Fingerprint",
        actors: ["alice"],
        route: "Trusted channel",
        artifacts: ["official installer", "SHA-256", "trusted digest"],
        status: "reference published",
        tone: "cyan",
        note: "Alice publishes the expected digest somewhere Mallory cannot silently replace it.",
      },
      {
        step: 2,
        title: "Mallory tries to tamper with the download mirror",
        actors: ["mallory"],
        route: "Untrusted mirror",
        artifacts: ["modified installer", "different digest"],
        status: "tampering",
        tone: "rose",
        note: "Mallory changes the file but cannot feasibly preserve Alice's existing SHA-256 value.",
      },
      {
        step: 3,
        title: "Bob detects the digest mismatch",
        actors: ["bob"],
        route: "Local comparison",
        artifacts: ["trusted digest", "download digest", "mismatch"],
        status: "rejected",
        tone: "emerald",
        note: "Bob hashes the download locally and rejects it when the digest differs.",
      },
    ],
    legend: [
      {
        title: "Trusted reference",
        description: "Integrity depends on obtaining the expected digest authentically.",
        tone: "cyan",
      },
      {
        title: "Second-preimage resistance",
        description: "A modified file cannot feasibly be crafted to match the fixed digest.",
        tone: "emerald",
      },
      {
        title: "Not authenticity alone",
        description: "A hash sent beside the file can be replaced by the same attacker.",
        tone: "amber",
      },
    ],
  },
  hmac: {
    eyebrow: "HMAC-SHA-256 · Keyed message authentication",
    title: "A shared secret turns a hash into sender proof",
    property: "Authenticity",
    summary: "share secret → compute tag → attacker alters message → verify or reject",
    participants: [ALICE, MALLORY, BOB],
    events: [
      {
        step: 1,
        title: "The Shared API Secret",
        actors: ["alice", "bob"],
        route: "Provisioned securely",
        artifacts: ["shared secret key"],
        status: "secret established",
        tone: "violet",
        note: "Alice and Bob possess the same secret; Mallory does not.",
      },
      {
        step: 2,
        title: "Computing the HMAC",
        actors: ["alice"],
        route: "Alice → Bob",
        artifacts: ["plaintext request", "HMAC-SHA-256 tag"],
        status: "keyed proof",
        tone: "cyan",
        note: "Alice authenticates the exact request bytes with the shared secret.",
      },
      {
        step: 3,
        title: "Mallory is foiled",
        actors: ["mallory"],
        route: "Active interception",
        artifacts: ["altered amount", "stale or guessed tag"],
        status: "forgery attempt",
        tone: "rose",
        note: "Mallory can edit visible data but cannot calculate a valid tag without the key.",
      },
      {
        step: 4,
        title: "Bob verifies or rejects in constant time",
        actors: ["bob"],
        route: "Local verification",
        artifacts: ["received tag", "recomputed tag", "timing-safe compare"],
        status: "authenticated",
        tone: "emerald",
        note: "Matching tags accept Alice's original request; altered requests are rejected.",
      },
    ],
    legend: [
      {
        title: "Integrity",
        description: "Any message change produces a different authentication tag.",
        tone: "cyan",
      },
      {
        title: "Authenticity",
        description: "A valid tag demonstrates knowledge of the shared secret.",
        tone: "emerald",
      },
      {
        title: "No confidentiality",
        description: "The message remains readable unless it is encrypted separately.",
        tone: "amber",
      },
    ],
  },
  symmetric: {
    eyebrow: "Symmetric encryption · One shared secret key",
    title: "The same secret key locks and unlocks the message",
    property: "Confidentiality",
    summary: "prepare plaintext → establish key → encrypt → observe ciphertext → decrypt",
    participants: [ALICE, EVE, BOB],
    events: [
      {
        step: 1,
        title: "Alice writes the Plaintext",
        actors: ["alice"],
        route: "Local preparation",
        artifacts: ["Meet me at noon"],
        status: "plaintext",
        tone: "neutral",
        note: "The original message is readable before encryption.",
      },
      {
        step: 2,
        title: "The Pre-Shared Secret",
        actors: ["alice", "bob"],
        route: "Established out of band",
        artifacts: ["one shared 256-bit key"],
        status: "secret key",
        tone: "violet",
        note: "Both peers need the same secret key, creating a separate distribution problem.",
      },
      {
        step: 3,
        title: "Alice encrypts with AES-256",
        actors: ["alice"],
        route: "Local encryption",
        artifacts: ["plaintext", "secret key", "unique nonce / IV", "ciphertext"],
        status: "encrypted",
        tone: "cyan",
        note: "Alice transforms readable data into ciphertext under the shared key.",
      },
      {
        step: 4,
        title: "What Eve sees on the wire",
        actors: ["eve"],
        route: "Public network",
        artifacts: ["ciphertext", "nonce / IV"],
        status: "content hidden",
        tone: "amber",
        note: "Eve can observe metadata and ciphertext but cannot read the message without the key.",
      },
      {
        step: 5,
        title: "Bob decrypts with the shared key",
        actors: ["bob"],
        route: "Local decryption",
        artifacts: ["ciphertext", "same secret key", "plaintext"],
        status: "decrypted",
        tone: "emerald",
        note: "Bob reverses the encryption and recovers Alice's message.",
      },
    ],
    legend: [
      {
        title: "Fast bulk encryption",
        description: "Symmetric ciphers efficiently protect large amounts of data.",
        tone: "cyan",
      },
      {
        title: "Shared-key problem",
        description: "The same secret must reach both peers without leaking.",
        tone: "violet",
      },
      {
        title: "Use AEAD",
        description: "Production systems add authentication with AES-GCM or ChaCha20-Poly1305.",
        tone: "amber",
      },
    ],
  },
  ecdh: {
    eyebrow: "ECDH · Asymmetric key agreement",
    title: "Public shares produce one private session secret",
    property: "Key agreement",
    summary: "choose public parameters → create private keys → exchange shares → derive secret",
    participants: [ALICE, EVE, BOB],
    events: [
      {
        step: 1,
        title: "Public Base Color",
        actors: ["alice", "bob"],
        route: "Public parameters",
        artifacts: ["X25519 group", "public base point"],
        status: "public",
        tone: "neutral",
        note: "Everyone may know the selected group and its public base point.",
      },
      {
        step: 2,
        title: "Alice & Bob pick Secret Colors",
        actors: ["alice", "bob"],
        route: "Independent local generation",
        artifacts: ["Alice private key", "Bob private key"],
        status: "private",
        tone: "violet",
        note: "Each private value remains on the endpoint that generated it.",
      },
      {
        step: 3,
        title: "Mixing and Exchanging",
        actors: ["alice", "bob", "eve"],
        route: "Alice ↔ Bob · Eve observes",
        artifacts: ["Alice public share", "Bob public share"],
        status: "public exchange",
        tone: "cyan",
        note: "The public shares cross the network without revealing either private key.",
      },
      {
        step: 4,
        title: "The Shared Secret is Born",
        actors: ["alice", "bob"],
        route: "Independent local derivation",
        artifacts: ["matching ECDH secret", "KDF → session key"],
        status: "shared secret",
        tone: "emerald",
        note: "Both sides derive the same secret and pass it through a KDF before use.",
      },
    ],
    legend: [
      {
        title: "Private keys stay local",
        description: "Only public shares travel across the network.",
        tone: "violet",
      },
      {
        title: "Shared result",
        description: "Both peers independently calculate identical secret material.",
        tone: "emerald",
      },
      {
        title: "Authentication required",
        description: "Unauthenticated ECDH remains vulnerable to an active MitM.",
        tone: "amber",
      },
    ],
  },
  rsa: {
    eyebrow: "RSA-OAEP · Asymmetric encryption",
    title: "A public key locks; the private key unlocks",
    property: "Confidentiality",
    summary:
      "generate keypair → encrypt with public key → intercept ciphertext → decrypt privately",
    participants: [ALICE, EVE, BOB],
    events: [
      {
        step: 1,
        title: "Bob generates a Keypair",
        actors: ["bob"],
        route: "Local key generation",
        artifacts: ["public key: publish", "private key: protect"],
        status: "keypair",
        tone: "violet",
        note: "Bob publishes the encryption key while keeping the decryption key secret.",
      },
      {
        step: 2,
        title: "Alice locks with Bob's Public Key",
        actors: ["alice"],
        route: "Alice → Bob",
        artifacts: ["plaintext", "Bob public key", "RSA-OAEP ciphertext"],
        status: "encrypted",
        tone: "cyan",
        note: "Alice uses Bob's authentic public key to encrypt a small secret or symmetric key.",
      },
      {
        step: 3,
        title: "Eve intercepts the parcel",
        actors: ["eve"],
        route: "Public network",
        artifacts: ["public key", "ciphertext"],
        status: "content hidden",
        tone: "amber",
        note: "The public key does not give Eve the private trapdoor needed to decrypt.",
      },
      {
        step: 4,
        title: "Bob decrypts with his Private Key",
        actors: ["bob"],
        route: "Local decryption",
        artifacts: ["RSA-OAEP ciphertext", "Bob private key", "plaintext"],
        status: "decrypted",
        tone: "emerald",
        note: "Only Bob's private key recovers the protected plaintext.",
      },
    ],
    legend: [
      {
        title: "Public encryption key",
        description: "Anyone may encrypt a message intended for Bob.",
        tone: "cyan",
      },
      {
        title: "Private decryption key",
        description: "Bob must protect the only key that opens the ciphertext.",
        tone: "violet",
      },
      {
        title: "No sender proof",
        description: "Encryption for Bob does not authenticate who created the ciphertext.",
        tone: "amber",
      },
    ],
  },
  certificate: {
    eyebrow: "X.509 PKI · Authenticated public-key distribution",
    title: "A certificate chain connects Bob's key to a trusted root",
    property: "Authentication",
    summary:
      "detect key substitution → request certificate → issue chain → validate → prove key",
    participants: [ALICE, MALLORY, BOB, TRENT],
    events: [
      {
        step: 1,
        title: "Mallory substitutes an unauthenticated public key",
        actors: ["alice", "mallory"],
        route: "Untrusted network",
        artifacts: ["key request", "Mallory's public key", "false identity"],
        status: "MitM possible",
        tone: "rose",
        note: "Encryption cannot expose a substituted key when Alice has no authenticated reference.",
      },
      {
        step: 2,
        title: "Bob creates a keypair and certificate request",
        actors: ["bob"],
        route: "Local generation",
        artifacts: ["private key", "public key", "signed CSR", "SAN request"],
        status: "request prepared",
        tone: "violet",
        note: "Bob keeps the private key and asks a CA to certify the public key and DNS name.",
      },
      {
        step: 3,
        title: "Trent validates Bob and issues a certificate",
        actors: ["bob", "trent"],
        route: "CA validation and issuance",
        artifacts: ["domain control", "leaf certificate", "intermediate signature"],
        status: "identity bound",
        tone: "emerald",
        note: "The CA validates authorization and signs a certificate binding Bob's key to the name.",
      },
      {
        step: 4,
        title: "Bob presents the certificate chain",
        actors: ["bob", "alice"],
        route: "TLS handshake",
        artifacts: ["leaf certificate", "intermediate certificates", "root omitted"],
        status: "chain presented",
        tone: "cyan",
        note: "Bob sends the public chain needed to reach a root already trusted by Alice.",
      },
      {
        step: 5,
        title: "Alice validates the chain and server identity",
        actors: ["alice", "trent"],
        route: "Local policy checks",
        artifacts: ["trusted root", "signatures", "validity", "SAN hostname", "key usage"],
        status: "identity verified",
        tone: "amber",
        note: "Alice accepts only a valid path whose leaf certificate authorizes the requested hostname.",
      },
      {
        step: 6,
        title: "Bob proves possession of the private key",
        actors: ["bob", "alice"],
        route: "TLS CertificateVerify",
        artifacts: ["handshake transcript", "private-key signature", "Finished"],
        status: "peer authenticated",
        tone: "emerald",
        note: "Bob signs the transcript so a thief holding only the public certificate cannot impersonate him.",
      },
    ],
    legend: [
      {
        title: "Chain of trust",
        description:
          "Each CA signature links the leaf certificate toward a locally trusted root.",
        tone: "emerald",
      },
      {
        title: "Identity checks",
        description: "The SAN hostname and certificate policy must match the intended server.",
        tone: "cyan",
      },
      {
        title: "Trust boundary",
        description: "Misissuance or an unsafe trust store can still authorize an attacker.",
        tone: "amber",
      },
    ],
  },
};
