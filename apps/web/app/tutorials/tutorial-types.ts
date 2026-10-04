import type { ToolFamily } from "@ocs/engine";

export interface TutorialCharacter {
  name: string;
  role: string;
  avatar: string;
  color: string;
}

export interface TutorialSeed {
  toolId: string;
  sampleInput: string;
  explanation: string;
}

export interface TutorialStep {
  title: string;
  speaker?: string;
  content: string;
  callout?: {
    type: "info" | "warning" | "security";
    text: string;
  };
}

export interface TutorialAfterTimeline {
  title: string;
  content: string;
  callout?: TutorialStep["callout"];
}

export type TutorialDifficulty = "Beginner" | "Intermediate" | "Advanced";
export type TlsTutorialVersion = "SSL 3.0" | "1.1" | "1.2" | "1.3";
export type DtlsTutorialVersion = "1.0" | "1.2" | "1.3";

export interface TutorialVariantMeta {
  id: string;
  label: string;
  title: string;
  subtitle: string;
  difficulty: TutorialDifficulty;
  readTime: string;
}

export interface TutorialMeta {
  id: string;
  number: string;
  title: string;
  subtitle: string;
  conceptId: string;
  family: ToolFamily;
  toolId: string;
  difficulty: TutorialDifficulty;
  readTime: string;
  characters: string[];
  summary: string;
  variants?: readonly TutorialVariantMeta[];
}

export interface TutorialContent {
  analogy: string;
  problem: string;
  visualization?:
    | {
        kind: "tls-handshake";
        version: TlsTutorialVersion;
      }
    | {
        kind: "dtls-handshake";
        version: DtlsTutorialVersion;
      };
  steps: TutorialStep[];
  afterTimeline?: TutorialAfterTimeline;
  takeaways: string[];
  seed: TutorialSeed;
}

export interface TutorialDef extends TutorialMeta, TutorialContent {}

export interface TutorialConceptMeta {
  id: string;
  title: string;
  description: string;
  badge: string;
  tutorials: TutorialMeta[];
}
