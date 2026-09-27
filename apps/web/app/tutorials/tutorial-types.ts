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

export interface TutorialMeta {
  id: string;
  number: string;
  title: string;
  subtitle: string;
  conceptId: string;
  family: ToolFamily;
  toolId: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  readTime: string;
  characters: string[];
  summary: string;
}

export interface TutorialContent {
  analogy: string;
  problem: string;
  steps: TutorialStep[];
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
