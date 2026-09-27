import type { TutorialContent } from "./tutorial-types";

const TUTORIAL_CONTENT_LOADERS: Record<string, () => Promise<{ default: TutorialContent }>> = {
  "1.1-the-scratched-postcard": () => import("./content/1.1-the-scratched-postcard"),
  "1.2-the-static-on-the-wire": () => import("./content/1.2-the-static-on-the-wire"),
  "1.3-the-digital-fingerprint": () => import("./content/1.3-the-digital-fingerprint"),
  "2.1-the-tampered-hash-trap": () => import("./content/2.1-the-tampered-hash-trap"),
  "2.2-the-secret-handshake": () => import("./content/2.2-the-secret-handshake"),
  "3.1-the-locked-steel-box": () => import("./content/3.1-the-locked-steel-box"),
  "3.2-the-reused-key-catastrophe": () => import("./content/3.2-the-reused-key-catastrophe"),
  "3.3-the-perfect-fusion-aead": () => import("./content/3.3-the-perfect-fusion-aead"),
  "4.1-the-paint-mixing-trick": () => import("./content/4.1-the-paint-mixing-trick"),
  "4.2-the-open-padlock": () => import("./content/4.2-the-open-padlock"),
  "4.3-the-royal-signet-ring": () => import("./content/4.3-the-royal-signet-ring"),
  "5.1-the-complete-tls-handshake": () => import("./content/5.1-the-complete-tls-handshake"),
  "5.2-the-imposter-in-the-middle": () => import("./content/5.2-the-imposter-in-the-middle"),
  "5.3-the-password-vault": () => import("./content/5.3-the-password-vault"),
  "5.4-the-pirate-treasure-chest": () => import("./content/5.4-the-pirate-treasure-chest"),
  "5.5-the-quantum-spy": () => import("./content/5.5-the-quantum-spy"),
};

const contentCache = new Map<string, TutorialContent>();

export async function loadTutorialContent(id: string): Promise<TutorialContent | null> {
  if (contentCache.has(id)) {
    return contentCache.get(id)!;
  }
  const loader = TUTORIAL_CONTENT_LOADERS[id];
  if (!loader) {
    return null;
  }
  const mod = await loader();
  contentCache.set(id, mod.default);
  return mod.default;
}
