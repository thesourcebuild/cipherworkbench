import type { Metadata } from "next";
import type { ReactNode } from "react";
import { SITE_URL } from "../site";

export const metadata: Metadata = {
  title: "Interactive cryptography tutorials",
  description:
    "Interactive lessons for understanding hashes, checksums, MACs, ciphers, and related cryptographic tools.",
  alternates: { canonical: `${SITE_URL}/tutorials/` },
};

export default function TutorialsLayout({ children }: { children: ReactNode }) {
  return children;
}
