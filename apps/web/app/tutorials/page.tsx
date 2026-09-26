"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

export default function TutorialsRedirect() {
  const router = useRouter();

  useEffect(() => {
    router.replace("/guides/");
  }, [router]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 p-6 text-center dark:bg-slate-950">
      <div className="space-y-3">
        <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
          Redirecting to Guides...
        </p>
        <Link
          href="/guides/"
          className="text-xs font-semibold text-indigo-600 underline dark:text-indigo-400"
        >
          Click here if you are not redirected automatically
        </Link>
      </div>
    </div>
  );
}
