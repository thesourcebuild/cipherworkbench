"use client";

import { useCallback, useEffect, useState } from "react";
import { THEME_STORAGE_KEY, type ThemePreference } from "./theme-constants";

function applyTheme(preference: ThemePreference): void {
  const dark =
    preference === "dark" ||
    (preference === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
}

/**
 * Light/Dark/System, persisted. The `.dark` class it toggles is what the shared
 * theme CSS keys its `dark:` variant off — see `packages/ui/styles/theme.css`.
 */
export function useTheme(): {
  preference: ThemePreference;
  setPreference: (next: ThemePreference) => void;
} {
  const [preference, setPreferenceState] = useState<ThemePreference>("system");

  // The inline script in layout.tsx has already applied the right class by now;
  // this only syncs React's copy of the value so the picker shows it selected.
  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
      if (stored === "light" || stored === "dark" || stored === "system") {
        setPreferenceState(stored);
      }
    } catch {
      // Private browsing can throw; "system" is a fine default.
    }
  }, []);

  // In "system" mode the OS preference can change while the app is open.
  useEffect(() => {
    if (preference !== "system") return;
    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => applyTheme("system");
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, [preference]);

  const setPreference = useCallback((next: ThemePreference) => {
    setPreferenceState(next);
    applyTheme(next);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // Preference is a convenience, not the product.
    }
  }, []);

  return { preference, setPreference };
}
