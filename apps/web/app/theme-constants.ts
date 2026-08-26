/**
 * Shared between the pre-hydration inline script in `layout.tsx` and the
 * `useTheme` hook. Duplicating the key string across those two would mean a
 * rename silently stops reading the saved preference.
 */
export const THEME_STORAGE_KEY = "cipherworkbench:theme";

export type ThemePreference = "light" | "dark" | "system";
