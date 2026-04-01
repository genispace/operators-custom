import { useCallback, useEffect, useState } from 'react';

export type PlaygroundTheme = 'light' | 'dark';

const STORAGE_KEY = 'gs_dev_playground_theme';

function readStoredTheme(): PlaygroundTheme {
  if (typeof window === 'undefined') return 'dark';
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === 'light' || v === 'dark') return v;
  } catch {
    /* ignore */
  }
  return 'dark';
}

function applyDomTheme(theme: PlaygroundTheme) {
  if (typeof document === 'undefined') return;
  document.documentElement.classList.remove('light', 'dark');
  document.documentElement.classList.add(theme);
}

/**
 * 与 Chat / shared-ui 一致：在 document.documentElement 上切换 `light` | `dark` class。
 * 持久化到 localStorage，供远程插件与调试台样式共用。
 */
export function usePlaygroundTheme() {
  const [theme, setThemeState] = useState<PlaygroundTheme>(readStoredTheme);

  useEffect(() => {
    applyDomTheme(theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      /* ignore */
    }
  }, [theme]);

  const setTheme = useCallback((t: PlaygroundTheme) => {
    setThemeState(t);
  }, []);

  const toggleTheme = useCallback(() => {
    setThemeState((t) => (t === 'dark' ? 'light' : 'dark'));
  }, []);

  return { theme, setTheme, toggleTheme };
}
