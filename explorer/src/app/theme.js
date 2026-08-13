// Light, dark, or system theme selection (explorer contract §2.2, §2.6).

/** @typedef {'system' | 'light' | 'dark'} ThemeMode */

const THEME_KEY = 'liveness-primer-explorer:theme';

/** @returns {ThemeMode} */
export function storedTheme() {
  try {
    const value = localStorage.getItem(THEME_KEY);
    return value === 'light' || value === 'dark' ? value : 'system';
  } catch {
    return 'system';
  }
}

/**
 * @param {ThemeMode} mode
 * @returns {void}
 */
export function persistTheme(mode) {
  try {
    localStorage.setItem(THEME_KEY, mode);
  } catch {
    // Theme preference is a convenience; storage failure is harmless here.
  }
}

/**
 * @param {ThemeMode} mode
 * @returns {void}
 */
export function applyTheme(mode) {
  const dark = matchMedia('(prefers-color-scheme: dark)').matches;
  const resolved = mode === 'system' ? (dark ? 'dark' : 'light') : mode;
  document.documentElement.dataset.theme = resolved;
}

/**
 * Re-apply on system changes while in system mode.
 *
 * @param {() => ThemeMode} currentMode
 * @returns {() => void} unsubscribe
 */
export function watchSystemTheme(currentMode) {
  const media = matchMedia('(prefers-color-scheme: dark)');
  const listener = () => {
    if (currentMode() === 'system') {
      applyTheme('system');
    }
  };
  media.addEventListener('change', listener);
  return () => media.removeEventListener('change', listener);
}
