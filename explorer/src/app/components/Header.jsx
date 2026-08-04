// Compact application header (explorer contract §2.2).

import { useId, useRef } from 'react';

import { abbreviatedDigest } from '../../lib/digest.js';

/**
 * @param {object} props
 * @param {string | null} props.filename
 * @param {string | null} props.digest
 * @param {string} props.query
 * @param {boolean} props.searchEnabled
 * @param {boolean} props.importing
 * @param {import('../theme.js').ThemeMode} props.theme
 * @param {(query: string) => void} props.onQueryChange
 * @param {(file: File) => void} props.onOpenFile
 * @param {() => void} props.onCancelImport
 * @param {(mode: import('../theme.js').ThemeMode) => void} props.onThemeChange
 */
export function Header({
  filename,
  digest,
  query,
  searchEnabled,
  importing,
  theme,
  onQueryChange,
  onOpenFile,
  onCancelImport,
  onThemeChange,
}) {
  const inputRef = useRef(/** @type {HTMLInputElement | null} */ (null));
  const searchId = useId();
  const themeId = useId();
  return (
    <header className="app-header">
      <p className="brand">
        <span className="brand-name">liveness primer</span>
        <span className="brand-surface">Report explorer</span>
      </p>
      {filename !== null && digest !== null && (
        <p className="report-identity">
          <span className="report-filename" title={filename}>
            {filename}
          </span>
          <span className="report-digest">
            digest{' '}
            <code title={`report SHA-256 ${digest}`}>{abbreviatedDigest(digest)}</code>
          </span>
        </p>
      )}
      <div className="header-search">
        <label className="visually-hidden" htmlFor={searchId}>
          Search path, symbol, message, rule, kind
        </label>
        <input
          id={searchId}
          type="search"
          placeholder="Search path, symbol, message, rule, kind"
          autoComplete="off"
          disabled={!searchEnabled}
          value={query}
          onChange={(event) => onQueryChange(event.currentTarget.value)}
        />
      </div>
      <div className="header-actions">
        {importing ? (
          <button type="button" onClick={onCancelImport}>
            Cancel import
          </button>
        ) : (
          <button type="button" onClick={() => inputRef.current?.click()}>
            Open report
          </button>
        )}
        <input
          ref={inputRef}
          className="visually-hidden"
          type="file"
          accept=".json,application/json"
          aria-label="Report JSON file"
          onChange={(event) => {
            const file = event.currentTarget.files?.[0];
            event.currentTarget.value = '';
            if (file !== undefined) {
              onOpenFile(file);
            }
          }}
        />
        <label className="visually-hidden" htmlFor={themeId}>
          Theme
        </label>
        <select
          id={themeId}
          value={theme}
          onChange={(event) =>
            onThemeChange(/** @type {import('../theme.js').ThemeMode} */ (event.currentTarget.value))
          }
        >
          <option value="system">System theme</option>
          <option value="light">Light theme</option>
          <option value="dark">Dark theme</option>
        </select>
      </div>
    </header>
  );
}
