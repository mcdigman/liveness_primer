# liveness primer report explorer

The static, client-side review surface for completed `liveness_primer`
reports, implementing [`.contracts/static_report_explorer.md`](../.contracts/static_report_explorer.md).

A reviewer opens a downloaded JSON report artifact; loading, validation,
projection, filtering, review persistence, and export all happen locally in
the browser. Nothing is uploaded. The only network request the application
can ever make is the explicit, optional `Load complete pinned file` action
against `https://raw.githubusercontent.com`.

## Layout

- `index.html`, `styles.css` — the application shell: semantic landmarks,
  theme tokens (light and dark), and the meta Content Security Policy.
- `src/lib/` — framework-neutral, strictly typed (JSDoc + `tsc --strict`)
  modules: schema and semantic validation, digesting, projection and
  locators, filtering, sorting, permalinks, review sessions, Markdown
  export, persistence, and complete-file loading. These modules have no DOM
  or framework dependency and are the reusable core (contract §2.2).
- `src/app/` — the DOM controller and the off-main-thread validation
  worker. All untrusted strings are inserted with text-safe DOM APIs.
- `src/generated/schemas.js` — generated from
  `liveness_primer/schemas/*.schema.json` by `generate-schemas.mjs`; CI
  verifies it is in sync. The pydantic models remain the source of truth.
- `build.mjs` — deterministic, dependency-free production build emitting
  content-hashed assets, the entry page, the supported schemas, and the
  license notice into `dist/`. The output works beneath a repository
  subpath (GitHub Pages is the reference host).
- `tests/unit/` — `node --test` suites for the `src/lib/` modules,
  including the shared Python-generated locator golden fixture
  (`tests/fixtures/locator_golden.json` at the repository root).
- `tests/browser/` — Playwright suites (Chromium, Firefox, WebKit):
  functional and keyboard flows, adversarial fixtures, axe accessibility
  scans, and computed-style contrast verification for every theme token
  pairing.

## Running locally

No installation is needed for the core loop (Node 22+):

```sh
node explorer/generate-schemas.mjs   # refresh embedded schemas
node --test explorer/tests/unit/*.test.mjs
node explorer/build.mjs              # emit explorer/dist/
python3 -m http.server 8931 --directory explorer   # serve the source tree
```

The dev toolchain (Prettier, ESLint, `tsc`, Playwright) is declared in
`package.json` and used by `.github/workflows/explorer.yml`:

```sh
cd explorer
npm ci
npm run format && npm run lint && npm run typecheck
npm run coverage
npm run build && npm run test:browser
```

## Review model

Dispositions (`expected` / `unexpected` / `unreviewed`) concern the
expected blast radius of a detector change; they are not the
internal-corpus annotation verdicts and are never written into
`Annotation`. Review state is saved in `localStorage` under the report's
SHA-256 digest, can be exported and re-imported as versioned
`ReviewSession` JSON (`review-session.schema.json`), and can be summarized
as escaped Markdown for a pull-request review.

## Accessibility

The explorer targets WCAG 2.2 AA (contract §13). Automated axe scans and
computed-style contrast checks run in CI; per contract §17.3 a documented
manual pass (screen reader, keyboard-only, 200% zoom, forced colors) is
additionally required before the first release and after material
interaction changes.
