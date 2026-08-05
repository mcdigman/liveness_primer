# liveness primer report explorer

A static desktop workbench for reviewing a completed `liveness_primer`
JSON report in the browser, implementing
[`static_report_explorer.md`](../.contracts/static_report_explorer.md).
The visual references live under [`design/mockups/`](../design/mockups/).

The explorer presents an already-computed report: it never runs a
detector, recomputes a diff, or reimplements the Python report model. A
reviewer opens a local report (no upload, no network), searches, filters,
groups, sorts, selects, and hides findings, inspects base/head analyzer
output with pinned source evidence, and exports the selection as Markdown
or a versioned JSON review record.

## Thin-client boundary

The Pydantic models and the exported JSON Schemas are the source of truth
(contract §4). In particular:

- Python serializes a unique `locator` on every `FindingDiff` during
  canonical assembly; the browser treats it as opaque structured data and
  never recomputes occurrence ordinals.
- `generate-validators.mjs` compiles the exported `report` and
  `explorer-review` schemas into `src/generated/validators.js` with Ajv
  standalone code generation, for the dialect each schema declares. The
  committed module is CI-checked for freshness and contains no runtime
  schema compilation, so the CSP needs no `unsafe-eval`.
- The portable review record is the generated `explorer-review` schema
  exported from the Python `ExplorerReview` model.

## Layout

- `src/lib/` — pure report-to-view logic (projection, facets, sorting,
  workspace state, exports, permalinks, bounded source fetch). Unit
  tested by `node --test` with 100% line / 96% branch coverage gates.
- `src/app/` — the React workbench (header, filter rail, status strip,
  Tabulator findings grid, export/context panel, import worker).
- `src/generated/` — the committed Ajv standalone validator module and
  its hand-maintained declarations.
- `tests/unit/` — node test suites over `src/lib`, sharing the
  Python-generated `tests/fixtures/locator_golden.json` fixture.
- `tests/browser/` — Playwright suites: workflow, layout/scroll, themes,
  accessibility (axe), adversarial content, network discipline, and
  performance evidence, served from a GitHub-Pages-style subpath.

## Development

Dependencies are local and pinned by `package-lock.json`; production
loads no CDN assets.

```sh
npm ci                      # install the pinned toolchain
npm run generate-validators # refresh src/generated after schema export
npm test                    # unit tests
npm run coverage            # unit tests with coverage gates
npm run lint                # eslint, zero warnings
npm run typecheck           # strict tsc over JS/JSX with JSDoc types
npm run format              # prettier check
npm run build               # production bundle into dist/
npm run licenses            # bundled-dependency license check
npm run serve               # serve dist/ at a local test subpath
npm run test:browser        # Playwright suites (builds first)
```

The production bundle is static HTML, CSS, and JavaScript with relative
asset references, deployable below a GitHub Pages subpath by
`.github/workflows/explorer-pages.yml` (trusted default-branch code only,
SHA-pinned actions, write permissions only in the deploy job).
