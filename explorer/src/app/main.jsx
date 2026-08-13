// Application entry point: mounts the workbench and pulls in the
// stylesheet graph (the explorer styles and the Tabulator base styles)
// for the production CSS bundle.

import 'tabulator-tables/dist/css/tabulator.min.css';
import '../styles.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './App.jsx';
import { applyTheme, storedTheme } from './theme.js';

// Resolve the persisted theme before the first paint.
applyTheme(storedTheme());

const root = document.getElementById('root');
if (root === null) {
  throw new Error('the explorer page is missing its #root element');
}
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
