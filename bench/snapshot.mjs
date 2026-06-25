// Copies the latest bench/report.json into bench/history/<date>.json so regressions are
// visible over time. Run after `pnpm bench`, before a release.
// Unlike bench/report.json (gitignored, regenerated every run), bench/history/*.json files
// are meant to be committed — that's the whole point of tracking history.
import { copyFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const reportPath = path.join(dir, 'report.json');
const historyDir = path.join(dir, 'history');

if (!existsSync(reportPath)) {
  console.error('bench/report.json not found — run `pnpm bench` first.');
  process.exit(1);
}

mkdirSync(historyDir, { recursive: true });

const report = JSON.parse(readFileSync(reportPath, 'utf8'));
const date = (report.generatedAt ?? new Date().toISOString()).slice(0, 10);
const dest = path.join(historyDir, `${date}.json`);

copyFileSync(reportPath, dest);
console.log(`Snapshotted bench/report.json -> bench/history/${date}.json`);
console.log('Commit this file to track benchmark results over time.');
