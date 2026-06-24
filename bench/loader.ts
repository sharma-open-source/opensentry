import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export interface BenchEntry {
  id: string;
  text: string;
  label: 'attack' | 'benign';
  category: string;
  sourceDataset: string;
}

const dir = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(dir, 'data');

export function loadBenchCorpora(): {
  attacks: BenchEntry[];
  benign: BenchEntry[];
  notinject: BenchEntry[];
} {
  const files = readdirSync(dataDir).filter((f) => f.endsWith('.json') && f !== 'manifest.json');
  const attacks: BenchEntry[] = [];
  const benign: BenchEntry[] = [];
  const notinject: BenchEntry[] = [];

  for (const file of files) {
    const data = JSON.parse(readFileSync(path.join(dataDir, file), 'utf8')) as {
      entries: BenchEntry[];
    };
    if (file === 'notinject.json') {
      notinject.push(...data.entries);
    } else if (file.startsWith('attacks_')) {
      attacks.push(...data.entries);
    } else if (file.startsWith('benign_')) {
      benign.push(...data.entries);
    }
  }
  return { attacks, benign, notinject };
}
