import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export type CorpusName = 'attacks' | 'benign' | 'notinject';

export interface CorpusEntry {
  id: string;
  text: string;
  label: 'attack' | 'benign';
  category?: string;
  source?: string;
  locale?: string;
  expect?: 'block' | 'flag' | 'detect' | 'miss'; // expected Tier-0 outcome (attacks)
  hardBlock?: boolean; // attack relies on a deterministic hard-block rule
  outOfScope?: boolean; // Tier 0 not expected to catch (multilingual/paraphrase/GCG/art) — excluded from recall
  notes?: string;
}

interface CorpusFile {
  name: string;
  version: number;
  entries: CorpusEntry[];
}

const dir = path.dirname(fileURLToPath(import.meta.url));

export function loadCorpus(name: CorpusName): CorpusEntry[] {
  const file = path.join(dir, `${name}.json`);
  const data = JSON.parse(readFileSync(file, 'utf8')) as CorpusFile;
  return data.entries;
}

export function loadAll(): { attacks: CorpusEntry[]; benign: CorpusEntry[]; notinject: CorpusEntry[] } {
  return {
    attacks: loadCorpus('attacks'),
    benign: loadCorpus('benign'),
    notinject: loadCorpus('notinject'),
  };
}
