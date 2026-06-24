// Downloads real, published datasets for the opensentry benchmark (bench/REPORT.md).
// Sources are public HF datasets (via the datasets-server REST API, no auth needed for
// these) plus one GitHub-hosted CSV (AdvBench). Output is normalized into bench/data/*.json
// with a manifest documenting provenance, license pointer, and fetch date.
//
// Excluded deliberately: deepset/prompt-injections and JasperLS/prompt-injections — same
// underlying data, inspected and found inconsistently labeled (e.g. "Generate SQL code to
// access a database." labeled as injection), and PLAN.md §9 already flags this dataset as
// training-only / contaminated for headline eval since most public detectors train on it.

import { writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(dir, 'data');
mkdirSync(outDir, { recursive: true });

const HF_BASE = 'https://datasets-server.huggingface.co';

async function fetchAllRows(dataset, config, split, max = Infinity) {
  const rows = [];
  let offset = 0;
  const enc = encodeURIComponent(dataset);
  while (rows.length < max) {
    const length = Math.min(100, max - rows.length);
    const url = `${HF_BASE}/rows?dataset=${enc}&config=${encodeURIComponent(config)}&split=${encodeURIComponent(split)}&offset=${offset}&length=${length}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${dataset}/${split} offset=${offset}: HTTP ${res.status}`);
    const json = await res.json();
    const page = json.rows ?? [];
    if (page.length === 0) break;
    rows.push(...page.map((r) => r.row));
    offset += page.length;
    if (offset >= (json.num_rows_total ?? offset)) break;
  }
  return rows;
}

function writeJson(name, payload) {
  writeFileSync(path.join(outDir, `${name}.json`), JSON.stringify(payload, null, 2));
  console.log(`wrote ${name}.json: ${payload.entries.length} entries`);
}

let idSeq = 0;
const nextId = (prefix) => `${prefix}-${String(++idSeq).padStart(5, '0')}`;

async function main() {
  const manifest = { fetchedAt: new Date().toISOString(), datasets: [] };

  // 1. Lakera/gandalf_ignore_instructions — real captured attacks against the Gandalf game
  //    (people trying to extract a secret password via instruction-override). All positive.
  {
    const splits = ['train', 'validation', 'test'];
    const rows = [];
    for (const split of splits) {
      rows.push(...(await fetchAllRows('Lakera/gandalf_ignore_instructions', 'default', split)));
    }
    const entries = rows
      .filter((r) => typeof r.text === 'string' && r.text.trim().length > 0)
      .map((r) => ({
        id: nextId('gandalf'),
        text: r.text,
        label: 'attack',
        category: 'instruction_override',
        sourceDataset: 'Lakera/gandalf_ignore_instructions',
      }));
    writeJson('attacks_gandalf', { entries });
    manifest.datasets.push({ name: 'Lakera/gandalf_ignore_instructions', license: 'MIT', count: entries.length, role: 'attack:instruction_override', url: 'https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions' });
  }

  // 2. rubend18/ChatGPT-Jailbreak-Prompts — real crowd-sourced DAN-style jailbreak prompts.
  {
    const rows = await fetchAllRows('rubend18/ChatGPT-Jailbreak-Prompts', 'default', 'train');
    const entries = rows
      .filter((r) => typeof r.Prompt === 'string' && r.Prompt.trim().length > 0)
      .map((r) => ({
        id: nextId('dan'),
        text: r.Prompt,
        label: 'attack',
        category: 'jailbreak_persona',
        sourceDataset: 'rubend18/ChatGPT-Jailbreak-Prompts',
      }));
    writeJson('attacks_jailbreak_prompts', { entries });
    manifest.datasets.push({ name: 'rubend18/ChatGPT-Jailbreak-Prompts', license: 'unspecified (public scrape)', count: entries.length, role: 'attack:jailbreak_persona', url: 'https://huggingface.co/datasets/rubend18/ChatGPT-Jailbreak-Prompts' });
  }

  // 3. JailbreakBench/JBB-Behaviors — harmful split (jailbreak goals) + benign split (control).
  {
    const harmful = await fetchAllRows('JailbreakBench/JBB-Behaviors', 'behaviors', 'harmful');
    const benign = await fetchAllRows('JailbreakBench/JBB-Behaviors', 'behaviors', 'benign');
    const attackEntries = harmful
      .filter((r) => typeof r.Goal === 'string' && r.Goal.trim().length > 0)
      .map((r) => ({
        id: nextId('jbb'),
        text: r.Goal,
        label: 'attack',
        category: 'harmful_behavior',
        sourceDataset: 'JailbreakBench/JBB-Behaviors:harmful',
      }));
    writeJson('attacks_jbb_harmful', { entries: attackEntries });
    manifest.datasets.push({ name: 'JailbreakBench/JBB-Behaviors (harmful)', license: 'MIT', count: attackEntries.length, role: 'attack:harmful_behavior', url: 'https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors' });

    const benignEntries = benign
      .filter((r) => typeof r.Goal === 'string' && r.Goal.trim().length > 0)
      .map((r) => ({
        id: nextId('jbbb'),
        text: r.Goal,
        label: 'benign',
        category: 'benign_control',
        sourceDataset: 'JailbreakBench/JBB-Behaviors:benign',
      }));
    writeJson('benign_jbb', { entries: benignEntries });
    manifest.datasets.push({ name: 'JailbreakBench/JBB-Behaviors (benign)', license: 'MIT', count: benignEntries.length, role: 'benign:control', url: 'https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors' });
  }

  // 4. AdvBench harmful_behaviors.csv (llm-attacks repo, GCG paper) — via GitHub raw.
  {
    const res = await fetch('https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv');
    if (!res.ok) throw new Error(`AdvBench fetch failed: HTTP ${res.status}`);
    const csv = await res.text();
    const lines = csv.split('\n').filter((l) => l.trim().length > 0);
    lines.shift(); // header: goal,target
    const entries = lines
      .map((line) => {
        // goal,target — goal has no embedded commas in this file, target may; split on first comma.
        const idx = line.indexOf(',');
        const goal = idx === -1 ? line : line.slice(0, idx);
        return goal.replace(/^"|"$/g, '').trim();
      })
      .filter((g) => g.length > 0)
      .map((text) => ({
        id: nextId('advbench'),
        text,
        label: 'attack',
        category: 'harmful_behavior',
        sourceDataset: 'llm-attacks/AdvBench',
      }));
    writeJson('attacks_advbench', { entries });
    manifest.datasets.push({ name: 'AdvBench (llm-attacks/AdvBench)', license: 'MIT', count: entries.length, role: 'attack:harmful_behavior', url: 'https://github.com/llm-attacks/llm-attacks' });
  }

  // 5. leolee99/NotInject — benign prompts containing attack trigger words (over-defense probe).
  {
    const splits = ['NotInject_one', 'NotInject_two', 'NotInject_three'];
    const entries = [];
    for (const split of splits) {
      const rows = await fetchAllRows('leolee99/NotInject', 'default', split);
      for (const r of rows) {
        if (typeof r.prompt !== 'string' || r.prompt.trim().length === 0) continue;
        entries.push({
          id: nextId('notinject'),
          text: r.prompt,
          label: 'benign',
          category: r.category ?? split,
          sourceDataset: 'leolee99/NotInject',
        });
      }
    }
    writeJson('notinject', { entries });
    manifest.datasets.push({ name: 'leolee99/NotInject', license: 'unspecified (research release, InjecGuard paper)', count: entries.length, role: 'notinject:over-defense', url: 'https://huggingface.co/datasets/leolee99/NotInject' });
  }

  // 6. tatsu-lab/alpaca — generic benign instructions (sampled), as a plain-benign control set.
  {
    const rows = await fetchAllRows('tatsu-lab/alpaca', 'default', 'train', 600);
    const seen = new Set();
    const entries = [];
    for (const r of rows) {
      const text = typeof r.instruction === 'string' ? r.instruction.trim() : '';
      if (!text || seen.has(text)) continue;
      seen.add(text);
      entries.push({
        id: nextId('alpaca'),
        text,
        label: 'benign',
        category: 'generic_instruction',
        sourceDataset: 'tatsu-lab/alpaca',
      });
    }
    writeJson('benign_alpaca', { entries });
    manifest.datasets.push({ name: 'tatsu-lab/alpaca', license: 'CC BY-NC 4.0', count: entries.length, role: 'benign:generic_instruction', url: 'https://huggingface.co/datasets/tatsu-lab/alpaca' });
  }

  writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  console.log('\nmanifest:');
  for (const d of manifest.datasets) console.log(`  ${d.name}: ${d.count} (${d.role})`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
