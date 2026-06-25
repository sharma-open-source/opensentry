// Minimal LRU (Map preserves insertion order) + a fast non-crypto string hash for keys.
// The cache is a best-effort perf optimization (re-scan identical inputs); a 32-bit hash
// collision is negligible for the configured entry count.

export function hashStr(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  }
  return (h >>> 0).toString(36);
}

export class LRU<K, V> {
  private m = new Map<K, V>();
  constructor(private readonly max: number) {
    if (max <= 0) throw new Error('LRU max must be > 0');
  }

  get(k: K): V | undefined {
    const v = this.m.get(k);
    if (v === undefined) return undefined;
    this.m.delete(k);
    this.m.set(k, v);
    return v;
  }

  set(k: K, v: V): void {
    if (this.m.has(k)) this.m.delete(k);
    this.m.set(k, v);
    if (this.m.size > this.max) {
      const first = this.m.keys().next().value;
      if (first !== undefined) this.m.delete(first as K);
    }
  }

  delete(k: K): boolean {
    return this.m.delete(k);
  }

  clear(): void {
    this.m.clear();
  }

  get size(): number {
    return this.m.size;
  }
}
