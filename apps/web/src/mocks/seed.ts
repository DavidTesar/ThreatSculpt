/** Deterministic pseudo-randomness, so fixtures are identical on every run and in CI. */

export function createRng(seed: number) {
  let state = seed >>> 0;
  return {
    /** Mulberry32 — small, fast, good enough for fixture spread. */
    next(): number {
      state = (state + 0x6d2b79f5) >>> 0;
      let t = state;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    },
    int(min: number, max: number): number {
      return min + Math.floor(this.next() * (max - min + 1));
    },
    pick<T>(items: readonly T[]): T {
      const item = items[Math.floor(this.next() * items.length)];
      if (item === undefined) throw new Error('pick() called with an empty array');
      return item;
    },
    /** Picks with weights, e.g. weighted(['a','b'], [3,1]) → 'a' 75% of the time. */
    weighted<T>(items: readonly T[], weights: readonly number[]): T {
      const total = weights.reduce((sum, w) => sum + w, 0);
      let roll = this.next() * total;
      for (let i = 0; i < items.length; i++) {
        roll -= weights[i] ?? 0;
        if (roll <= 0) {
          const item = items[i];
          if (item !== undefined) return item;
        }
      }
      return items[items.length - 1] as T;
    },
    bool(probability = 0.5): boolean {
      return this.next() < probability;
    },
  };
}

export type Rng = ReturnType<typeof createRng>;

/** Stable UUID-shaped ids, derived from the seed rather than random, for reproducibility. */
export function makeId(rng: Rng, prefix: string, index: number): string {
  const hex = (n: number) => n.toString(16).padStart(2, '0');
  const bytes = Array.from({ length: 6 }, () => hex(rng.int(0, 255))).join('');
  return `${prefix}${index.toString(16).padStart(4, '0')}-0000-4000-8000-${bytes}`;
}
