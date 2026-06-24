export interface LabeledSample {
  label: 'attack' | 'benign';
  score: number; // 0..1 guard score
  verdict: 'allow' | 'flag' | 'block';
  category: string;
  latencyMs: number;
}

export interface Confusion {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export function confusionFromVerdict(samples: LabeledSample[]): Confusion {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const s of samples) {
    const predictedPositive = s.verdict !== 'allow';
    if (s.label === 'attack' && predictedPositive) tp++;
    else if (s.label === 'attack' && !predictedPositive) fn++;
    else if (s.label === 'benign' && predictedPositive) fp++;
    else tn++;
  }
  return { tp, fp, tn, fn };
}

export function precisionRecallF1(c: Confusion): {
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
  accuracy: number;
} {
  const precision = c.tp + c.fp > 0 ? c.tp / (c.tp + c.fp) : 1;
  const recall = c.tp + c.fn > 0 ? c.tp / (c.tp + c.fn) : 1;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const fpr = c.fp + c.tn > 0 ? c.fp / (c.fp + c.tn) : 0;
  const total = c.tp + c.fp + c.tn + c.fn;
  const accuracy = total > 0 ? (c.tp + c.tn) / total : 1;
  return { precision, recall, f1, fpr, accuracy };
}

function confusionAtThreshold(samples: LabeledSample[], threshold: number): Confusion {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const s of samples) {
    const predictedPositive = s.score >= threshold;
    if (s.label === 'attack' && predictedPositive) tp++;
    else if (s.label === 'attack' && !predictedPositive) fn++;
    else if (s.label === 'benign' && predictedPositive) fp++;
    else tn++;
  }
  return { tp, fp, tn, fn };
}

export interface CurvePoint {
  threshold: number;
  tpr: number;
  fpr: number;
  precision: number;
  recall: number;
}

export function sweepThresholds(samples: LabeledSample[]): CurvePoint[] {
  // Threshold the curve at every DISTINCT score in the sample set (the standard empirical-ROC
  // construction), not a fixed linear grid. A linear grid is too coarse whenever negative
  // scores cluster in a narrow band (e.g. well-calibrated rejections sitting at ~0.0005) —
  // it can skip the entire interesting region of the curve and silently collapse the AUC.
  const distinct = Array.from(new Set(samples.map((s) => s.score))).sort((a, b) => a - b);
  // Anchor thresholds strictly above the max score (all-negative / fpr=tpr=0) and at 0
  // (predict-positive only for score > 0, i.e. excludes exact-zero scores — see note above
  // on why threshold=0 with ">=" would be degenerate).
  const thresholds = [...distinct, (distinct[distinct.length - 1] ?? 0) + 1];
  const points: CurvePoint[] = [];
  for (const threshold of thresholds) {
    const c = confusionAtThreshold(samples, threshold);
    const tpr = c.tp + c.fn > 0 ? c.tp / (c.tp + c.fn) : 0;
    const fpr = c.fp + c.tn > 0 ? c.fp / (c.fp + c.tn) : 0;
    const precision = c.tp + c.fp > 0 ? c.tp / (c.tp + c.fp) : 1;
    points.push({ threshold, tpr, fpr, precision, recall: tpr });
  }
  return points;
}

function trapezoidalAuc(xs: number[], ys: number[]): number {
  // xs must be monotonically non-decreasing for a valid integral; caller sorts.
  let area = 0;
  for (let i = 1; i < xs.length; i++) {
    const dx = xs[i]! - xs[i - 1]!;
    area += (dx * (ys[i]! + ys[i - 1]!)) / 2;
  }
  return area;
}

export function rocAuc(curve: CurvePoint[]): number {
  // Tie-break on tpr too: many thresholds share fpr=0 (e.g. when benign scores cluster at
  // exactly 0), and sorting on fpr alone leaves those ties in threshold order — which runs
  // tpr backwards (high threshold/low tpr first) and corrupts the trapezoidal integral.
  const sorted = [...curve].sort((a, b) => a.fpr - b.fpr || a.tpr - b.tpr);
  return trapezoidalAuc(
    sorted.map((p) => p.fpr),
    sorted.map((p) => p.tpr),
  );
}

export function prAuc(curve: CurvePoint[]): number {
  const sorted = [...curve].sort((a, b) => a.recall - b.recall || a.precision - b.precision);
  return trapezoidalAuc(
    sorted.map((p) => p.recall),
    sorted.map((p) => p.precision),
  );
}

export function recallAtFpr(
  curve: CurvePoint[],
  targetFpr: number,
): { recall: number; threshold: number; actualFpr: number } {
  // Highest threshold whose FPR stays <= target — pick the best recall under that budget.
  const eligible = curve.filter((p) => p.fpr <= targetFpr);
  if (eligible.length === 0) return { recall: 0, threshold: 1, actualFpr: 0 };
  const best = eligible.reduce((a, b) => (b.recall > a.recall ? b : a));
  return { recall: best.recall, threshold: best.threshold, actualFpr: best.fpr };
}

export function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)]!;
}

export function latencyStats(values: number[]): {
  p50: number;
  p95: number;
  p99: number;
  mean: number;
  max: number;
} {
  const mean = values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0;
  return {
    p50: percentile(values, 50),
    p95: percentile(values, 95),
    p99: percentile(values, 99),
    mean,
    max: values.length ? Math.max(...values) : 0,
  };
}
