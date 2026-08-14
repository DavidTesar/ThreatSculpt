/**
 * The one payload the generated types cannot describe.
 *
 * `findings.score_factors` is `dict[str, Any]` in the control plane's Pydantic
 * model, so the OpenAPI schema says `{ [key: string]: unknown }` and generation
 * has nothing to work from. Every other shape in this client is derived from the
 * schema; this one is validated at runtime instead, which is the honest response
 * to an untyped field — restating it as a hand-written interface would assert a
 * shape nothing checks, which is exactly the class of bug the generated client
 * removes.
 *
 * A payload that does not parse is reported as absent rather than guessed at, so
 * the detail view says it cannot explain the score instead of rendering a wrong
 * explanation of a number the customer is being asked to act on.
 *
 * **This is worth fixing in the backend.** Typing `RiskScore.score_factors()` as a
 * Pydantic model would put this shape in the schema and delete this file.
 */

import { z } from 'zod';

/** One multiplier and the input value that selected it. */
const factorSchema = z.object({
  value: z.string(),
  multiplier: z.number(),
});

/**
 * The rescale from the raw product to the reported 0–100 score.
 *
 * Read from the payload rather than recomputed: the multiplier table lives in the
 * control plane, and a UI that re-derives the divisor from its own copy disagrees
 * with the stored score the moment the backend retunes a tier — a discrepancy that
 * reads as a bug in the very number the explanation exists to defend.
 */
const normalizationSchema = z.object({
  raw: z.number(),
  max_raw: z.number(),
  scale: z.number(),
  formula: z.string(),
  rounding: z.string(),
});

export const scoreFactorsSchema = z.object({
  cvss_base: z.number(),
  exploit_maturity: factorSchema,
  exposure: factorSchema,
  asset_criticality: factorSchema,
  services_affected: z.array(z.string()).default([]),
  normalization: normalizationSchema.optional(),
  notes: z.array(z.string()).default([]),
});

export type ScoreFactor = z.infer<typeof factorSchema>;
export type ScoreNormalization = z.infer<typeof normalizationSchema>;
export type ScoreFactors = z.infer<typeof scoreFactorsSchema>;

/**
 * Parses `finding.score_factors`. Returns `null` when the field is absent or does
 * not match, so callers must handle "no explanation available" explicitly.
 */
export function parseScoreFactors(raw: unknown): ScoreFactors | null {
  const result = scoreFactorsSchema.safeParse(raw);
  return result.success ? result.data : null;
}
