/**
 * Generates `src/lib/api/schema.gen.ts` from the committed `openapi.json`.
 *
 * Deliberately reads the checked-in schema rather than a running server: the
 * schema file is what CI compares against, so generation must be reproducible
 * from the repository alone, with no service to reach.
 *
 * Run `npm run openapi:dump` first to refresh openapi.json from the control plane.
 */

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import openapiTS, { astToString } from 'openapi-typescript';

const SCHEMA_URL = new URL('../openapi.json', import.meta.url);
const OUTPUT_PATH = fileURLToPath(new URL('../src/lib/api/schema.gen.ts', import.meta.url));

const BANNER = `/**
 * GENERATED FILE — DO NOT EDIT BY HAND.
 *
 * Produced from apps/web/openapi.json, which is FastAPI's own schema for the
 * control plane, by:
 *
 *     npm run openapi          # = openapi:dump && openapi:types
 *
 * Every edit here is discarded by the next run, and CI fails the build when this
 * file differs from what regeneration produces. If a shape here looks wrong, it is
 * wrong in the control plane's Pydantic models — fix it there.
 *
 * Consume it through the aliases in src/types/domain.ts rather than reaching into
 * components['schemas'] from feature code.
 */
`;

const ast = await openapiTS(SCHEMA_URL);

writeFileSync(OUTPUT_PATH, `${BANNER}\n${astToString(ast)}`, 'utf8');
process.stdout.write(`wrote ${OUTPUT_PATH}\n`);
