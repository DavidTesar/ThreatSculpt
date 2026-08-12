import { setupServer } from 'msw/node';
import { handlers } from './handlers';

/** The Node-side mock server used by Vitest. */
export const server = setupServer(...handlers);
