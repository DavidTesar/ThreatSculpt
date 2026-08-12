/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base path for the control-plane API. Defaults to `/api/v1`. */
  readonly VITE_API_BASE?: string;
  /** Set to "false" to talk to a real backend instead of the MSW fixtures. */
  readonly VITE_USE_MOCKS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
