import { createContext } from 'react';
import type { CurrentPrincipal, Role } from '@/types/domain';
import type { LoginRequest, RegisterRequest } from '@/lib/api/endpoints';

export type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated';

export interface AuthContextValue {
  status: AuthStatus;
  principal: CurrentPrincipal | null;
  role: Role | null;
  login: (credentials: LoginRequest) => Promise<void>;
  register: (details: RegisterRequest) => Promise<void>;
  logout: () => Promise<void>;
  /** True when `role` meets the minimum. Presentation only — the server still enforces. */
  can: (minimum: Role) => boolean;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
