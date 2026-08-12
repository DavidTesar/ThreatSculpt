import { useContext } from 'react';
import { AuthContext, type AuthContextValue } from './authContext';

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside an AuthProvider.');
  return ctx;
}
