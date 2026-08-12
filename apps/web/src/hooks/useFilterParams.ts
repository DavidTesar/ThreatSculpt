import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';

/**
 * Filter state kept in the URL rather than component state.
 *
 * A filtered findings view is something an analyst pastes into a ticket, so it has to
 * survive being sent to someone else and being reloaded. Back/forward navigation working
 * correctly falls out of the same choice.
 */
export function useFilterParams<T extends Record<string, string>>(defaults: T) {
  const [searchParams, setSearchParams] = useSearchParams();

  const values = useMemo(() => {
    const entries = Object.keys(defaults).map((key) => [
      key,
      searchParams.get(key) ?? defaults[key] ?? '',
    ]);
    return Object.fromEntries(entries) as T;
  }, [searchParams, defaults]);

  const setValue = useCallback(
    (key: keyof T & string, value: string) => {
      setSearchParams(
        (current) => {
          const next = new URLSearchParams(current);
          if (!value || value === defaults[key]) next.delete(key);
          else next.set(key, value);
          // Any filter change invalidates the current page position.
          if (key !== 'page') next.delete('page');
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams, defaults],
  );

  const reset = useCallback(() => {
    setSearchParams(new URLSearchParams(), { replace: true });
  }, [setSearchParams]);

  const activeCount = useMemo(
    () =>
      Object.keys(defaults).filter(
        (key) => key !== 'page' && values[key] && values[key] !== defaults[key],
      ).length,
    [values, defaults],
  );

  return { values, setValue, reset, activeCount };
}
