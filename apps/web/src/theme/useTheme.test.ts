import { beforeEach, describe, expect, it } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { useTheme } from './useTheme';

describe('useTheme', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
  });

  it('adopts the theme the inline boot script already applied', () => {
    document.documentElement.setAttribute('data-theme', 'dark');

    const { result } = renderHook(() => useTheme());

    expect(result.current.theme).toBe('dark');
  });

  it('falls back to the system preference when nothing is set', () => {
    const { result } = renderHook(() => useTheme());

    // The test environment reports no dark preference.
    expect(result.current.theme).toBe('light');
  });

  it('toggles and reflects the change on the document element', () => {
    const { result } = renderHook(() => useTheme());

    act(() => result.current.toggle());

    expect(result.current.theme).toBe('dark');
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
  });

  it('persists the choice so a reload keeps it', () => {
    const { result } = renderHook(() => useTheme());

    act(() => result.current.setTheme('dark'));

    expect(localStorage.getItem('ts.theme')).toBe('dark');
  });
});
