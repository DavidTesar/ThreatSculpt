import { useCallback, useMemo, useRef, useState, type ReactNode } from 'react';
import { Icon } from './Icon';
import { ToastContext, type ToastContextValue, type ToastTone } from './toastContext';

interface Toast {
  id: number;
  tone: ToastTone;
  message: string;
}

const DEFAULT_DURATION_MS = 5000;
const ERROR_DURATION_MS = 8000;

const TONE_ICON = { success: 'check', error: 'alert', info: 'info' } as const;
const TONE_COLOR = { success: 'ok', error: 'danger', info: 'info' } as const;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<readonly Toast[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const notify = useCallback(
    (message: string, tone: ToastTone = 'info') => {
      const id = nextId.current++;
      setToasts((current) => [...current, { id, tone, message }]);
      window.setTimeout(
        () => dismiss(id),
        tone === 'error' ? ERROR_DURATION_MS : DEFAULT_DURATION_MS,
      );
    },
    [dismiss],
  );

  const value = useMemo<ToastContextValue>(() => ({ notify }), [notify]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      {/*
        Errors are assertive so they interrupt; successes are polite so they queue behind
        whatever the user is currently reading.
      */}
      <div className="toaster">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`toast toast--${toast.tone}`}
            role={toast.tone === 'error' ? 'alert' : 'status'}
            aria-live={toast.tone === 'error' ? 'assertive' : 'polite'}
          >
            <Icon
              name={TONE_ICON[toast.tone]}
              size={15}
              style={{ color: `var(--${TONE_COLOR[toast.tone]})`, marginTop: 2, flexShrink: 0 }}
            />
            <span className="toast__text">{toast.message}</span>
            <button
              type="button"
              className="toast__close"
              onClick={() => dismiss(toast.id)}
              aria-label="Dismiss notification"
            >
              <Icon name="close" size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
