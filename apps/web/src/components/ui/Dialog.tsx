import { useEffect, useId, useRef, type ReactNode } from 'react';
import { Button } from './Button';

/**
 * Built on the native `<dialog>` element, which supplies the focus trap, the inert
 * background, Escape-to-close, and the top-layer backdrop for free. Reimplementing those
 * by hand is where hand-rolled modals usually get accessibility wrong.
 */

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children?: ReactNode;
  footer?: ReactNode;
  /** Blocks Escape and backdrop dismissal — for a dialog showing an unrecoverable secret. */
  dismissible?: boolean;
}

export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  dismissible = true,
}: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descId = useId();

  useEffect(() => {
    const node = ref.current;
    if (!node) return;

    if (open && !node.open) {
      // jsdom does not implement showModal; fall back so tests can still assert content.
      if (typeof node.showModal === 'function') node.showModal();
      else node.setAttribute('open', '');
    } else if (!open && node.open) {
      if (typeof node.close === 'function') node.close();
      else node.removeAttribute('open');
    }
  }, [open]);

  useEffect(() => {
    const node = ref.current;
    if (!node) return;

    const handleCancel = (event: Event) => {
      event.preventDefault();
      if (dismissible) onClose();
    };

    node.addEventListener('cancel', handleCancel);
    return () => node.removeEventListener('cancel', handleCancel);
  }, [dismissible, onClose]);

  // Click on the backdrop is a click on the dialog element itself, outside its content box.
  const handleBackdropClick = (event: React.MouseEvent<HTMLDialogElement>) => {
    if (!dismissible || event.target !== ref.current) return;
    onClose();
  };

  return (
    /*
     * jsx-a11y classes <dialog> as non-interactive and asks for a keyboard equivalent to
     * the click handler. It already has one, natively: the element's own `cancel` event
     * fires on Escape and is wired to onClose above. The click handler only adds
     * click-outside-to-dismiss on top of that, so no keyboard user is left without a way
     * out — which is the outcome the rule exists to protect.
     */
    /* eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-noninteractive-element-interactions */
    <dialog
      ref={ref}
      className="dialog"
      aria-labelledby={titleId}
      aria-describedby={description ? descId : undefined}
      onClick={handleBackdropClick}
    >
      <div className="dialog__head">
        <h2 className="dialog__title" id={titleId}>
          {title}
        </h2>
        {description ? (
          <p className="dialog__desc" id={descId}>
            {description}
          </p>
        ) : null}
      </div>
      {children ? <div className="dialog__body">{children}</div> : null}
      <div className="dialog__foot">
        {footer ?? (
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
        )}
      </div>
    </dialog>
  );
}
