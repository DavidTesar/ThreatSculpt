import { useState } from 'react';
import { Dialog } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { formatDateTime } from '@/lib/format';
import type { EnrollmentToken } from '@/types/domain';

/**
 * The enrollment token is shown exactly once and is not retrievable afterwards
 * (DATA-MODEL.md). The UI has to make that unmissable *before* the user closes it, so:
 *
 *  - the warning sits above the token, not below it, where it would be read too late;
 *  - the dialog is non-dismissible — no Escape, no backdrop click — so it cannot be
 *    closed by reflex;
 *  - the confirm button requires an explicit acknowledgement checkbox.
 *
 * Losing this token is not catastrophic (issue another), but silently losing it and not
 * realising until the agent fails to enroll wastes an afternoon.
 */
export function EnrollmentTokenDialog({
  token,
  agentName,
  onClose,
}: {
  token: EnrollmentToken | null;
  agentName: string;
  onClose: () => void;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token.token);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2500);
    } catch {
      // Clipboard access can be denied; the token is selectable on screen regardless.
      setCopied(false);
    }
  };

  const handleClose = () => {
    setAcknowledged(false);
    setCopied(false);
    onClose();
  };

  return (
    <Dialog
      open={token !== null}
      onClose={handleClose}
      dismissible={false}
      title="Copy this enrollment token now"
      description={`This is the only time it will be shown. Once you close this dialog it cannot be retrieved — you would have to issue a new one for ${agentName}.`}
      footer={
        <Button variant="primary" disabled={!acknowledged} onClick={handleClose}>
          I have saved the token
        </Button>
      }
    >
      <div className="alert alert--warn">
        <Icon name="alert" size={16} className="alert__icon" />
        <div>
          <p className="alert__title">You will not see this again</p>
          <p style={{ fontSize: 'var(--text-xs)' }}>
            ThreatSculpt stores only a hash of this token, so it genuinely cannot be shown a second
            time. It is single-use and expires{' '}
            {token ? formatDateTime(token.expires_at) : 'in one hour'}.
          </p>
        </div>
      </div>

      <div className="tokenbox">
        <code className="tokenbox__value">{token?.token}</code>
        <Button size="sm" variant="secondary" onClick={() => void handleCopy()}>
          <Icon name={copied ? 'check' : 'copy'} size={13} />
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
      <p aria-live="polite" className="visually-hidden">
        {copied ? 'Enrollment token copied to clipboard.' : ''}
      </p>

      <div>
        <p className="field__label" style={{ marginBottom: 'var(--space-2xs)' }}>
          Then, on the scanner host:
        </p>
        <pre
          style={{
            background: 'var(--surface-inset)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius-md)',
            padding: 'var(--space-sm)',
            fontSize: 'var(--text-xs)',
            overflowX: 'auto',
            lineHeight: 1.7,
          }}
        >
          <code>
            threatsculpt-agent enroll \{'\n'}
            {'  '}--token {token?.token ?? 'tse_…'} \{'\n'}
            {'  '}--name {agentName}
          </code>
        </pre>
        <p className="field__hint" style={{ marginTop: 'var(--space-2xs)' }}>
          The agent trades this token for a permanent API key on first start and writes it to a file
          readable only by its own service account.
        </p>
      </div>

      <label className="checkbox">
        <input
          type="checkbox"
          checked={acknowledged}
          onChange={(event) => setAcknowledged(event.target.checked)}
        />
        <span className="checkbox__text">
          I have copied the token somewhere safe
          <span className="checkbox__desc">Closing without it means issuing a replacement.</span>
        </span>
      </label>
    </Dialog>
  );
}
