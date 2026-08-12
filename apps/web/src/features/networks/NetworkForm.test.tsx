import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { renderApp } from '@/test/utils';
import { NetworkForm } from './NetworkForm';

describe('NetworkForm validation', () => {
  it('requires a name and a CIDR before submitting', async () => {
    const onSubmit = vi.fn();
    const { user } = renderApp(
      <NetworkForm onSubmit={onSubmit} onCancel={() => {}} isSubmitting={false} />,
    );

    await user.click(screen.getByRole('button', { name: /add network/i }));

    expect(await screen.findByText(/recognisable name/i)).toBeInTheDocument();
    expect(screen.getByText(/enter a cidr block/i)).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it.each([
    ['10.0.0', 'missing an octet'],
    ['10.0.0.0', 'missing a prefix'],
    ['999.0.0.0/16', 'octet out of range'],
    ['10.0.0.0/33', 'prefix out of range'],
    ['not-a-network', 'not an address at all'],
  ])('rejects %s (%s)', async (value) => {
    const onSubmit = vi.fn();
    const { user } = renderApp(
      <NetworkForm onSubmit={onSubmit} onCancel={() => {}} isSubmitting={false} />,
    );

    await user.type(screen.getByLabelText(/name/i), 'Test network');
    await user.type(screen.getByLabelText(/cidr block/i), value);
    await user.click(screen.getByRole('button', { name: /add network/i }));

    expect(await screen.findByText(/valid ipv4 cidr block/i)).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('accepts a valid CIDR and submits trimmed values', async () => {
    const onSubmit = vi.fn();
    const { user } = renderApp(
      <NetworkForm onSubmit={onSubmit} onCancel={() => {}} isSubmitting={false} />,
    );

    await user.type(screen.getByLabelText(/name/i), 'Datacentre — production');
    await user.type(screen.getByLabelText(/cidr block/i), '10.40.0.0/16');
    await user.click(screen.getByRole('button', { name: /add network/i }));

    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    expect(onSubmit).toHaveBeenCalledWith({
      name: 'Datacentre — production',
      cidr: '10.40.0.0/16',
      authorized: false,
      authorization_note: null,
    });
  });

  it('warns about the consequences of authorizing a range', () => {
    renderApp(<NetworkForm onSubmit={() => {}} onCancel={() => {}} isSubmitting={false} />);

    expect(screen.getByText(/only authorize ranges you own/i)).toBeInTheDocument();
    expect(screen.getByText(/unlawful in most jurisdictions/i)).toBeInTheDocument();
  });

  it('asks for an authorization record only once the box is ticked', async () => {
    const { user } = renderApp(
      <NetworkForm onSubmit={() => {}} onCancel={() => {}} isSubmitting={false} />,
    );

    expect(screen.queryByLabelText(/authorization record/i)).not.toBeInTheDocument();

    await user.click(screen.getByLabelText(/this network is authorized/i));

    expect(await screen.findByLabelText(/authorization record/i)).toBeInTheDocument();
  });

  it('associates each error with its field for assistive tech', async () => {
    const { user } = renderApp(
      <NetworkForm onSubmit={() => {}} onCancel={() => {}} isSubmitting={false} />,
    );

    await user.click(screen.getByRole('button', { name: /add network/i }));

    const cidr = await screen.findByLabelText(/cidr block/i);
    expect(cidr).toHaveAttribute('aria-invalid', 'true');

    const describedBy = cidr.getAttribute('aria-describedby');
    expect(describedBy).toBeTruthy();
    // The error text must be reachable from the input, not just visually adjacent to it.
    const ids = (describedBy ?? '').split(' ');
    const texts = ids.map((id) => document.getElementById(id)?.textContent ?? '');
    expect(texts.join(' ')).toMatch(/enter a cidr block/i);
  });
});
