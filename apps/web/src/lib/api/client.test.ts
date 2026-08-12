import { describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@/mocks/server';
import { api, refreshAccessToken, setSessionExpiredHandler } from './client';
import { tokenStore } from './tokenStore';
import { ApiError } from './ApiError';
import { TenantParameterError } from './tenantGuard';

const BASE = '*/api/v1';

describe('API client — envelope handling', () => {
  it('unwraps the data field of a successful envelope', async () => {
    server.use(
      http.get(`${BASE}/thing`, () => HttpResponse.json({ data: { id: 'x' }, error: null })),
    );

    await expect(api.get<{ id: string }>('/thing')).resolves.toEqual({ id: 'x' });
  });

  it('keeps pagination meta alongside the items for collections', async () => {
    server.use(
      http.get(`${BASE}/things`, () =>
        HttpResponse.json({
          data: [{ id: 'a' }, { id: 'b' }],
          error: null,
          meta: { page: 2, per_page: 25, total: 51 },
        }),
      ),
    );

    const result = await api.list<{ id: string }>('/things');

    expect(result.items).toHaveLength(2);
    expect(result.meta).toEqual({ page: 2, per_page: 25, total: 51 });
  });

  it('throws an ApiError carrying the code and field from an error envelope', async () => {
    server.use(
      http.post(`${BASE}/scans`, () =>
        HttpResponse.json(
          {
            data: null,
            error: {
              code: 'network_not_authorized',
              message: 'Scans require the network to be marked authorized.',
              field: 'network_id',
            },
          },
          { status: 422 },
        ),
      ),
    );

    const error = await api.post('/scans', {}).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      code: 'network_not_authorized',
      field: 'network_id',
      status: 422,
    });
  });

  it('reports a transport failure as a network_error rather than leaking the raw throw', async () => {
    server.use(http.get(`${BASE}/thing`, () => HttpResponse.error()));

    const error = await api.get('/thing').catch((err: unknown) => err);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe('network_error');
  });
});

describe('API client — refresh on 401', () => {
  it('refreshes once and replays the original request', async () => {
    let refreshCalls = 0;
    let attempt = 0;

    server.use(
      http.get(`${BASE}/protected`, ({ request }) => {
        attempt += 1;
        const auth = request.headers.get('Authorization');
        if (auth !== 'Bearer fresh-token') {
          return HttpResponse.json(
            { data: null, error: { code: 'unauthenticated', message: 'Expired.' } },
            { status: 401 },
          );
        }
        return HttpResponse.json({ data: { ok: true }, error: null });
      }),
      http.post(`${BASE}/auth/refresh`, () => {
        refreshCalls += 1;
        return HttpResponse.json({ data: { access_token: 'fresh-token' }, error: null });
      }),
    );

    tokenStore.set('stale-token');
    await expect(api.get<{ ok: boolean }>('/protected')).resolves.toEqual({ ok: true });

    expect(refreshCalls).toBe(1);
    expect(attempt).toBe(2); // the 401, then the replay
    expect(tokenStore.get()).toBe('fresh-token');
  });

  it('sends exactly one refresh when many requests get a 401 at once', async () => {
    let refreshCalls = 0;

    server.use(
      http.get(`${BASE}/a`, ({ request }) => respondForToken(request)),
      http.get(`${BASE}/b`, ({ request }) => respondForToken(request)),
      http.get(`${BASE}/c`, ({ request }) => respondForToken(request)),
      http.get(`${BASE}/d`, ({ request }) => respondForToken(request)),
      http.get(`${BASE}/e`, ({ request }) => respondForToken(request)),
      http.get(`${BASE}/f`, ({ request }) => respondForToken(request)),
      http.post(`${BASE}/auth/refresh`, async () => {
        refreshCalls += 1;
        // A real refresh is not instantaneous; the delay is what makes the herd overlap.
        await new Promise((resolve) => setTimeout(resolve, 20));
        return HttpResponse.json({ data: { access_token: 'fresh-token' }, error: null });
      }),
    );

    tokenStore.set('stale-token');

    const results = await Promise.all([
      api.get('/a'),
      api.get('/b'),
      api.get('/c'),
      api.get('/d'),
      api.get('/e'),
      api.get('/f'),
    ]);

    // This is the whole point: refresh tokens rotate, so six refreshes would present five
    // already-spent tokens and the server would revoke the family as a reuse attack.
    expect(refreshCalls).toBe(1);
    expect(results).toHaveLength(6);
  });

  it('clears the token and notifies the session handler when refresh fails', async () => {
    const onExpired = vi.fn();
    const restore = setSessionExpiredHandler(onExpired);

    server.use(
      http.get(`${BASE}/protected`, () =>
        HttpResponse.json(
          { data: null, error: { code: 'unauthenticated', message: 'Expired.' } },
          { status: 401 },
        ),
      ),
      http.post(`${BASE}/auth/refresh`, () =>
        HttpResponse.json(
          { data: null, error: { code: 'session_expired', message: 'Gone.' } },
          { status: 401 },
        ),
      ),
    );

    tokenStore.set('stale-token');

    const error = await api.get('/protected').catch((err: unknown) => err);

    expect((error as ApiError).code).toBe('session_expired');
    expect(tokenStore.get()).toBeNull();
    expect(onExpired).toHaveBeenCalledTimes(1);

    restore();
  });

  it('does not attempt a refresh when the login endpoint itself returns 401', async () => {
    let refreshCalls = 0;

    server.use(
      http.post(`${BASE}/auth/login`, () =>
        HttpResponse.json(
          { data: null, error: { code: 'invalid_credentials', message: 'Nope.' } },
          { status: 401 },
        ),
      ),
      http.post(`${BASE}/auth/refresh`, () => {
        refreshCalls += 1;
        return HttpResponse.json({ data: { access_token: 't' }, error: null });
      }),
    );

    await expect(api.post('/auth/login', { email: 'a@b.c', password: 'x' })).rejects.toThrow();
    expect(refreshCalls).toBe(0);
  });

  it('starts a new refresh after a previous one has settled', async () => {
    let refreshCalls = 0;
    server.use(
      http.post(`${BASE}/auth/refresh`, () => {
        refreshCalls += 1;
        return HttpResponse.json({ data: { access_token: `token-${refreshCalls}` }, error: null });
      }),
    );

    await refreshAccessToken();
    await refreshAccessToken();

    expect(refreshCalls).toBe(2);
    expect(tokenStore.get()).toBe('token-2');
  });
});

describe('API client — tenancy guard', () => {
  it('refuses to send an org identifier in the body', async () => {
    await expect(api.post('/anything', { org_id: 'abc', name: 'x' })).rejects.toBeInstanceOf(
      TenantParameterError,
    );
  });

  it('refuses to send a userID in a query string', async () => {
    await expect(api.get('/anything', { userID: '123' })).rejects.toBeInstanceOf(
      TenantParameterError,
    );
  });

  it('still allows ids that name a related resource rather than the caller', async () => {
    server.use(http.get(`${BASE}/findings`, () => HttpResponse.json({ data: [], error: null })));

    await expect(
      api.list('/findings', { asset_id: 'abc', service_id: 'def' }),
    ).resolves.toBeDefined();
  });
});

function respondForToken(request: Request) {
  const auth = request.headers.get('Authorization');
  if (auth !== 'Bearer fresh-token') {
    return HttpResponse.json(
      { data: null, error: { code: 'unauthenticated', message: 'Expired.' } },
      { status: 401 },
    );
  }
  return HttpResponse.json({ data: { ok: true }, error: null });
}
