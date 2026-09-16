'use client';

type ApiErrorBody = { error?: { message?: string; code?: string } };

export function apiEndpoint(path: string) {
  const configured = process.env.NEXT_PUBLIC_TLS_SENTINEL_API_URL;
  if (configured) return `${configured}${path}`;
  if (typeof window !== 'undefined') {
    if (window.location.protocol === 'https:')
      return `${window.location.origin}${path}`;
    return `${window.location.protocol}//${window.location.hostname}:8787${path}`;
  }
  return `http://localhost:8787${path}`;
}

export async function apiRequest<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body) headers.set('Content-Type', 'application/json');
  const response = await fetch(apiEndpoint(path), {
    ...init,
    headers,
    credentials: 'include',
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as ApiErrorBody;
    if (response.status === 401 && typeof window !== 'undefined') {
      window.dispatchEvent(new Event('tls-sentinel-auth-required'));
    }
    const error = new Error(
      body.error?.message || `Request failed (${response.status}).`,
    );
    Object.assign(error, { status: response.status, code: body.error?.code });
    throw error;
  }
  return response.json() as Promise<T>;
}
