import type { QueryClient } from '@tanstack/react-query';

export function panelOrigin(value: string): URL | null {
  try {
    const url = new URL(value.trim());
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      url.pathname !== '/'
    )
      return null;
    return url;
  } catch {
    return null;
  }
}

export function isLocalPanelOrigin(value: string): boolean {
  const hostname = panelOrigin(value)?.hostname.toLowerCase();
  return Boolean(
    hostname &&
    (hostname === 'localhost' ||
      hostname === '[::1]' ||
      /^127(?:\.\d{1,3}){3}$/.test(hostname)),
  );
}

export function isSecureLanOrigin(value: string): boolean {
  return (
    panelOrigin(value)?.protocol === 'https:' && !isLocalPanelOrigin(value)
  );
}

// Cached inventory, admin data and in-flight requests belong to one session.
// Cancel before removal so a late response cannot repopulate the next session.
export function clearWorkspaceCache(client: QueryClient) {
  const filter = {
    predicate: (query: { queryKey: readonly unknown[] }) =>
      query.queryKey[0] !== 'bootstrap',
  };
  void client.cancelQueries(filter);
  client.removeQueries(filter);
}
