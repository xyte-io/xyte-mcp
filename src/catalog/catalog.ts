import catalog from './endpoints.generated.json' with { type: 'json' };
import type { EndpointSpec, GeneratedCatalog, HttpMethod, Namespace } from './types.js';

const generated = catalog as GeneratedCatalog;

const ENDPOINTS: readonly EndpointSpec[] = Object.freeze(
  generated.endpoints as EndpointSpec[]
);

const BY_KEY = new Map<string, EndpointSpec>(
  ENDPOINTS.map((endpoint) => [endpoint.key, endpoint])
);

export interface EndpointFilter {
  namespace?: Namespace;
  group?: string;
  method?: HttpMethod;
  /** Case-insensitive substring match over key, title and path. */
  search?: string;
  /** When false, mutating endpoints are omitted. */
  includeMutating?: boolean;
}

export function getEndpoint(key: string): EndpointSpec | undefined {
  return BY_KEY.get(key);
}

export function allEndpoints(): readonly EndpointSpec[] {
  return ENDPOINTS;
}

export function endpointCount(): number {
  return ENDPOINTS.length;
}

export function listEndpoints(filter: EndpointFilter = {}): EndpointSpec[] {
  const search = filter.search?.trim().toLowerCase();
  const group = filter.group?.trim().toLowerCase();

  return ENDPOINTS.filter((endpoint) => {
    if (filter.namespace && endpoint.namespace !== filter.namespace) return false;
    if (group && endpoint.group.toLowerCase() !== group) return false;
    if (filter.method && endpoint.method !== filter.method) return false;
    if (filter.includeMutating === false && endpoint.mutating) return false;
    if (search) {
      const haystack = `${endpoint.key} ${endpoint.title} ${endpoint.pathTemplate}`.toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });
}

/** Distinct `group` values, for discovery and error messages. */
export function listGroups(namespace?: Namespace): string[] {
  const groups = new Set<string>();
  for (const endpoint of ENDPOINTS) {
    if (namespace && endpoint.namespace !== namespace) continue;
    if (endpoint.group) groups.add(endpoint.group);
  }
  return [...groups].sort();
}

/**
 * Keys closest to `key` by simple token overlap — used to make an
 * unknown-endpoint error actionable instead of a dead end.
 */
export function suggestKeys(key: string, limit = 5): string[] {
  const needle = key.toLowerCase();
  const tokens = needle.split('.').filter(Boolean);

  return ENDPOINTS.map((endpoint) => {
    const candidate = endpoint.key.toLowerCase();
    let score = 0;
    if (candidate.includes(needle)) score += 10;
    for (const token of tokens) {
      if (token.length > 2 && candidate.includes(token)) score += 1;
    }
    return { key: endpoint.key, score };
  })
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score || a.key.localeCompare(b.key))
    .slice(0, limit)
    .map((entry) => entry.key);
}
