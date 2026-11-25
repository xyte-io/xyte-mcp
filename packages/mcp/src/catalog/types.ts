/**
 * Shape of the generated endpoint catalog.
 *
 * The catalog is produced by `scripts/generate-catalog.mjs` from hub's Bruno
 * collection and committed as `endpoints.generated.json`. Nothing at runtime
 * derives endpoint facts — they all come from that file.
 */

export type Namespace = 'organization' | 'partner';

/** Which credential an endpoint needs. Device-scoped endpoints are excluded. */
export type AuthScope = 'organization' | 'partner';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** Which host the path is relative to. */
export type ApiBase = 'hub' | 'entry';

export type BodyType = 'none' | 'json';

export interface EndpointSpec {
  /** Stable dotted identifier, e.g. `organization.devices.getDevices`. */
  key: string;
  namespace: Namespace;
  /** Bruno subfolder, lowercased. Empty for endpoints at the namespace root. */
  group: string;
  action: string;
  title: string;
  description?: string;
  method: HttpMethod;
  base: ApiBase;
  /** Path with `:name` placeholders, e.g. `/core/v1/organization/devices/:device_id`. */
  pathTemplate: string;
  pathParams: string[];
  queryParams: string[];
  authScope: AuthScope;
  bodyType: BodyType;
  /** Verbatim example body from the Bruno file, when present. */
  bodyExample?: string;
  /** True for anything that is not GET/HEAD. Drives the write guard. */
  mutating: boolean;
  /** Bruno file this row was generated from, relative to the collection root. */
  sourceFile: string;
}

export interface GeneratedCatalog {
  /** Bumped when the generator's output shape changes. */
  catalogVersion: 1;
  generatedFrom: string;
  endpoints: EndpointSpec[];
}
