type FrontendConfigPayload = {
  app_name: string;
  api_base_url?: string | null;
  oidc_authority?: string | null;
  oidc_client_id?: string | null;
  oidc_redirect_uri?: string | null;
  docs_html?: string | null;
  api_docs_path?: string | null;
};

const isDev = import.meta.env.DEV;
const defaultDocsPath = '/docs';

const envApiBaseUrl = nonEmpty(import.meta.env.VITE_API_BASE_URL);
const defaultApiBaseUrl = normalizeBaseUrl(
  envApiBaseUrl ?? (isDev ? 'http://localhost:8080' : ''),
);
const defaultAppName = nonEmpty(import.meta.env.VITE_APP_NAME) ?? 'Valkey Token Manager';
const defaultOidcAuthority =
  nonEmpty(import.meta.env.VITE_OIDC_AUTHORITY) ?? 'https://id.sct.sintef.no/realms/sintef';
const defaultOidcClientId =
  nonEmpty(import.meta.env.VITE_OIDC_CLIENT_ID) ?? 'rusty-valkey-forward-auth-dev';
const defaultOidcRedirectUri = nonEmpty(import.meta.env.VITE_OIDC_REDIRECT_URI);

export let API_BASE_URL = defaultApiBaseUrl;
export let APP_NAME = defaultAppName;
export let OIDC_AUTHORITY = defaultOidcAuthority;
export let OIDC_CLIENT_ID = defaultOidcClientId;
export let OIDC_REDIRECT_URI = defaultOidcRedirectUri;
export let DOCS_HTML: string | undefined;
export let API_DOCS_PATH = defaultDocsPath;

let runtimeConfigLoaded = false;

export async function loadRuntimeConfig(): Promise<void> {
  if (runtimeConfigLoaded) {
    return;
  }

  const configUrl = joinUrl(defaultApiBaseUrl, '/frontend/config');

  try {
    const response = await fetch(configUrl, {
      cache: 'no-store',
    });

    if (!response.ok) {
      throw new Error(`unexpected status ${response.status}`);
    }

    const payload = (await response.json()) as FrontendConfigPayload;
    const payloadAppName = nonEmpty(payload.app_name);
    const payloadApiBaseUrl = nonEmpty(payload.api_base_url ?? undefined);
    const payloadOidcAuthority = nonEmpty(payload.oidc_authority ?? undefined);
    const payloadOidcClientId = nonEmpty(payload.oidc_client_id ?? undefined);
    const payloadOidcRedirectUri = nonEmpty(payload.oidc_redirect_uri ?? undefined);
    const payloadDocsHtml = normalizeHtml(payload.docs_html ?? undefined);
    const payloadDocsPath = normalizeDocsPath(payload.api_docs_path ?? undefined);

    APP_NAME = payloadAppName ?? defaultAppName;
    API_BASE_URL = normalizeBaseUrl(payloadApiBaseUrl ?? defaultApiBaseUrl);
    OIDC_AUTHORITY = payloadOidcAuthority ?? defaultOidcAuthority;
    OIDC_CLIENT_ID = payloadOidcClientId ?? defaultOidcClientId;
    OIDC_REDIRECT_URI = payloadOidcRedirectUri ?? defaultOidcRedirectUri;
    DOCS_HTML = payloadDocsHtml;
    API_DOCS_PATH = payloadDocsPath;
  } catch (error) {
    if (import.meta.env.DEV) {
      console.warn('Failed to load frontend config from API, falling back to defaults.', error);
    } else {
      console.warn('Failed to load frontend config from API, using defaults.');
    }
    // Keep defaults in place.
  } finally {
    runtimeConfigLoaded = true;
  }
}

function nonEmpty(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function normalizeHtml(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  return value.trim().length > 0 ? value : undefined;
}

function normalizeDocsPath(path: string | undefined): string {
  if (!path) {
    return defaultDocsPath;
  }
  const trimmed = path.trim();
  if (!trimmed) {
    return defaultDocsPath;
  }
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return trimmed;
  }
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

function normalizeBaseUrl(value: string): string {
  const trimmed = value.trim();
  if (!trimmed || trimmed === '/') {
    return '';
  }

  let normalized = trimmed;
  while (normalized.endsWith('/') && !normalized.endsWith('://')) {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}

function joinUrl(base: string, path: string): string {
  if (!base) {
    return path;
  }
  const normalizedBase = base.endsWith('/') ? base.slice(0, -1) : base;
  if (path.startsWith('/')) {
    return `${normalizedBase}${path}`;
  }
  return `${normalizedBase}/${path}`;
}
