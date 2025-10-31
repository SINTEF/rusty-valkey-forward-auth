const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080';

type ApiError = {
  detail?: string;
  message?: string;
};

export type TokenSummary = {
  id: string;
  description?: string;
  created_at: string;
};

export type CreateTokenResponse = {
  token: string;
  id: string;
  sub: string;
  description?: string;
  created_at: string;
};

function authHeaders(accessToken: string): HeadersInit {
  return {
    Authorization: `Bearer ${accessToken}`,
  };
}

async function parseError(response: Response): Promise<never> {
  const text = await response.text();

  try {
    const body = JSON.parse(text) as ApiError;
    const errorMessage = body.detail || body.message;
    if (errorMessage) {
      throw new Error(`${response.status} ${response.statusText}: ${errorMessage}`);
    }
  } catch {
    // Ignore JSON parse errors and fall back to raw text.
  }

  const message = text || 'no response body';
  throw new Error(`${response.status} ${response.statusText}: ${message}`);
}

export async function fetchMyTokens(accessToken: string): Promise<TokenSummary[]> {
  const response = await fetch(`${API_BASE_URL}/api/me/tokens`, {
    headers: authHeaders(accessToken),
  });

  if (!response.ok) {
    await parseError(response);
  }

  return response.json();
}

export async function createMyToken(
  accessToken: string,
  description: string,
): Promise<CreateTokenResponse> {
  const payload = description.trim().length > 0 ? { description: description.trim() } : {};
  const response = await fetch(`${API_BASE_URL}/api/me/tokens`, {
    method: 'POST',
    headers: {
      ...authHeaders(accessToken),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    await parseError(response);
  }

  return response.json();
}

export async function deleteMyToken(accessToken: string, tokenId: string): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/api/me/tokens/${encodeURIComponent(tokenId)}`, {
    method: 'DELETE',
    headers: authHeaders(accessToken),
  });

  if (!response.ok) {
    await parseError(response);
  }
}
