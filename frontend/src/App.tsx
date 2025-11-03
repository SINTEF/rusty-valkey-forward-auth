import { type FormEvent, useEffect, useState } from 'react';
import './App.css';
import { hasAuthParams, useAuth } from 'react-oidc-context';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  createMyToken,
  deleteMyToken,
  fetchMyTokens,
  type CreateTokenResponse,
  type TokenSummary,
} from './api/tokens';
import { API_BASE_URL, API_DOCS_PATH, APP_NAME, DOCS_HTML } from './config';

function App() {
  const auth = useAuth();
  const queryClient = useQueryClient();
  const {
    activeNavigator,
    isAuthenticated,
    isLoading,
    error,
    signinRedirect,
    signoutRedirect,
    user,
  } = auth;
  const accessToken = user?.access_token;

  const [description, setDescription] = useState('');
  const [lastCreatedToken, setLastCreatedToken] = useState<CreateTokenResponse | null>(null);
  const [hasCopiedToken, setHasCopiedToken] = useState(false);
  const [confirmingTokenId, setConfirmingTokenId] = useState<string | null>(null);
  const docsHref =
    API_DOCS_PATH.startsWith('http://') || API_DOCS_PATH.startsWith('https://')
      ? API_DOCS_PATH
      : `${API_BASE_URL}${API_DOCS_PATH}`;
  const showDocsLink = docsHref.trim().length > 0;
  const docsHtml = DOCS_HTML?.trim() ?? '';
  const hasDocsContent = docsHtml.length > 0;

  const tokensQuery = useQuery<TokenSummary[], Error>({
    queryKey: ['api', 'tokens', accessToken],
    queryFn: () => {
      if (!accessToken) {
        throw new Error('Missing access token');
      }
      return fetchMyTokens(accessToken);
    },
    enabled: Boolean(accessToken),
  });

  useEffect(() => {
    if (!hasAuthParams() && !isAuthenticated && !activeNavigator && !isLoading) {
      signinRedirect({ state: window.location.pathname });
    }
  }, [isAuthenticated, activeNavigator, isLoading, signinRedirect]);

  const createTokenMutation = useMutation<CreateTokenResponse, Error, string>({
    mutationFn: async (inputDescription) => {
      if (!accessToken) {
        throw new Error('Missing access token');
      }
      return createMyToken(accessToken, inputDescription);
    },
    onSuccess: (data) => {
      setLastCreatedToken(data);
      setHasCopiedToken(false);
      setDescription('');
      setConfirmingTokenId(null);
      queryClient.invalidateQueries({ queryKey: ['api', 'tokens', accessToken] });
    },
  });

  const deleteTokenMutation = useMutation<void, Error, string>({
    mutationFn: async (tokenId) => {
      if (!accessToken) {
        throw new Error('Missing access token');
      }
      await deleteMyToken(accessToken, tokenId);
    },
    onSuccess: () => {
      setConfirmingTokenId(null);
      queryClient.invalidateQueries({ queryKey: ['api', 'tokens', accessToken] });
    },
  });

  const handleCreateToken = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLastCreatedToken(null);
    setConfirmingTokenId(null);
    createTokenMutation.mutate(description);
  };

  const pendingDeletionId =
    deleteTokenMutation.isPending && deleteTokenMutation.variables
      ? deleteTokenMutation.variables
      : null;

  const handleDelete = (tokenId: string) => {
    deleteTokenMutation.mutate(tokenId);
  };

  const handleCopyToken = async (token: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(token);
      } else {
        const textArea = document.createElement('textarea');
        textArea.value = token;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
      }
      setHasCopiedToken(true);
    } catch {
      setHasCopiedToken(false);
    }
  };

  const refresh = () => {
    try {
      window.sessionStorage.clear();
    } finally {
      window.location.reload();
    }
  };

  if (activeNavigator === 'signinSilent') {
    return <div className="status">Signing you in…</div>;
  }

  if (activeNavigator === 'signoutRedirect') {
    return <div className="status">Signing you out…</div>;
  }

  if (isLoading) {
    return <div className="status">Loading…</div>;
  }

  if (error) {
    return (
      <div className="status">
        <div className="status-panel">
          <p className="error">Authentication failed: {error.message}</p>
          <button
            type="button"
            onClick={refresh}
          >
            Refresh
          </button>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="screen">
        <h1>{APP_NAME}</h1>
        <p className="muted">Sign in required</p>
        <button type="button" onClick={() => signinRedirect()}>
          Sign in
        </button>
        {showDocsLink && (
          <a className="docs-link" href={docsHref} target="_blank" rel="noreferrer">
            Token API docs
          </a>
        )}
      </div>
    );
  }

  const identityName =
    user?.profile.email ??
    user?.profile.sub;

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) {
      return timestamp;
    }
    return date.toLocaleString();
  };

  return (
    <div className="screen">
      <header className="header">
        <div>
          <h1>{APP_NAME}</h1>
          <p className="muted">Signed in as {identityName}</p>
        </div>
        <button type="button" onClick={() => signoutRedirect()}>
          Sign out
        </button>
      </header>

      {hasDocsContent && (
        <section className="section">
          <div className="docs-content" dangerouslySetInnerHTML={{ __html: docsHtml }} />
        </section>
      )}

      <section className="section">
        <h2>Create a token</h2>
        <p className="muted">
          Descriptions are optional and help you remember what a token is used for.
        </p>
        <form className="token-form" onSubmit={handleCreateToken}>
          <label htmlFor="description" className="muted">
            Description
          </label>
          <input
            id="description"
            name="description"
            type="text"
            maxLength={256}
            placeholder="e.g. staging deployment"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            disabled={createTokenMutation.isPending}
          />
          <button type="submit" disabled={createTokenMutation.isPending}>
            {createTokenMutation.isPending ? 'Creating…' : 'Create token'}
          </button>
        </form>
        {lastCreatedToken && (
          <div className="notice" role="status">
            <h3>New token</h3>
            <p className="muted">
              Copy the value below now. This is the only time the full token is shown.
            </p>
            <div className="token-display">
              <div className="token-value" data-testid="created-token">
                {lastCreatedToken.token}
              </div>
              <button
                type="button"
                className="outline copy-button"
                onClick={() => handleCopyToken(lastCreatedToken.token)}
              >
                {hasCopiedToken ? 'Copied!' : 'Copy'}
              </button>
            </div>
            {lastCreatedToken.description && (
              <p className="muted">Description: {lastCreatedToken.description}</p>
            )}
          </div>
        )}
        {createTokenMutation.isError && (
          <p className="error" role="alert">
            Failed to create token: {createTokenMutation.error.message}
          </p>
        )}
      </section>

      <section className="section">
        <h2>Your tokens</h2>
        {tokensQuery.isPending && <p className="muted">Loading tokens…</p>}
        {tokensQuery.isError && (
          <p className="error" role="alert">
            Failed to load tokens: {tokensQuery.error.message}
          </p>
        )}
        {tokensQuery.isSuccess && tokensQuery.data.length === 0 && (
          <p className="muted">You do not have any tokens yet.</p>
        )}
        {tokensQuery.isSuccess && tokensQuery.data.length > 0 && (
          <ul className="token-list">
            {tokensQuery.data.map((token) => (
              <li key={token.id} className="token-card">
                <div className="token-meta">
                  <p className="token-name">{token.description || 'No description'}</p>
                  <p className="muted">Created {formatTimestamp(token.created_at)}</p>
                </div>
                <div className="token-actions">
                  {confirmingTokenId === token.id ? (
                    <div className="confirm-delete">
                      <p className="muted">Delete this token?</p>
                      <div className="confirm-actions">
                        <button
                          type="button"
                          className="outline"
                          onClick={() => setConfirmingTokenId(null)}
                          disabled={deleteTokenMutation.isPending && pendingDeletionId === token.id}
                        >
                          Cancel
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDelete(token.id)}
                          disabled={deleteTokenMutation.isPending && pendingDeletionId === token.id}
                        >
                          {deleteTokenMutation.isPending && pendingDeletionId === token.id
                            ? 'Deleting…'
                            : 'Delete'}
                        </button>
                      </div>
                    </div>
                  ) : (
                    <button
                      type="button"
                      className="outline"
                      onClick={() => setConfirmingTokenId(token.id)}
                      disabled={deleteTokenMutation.isPending && pendingDeletionId === token.id}
                    >
                      Delete
                    </button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
        {deleteTokenMutation.isError && (
          <p className="error" role="alert">
            Failed to delete token: {deleteTokenMutation.error.message}
          </p>
        )}
      </section>

      {showDocsLink && (
        <section className="section">
          <h2>Token API reference</h2>
          <p className="muted">
            API key management docs:{' '}
            <a className="docs-link" href={docsHref} target="_blank" rel="noreferrer">
              Open token API docs
            </a>
          </p>
        </section>
      )}
    </div>
  );
}
export default App;
