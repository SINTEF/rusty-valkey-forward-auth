import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { AuthProvider, type AuthProviderProps } from 'react-oidc-context';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  APP_NAME,
  OIDC_AUTHORITY,
  OIDC_CLIENT_ID,
  OIDC_REDIRECT_URI,
  loadRuntimeConfig,
} from './config';

async function bootstrap() {
  await loadRuntimeConfig();

  const redirect_uri = OIDC_REDIRECT_URI ?? window.location.origin;
  document.title = APP_NAME;

  const oidcConfig: AuthProviderProps = {
    authority: OIDC_AUTHORITY,
    client_id: OIDC_CLIENT_ID,
    redirect_uri,
    onSigninCallback: () => {
      window.history.replaceState({}, document.title, window.location.pathname);
    },
  };

  const queryClient = new QueryClient();

  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <AuthProvider {...oidcConfig}>
        <QueryClientProvider client={queryClient}>
          <App />
        </QueryClientProvider>
      </AuthProvider>
    </StrictMode>,
  );
}

void bootstrap();
