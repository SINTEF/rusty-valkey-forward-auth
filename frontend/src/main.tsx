import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { AuthProvider, type AuthProviderProps } from 'react-oidc-context';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const redirect_uri = window.location.origin;

const oidcConfig: AuthProviderProps = {
  authority: 'https://id.sct.sintef.no/realms/sintef',
  client_id: 'rusty-valkey-forward-auth-dev',
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
)
