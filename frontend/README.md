# Token Management UI

Web interface for managing personal API tokens in the Rusty Valkey Forward Auth service.

## What it does

Users authenticate via OAuth/OIDC to manage their API tokens:

- Create bearer tokens for authenticating with the forward auth service
- View active tokens with creation timestamps and descriptions
- Delete tokens that are no longer needed

Token values are shown only once at creation time for security. Afterward, only metadata (description, creation date) remains visible.

## Development

```bash
# Install dependencies
npm install

# Start dev server
npm run dev

# Build for production
npm run build
```

## Configuration

Set the backend API URL via environment variable:

```bash
VITE_API_BASE_URL=http://localhost:8080
```

Defaults to `http://localhost:8080` if not set.

## Stack

- React 19 + TypeScript
- Vite (build tool)
- react-oidc-context (OAuth/OIDC)
- TanStack Query (data fetching)
