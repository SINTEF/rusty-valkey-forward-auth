# Rusty Valkey Forward Auth

Lightweight API Key management solution. Supports OAuth2/OIDC authentication, Valkey storage, and Traefik forward auth.

Can be useful to provide an easy and old-school API key authentication mechanism to a HTTP service behind Traefik.

## Features

- **Forward Auth**: Request validation for Traefik proxy
- **Token Management**: Create, list, and delete API tokens via OAuth2-secured APIs
- **Token Storage**: Tokens stored as blake3 hashes in Valkey with Lua script synchronization
- **Web UI**: React-based interface for user self-service token management
- **OAuth2/OIDC**: Integrated OAuth2 resource server for API and UI authentication
- **Multi-user**: Admin APIs for managing tokens across users, self-service APIs for personal tokens

## Stack

- **Backend**: Stateless HTTP API in Rust
- **Frontend**: Web UI in TypeScript + React + Vite
- **Storage**: Valkey, a Redis fork, for token storage

## Quick Start

### Prerequisites

- Rust 1.90+
- Node.js 24+
- Valkey on `localhost:6379`
- An OAuth2/OIDC provider

### Configuration

Create `settings.toml` or use environment variables:

```toml
[http]
address = "127.0.0.1"
port = 8080

[valkey]
url = "redis://localhost:6379"

[oauth]
issuer_url = "https://your-oauth-provider"
# OR: jwks_url = "https://your-jwks-endpoint"

[oauth.claims]
subject = "sub"
groups = "groups"

[oauth.admin]
group = "admin"

[frontend]
oidc_authority = "https://your-oauth-provider"
oidc_client_id = "your-client-id"
```

### Running

```bash
# Build and run
cargo run
```

The service runs on `http://localhost:8080` and serves the frontend UI at `/`.

## Development

### Setup

Install pre-commit hooks:

```bash
pre-commit install
```

### Backend

```bash
cargo check          # Validate
cargo clippy         # Lint
cargo clippy --test  # Lint tests
cargo fmt            # Format
cargo test           # Test (requires Valkey on localhost:6379)
```

### Frontend

Build frontend before running the service:

```bash
cd frontend
npm install
npm run build
```

Or run dev server separately:

```bash
npm run dev      # Dev server on http://localhost:5173
npm run lint     # Linting
```

Set `VITE_API_BASE_URL` to point to your backend API (defaults to `http://localhost:8080`).

## Deployment

### Docker

```bash
docker build -t rusty-valkey-forward-auth .
docker run -e VALKEY_URL=redis://host.docker.internal:6379 \
           -p 8080:8080 \
           rusty-valkey-forward-auth
```

Multi-stage build: Rust backend + Node.js frontend compiled, served from distroless runtime.

### Kubernetes (Helm)

```bash
helm install rvfa ./charts/rusty-valkey-forward-auth \
  --set valkey.url=redis://valkey:6379 \
  --set oauth.issuerUrl=https://your-oauth-provider
```

See [charts/rusty-valkey-forward-auth/](charts/rusty-valkey-forward-auth/) for full Helm configuration.

## Traefik Integration

Configure Traefik to use this service for forward authentication:

```yaml
http:
  middlewares:
    rusty-valkey-auth:
      forwardAuth:
        address: "http://rusty-valkey-forward-auth:8080/forward-auth"
```

## Endpoints

- `/` - Frontend UI (OAuth2 secured)
- `/docs` - API documentation

### API Admin Endpoints (requires admin group)

- `POST /api/users/{sub}/tokens` - Create token for user
- `GET /api/users/{sub}/tokens` - List user tokens
- `DELETE /api/users/{sub}/tokens/{id}` - Delete user token

### API User Endpoints (authenticated)

- `GET /api/me/tokens` - List own tokens
- `POST /api/me/tokens` - Create own token
- `DELETE /api/me/tokens/{id}` - Delete own token

### API Service Endpoints

- `GET /health/live` - Liveness probe
- `GET /health/ready` - Readiness probe
- `GET /forward-auth` - Forward auth validator

## License

This project is licensed under the [Apache License 2.0](LICENSE).
