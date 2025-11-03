# Rusty Valkey Forward Auth Helm Chart

Helm chart for deploying the Rusty Valkey Forward Auth service on Kubernetes.

## Overview

This chart deploys:

- **Rusty Valkey Forward Auth**: Stateless Rust API for token management and Traefik forward authentication
- **Valkey**: Built-in Redis fork for token storage (can be disabled to use external instance)

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- An OAuth2/OIDC provider (Keycloak, Azure AD, etc.)
- PersistentVolume provisioner (if using bundled Valkey with persistence)

## Quick Start

### Add the Helm Repository

```bash
helm repo add rusty-valkey-forward-auth https://sintef.github.io/rusty-valkey-forward-auth
helm repo update
```

### Generate Token Salt

The `tokenSalt` is a critical security parameter used to hash API tokens. Generate a secure 64-character hex string:

```bash
openssl rand -hex 32
```

Keep this value secret and consistent across deployments!

### Minimal Installation

```bash
helm install rvfa rusty-valkey-forward-auth/rusty-valkey-forward-auth \
  --set config.tokenSalt="YOUR_64_HEX_CHARACTER_SALT" \
  --set config.oauth.issuerUrl="https://your-oauth-provider/realms/your-realm" \
  --set config.frontend.oidcAuthority="https://your-oauth-provider/realms/your-realm" \
  --set config.frontend.oidcClientId="your-client-id"
```

### Using a Values File

Create a `my-values.yaml`:

```yaml
config:
  tokenSalt: "..."
  oauth:
    issuerUrl: https://your-oauth-provider/realms/your-realm
  frontend:
    appName: "My Token Management"
    oidcAuthority: https://your-oauth-provider/realms/your-realm
    oidcClientId: your-client-id
```

Install:

```bash
helm install rvfa rusty-valkey-forward-auth/rusty-valkey-forward-auth -f my-values.yaml
```

### Installing from Source

If you prefer to install directly from the repository source:

```bash
helm install rvfa ./charts/rusty-valkey-forward-auth -f my-values.yaml
```

## Configuration

### Essential Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `config.tokenSalt` | 64-character hex salt for token hashing | **Yes** | `""` |
| `config.oauth.issuerUrl` | OAuth2/OIDC issuer URL | **Yes** | `""` |
| `config.frontend.oidcAuthority` | Frontend OIDC authority URL | **Yes** | `""` |
| `config.frontend.oidcClientId` | Frontend OIDC client ID | **Yes** | `""` |
| `config.frontend.appName` | Application display name | No | `""` |
| `config.oauth.admin.group` | Admin group name for user management | No | `"admin"` |
| `config.oauth.audiences` | List of accepted JWT audiences | No | `[]` |
| `config.cors.enabled` | Enable CORS support | No | `false` |
| `config.cors.allowOrigins` | List of allowed CORS origins | No | `[]` |
| `valkey.enabled` | Use bundled Valkey chart | No | `true` |
| `valkey.dataStorage.requestedSize` | Valkey storage size | No | `4Gi` |
| `ingress.enabled` | Enable ingress resource | No | `false` |

### Valkey Configuration

#### Using Bundled Valkey (Default)

```yaml
valkey:
  enabled: true
  dataStorage:
    requestedSize: 4Gi
    # className: standard
```

#### Using External Valkey

```yaml
valkey:
  enabled: false

config:
  valkey:
    url: redis://external-valkey:6379/0
    username: myuser  # Optional
    password: mypassword  # Optional
    # usernameSecret:
    #   name: existing-secret
    #   key: valkey-username
    # passwordSecret:
    #   name: existing-secret
    #   key: valkey-password
```

### Security: Using Kubernetes Secrets

The chart automatically creates a Kubernetes Secret for sensitive values (token salt, Valkey credentials) when you provide them in `config`:

```yaml
config:
  tokenSalt: "...your-64-hex-character-salt..."
  valkey:
    username: "valkey-user"
    password: "secure-password"
```

These values are automatically stored in a Secret named `<release-name>-config` and referenced via `secretKeyRef` in the deployment.

Alternatively, you can create and manage the secret yourself, then reference it:

```bash
# Create your own secret
kubectl create secret generic rvfa-secrets \
  --from-literal=token-salt="your-64-hex-salt" \
  --from-literal=valkey-username="valkey-user" \
  --from-literal=valkey-password="secure-password"
```

Then reference it in values:

```yaml
config:
  tokenSaltSecret:
    name: rvfa-secrets
    key: token-salt
  valkey:
    usernameSecret:
      name: rvfa-secrets
      key: valkey-username
    passwordSecret:
      name: rvfa-secrets
      key: valkey-password
```

When using external secret references, the chart will use those instead of creating a managed secret.

### Setting up username/password authentication in Valkey

The official Valkey helm chart is not very straightforward to setup username/password authentication, but it can be configured like the following:

```yaml
kind: Secret
apiVersion: v1
metadata:
  name: valkey-users
type: Opaque
stringData:
  users.acl: |
    user valkey-user on >secure-password ~* +@all
```

```yaml
valkey:
  auth:
    enabled: false # auth will be enabled using extraValkeySecrets
  valkeyConfig: |
    aclfile /secrets/users.acl
  extraValkeySecrets:
    - name: valkey-users
      mountPath: /secrets
```

### Ingress Configuration

```yaml
ingress:
  enabled: true
  className: nginx
  annotations: {}
  hosts:
    - host: tokens.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: tokens-tls
      hosts:
        - tokens.example.com
```

## License

Apache License 2.0
