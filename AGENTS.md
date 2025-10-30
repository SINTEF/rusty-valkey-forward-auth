# AGENTS.md

Quick-start notes for any agent touching this repo.

## Project at a Glance

- Rust service offering Traefik forward-auth plus API token CRUD.
- Tokens live in Valkey as blake3 hashes; Lua keeps user/token sets in sync.
- OAuth2 resource server (tower-oauth2-resource-server 0.8.0) secures the admin API and provides self-service user flows.

## Essential Commands

- `cargo check` for fast validation.
- `cargo clippy` and `cargo clippy --test` for linting.
- `cargo fmt` for formatting.
- `cargo test` to run tests.
- `cargo run` (config via `PORT`, `ADDRESS`, `VALKEY_URL`, or `CONFIG_FILE`).

## Code Map

- `config.rs`: load settings from env + `settings.toml` with `confique`.
- `storage.rs`: Valkey CRUD for tokens (`auth:token:{hash}` + `auth:user_tokens:{sub}`), includes Lua delete script.
- `http.rs`: Axum HTTP layer (`/health/*`, `/api/users/{sub}/tokens`, `/forward-auth`, docs at `/docs`).
- `auth.rs`: wraps tower-oauth2-resource-server, builds claim helpers, and exposes middleware/extractors for admin & user endpoints.

## Authentication Notes

- Configure `oauth.issuer_url` (or `oauth.jwks_url`) plus any `oauth.audiences` to enable validation; the service will refuse to start without a usable resource-server setup.
- `oauth.claims.subject` selects the claim that becomes the user `sub`; `oauth.claims.groups` & `oauth.admin.group` control admin gating (case-sensitivity toggles available).
- Admin token management lives at `/api/users/{sub}/tokens` and requires the configured admin group to pass validation.
- Authenticated users may manage their own tokens via `/api/me/tokens` and `/api/me/tokens/{id}` (subject derived from the validated JWT).
- Forward-auth remains standalone and does not participate in OAuth2 validation.

## Testing Notes

- Needs Valkey on `localhost:6379`.
- Existing tests cover happy-path and edge cases; keep new ones serial.

## Coding practices

- KISS: keep it simple, stupid.
- Prefer clarity over cleverness.
- Always run cargo clippy and cargo fmt to check that you did things correctly.
- Things must be tested. Run cargo test to check. Running the tests in the sandbox requires elevated privilege I guess ($ /bin/zsh -lc 'cargo test'), with a longer timeout than the default one.
