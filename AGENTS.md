# AGENTS.md

Quick-start notes for any agent touching this repo.

## Project at a Glance

- Rust service offering Traefik forward-auth plus API token CRUD.
- Tokens live in Valkey/Redis as blake3 hashes; Lua keeps user/token sets in sync.

## Essential Commands

- `cargo check` for fast validation.
- `cargo clippy` and `cargo clippy --test` for linting.
- `cargo fmt` for formatting.
- `cargo test` to run tests.
- `cargo run` (config via `PORT`, `ADDRESS`, `REDIS_URL`, or `CONFIG_FILE`).

## Code Map

- `config.rs`: load settings from env + `settings.toml` with `confique`.
- `storage.rs`: Redis CRUD for tokens (`auth:token:{hash}` + `auth:user_tokens:{sub}`), includes Lua delete script.
- `http.rs`: Axum HTTP layer (`/health/*`, `/api/users/{sub}/tokens`, `/forward-auth`, docs at `/docs`).

## Testing Notes

- Needs Redis on `localhost:6379`.
- Existing tests cover happy-path and edge cases; keep new ones serial.
