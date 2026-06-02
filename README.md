# splunk-cloud-cli

CLI for Splunk Cloud Platform REST API (Victoria Experience), written in Rust. Ships as a single static binary.

## Scope

`splunk-cloud-cli` works on **content that lives inside a Splunk stack** (saved searches, dashboards, KV Store, knowledge objects, search jobs, metrics catalog, federated search). Stack-level administration — apps, indexes, users, HEC tokens, IP allowlists, limits, maintenance windows — belongs to the official [ACS CLI](https://help.splunk.com/en/splunk-cloud-platform/administer/admin-config-service-manual/) and is intentionally not implemented here.

### ACS CLI vs. splunk-cloud-cli

| Area | ACS CLI | splunk-cloud-cli |
|---|---|---|
| Endpoint | `admin.splunk.com` (ACS) | `https://<stack>.splunkcloud.com:8089` (Splunkd REST) |
| apps / app permissions | authoritative | — |
| indexes / Self-Storage | authoritative | read-only (write via ACS) |
| users / roles / capabilities | authoritative | `auth whoami` only |
| HEC token | authoritative | — |
| ip-allowlist / outbound-port | authoritative | — |
| limits.conf / maintenance window | authoritative | — |
| restart / deployment status | authoritative | — |
| saved searches / alerts | — | **authoritative** |
| dashboards (`data/ui/views`) | — | **authoritative** |
| KV Store (collection / data) | — | **authoritative** |
| knowledge objects (lookup / props / transforms / macros / tags / eventtypes) | — | **authoritative** |
| data models | — | **authoritative** |
| federated search (provider / index) | — | **authoritative** |
| metrics catalog | — | **authoritative** |
| search jobs (`search/jobs`, `search/jobs/export`) | — | **authoritative** |
| alert actions / fired alerts | — | **authoritative** |

Think of ACS CLI as "the knobs on the stack" and splunk-cloud-cli as "the content on the stack." In multi-stack operations they are used together: ACS CLI provisions the stack, splunk-cloud-cli deploys content onto it.

## Installation

```bash
cargo install --path .
# or: cargo build --release && cp target/release/splunk-cloud-cli ~/bin/
```

### Homebrew (after a release is cut)

```bash
brew install hiboma/tap/splunk-cloud-cli
```

The formula template lives at `packaging/homebrew/splunk-cloud-cli.rb`. Release flow:

1. Push a `v*` tag → `.github/workflows/release.yml` builds tarballs for darwin/linux × arm64/amd64 and attaches them to the GitHub release.
2. Compute sha256 for each tarball, fill in the four `REPLACE_WITH_SHA256_*` placeholders, bump `version`, and open a PR against the `hiboma/tap` repository.

## Configuration

All settings — including the stack URL and credentials — can live in a TOML file, but environment variables always win when present. Credentials are never accepted via command-line flags (which would leak through shell history and `ps`).

Config file search order (first hit wins):

1. `./.splunk-cloud-cli.toml`
2. `$XDG_CONFIG_HOME/splunk-cloud-cli/config.toml`
3. `~/.config/splunk-cloud-cli/config.toml`

### Full TOML example

```toml
base_url     = "https://prd-p-xxxxxx.splunkcloud.com:8089"

# Pick exactly one auth method.
token        = "eyJEXAMPLEHEADER00.eyJEXAMPLEPAYLOAD0.EXAMPLESIGN0"   # Bearer token (recommended)
# session_key = "..."                       # Splunk session key
# username   = "admin"                      # Basic auth
# password   = "..."

# Or sign in interactively with `auth login` (Entra ID device code flow).
# These identifiers are not secrets. See "Sign in with Entra ID" below.
# oauth_tenant_id = "a271068e-1b87-40f0-a7f2-f9c9624e3f7c"
# oauth_client_id = "325df464-153b-4bc5-adac-7e5014b58bb4"
# oauth_scope     = "api://325df464-153b-4bc5-adac-7e5014b58bb4/user_impersonation"

default_app  = "search"                     # servicesNS default app
default_user = "nobody"                     # servicesNS default user
format       = "pretty"                     # pretty | json | yaml | csv
```

### Environment variables

Any TOML field that is a secret (or the stack URL) can be overridden via env. Preferred for CI and for keeping secrets out of files.

| Variable | Overrides TOML field |
|---|---|
| `SPLUNK_BASE_URL` | `base_url` |
| `SPLUNK_TOKEN` | `token` |
| `SPLUNK_SESSION_KEY` | `session_key` |
| `SPLUNK_USERNAME` / `SPLUNK_PASSWORD` | `username` / `password` |
| `SPLUNK_APP` | `default_app` |
| `SPLUNK_USER` | `default_user` |
| `SPLUNK_OAUTH_TENANT_ID` | `oauth_tenant_id` |
| `SPLUNK_OAUTH_CLIENT_ID` | `oauth_client_id` |
| `SPLUNK_OAUTH_SCOPE` | `oauth_scope` |

Per-field resolution: CLI flag (where present) → environment variable → config file → built-in default.

### Wildcard namespace (`--app -` / `--user -`)

Splunk treats `-` as a wildcard in `servicesNS/{user}/{app}/...`. Pass `-` to either flag to broaden the lookup across apps or users:

```bash
# Search for a dashboard regardless of which app it lives in
splunk-cloud-cli --app - dashboard ls | jq '.entry[] | {name, app: .acl.app}'

# Both wildcards — typical when you don't know the owner either
splunk-cloud-cli --app - --user - dashboard get <internal_id>
```

Use this when a `get` call returns 404 even though the object visibly exists in Splunk Web — it usually means the object is in a different app or owned by another user.

### Protect the config file

If the config file contains any of `token` / `session_key` / `password`, the CLI emits a warning to stderr when the file is group/world-readable. Always chmod 600:

```bash
chmod 600 ~/.config/splunk-cloud-cli/config.toml
```

### Credential storage (macOS Keychain)

The secret fields — `token`, `session_key`, `password` — can live in the OS credential store instead of `config.toml`. Storing secrets in the Keychain keeps them out of plaintext config files (and out of dotfile backups, Time Machine snapshots, accidental git commits).

Resolution order for each secret, highest priority first:

1. Environment variable (`SPLUNK_TOKEN`, `SPLUNK_SESSION_KEY`, `SPLUNK_PASSWORD`)
2. **macOS Keychain** (login keychain, `service=dev.splunk-cloud-cli`, `account=<field>`)
3. `config.toml`

If the Keychain itself reports a backend failure (e.g. the user denied an access prompt), the CLI refuses to fall back to `config.toml` and surfaces a "no credential set" error. Silently picking up a stale plaintext secret would defeat the point of moving the secret out of the toml in the first place. When the backend is simply unavailable (non-macOS build, CI sandbox without a default keychain), the fallback proceeds normally.

#### Storing a secret

```bash
# Interactive prompt (input is hidden)
splunk-cloud-cli credentials set token
splunk-cloud-cli credentials set session-key
splunk-cloud-cli credentials set password

# Non-interactive (CI / scripts)
echo "$SPLUNK_TOKEN" | splunk-cloud-cli credentials set token --stdin

# Confirm presence (the value is never printed)
splunk-cloud-cli credentials status
```

#### Migrating from config.toml

To move any existing `token` / `session_key` / `password` out of `config.toml` and into the Keychain in one step:

```bash
splunk-cloud-cli credentials migrate
```

`migrate` is transactional: it writes to the Keychain first, then atomically rewrites `config.toml` (0600). If the rewrite fails, the Keychain entries it just wrote are rolled back so the user is never left in an inconsistent half-migrated state. Unsupported TOML quoting forms (literal strings, multi-line basic/literal, escaped quotes) are refused rather than silently mishandled.

By default, `migrate` removes the plaintext lines from `config.toml` outright. Choosing to keep a 0600 backup is supported but warned about — any copy left on disk re-introduces the risk we just migrated away from.

#### Inspecting the entries

The entries live in your **login** keychain as `generic password` items:

| Attribute | Value |
|---|---|
| Kind | `application password` |
| Service (Name / Where) | `dev.splunk-cloud-cli` |
| Account | `token` / `session_key` / `password` |

```
# GUI
Keychain Access.app → login → Passwords → search "dev.splunk-cloud-cli"

# CLI (metadata only; value is not printed)
security find-generic-password -s dev.splunk-cloud-cli -a token
```

#### Removing an entry

```bash
splunk-cloud-cli credentials delete token
# or via macOS:
security delete-generic-password -s dev.splunk-cloud-cli -a token
```

#### Notes on Keychain prompts

macOS shows an access-prompt dialog the first time the binary reads a Keychain entry. Choosing **Always Allow** suppresses subsequent prompts. The dialog reappears whenever the binary's code signature changes (e.g. after `cargo install` rebuilds the binary).

### Sign in with Entra ID (OAuth device code flow)

Instead of pasting a long-lived token, you can sign in interactively against Microsoft Entra ID. The CLI runs the OAuth 2.0 **device code flow**: it shows a short one-time code, then (on a terminal) waits for you to press Enter and opens the sign-in page in your browser; you enter the code and approve. The CLI stores the resulting JWT access token (plus a refresh token) in the OS credential store. Splunk Cloud is configured to validate that JWT as a Bearer token — the CLI never sees your password.

When stdout/stdin are not a terminal (piped or CI), the CLI does not wait or open a browser: it prints the URL and code and proceeds to poll, so scripts don't block.

This requires an Entra ID app registration with a public client (device code) enabled, and a matching OAuth 2.0 configuration on the Splunk Cloud side. Put the (non-secret) tenant and client identifiers in the config file:

```toml
base_url        = "https://prd-p-xxxxxx.splunkcloud.com:8089"

# Entra ID OAuth (used by `auth login`)
oauth_tenant_id = "a271068e-1b87-40f0-a7f2-f9c9624e3f7c"
oauth_client_id = "325df464-153b-4bc5-adac-7e5014b58bb4"
# oauth_scope   = "api://325df464-153b-4bc5-adac-7e5014b58bb4/user_impersonation"
# ^ optional; defaults to api://<client_id>/user_impersonation. `offline_access` is always added.
```

These three can also come from `SPLUNK_OAUTH_TENANT_ID` / `SPLUNK_OAUTH_CLIENT_ID` / `SPLUNK_OAUTH_SCOPE`. They are not secrets, so unlike the auth fields they may live in the config file or env without special handling.

```bash
# Sign in. Shows a code, then opens the browser on Enter. Approve there.
splunk-cloud-cli auth login

# Same, but also copy the one-time code to the clipboard (macOS only).
# Only the code is copied — never the access/refresh token.
splunk-cloud-cli auth login --copy

# Use the CLI as usual — the stored token is picked up automatically.
splunk-cloud-cli auth whoami

# Inspect token state (the value itself is never printed).
splunk-cloud-cli auth status

# Sign out (removes the access token, refresh token, and expiry).
splunk-cloud-cli auth logout
```

The access token typically expires after ~1 hour. When it is close to expiry, the CLI uses the stored refresh token to obtain a new one automatically and writes the result back to the credential store — no re-login needed until the refresh token itself expires. If the refresh fails (revoked or expired), run `auth login` again.

Storage layout in the credential store (`service=dev.splunk-cloud-cli`):

| Account | Contents |
|---|---|
| `token` | OAuth access token (shared with the manually-set Bearer token slot) |
| `refresh_token` | OAuth refresh token (long-lived secret) |
| `token_expiry` | Access token expiry as a UNIX timestamp |

Because the access token is stored in the same `token` slot as a manually-set Bearer token, every other subcommand works unchanged after `auth login`. Automatic refresh only kicks in when a refresh token and expiry are present and `SPLUNK_TOKEN` is **not** set in the environment (an explicit `SPLUNK_TOKEN` is treated as a fixed value and never overwritten).

### Example: direnv `.envrc`

```bash
export SPLUNK_BASE_URL="https://prd-p-xxxxxx.splunkcloud.com:8089"
export SPLUNK_TOKEN="$(op read op://Private/splunk-prod-token/credential)"
export SPLUNK_APP="search"
```

### Example: one-shot

```bash
env SPLUNK_BASE_URL=https://... SPLUNK_TOKEN="$(pass splunk/prod)" \
  splunk-cloud-cli auth whoami
```

## Usage

### Search

```bash
splunk-cloud-cli search run --query 'index=_internal | head 10'
splunk-cloud-cli search export --query 'index=_internal' --earliest -1h
splunk-cloud-cli search jobs-ls
splunk-cloud-cli search jobs-get <SID>
splunk-cloud-cli search results <SID>
splunk-cloud-cli search control <SID> cancel
```

#### Validate SPL syntax (no job is created)

`search parse` calls `/services/search/parser` with `parse_only=true`. The parser inspects the SPL and returns either the parsed structure or `messages[].type = "FATAL"` — no search job is dispatched and no events are read. Useful in CI to gate saved-search / dashboard PRs.

```bash
# OK: prints parsed JSON, exit 0
splunk-cloud-cli search parse --query 'index=_internal | stats count by sourcetype'

# Syntax error: prints the FATAL message JSON, then a one-line error to stderr, exit 1
splunk-cloud-cli search parse --query '| bizzbuzz foo'

# Read SPL from a file or stdin
splunk-cloud-cli search parse --query @./alert.spl
cat alert.spl | splunk-cloud-cli search parse --query @-
```

Notes:

- Splunk's `POST /services/search/jobs` does **not** support `exec_mode=parse`. Use this subcommand (which targets `/services/search/parser`) instead.
- `--enable-lookups` resolves lookup tables during parsing (slower, but catches references to missing lookups).
- `--reload-macros` forces a macro reload before parsing.
- Pair with `-f json` for CI:

  ```bash
  if ! splunk-cloud-cli -f json search parse --query @./alert.spl > parsed.json 2> err.txt; then
    cat err.txt && exit 1
  fi
  ```

### Saved Search

```bash
splunk-cloud-cli saved-search ls
splunk-cloud-cli saved-search get my_search
splunk-cloud-cli saved-search create my_search --search 'index=_internal' --param cron_schedule='*/5 * * * *'
splunk-cloud-cli saved-search update my_search --param description='updated'
splunk-cloud-cli saved-search dispatch my_search
splunk-cloud-cli saved-search rm my_search
```

### Dashboard

```bash
splunk-cloud-cli dashboard ls
splunk-cloud-cli dashboard get my_dashboard
splunk-cloud-cli dashboard create my_dashboard --data @./dashboard.xml
splunk-cloud-cli dashboard update my_dashboard --data @./dashboard.xml --changelog 'fix title'
splunk-cloud-cli dashboard history my_dashboard
splunk-cloud-cli dashboard revision my_dashboard --revision-id <SHA>
```

`--data` takes a literal string, `@path` for a file, or `@-` for stdin.

### KV Store

```bash
splunk-cloud-cli kvstore collection-ls
splunk-cloud-cli kvstore collection-create mycoll
splunk-cloud-cli kvstore data-insert mycoll --data '{"field":"value"}'
splunk-cloud-cli kvstore data-ls mycoll --query '{"field":"value"}' --limit 10
splunk-cloud-cli kvstore data-get mycoll <KEY>
splunk-cloud-cli kvstore data-batch-save mycoll --data @records.json
splunk-cloud-cli kvstore data-rm mycoll <KEY>
```

### Knowledge objects

```bash
splunk-cloud-cli knowledge lookup-ls
splunk-cloud-cli knowledge macros-ls
splunk-cloud-cli knowledge tags-ls
splunk-cloud-cli knowledge eventtypes-ls
splunk-cloud-cli knowledge datamodel-ls
```

### Federated Search

```bash
splunk-cloud-cli federated provider-ls
splunk-cloud-cli federated provider-create myprov \
  --param type=splunk --param hostPort=remote.example:8089 --param mode=standard
splunk-cloud-cli federated index-ls
splunk-cloud-cli federated settings
```

### Indexes (read-only)

Read-only inspection of `/services/data/indexes`. Creating, updating, or deleting indexes belongs to the [ACS CLI](https://help.splunk.com/en/splunk-cloud-platform/administer/admin-config-service-manual/); this CLI intentionally does not implement those operations.

```bash
splunk-cloud-cli index ls
splunk-cloud-cli index ls --summarize
splunk-cloud-cli index get _internal
```

`--summarize` switches to the Splunkd summary response (`currentDBSizeMB`, `totalEventCount`, `minTime`, `maxTime`), which is much smaller than the full index configuration payload.

### Metrics Catalog

```bash
splunk-cloud-cli metrics names --earliest -24h
splunk-cloud-cli metrics dimensions --metric-name 'cpu.usage'
splunk-cloud-cli metrics rollup-ls
```

### Alerts

```bash
splunk-cloud-cli alert actions-ls
splunk-cloud-cli alert fired-ls
```

### Output formats

`-f pretty|json|yaml|csv` (default `pretty`). CSV extracts `results[]` or `entry[]` from the response.

## Shell completions

```bash
splunk-cloud-cli completion zsh > ~/.zsh/completions/_splunk-cloud-cli
splunk-cloud-cli completion bash > ~/.local/share/bash-completion/completions/splunk-cloud-cli
splunk-cloud-cli completion fish > ~/.config/fish/completions/splunk-cloud-cli.fish
```

## Development

```bash
cargo build
cargo test
cargo build --release
```

Integration tests use `mockito` against loopback HTTP. Production connections enforce `https://` (`localhost` / `127.0.0.1` are the only HTTP exceptions).

## Coverage

* Victoria Experience only (Classic Experience is not supported)
* Based on Splunk Cloud Platform 10.3.2512 REST API
* Streaming: `search/jobs/export` is forwarded as chunked JSON Lines to stdout

## License

MIT
