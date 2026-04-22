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
token        = "eyJraWQi..."                # Bearer token (recommended)
# session_key = "..."                       # Splunk session key
# username   = "admin"                      # Basic auth
# password   = "..."

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
cargo test      # 7 unit + 6 integration
cargo build --release
```

Integration tests use `mockito` against loopback HTTP. Production connections enforce `https://` (`localhost` / `127.0.0.1` are the only HTTP exceptions).

## Coverage

* Victoria Experience only (Classic Experience is not supported)
* Based on Splunk Cloud Platform 10.3.2512 REST API
* Streaming: `search/jobs/export` is forwarded as chunked JSON Lines to stdout

## License

MIT
