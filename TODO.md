# TODO

## リリース準備

### 5-2 GitHub Actions による配布（実装済み）

- `.github/workflows/release.yml` がタグプッシュ（`v*`）で darwin/linux × arm64/amd64 のバイナリを配布する。
- `.github/workflows/ci.yml` が push/PR で check / clippy / fmt / test を回す。
- `cargo-dist` には依存せず、mde-cli と同じスタイルの手書きワークフロー。

### 5-3 Homebrew formula（テンプレートあり）

- `packaging/homebrew/splunk-cloud-cli.rb` にドラフトがある。
- タグをプッシュしてリリースを作った後、各 tarball の sha256 を計算し、`REPLACE_WITH_SHA256_*` を置き換えて `hiboma/tap` リポジトリに PR を送る。
- `brew upgrade` は default branch のみ参照するため、tap は default branch に push する。

## セキュリティ hardening

- 監査ログ出力（どの REST エンドポイントを叩いたか記録する仕組み）
- `keyring` (macOS Keychain) 連携で token をセキュアに保存
- `clear_env` は不要判定（子プロセス起動はないため、現状は漏洩経路なし）

## フェーズ 4 の積み残し

- `federated provider-update` / `federated index-update`（POST で更新系）
- `knowledge lookup-create` / `lookup-update`（バイナリ CSV アップロード）
- `datamodel` の `pivot` / `acceleration`
- `alert action` の個別 CRUD

これらは REST の受ける form 形式が複雑なので、需要が出たら都度追加する方針。
