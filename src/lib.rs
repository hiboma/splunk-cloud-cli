//! `splunk-cloud-cli` ライブラリクレート。
//!
//! バイナリと統合テストの両方から参照される共通 API を公開する。
pub mod auth;
pub mod cli;
pub mod client;
pub mod commands;
pub mod config;
pub mod error;
pub mod oauth;
pub mod output;
pub mod transport;
pub mod util;

#[cfg(test)]
pub(crate) mod test_support {
    /// Synchronize all tests that read or mutate process environment variables.
    pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
