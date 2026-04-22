//! `splunk-cloud-cli` ライブラリクレート。
//!
//! バイナリと統合テストの両方から参照される共通 API を公開する。
pub mod auth;
pub mod cli;
pub mod client;
pub mod commands;
pub mod config;
pub mod error;
pub mod output;
pub mod util;
