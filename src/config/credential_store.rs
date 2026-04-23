//! OS 固有の機密情報ストアへの抽象インターフェース。
//!
//! Splunk Cloud では token / session_key / password の 3 種が長期保持の対象となる。
//! いずれも平文で `config.toml` に書くと Time Machine バックアップや dotfile repo 事故、
//! 同一 uid で動くマルウェアから読まれる経路を増やすため、macOS では Keychain に退避する。
//!
//! トレイトは複数フィールドを扱えるよう key-value API とし、
//! 実体は macOS 限定の `KeychainStore` とテスト用の `MemoryStore` を提供する。
//! Linux / Windows バックエンドは追加コストが低いので、需要が出たらここに足す。

use std::fmt;

/// Keychain の "service" 属性として使うアプリ識別子。
/// 他アプリとの衝突を避ける名前空間となる。
pub const SERVICE: &str = "dev.splunk-cloud-cli";

/// Bearer token を格納するエントリのキー。
pub const KEY_TOKEN: &str = "token";
/// Splunk session key を格納するエントリのキー。
pub const KEY_SESSION_KEY: &str = "session_key";
/// Basic 認証用パスワードを格納するエントリのキー。
pub const KEY_PASSWORD: &str = "password";

/// 既知のキー一覧。`status` / テスト / 逐次走査で使う。
pub const KNOWN_KEYS: &[&str] = &[KEY_TOKEN, KEY_SESSION_KEY, KEY_PASSWORD];

#[derive(Debug)]
pub enum StoreError {
    /// ストアそのものが使えない状態（非 macOS ビルド、default keychain が無い CI sandbox など）。
    Unavailable(String),
    /// ストアには到達したが I/O レベルで失敗した状態（拒否プロンプト、daemon ダウン、ACL 不一致）。
    Backend(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Unavailable(s) => write!(f, "credential store unavailable: {}", s),
            StoreError::Backend(s) => write!(f, "credential store error: {}", s),
        }
    }
}

impl std::error::Error for StoreError {}

/// 機密情報ストアの抽象インターフェース。
///
/// `key` はエントリの識別子（例: "token"）であり、値そのものではない。
/// `get` はエントリが存在しない通常状態を `Ok(None)` で返す。
/// バックエンド起因の失敗は `Err` として伝播させ、
/// 呼び出し側が「未保存」と「到達不能」を区別できるようにする。
pub trait CredentialStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError>;
    fn set(&self, key: &str, value: &str) -> Result<(), StoreError>;
    fn delete(&self, key: &str) -> Result<(), StoreError>;
}

#[cfg(target_os = "macos")]
mod keychain {
    use super::{CredentialStore, StoreError, SERVICE};
    use keyring::Entry;

    pub struct KeychainStore;

    impl KeychainStore {
        pub fn new() -> Self {
            Self
        }

        fn entry(key: &str) -> Result<Entry, StoreError> {
            // Keychain API の第二引数は "account" と呼ばれる。
            // 本 CLI では論理キー（"token" など）をそのまま account として使う。
            Entry::new(SERVICE, key).map_err(|e| StoreError::Backend(e.to_string()))
        }
    }

    impl Default for KeychainStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CredentialStore for KeychainStore {
        fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
            let entry = Self::entry(key)?;
            match entry.get_password() {
                Ok(v) => Ok(Some(v)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(classify_keyring_err(e)),
            }
        }

        fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
            let entry = Self::entry(key)?;
            entry.set_password(value).map_err(classify_keyring_err)
        }

        fn delete(&self, key: &str) -> Result<(), StoreError> {
            let entry = Self::entry(key)?;
            match entry.delete_credential() {
                Ok(()) => Ok(()),
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(classify_keyring_err(e)),
            }
        }
    }

    /// `keyring::Error` を `Unavailable`（ストアが無い）と `Backend`（到達失敗）に分類する。
    ///
    /// `errSecNoDefaultKeychain` に相当する文面を `Backend` 扱いにすると、
    /// Keychain を一度も使っていないユーザーで TOML フォールバックを常に拒否してしまう。
    /// そのため「default keychain が見つからない」系は `Unavailable` に寄せる。
    fn classify_keyring_err(e: keyring::Error) -> StoreError {
        let msg = e.to_string();
        let lower = msg.to_lowercase();
        let unavailable = lower.contains("no default keychain")
            || lower.contains("default keychain could not be found")
            || lower.contains("no platform credential store");
        if unavailable {
            StoreError::Unavailable(msg)
        } else {
            StoreError::Backend(msg)
        }
    }
}

#[cfg(target_os = "macos")]
pub use keychain::KeychainStore;

/// 現在のプラットフォームで利用可能な既定のストアを返す。
/// バックエンドが無い場合は `None`。
pub fn default_store() -> Option<Box<dyn CredentialStore>> {
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(KeychainStore::new()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

#[cfg(test)]
pub mod test_support {
    use super::{CredentialStore, StoreError};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// テスト用インメモリ実装。
    pub struct MemoryStore {
        inner: Mutex<HashMap<String, String>>,
    }

    impl MemoryStore {
        pub fn new() -> Self {
            Self {
                inner: Mutex::new(HashMap::new()),
            }
        }
    }

    impl Default for MemoryStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CredentialStore for MemoryStore {
        fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
            Ok(self.inner.lock().unwrap().get(key).cloned())
        }

        fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
            self.inner
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn delete(&self, key: &str) -> Result<(), StoreError> {
            self.inner.lock().unwrap().remove(key);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MemoryStore;
    use super::*;

    #[test]
    fn memory_store_roundtrip() {
        let s = MemoryStore::new();
        assert!(s.get("k").unwrap().is_none());
        s.set("k", "v").unwrap();
        assert_eq!(s.get("k").unwrap().as_deref(), Some("v"));
        s.delete("k").unwrap();
        assert!(s.get("k").unwrap().is_none());
    }

    #[test]
    fn memory_store_delete_missing_is_ok() {
        let s = MemoryStore::new();
        s.delete("missing").unwrap();
    }

    #[test]
    fn known_keys_are_three_splunk_fields() {
        assert_eq!(KNOWN_KEYS, &[KEY_TOKEN, KEY_SESSION_KEY, KEY_PASSWORD]);
    }
}
