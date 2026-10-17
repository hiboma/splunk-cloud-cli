use std::path::Path;
use std::process::{Command, Output};

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_splunk-cloud-cli"))
        .env_clear()
        .env("XDG_CONFIG_HOME", dir.join("user-config"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn project_config_requires_explicit_selection() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".splunk-cloud-cli.toml"),
        "token = \"DUMMY_UNTERMINATED_SECRET\n",
    )
    .unwrap();
    let ignored = run(dir.path(), &["auth", "whoami"]);
    let text = combined(&ignored);
    assert!(!ignored.status.success());
    assert!(text.contains("base_url not set"), "{text}");
    assert!(!text.contains("failed to parse"));

    // A global flag also works after the subcommand.
    let selected = run(
        dir.path(),
        &["auth", "whoami", "--config", ".splunk-cloud-cli.toml"],
    );
    let text = combined(&selected);
    assert!(!selected.status.success());
    assert!(text.contains("invalid TOML configuration"), "{text}");
    assert!(!text.contains("DUMMY_UNTERMINATED_SECRET"));
}

#[test]
fn syntax_and_deserialization_errors_never_echo_values() {
    let dir = tempfile::tempdir().unwrap();
    for input in [
        "token = \"DUMMY_SECRET_CANARY\n",
        "session_key = \"DUMMY_SECRET_CANARY\n",
        "password = \"DUMMY_SECRET_CANARY\n",
        "format = \"DUMMY_SECRET_CANARY\"\n",
        "token = \"DUMMY_SECRET_CANARY\"\ntoken = \"duplicate\"\n",
    ] {
        std::fs::write(dir.path().join("selected.toml"), input).unwrap();
        for args in [
            vec!["--config", "selected.toml", "auth", "whoami"],
            vec![
                "--config",
                "selected.toml",
                "doctor",
                "--no-connect",
                "--strict",
            ],
            vec![
                "--config",
                "selected.toml",
                "credentials",
                "migrate",
                "--dry-run",
            ],
        ] {
            let output = run(dir.path(), &args);
            let text = combined(&output);
            assert!(!output.status.success(), "{text}");
            assert!(text.contains("selected.toml"), "{text}");
            assert!(text.contains("line ") && text.contains("column "), "{text}");
            assert!(text.contains("invalid TOML configuration"), "{text}");
            assert!(!text.contains("DUMMY_SECRET_CANARY"), "{text}");
        }
    }
}

#[test]
fn explicit_missing_config_is_an_error_even_when_default_exists() {
    let dir = tempfile::tempdir().unwrap();
    let default_dir = dir.path().join("user-config/splunk-cloud-cli");
    std::fs::create_dir_all(&default_dir).unwrap();
    std::fs::write(
        default_dir.join("config.toml"),
        "default_app = \"search\"\n",
    )
    .unwrap();
    for args in [
        vec!["--config", "missing.toml", "auth", "whoami"],
        vec![
            "--config",
            "missing.toml",
            "doctor",
            "--strict",
            "--no-connect",
        ],
        vec![
            "--config",
            "missing.toml",
            "credentials",
            "migrate",
            "--dry-run",
        ],
    ] {
        let output = run(dir.path(), &args);
        let text = combined(&output);
        assert!(!output.status.success(), "{text}");
        assert!(
            text.contains("failed to read config file missing.toml"),
            "{text}"
        );
    }
}

#[test]
fn user_config_is_loaded_and_explicit_valid_config_overrides_it() {
    let dir = tempfile::tempdir().unwrap();
    let default_dir = dir.path().join("user-config/splunk-cloud-cli");
    std::fs::create_dir_all(&default_dir).unwrap();
    std::fs::write(
        default_dir.join("config.toml"),
        "format = \"DUMMY_INVALID_FORMAT\"\n",
    )
    .unwrap();
    let output = run(dir.path(), &["auth", "whoami"]);
    assert!(combined(&output).contains("invalid TOML configuration"));
    std::fs::write(
        dir.path().join("valid.toml"),
        "default_app = \"custom\"\nformat = \"json\"\n",
    )
    .unwrap();
    let output = run(dir.path(), &["--config", "valid.toml", "auth", "whoami"]);
    assert!(combined(&output).contains("base_url not set"));
    let settings =
        splunk_cloud_cli::config::load_settings_from(Some(&dir.path().join("valid.toml"))).unwrap();
    assert_eq!(settings.default_app.as_deref(), Some("custom"));
    assert!(matches!(
        settings.format,
        Some(splunk_cloud_cli::cli::OutputFormat::Json)
    ));
}

#[test]
fn empty_or_relative_xdg_cannot_select_cwd_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".config/splunk-cloud-cli")).unwrap();
    std::fs::write(
        home.join(".config/splunk-cloud-cli/config.toml"),
        "default_app = \"search\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("splunk-cloud-cli")).unwrap();
    std::fs::write(
        dir.path().join("splunk-cloud-cli/config.toml"),
        "token = \"DUMMY_SECRET_CANARY\n",
    )
    .unwrap();
    for xdg in ["", "."] {
        let output = Command::new(env!("CARGO_BIN_EXE_splunk-cloud-cli"))
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", xdg)
            .current_dir(dir.path())
            .args(["auth", "whoami"])
            .output()
            .unwrap();
        let text = combined(&output);
        assert!(!output.status.success());
        assert!(!text.contains("invalid TOML"), "{text}");
        assert!(!text.contains("DUMMY_SECRET_CANARY"));
        assert!(
            text.contains(if xdg.is_empty() {
                "base_url not set"
            } else {
                "XDG_CONFIG_HOME must be an absolute path"
            }),
            "{text}"
        );
    }
}
