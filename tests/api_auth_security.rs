use splunk_cloud_cli::client::SplunkClient;
use splunk_cloud_cli::config::{AuthMethod, Credentials};

const CANARY: &str = "DUMMY_AUTH_RESPONSE_SECRET";

fn client(url: String, session_key: bool, debug: bool) -> SplunkClient {
    SplunkClient::new_with_debug(
        Credentials {
            base_url: url,
            auth: if session_key {
                AuthMethod::SessionKey("dummy-session".into())
            } else {
                AuthMethod::BearerToken("dummy-bearer".into())
            },
            default_app: "search".into(),
            default_user: "nobody".into(),
            oauth: None,
        },
        debug,
    )
    .unwrap()
}

#[tokio::test]
async fn all_response_paths_discard_auth_failure_bodies() {
    for status in [401, 403] {
        for session_key in [false, true] {
            for mode in ["json", "bytes", "stream", "allow_error"] {
                let mut server = mockito::Server::new_async().await;
                let response = server
                    .mock(if mode == "allow_error" { "POST" } else { "GET" }, "/test")
                    .match_query(mockito::Matcher::Any)
                    .with_status(status)
                    .with_header("x-reflected-secret", CANARY)
                    .with_body(format!(r#"{{"messages":[{{"text":"{CANARY}"}}]}}"#))
                    .expect(if status == 401 { 2 } else { 1 })
                    .create_async()
                    .await;
                let client = client(server.url(), session_key, true);
                let error = match mode {
                    "json" => client.get("/test", &[]).await.unwrap_err(),
                    "bytes" => client.get_bytes("/test", &[]).await.unwrap_err(),
                    "stream" => client
                        .get_stream_lines("/test", &[], |_| {
                            panic!("auth failure reached stream callback")
                        })
                        .await
                        .unwrap_err(),
                    _ => client
                        .post_form_allow_error("/test", &[])
                        .await
                        .unwrap_err(),
                };
                assert!(error.to_string().contains(&status.to_string()));
                assert!(!error.to_string().contains(CANARY));
                assert!(!format!("{error:?}").contains(CANARY));
                response.assert_async().await;
            }
        }
    }
}

// A child test process lets us inspect actual debug stderr without changing
// this process's environment or touching the OS credential store.
#[tokio::test]
async fn debug_response_child() {
    let Ok(url) = std::env::var("SPLUNK_TEST_RESPONSE_URL") else {
        return;
    };
    let error = client(url, false, true)
        .get("/test", &[])
        .await
        .unwrap_err();
    eprintln!("{error}");
}

#[tokio::test]
async fn debug_stderr_omits_auth_response_headers_and_body() {
    for status in [401, 403] {
        let mut server = mockito::Server::new_async().await;
        let response = server
            .mock("GET", "/test")
            .match_query(mockito::Matcher::Any)
            .with_status(status)
            .with_header("x-reflected-secret", CANARY)
            .with_body(CANARY)
            .expect(if status == 401 { 2 } else { 1 })
            .create_async()
            .await;
        let url = server.url();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "debug_response_child", "--nocapture"])
                .env_clear()
                .env("SPLUNK_TEST_RESPONSE_URL", url)
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(&status.to_string()), "{stderr}");
        assert!(!stderr.contains(CANARY), "{stderr}");
        assert!(!stderr.contains("x-reflected-secret"), "{stderr}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains(CANARY));
        response.assert_async().await;
    }
}

#[tokio::test]
async fn successful_bytes_stream_and_non_auth_errors_remain_visible() {
    let mut server = mockito::Server::new_async().await;
    let success = server
        .mock("GET", "/test")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_body("first\nsecond\n")
        .expect(2)
        .create_async()
        .await;
    let client = client(server.url(), false, false);
    assert_eq!(
        client.get_bytes("/test", &[]).await.unwrap(),
        b"first\nsecond\n"
    );
    let mut lines = Vec::new();
    client
        .get_stream_lines("/test", &[], |line| {
            lines.push(line.to_owned());
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(lines, ["first", "second"]);
    success.assert_async().await;
    let error = server
        .mock("GET", "/error")
        .match_query(mockito::Matcher::Any)
        .with_status(400)
        .with_body("query syntax error")
        .create_async()
        .await;
    assert!(client
        .get("/error", &[])
        .await
        .unwrap_err()
        .to_string()
        .contains("query syntax error"));
    error.assert_async().await;
}
