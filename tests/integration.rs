use splunk_cloud_cli::client::SplunkClient;
use splunk_cloud_cli::config::{AuthMethod, Credentials};

fn creds(server_url: &str) -> Credentials {
    Credentials {
        base_url: server_url.to_string(),
        auth: AuthMethod::BearerToken("test-token".to_string()),
        default_app: "search".to_string(),
        default_user: "nobody".to_string(),
    }
}

#[tokio::test]
async fn whoami_returns_json() {
    let mut server = mockito::Server::new_async().await;
    let body = r#"{"entry":[{"name":"admin","content":{"username":"admin"}}]}"#;
    let _m = server
        .mock("GET", "/services/authentication/current-context")
        .match_query(mockito::Matcher::UrlEncoded(
            "output_mode".into(),
            "json".into(),
        ))
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let client = SplunkClient::new(creds(&server.url())).unwrap();
    let value = client
        .get("/services/authentication/current-context", &[])
        .await
        .unwrap();
    assert_eq!(value["entry"][0]["name"], "admin");
}

#[tokio::test]
async fn search_run_posts_form() {
    let mut server = mockito::Server::new_async().await;
    let body = r#"{"results":[{"_raw":"ok"}]}"#;
    let _m = server
        .mock("POST", "/services/search/jobs")
        .match_query(mockito::Matcher::UrlEncoded(
            "output_mode".into(),
            "json".into(),
        ))
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("search".into(), "search index=_internal".into()),
            mockito::Matcher::UrlEncoded("exec_mode".into(), "oneshot".into()),
        ]))
        .with_status(200)
        .with_body(body)
        .create_async()
        .await;

    let client = SplunkClient::new(creds(&server.url())).unwrap();
    let value = client
        .post_form(
            "/services/search/jobs",
            &[
                ("search", "search index=_internal"),
                ("earliest_time", "-15m"),
                ("latest_time", "now"),
                ("exec_mode", "oneshot"),
                ("count", "100"),
                ("output_mode", "json"),
            ],
        )
        .await
        .unwrap();
    assert_eq!(value["results"][0]["_raw"], "ok");
}

#[tokio::test]
async fn saved_search_list_uses_ns_path() {
    let mut server = mockito::Server::new_async().await;
    let body = r#"{"entry":[{"name":"my_search"}]}"#;
    let _m = server
        .mock("GET", "/servicesNS/nobody/search/saved/searches")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("count".into(), "30".into()),
            mockito::Matcher::UrlEncoded("output_mode".into(), "json".into()),
        ]))
        .with_status(200)
        .with_body(body)
        .create_async()
        .await;

    let client = SplunkClient::new(creds(&server.url())).unwrap();
    let path = client.ns_path(None, None, "saved/searches");
    let value = client.get(&path, &[("count", "30")]).await.unwrap();
    assert_eq!(value["entry"][0]["name"], "my_search");
}

#[tokio::test]
async fn kvstore_data_insert_sends_json() {
    let mut server = mockito::Server::new_async().await;
    let body = r#"{"_key":"abc"}"#;
    let _m = server
        .mock(
            "POST",
            "/servicesNS/nobody/search/storage/collections/data/mycoll",
        )
        .match_query(mockito::Matcher::Any)
        .match_body(r#"{"field":"value"}"#)
        .with_status(201)
        .with_body(body)
        .create_async()
        .await;

    let client = SplunkClient::new(creds(&server.url())).unwrap();
    let path = client.ns_path(None, None, "storage/collections/data/mycoll");
    let value = client
        .post_json(&path, &serde_json::json!({"field":"value"}))
        .await
        .unwrap();
    assert_eq!(value["_key"], "abc");
}

#[tokio::test]
async fn api_error_is_surfaced() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/services/search/jobs")
        .match_query(mockito::Matcher::Any)
        .with_status(500)
        .with_body("boom")
        .create_async()
        .await;

    let client = SplunkClient::new(creds(&server.url())).unwrap();
    let err = client
        .get("/services/search/jobs", &[])
        .await
        .expect_err("should surface 500");
    let msg = format!("{}", err);
    assert!(msg.contains("500"), "got: {}", msg);
    assert!(msg.contains("boom"), "got: {}", msg);
}

#[tokio::test]
async fn post_form_allow_error_retries_once_on_401() {
    let mut server = mockito::Server::new_async().await;
    let _first = server
        .mock("POST", "/services/search/parser")
        .match_query(mockito::Matcher::Any)
        .with_status(401)
        .with_body(r#"{"messages":[{"type":"WARN","text":"unauthorized"}]}"#)
        .expect(1)
        .create_async()
        .await;
    let _second = server
        .mock("POST", "/services/search/parser")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"{"messages":[]}"#)
        .expect(1)
        .create_async()
        .await;

    let client = SplunkClient::new(creds(&server.url())).unwrap();
    let (status, value) = client
        .post_form_allow_error(
            "/services/search/parser",
            &[("q", "search index=_internal")],
        )
        .await
        .expect("retry should succeed");
    assert_eq!(status.as_u16(), 200);
    assert_eq!(value["messages"], serde_json::json!([]));
}

#[tokio::test]
async fn search_parse_sends_all_four_form_fields() {
    // Parse サブコマンドが parser エンドポイントへ送るフォームの契約を固定する。
    // q / parse_only / enable_lookups / reload_macros の 4 フィールドが
    // 常に送られていることを mockito の match_body で検証する。
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/services/search/parser")
        .match_query(mockito::Matcher::UrlEncoded(
            "output_mode".into(),
            "json".into(),
        ))
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("q".into(), "search index=_internal".into()),
            mockito::Matcher::UrlEncoded("parse_only".into(), "true".into()),
            mockito::Matcher::UrlEncoded("enable_lookups".into(), "false".into()),
            mockito::Matcher::UrlEncoded("reload_macros".into(), "false".into()),
        ]))
        .with_status(200)
        .with_body(r#"{"messages":[]}"#)
        .expect(1)
        .create_async()
        .await;

    let client = SplunkClient::new(creds(&server.url())).unwrap();
    let (status, _) = client
        .post_form_allow_error(
            "/services/search/parser",
            &[
                ("q", "search index=_internal"),
                ("parse_only", "true"),
                ("enable_lookups", "false"),
                ("reload_macros", "false"),
            ],
        )
        .await
        .unwrap();
    assert_eq!(status.as_u16(), 200);
}

#[tokio::test]
async fn post_form_allow_error_returns_json_on_400() {
    let mut server = mockito::Server::new_async().await;
    let body = r#"{"messages":[{"type":"FATAL","text":"Unknown search command 'bizzbuzz'."}]}"#;
    let _m = server
        .mock("POST", "/services/search/parser")
        .match_query(mockito::Matcher::UrlEncoded(
            "output_mode".into(),
            "json".into(),
        ))
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let client = SplunkClient::new(creds(&server.url())).unwrap();
    let (status, value) = client
        .post_form_allow_error(
            "/services/search/parser",
            &[("q", "search | bizzbuzz"), ("parse_only", "true")],
        )
        .await
        .expect("4xx with JSON body should still return Ok");
    assert_eq!(status.as_u16(), 400);
    assert_eq!(value["messages"][0]["type"], "FATAL");
    assert!(value["messages"][0]["text"]
        .as_str()
        .unwrap()
        .contains("bizzbuzz"));
}

#[tokio::test]
async fn post_form_allow_error_surfaces_500() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/services/search/parser")
        .match_query(mockito::Matcher::Any)
        .with_status(500)
        .with_body("internal boom")
        .create_async()
        .await;

    let client = SplunkClient::new(creds(&server.url())).unwrap();
    let err = client
        .post_form_allow_error("/services/search/parser", &[("q", "x")])
        .await
        .expect_err("5xx should be Err even with allow_error");
    let msg = format!("{}", err);
    assert!(msg.contains("500"), "got: {}", msg);
    assert!(msg.contains("boom"), "got: {}", msg);
}

#[tokio::test]
async fn http_on_non_loopback_is_rejected() {
    let bad = Credentials {
        base_url: "http://example.com".to_string(),
        auth: AuthMethod::BearerToken("t".into()),
        default_app: "search".into(),
        default_user: "nobody".into(),
    };
    // `SplunkClient` は Debug を派生しないため `expect_err` は使えない。
    // `auth` に session key が載るので派生 Debug 経由の漏洩を防ぐための設計。
    let err = match SplunkClient::new(bad) {
        Ok(_) => panic!("should reject non-HTTPS, non-loopback base_url"),
        Err(e) => e,
    };
    assert!(format!("{}", err).contains("HTTPS"));
}
