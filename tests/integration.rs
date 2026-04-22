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
async fn http_on_non_loopback_is_rejected() {
    let bad = Credentials {
        base_url: "http://example.com".to_string(),
        auth: AuthMethod::BearerToken("t".into()),
        default_app: "search".into(),
        default_user: "nobody".into(),
    };
    let err = SplunkClient::new(bad).expect_err("should reject");
    assert!(format!("{}", err).contains("HTTPS"));
}
