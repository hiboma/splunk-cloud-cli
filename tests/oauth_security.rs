//! Adversarial checks use only local mock servers and fabricated credentials.
use splunk_cloud_cli::oauth::{self, OAuthConfig, OAuthSession, SplunkToken, TokenSet};
use splunk_cloud_cli::transport::HttpClient;

fn config() -> OAuthConfig {
    OAuthConfig {
        tenant_id: "test-tenant".into(),
        client_id: "test-client".into(),
        scope: "api://test-client/read api://test-client/write".into(),
    }
}

fn session(base: &str, expired: bool) -> OAuthSession {
    OAuthSession::from_login(
        &TokenSet {
            access_token: "dummy-entra-assertion".into(),
            refresh_token: Some("dummy-refresh-token".into()),
            expires_at: oauth::now_unix() + 3600,
        },
        &SplunkToken {
            access_token: "dummy-splunk-token".into(),
            expires_at: if expired { 0 } else { oauth::now_unix() + 3600 },
        },
        &config(),
        base,
    )
    .unwrap()
}

#[tokio::test]
async fn every_identity_mismatch_rejects_valid_and_expired_sessions_before_requests() {
    let mut original = mockito::Server::new_async().await;
    let mut destination = mockito::Server::new_async().await;
    let original_requests = original
        .mock("POST", "/oauth2/v1/token")
        .expect(0)
        .create_async()
        .await;
    let destination_requests = destination
        .mock("POST", "/oauth2/v1/token")
        .expect(0)
        .create_async()
        .await;
    let http = HttpClient::new().unwrap();
    for expired in [false, true] {
        for field in ["origin", "tenant", "client", "scope"] {
            let mut cfg = config();
            let base = if field == "origin" {
                destination.url()
            } else {
                original.url()
            };
            match field {
                "tenant" => cfg.tenant_id = "another-tenant".into(),
                "client" => cfg.client_id = "another-client".into(),
                "scope" => cfg.scope = "api://test-client/READ".into(),
                _ => {}
            }
            let saved = session(&original.url(), expired);
            let error = match oauth::ensure_fresh_session(&saved, &cfg, &base, &http).await {
                Ok(_) => panic!("{field} mismatch accepted; expired={expired}"),
                Err(error) => error,
            };
            assert!(error.partial.is_none());
            assert!(error.error.to_string().contains("auth login"));
        }
    }
    original_requests.assert_async().await;
    destination_requests.assert_async().await;
}

#[tokio::test]
async fn same_identity_keeps_valid_token_and_reexchanges_expired_token() {
    let mut server = mockito::Server::new_async().await;
    let exchange = server
        .mock("POST", "/oauth2/v1/token")
        .match_body(mockito::Matcher::UrlEncoded(
            "client_assertion".into(),
            "dummy-entra-assertion".into(),
        ))
        .with_status(200)
        .with_body(r#"{"access_token":"dummy-new-token","expires_in":3600}"#)
        .expect(1)
        .create_async()
        .await;
    let http = HttpClient::new().unwrap();
    let mut cfg = config();
    // Ordering, duplicates and explicit offline_access do not change the scope set.
    cfg.scope =
        "offline_access api://test-client/write api://test-client/read api://test-client/read"
            .into();
    for expired in [false, true] {
        let saved = session(&server.url(), expired);
        let result =
            oauth::ensure_fresh_session(&saved, &cfg, &format!("{}/", server.url()), &http)
                .await
                .unwrap_or_else(|error| panic!("{}", error.error));
        assert_eq!(result.changed, expired);
        assert_eq!(
            result.session.splunk_token,
            if expired {
                "dummy-new-token"
            } else {
                "dummy-splunk-token"
            }
        );
        assert_eq!(result.session.binding, saved.binding);
        assert_eq!(result.session.refresh_token, saved.refresh_token);
        result.session.validate(&cfg, &server.url()).unwrap();
    }
    exchange.assert_async().await;
}

#[tokio::test]
async fn legacy_and_unknown_schema_sessions_require_login_without_requests() {
    let mut server = mockito::Server::new_async().await;
    let requests = server
        .mock("POST", "/oauth2/v1/token")
        .expect(0)
        .create_async()
        .await;
    let http = HttpClient::new().unwrap();
    for expired in [false, true] {
        for legacy in [true, false] {
            let mut value = serde_json::to_value(session(&server.url(), expired)).unwrap();
            if legacy {
                value.as_object_mut().unwrap().remove("binding");
            } else {
                value["binding"]["version"] = serde_json::json!(999);
            }
            let saved = OAuthSession::from_json(&value.to_string()).unwrap();
            assert!(saved.requires_login());
            assert!(
                oauth::ensure_fresh_session(&saved, &config(), &server.url(), &http)
                    .await
                    .is_err()
            );
        }
    }
    requests.assert_async().await;
}

#[test]
fn malformed_session_errors_do_not_echo_stored_data() {
    for raw in [
        "dummy-secret-invalid-json",
        r#"{"splunk_token":"dummy-secret", "splunk_expires_at":"dummy-secret"}"#,
        r#"{"binding":{"version":"dummy-secret"}}"#,
    ] {
        let error = OAuthSession::from_json(raw).unwrap_err();
        assert!(!error.to_string().contains("dummy-secret"));
        assert!(!format!("{error:?}").contains("dummy-secret"));
        assert!(error.to_string().contains("auth login"));
    }
}

#[tokio::test]
async fn exchange_failures_do_not_echo_any_response_format() {
    let secret = "dummy-secret-fragment";
    let bodies = [
        format!(r#"{{"error":"invalid_grant","error_description":"{secret}"}}"#),
        format!("client_assertion={secret}"),
        format!("{}{}", "x".repeat(199), secret.repeat(30)),
        "client_assertion=%64%75%6d%6d%79%2d%73%65%63%72%65%74%2d%66%72%61%67%6d%65%6e%74"
            .to_string(),
        format!(r#"{{"error":"{secret}"}}"#),
        format!(r#"{{"messages":[{{"text":"{secret}"}}]}}"#),
    ];
    let http = HttpClient::new().unwrap();
    for body in bodies {
        let mut server = mockito::Server::new_async().await;
        let response = server
            .mock("POST", "/oauth2/v1/token")
            .with_status(400)
            .with_body(&body)
            .create_async()
            .await;
        let error = oauth::exchange_for_splunk_token(&server.url(), "test-client", &http, secret)
            .await
            .unwrap_err();
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(rendered.contains("400"));
            assert!(!rendered.contains(secret));
            assert!(!rendered.contains("%64%75"));
            assert!(!rendered.contains(&"x".repeat(20)));
        }
        response.assert_async().await;
    }
}

#[tokio::test]
async fn exchange_307_and_308_never_forward_assertion_to_destination() {
    let http = HttpClient::new().unwrap();
    for status in [307, 308] {
        let mut source = mockito::Server::new_async().await;
        let mut destination = mockito::Server::new_async().await;
        let unexpected = destination
            .mock("POST", "/capture")
            .expect(0)
            .with_status(200)
            .with_body(r#"{"access_token":"unexpected-token"}"#)
            .create_async()
            .await;
        let redirect = source
            .mock("POST", "/oauth2/v1/token")
            .with_status(status)
            .with_header("location", &format!("{}/capture", destination.url()))
            .create_async()
            .await;
        assert!(oauth::exchange_for_splunk_token(
            &source.url(),
            "test-client",
            &http,
            "dummy-assertion"
        )
        .await
        .is_err());
        redirect.assert_async().await;
        unexpected.assert_async().await;
    }
}

#[tokio::test]
async fn malformed_success_responses_do_not_echo_values() {
    let mut server = mockito::Server::new_async().await;
    let response = server
        .mock("POST", "/oauth2/v1/token")
        .with_status(200)
        .with_body(r#"{"access_token":"dummy-token","expires_in":"dummy-secret"}"#)
        .create_async()
        .await;
    let error = oauth::exchange_for_splunk_token(
        &server.url(),
        "client",
        &HttpClient::new().unwrap(),
        "dummy-assertion",
    )
    .await
    .unwrap_err();
    assert!(!error.to_string().contains("dummy-secret"));
    assert!(!format!("{error:?}").contains("dummy-secret"));
    response.assert_async().await;
}
