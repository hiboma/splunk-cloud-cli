use splunk_cloud_cli::auth::Authorizer;
use splunk_cloud_cli::client::SplunkClient;
use splunk_cloud_cli::config::{AuthMethod, Credentials};
use splunk_cloud_cli::transport::{Endpoint, HttpClient};

fn credentials(base_url: String, auth: AuthMethod) -> Credentials {
    Credentials {
        base_url,
        auth,
        default_app: "search".into(),
        default_user: "nobody".into(),
        oauth: None,
    }
}

#[test]
fn endpoints_accept_only_service_origins() {
    for (input, expected) in [
        ("https://EXAMPLE.com:443/", "https://example.com"),
        ("https://example.com:8089", "https://example.com:8089"),
        ("http://localhost:49123/", "http://localhost:49123"),
        ("http://127.0.0.1:49123", "http://127.0.0.1:49123"),
        ("http://[::1]:49123", "http://[::1]:49123"),
    ] {
        assert_eq!(Endpoint::parse(input).unwrap().as_str(), expected);
    }
    for input in [
        "http://example.com",
        "http://localhost.example.com",
        "http://localhost:80@example.com",
        "https://user:SECRET@example.com",
        "https://@example.com",
        "https://example.com/path",
        "https://example.com/./",
        "https://example.com?token=SECRET",
        "https://example.com#SECRET",
        "ftp://example.com",
        "https:///example.com",
        "https://example.com\\path",
        " https://example.com",
        "https://example.com\n",
        "not-a-url-SECRET",
    ] {
        let error = Endpoint::parse(input).unwrap_err().to_string();
        assert!(!error.contains("SECRET"));
        assert!(SplunkClient::new(credentials(
            input.into(),
            AuthMethod::BearerToken("dummy".into())
        ))
        .is_err());
    }
}

#[tokio::test]
async fn direct_authorizer_rejects_invalid_endpoint() {
    let creds = credentials(
        "http://localhost:80@example.com".into(),
        AuthMethod::Basic {
            username: "dummy".into(),
            password: "dummy-password".into(),
        },
    );
    let auth = Authorizer::new_with_store(&creds, HttpClient::new().unwrap(), None);
    assert!(auth.auth_header().await.is_err());
}

#[tokio::test]
async fn bearer_and_session_requests_do_not_follow_redirects() {
    for status in [301, 302, 303, 307, 308] {
        for method in [
            AuthMethod::BearerToken("dummy-bearer".into()),
            AuthMethod::SessionKey("dummy-session".into()),
        ] {
            let mut source = mockito::Server::new_async().await;
            let mut destination = mockito::Server::new_async().await;
            let receiver = destination
                .mock("GET", "/destination")
                .expect(0)
                .create_async()
                .await;
            let redirect = source
                .mock("GET", "/services/test?output_mode=json")
                .with_status(status)
                .with_header("location", &format!("{}/destination", destination.url()))
                .create_async()
                .await;
            let client = SplunkClient::new(credentials(source.url(), method)).unwrap();
            assert!(client.get("/services/test", &[]).await.is_err());
            redirect.assert_async().await;
            receiver.assert_async().await;
        }
    }
}

#[tokio::test]
async fn basic_login_does_not_redirect_password_or_echo_error_body() {
    for status in [302, 307, 308, 401, 500] {
        let mut source = mockito::Server::new_async().await;
        let mut destination = mockito::Server::new_async().await;
        let receiver = destination
            .mock("POST", "/destination")
            .expect(0)
            .create_async()
            .await;
        let redirect = source
            .mock("POST", "/services/auth/login?output_mode=json")
            .match_body("username=dummy&password=dummy-password")
            .with_status(status)
            .with_header("location", &format!("{}/destination", destination.url()))
            .with_body("dummy-password dummy-session")
            .create_async()
            .await;
        let creds = credentials(
            source.url(),
            AuthMethod::Basic {
                username: "dummy".into(),
                password: "dummy-password".into(),
            },
        );
        let auth = Authorizer::new_with_store(&creds, HttpClient::new().unwrap(), None);
        let error = auth.auth_header().await.unwrap_err();
        assert!(!format!("{error:?} {error}").contains("dummy-password"));
        assert!(!format!("{error:?} {error}").contains("dummy-session"));
        redirect.assert_async().await;
        receiver.assert_async().await;
    }
}

#[tokio::test]
async fn post_secret_body_is_not_replayed_even_to_same_origin() {
    for status in [307, 308] {
        let mut server = mockito::Server::new_async().await;
        let receiver = server
            .mock("POST", "/destination")
            .expect(0)
            .create_async()
            .await;
        let redirect = server
            .mock("POST", "/source")
            .with_status(status)
            .with_header("location", "/destination")
            .create_async()
            .await;
        let response = HttpClient::new()
            .unwrap()
            .post(&format!("{}/source", server.url()))
            .form(&[("refresh_token", "dummy-refresh")])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status as u16);
        redirect.assert_async().await;
        receiver.assert_async().await;
    }
}

#[tokio::test]
async fn loopback_basic_login_still_succeeds_and_is_cached() {
    let mut server = mockito::Server::new_async().await;
    let login = server
        .mock("POST", "/services/auth/login?output_mode=json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"sessionKey":"dummy-session"}"#)
        .expect(1)
        .create_async()
        .await;
    let creds = credentials(
        format!("{}/", server.url()),
        AuthMethod::Basic {
            username: "dummy".into(),
            password: "dummy-password".into(),
        },
    );
    let auth = Authorizer::new_with_store(&creds, HttpClient::new().unwrap(), None);
    for _ in 0..2 {
        assert_eq!(
            auth.auth_header().await.unwrap()["authorization"],
            "Splunk dummy-session"
        );
    }
    login.assert_async().await;
}

#[tokio::test]
async fn request_path_cannot_change_authority_before_basic_login() {
    let mut server = mockito::Server::new_async().await;
    let login = server
        .mock("POST", "/services/auth/login?output_mode=json")
        .expect(0)
        .create_async()
        .await;
    let client = SplunkClient::new_with_debug(
        credentials(
            server.url(),
            AuthMethod::Basic {
                username: "dummy".into(),
                password: "dummy-password".into(),
            },
        ),
        true,
    )
    .unwrap();
    for path in ["@other.example.com/SECRET", ".suffix.example.com/SECRET"] {
        let error = client.get(path, &[]).await.unwrap_err();
        assert!(error.to_string().contains("request path must stay"));
        assert!(!format!("{error:?} {error}").contains("SECRET"));
    }
    login.assert_async().await;

    // Also cover a valid URL whose host was extended rather than invalid syntax
    // after the ephemeral port in the local server address.
    let client = SplunkClient::new(credentials(
        "https://service.example.com".into(),
        AuthMethod::BearerToken("dummy".into()),
    ))
    .unwrap();
    assert!(client
        .get(".suffix.example.com/SECRET", &[])
        .await
        .unwrap_err()
        .to_string()
        .contains("request path must stay"));
}

#[tokio::test]
async fn same_origin_path_and_query_remain_supported() {
    let mut server = mockito::Server::new_async().await;
    let request = server
        .mock(
            "GET",
            "/services/test?existing=yes&extra=value&output_mode=json",
        )
        .match_header("authorization", "Bearer dummy")
        .with_status(200)
        .with_body(r#"{"ok":true}"#)
        .create_async()
        .await;
    let client = SplunkClient::new(credentials(
        server.url(),
        AuthMethod::BearerToken("dummy".into()),
    ))
    .unwrap();
    assert_eq!(
        client
            .get("/services/test?existing=yes", &[("extra", "value")])
            .await
            .unwrap()["ok"],
        true
    );
    request.assert_async().await;
}
