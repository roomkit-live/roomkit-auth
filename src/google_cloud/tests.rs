#![expect(clippy::unwrap_used, reason = "failed fixtures fail the test")]
//! The identity of a key against a local token endpoint. The assertions
//! expected are google-auth's (2.56.3), signed with the test key of the
//! fixtures at 2026-01-01T00:00:00Z:
//! `service_account.Credentials.from_service_account_info(info,
//! scopes=[cloud-platform])._make_authorization_grant_assertion()`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

use super::*;

/// The fixtures' clock: 2026-01-01T00:00:00Z.
const CLOCK: f64 = 1_767_225_600.0;

const WITH_ITS_ID: &str = "eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAidGVzdC1vbmx5LWtleS0xIn0.eyJpYXQiOiAxNzY3MjI1NjAwLCAiZXhwIjogMTc2NzIyOTIwMCwgImlzcyI6ICJydW5uZXJAcHJvai0xLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwgImF1ZCI6ICJodHRwczovL29hdXRoMi5nb29nbGVhcGlzLmNvbS90b2tlbiIsICJzY29wZSI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9hdXRoL2Nsb3VkLXBsYXRmb3JtIn0.dh5ooVl9pn3NYpOWjwuyK-_yOjNZE2IVOE5V_MZep2T8ENZWvrl7C4SpdtREuw3mYopSOORYIFj52UcifpMEy1s2GIRewranCRQKdU8tOSK1fW8wJD4OP3iWUnjO-NvqUzg8XSdSKPWfakyD3UOX5afBuefaL9xYeEvL7A9sz1Nrzn2j0NgGK0eDtDmccAMaccoO7Dbf0kLx0wWDAY4fKY6pO16Vg6GZ8RcL12X1bE_FWdYh9hTv-BJ9oaqQl4kSAxgGq32ADhJmXss-_DORxA_uOSlfIm5VeI2DVCdkjhUccxYrd98grGFGyUGOWH1uFy1M-Gl7f510pNxLTF4F1w";
const WITHOUT_AN_ID: &str = "eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJSUzI1NiJ9.eyJpYXQiOiAxNzY3MjI1NjAwLCAiZXhwIjogMTc2NzIyOTIwMCwgImlzcyI6ICJydW5uZXJAcHJvai0xLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwgImF1ZCI6ICJodHRwczovL29hdXRoMi5nb29nbGVhcGlzLmNvbS90b2tlbiIsICJzY29wZSI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9hdXRoL2Nsb3VkLXBsYXRmb3JtIn0.HuvFSwnvy-RjDjcl-8WcvVcW6O1vV7Tf8v6WskQFZB2G48ooqMsOQsh17yDTY1DZqfYE83KKKpgel1bm74X6Z_OjdWODvOxHCjlTCM004xRVV9BdsWJOUFsS-swdevLJPp9RWMfHrU6kZPNJ3hGxgfFsGk1nyNIEcpkIxvuTUiZGiepl9a1RqojbLObb6FdPNPDrxWRTFJhFb5YUsIcWL5WYqpcHtBqCvNUh7yU_RbVnJ1miAVGS-PBmOAeCRjp-OoPZE5J_WH1oAMyFNLkNyroQeaff9dy2NcjVgi2J4gC53Rpzz1gVBm_hgLdckEgYBzdYmpohsheeoKuO8XjCjw";

/// The test key of the fixtures, PKCS#1, in PEM.
fn pem() -> String {
    let der = STANDARD.encode(include_bytes!("../../tests/fixtures/test-only-rsa.der"));
    let lines: Vec<&str> = der
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
        lines.join("\n")
    )
}

fn key_file(key_id: Option<&str>) -> String {
    let mut key = json!({
        "type": "service_account",
        "client_email": "runner@proj-1.iam.gserviceaccount.com",
        "token_uri": "https://oauth2.example/token",
        "private_key": pem(),
    });
    if let Some(key_id) = key_id {
        key["private_key_id"] = key_id.into();
    }
    key.to_string()
}

/// A token endpoint that answers each post with the next of its answers.
#[derive(Clone, Default)]
struct Endpoint {
    answers: Arc<Mutex<VecDeque<(StatusCode, String)>>>,
    posted: Arc<Mutex<Vec<(String, String)>>>,
}

async fn answered(
    State(endpoint): State<Endpoint>,
    headers: axum::http::HeaderMap,
    body: String,
) -> impl IntoResponse {
    let agent = headers
        .get("user-agent")
        .and_then(|agent| agent.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    endpoint.posted.lock().unwrap().push((agent, body));
    let next = endpoint.answers.lock().unwrap().pop_front();
    next.unwrap_or((StatusCode::IM_A_TEAPOT, String::new()))
}

struct Replayed {
    identity: GoogleCloud,
    endpoint: Endpoint,
    clock: Arc<Mutex<f64>>,
    waits: Arc<Mutex<Vec<Duration>>>,
}

async fn replayed(key: &str, answers: Vec<(StatusCode, Value)>) -> Replayed {
    let endpoint = Endpoint::default();
    endpoint.answers.lock().unwrap().extend(
        answers
            .into_iter()
            .map(|(status, body)| (status, body.to_string())),
    );
    let app = Router::new()
        .route("/token", post(answered))
        .with_state(endpoint.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    let clock = Arc::new(Mutex::new(CLOCK));
    let waits = Arc::new(Mutex::new(Vec::new()));
    let (read, kept) = (Arc::clone(&clock), Arc::clone(&waits));
    let pace = Pace {
        now: Arc::new(move || *read.lock().unwrap()),
        wait: Arc::new(move |wait| {
            kept.lock().unwrap().push(wait);
            Box::pin(std::future::ready(()))
        }),
    };
    let identity = GoogleCloud::service_account(key, "fixture-client/1").unwrap();
    let identity = identity.replaying(&origin, pace).unwrap();
    Replayed {
        identity,
        endpoint,
        clock,
        waits,
    }
}

fn granted(token: &str, expires_in: Value) -> (StatusCode, Value) {
    let mut body = json!({"access_token": token, "token_type": "Bearer"});
    if !expires_in.is_null() {
        body["expires_in"] = expires_in;
    }
    (StatusCode::OK, body)
}

fn form(body: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect()
}

#[tokio::test]
async fn a_key_s_assertion_is_google_auth_s_and_its_token_is_sent() {
    for (key_id, assertion) in [
        (Some("test-only-key-1"), WITH_ITS_ID),
        (None, WITHOUT_AN_ID),
    ] {
        let run = replayed(&key_file(key_id), vec![granted("t-1", 3599.into())]).await;
        let token = run.identity.access_token().await.unwrap();
        assert_eq!(token.expose_secret(), "t-1");
        let posted = run.endpoint.posted.lock().unwrap().clone();
        let (agent, body) = &posted[0];
        assert_eq!(agent, "fixture-client/1");
        let expected = [
            ("assertion".to_owned(), assertion.to_owned()),
            ("grant_type".to_owned(), JWT_GRANT.to_owned()),
        ];
        assert_eq!(form(body), expected);
    }
}

#[tokio::test]
async fn a_token_is_kept_until_shortly_before_it_expires() {
    let answers = vec![granted("t-1", 3599.into()), granted("t-2", "3599".into())];
    let run = replayed(&key_file(None), answers).await;
    assert_eq!(
        run.identity.access_token().await.unwrap().expose_secret(),
        "t-1"
    );
    *run.clock.lock().unwrap() = CLOCK + 3599.0 - 226.0;
    assert_eq!(
        run.identity.access_token().await.unwrap().expose_secret(),
        "t-1"
    );
    *run.clock.lock().unwrap() = CLOCK + 3599.0 - 225.0;
    assert_eq!(
        run.identity.access_token().await.unwrap().expose_secret(),
        "t-2"
    );
    assert_eq!(run.endpoint.posted.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_token_that_names_no_lifetime_is_kept() {
    let run = replayed(&key_file(None), vec![granted("t-1", Value::Null)]).await;
    run.identity.access_token().await.unwrap();
    *run.clock.lock().unwrap() = CLOCK + 1e9;
    assert_eq!(
        run.identity.access_token().await.unwrap().expose_secret(),
        "t-1"
    );
    assert_eq!(run.endpoint.posted.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_passing_refusal_is_tried_again_after_one_second_then_two() {
    let busy = (
        StatusCode::SERVICE_UNAVAILABLE,
        json!({"error": "internal_failure"}),
    );
    let run = replayed(&key_file(None), vec![busy.clone(), busy.clone(), busy]).await;
    assert_eq!(
        run.identity.access_token().await.unwrap_err(),
        Error::Http(503)
    );
    let waits = run.waits.lock().unwrap().clone();
    assert_eq!(waits.len(), 2);
    for (wait, longest) in waits.iter().zip([1.0, 2.0]) {
        let wait = wait.as_secs_f64();
        assert!(wait <= longest && wait >= longest * 0.9, "{wait}");
    }
    let named = (
        StatusCode::BAD_REQUEST,
        json!({"error": "temporarily_unavailable"}),
    );
    let run = replayed(&key_file(None), vec![named, granted("t-1", 60.into())]).await;
    assert_eq!(
        run.identity.access_token().await.unwrap().expose_secret(),
        "t-1"
    );
}

#[tokio::test]
async fn a_refusal_or_an_answer_without_a_token_fails_at_once() {
    let refused = (
        StatusCode::BAD_REQUEST,
        json!({"error": "invalid_grant", "error_description": "Invalid JWT Signature."}),
    );
    let without = (StatusCode::OK, json!({"token_type": "Bearer"}));
    for (answer, failure) in [(refused, Error::Http(400)), (without, Error::Protocol)] {
        let run = replayed(&key_file(None), vec![answer]).await;
        assert_eq!(run.identity.access_token().await.unwrap_err(), failure);
        assert_eq!(run.endpoint.posted.lock().unwrap().len(), 1);
        assert!(run.waits.lock().unwrap().is_empty());
    }
}

#[test]
fn contents_that_are_no_key_are_refused() {
    let without = |member: &str| {
        let mut key: Value = serde_json::from_str(&key_file(None)).unwrap();
        key.as_object_mut().unwrap().remove(member);
        key.to_string()
    };
    let not_pem = key_file(None).replace("-----BEGIN RSA", "-----BEGIN NOT");
    for contents in [
        "not json".to_owned(),
        "[]".to_owned(),
        without("client_email"),
        without("token_uri"),
        without("private_key"),
        not_pem,
    ] {
        let refused = GoogleCloud::service_account(&contents, "fixture-client/1");
        assert_eq!(refused.unwrap_err(), Error::Configuration, "{contents}");
    }
}

#[test]
fn an_identity_shows_no_key() {
    let identity = GoogleCloud::service_account(&key_file(None), "fixture-client/1").unwrap();
    let shown = format!("{identity:?}");
    assert!(!shown.contains("PRIVATE KEY"), "{shown}");
    assert!(shown.contains("runner@proj-1"), "{shown}");
}
