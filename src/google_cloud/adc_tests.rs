#![expect(clippy::unwrap_used, reason = "failed fixtures fail the test")]
//! Application Default Credentials, the metadata server and a borrowed
//! account, against a local fake of every endpoint, in an environment the
//! test gives: what google-auth (2.56.3) sends, as RoomKit's Python Vertex
//! cases record it.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{Router, body::Bytes, extract::State, http::HeaderMap, http::Method, http::Uri};
use axum::{http::StatusCode, response::IntoResponse};
use serde_json::{Value, json};

use super::*;

const CLOCK: f64 = 1_767_225_600.0;

/// What the fake answers a request with: a status, headers and a body.
type Answer = (StatusCode, Vec<(String, String)>, String);

/// A request the fake got: its method, its path and query, its
/// `Authorization`, its `Metadata-Flavor`, its body.
#[derive(Clone, Debug, PartialEq)]
struct Got {
    method: String,
    target: String,
    authorization: Option<String>,
    flavor: Option<String>,
    body: String,
}

#[derive(Clone, Default)]
struct Fake {
    answers: Arc<Mutex<VecDeque<Answer>>>,
    got: Arc<Mutex<Vec<Got>>>,
}

async fn answered(
    State(fake): State<Fake>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    fake.got.lock().unwrap().push(Got {
        method: method.to_string(),
        target: uri.path_and_query().unwrap().to_string(),
        authorization: header("authorization"),
        flavor: header("metadata-flavor"),
        body: String::from_utf8_lossy(&body).into_owned(),
    });
    let next = fake.answers.lock().unwrap().pop_front();
    let (status, headers, body) =
        next.unwrap_or((StatusCode::IM_A_TEAPOT, Vec::new(), String::new()));
    let mut answer = (status, body).into_response();
    for (name, value) in headers {
        answer.headers_mut().insert(
            axum::http::HeaderName::try_from(name).unwrap(),
            value.parse().unwrap(),
        );
    }
    answer
}

fn json_answer(body: &Value) -> Answer {
    (
        StatusCode::OK,
        vec![("content-type".into(), "application/json".into())],
        body.to_string(),
    )
}

fn token(access: &str) -> Answer {
    json_answer(&json!({"access_token": access, "expires_in": 3599, "token_type": "Bearer"}))
}

/// A test's environment: its variables and its files.
fn environment(variables: &[(&str, &str)], files: &[(&str, String)]) -> Environment {
    let variables: HashMap<String, String> = variables
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    let files: HashMap<PathBuf, String> = files
        .iter()
        .map(|(path, contents)| (PathBuf::from(path), contents.clone()))
        .collect();
    Environment {
        variable: Arc::new(move |name| variables.get(name).cloned()),
        file: Arc::new(move |path: &Path| files.get(path).cloned()),
        windows: false,
    }
}

struct Run {
    identity: GoogleCloud,
    fake: Fake,
    waits: Arc<Mutex<Vec<Duration>>>,
}

async fn run(environment: &Environment, answers: Vec<Answer>, borrowing: Option<&str>) -> Run {
    let fake = Fake::default();
    fake.answers.lock().unwrap().extend(answers);
    let app = Router::new().fallback(answered).with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    let waits = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&waits);
    let pace = Pace {
        now: Arc::new(|| CLOCK),
        wait: Arc::new(move |wait| {
            kept.lock().unwrap().push(wait);
            Box::pin(std::future::ready(()))
        }),
    };
    let identity = GoogleCloud::application_default_in(environment, "fixture-client/1").unwrap();
    let identity = match borrowing {
        Some(target) => identity.borrowing(target).unwrap(),
        None => identity,
    };
    let identity = identity.replaying(&origin, pace).unwrap();
    Run {
        identity,
        fake,
        waits,
    }
}

fn user(quota_project: Option<&str>) -> String {
    let mut user = json!({
        "type": "authorized_user",
        "client_id": "client-1",
        "client_secret": "secret-1",
        "refresh_token": "refresh-1",
    });
    if let Some(quota_project) = quota_project {
        user["quota_project_id"] = quota_project.into();
    }
    user.to_string()
}

#[tokio::test]
async fn a_user_s_file_is_refreshed_as_google_auth_refreshes_it() {
    let env = environment(
        &[("GOOGLE_APPLICATION_CREDENTIALS", "/adc.json")],
        &[("/adc.json", user(Some("quota-1")))],
    );
    let run = run(&env, vec![token("t-1")], None).await;
    assert_eq!(run.identity.quota_project(), Some("quota-1"));
    assert_eq!(
        run.identity.access_token().await.unwrap().expose_secret(),
        "t-1"
    );
    let got = run.fake.got.lock().unwrap().clone();
    assert_eq!(
        (got[0].method.as_str(), got[0].target.as_str()),
        ("POST", "/token")
    );
    assert_eq!(
        got[0].body,
        "grant_type=refresh_token&client_id=client-1&client_secret=secret-1&refresh_token=refresh-1"
    );
}

#[tokio::test]
async fn gcloud_s_file_is_found_where_gcloud_writes_it() {
    for (variables, path) in [
        (
            vec![("CLOUDSDK_CONFIG", "/gcloud")],
            "/gcloud/application_default_credentials.json",
        ),
        (
            vec![("HOME", "/home/a")],
            "/home/a/.config/gcloud/application_default_credentials.json",
        ),
    ] {
        let env = environment(&variables, &[(path, user(None))]);
        let run = run(&env, vec![token("t-1")], None).await;
        assert_eq!(
            run.identity.access_token().await.unwrap().expose_secret(),
            "t-1"
        );
    }
    let mut env = environment(&[("APPDATA", "C:\\Users\\a\\AppData")], &[]);
    env.windows = true;
    let file = env.gcloud_file().unwrap();
    assert_eq!(
        file,
        Path::new("C:\\Users\\a\\AppData")
            .join("gcloud")
            .join("application_default_credentials.json")
    );
}

#[tokio::test]
async fn a_borrowed_account_is_lent_a_token_with_its_borrower_s() {
    let env = environment(
        &[("GOOGLE_APPLICATION_CREDENTIALS", "/adc.json")],
        &[("/adc.json", user(None))],
    );
    let lent = json_answer(&json!({"accessToken": "lent-1", "expireTime": "2026-01-01T01:00:00Z"}));
    let run = run(
        &env,
        vec![token("t-1"), lent],
        Some("runner@proj-1.iam.gserviceaccount.com"),
    )
    .await;
    assert_eq!(
        run.identity.access_token().await.unwrap().expose_secret(),
        "lent-1"
    );
    let got = run.fake.got.lock().unwrap().clone();
    let borrowed = &got[1];
    assert_eq!(
        borrowed.target,
        "/v1/projects/-/serviceAccounts/runner@proj-1.iam.gserviceaccount.com:generateAccessToken"
    );
    assert_eq!(borrowed.authorization.as_deref(), Some("Bearer t-1"));
    let body: Value = serde_json::from_str(&borrowed.body).unwrap();
    assert_eq!(
        body,
        json!({"delegates": null, "scope": [key::SCOPE], "lifetime": "3600s"})
    );
}

#[tokio::test]
async fn the_machine_s_account_is_asked_of_its_metadata_server() {
    let flavor = vec![("metadata-flavor".to_owned(), "Google".to_owned())];
    let answers = vec![
        (StatusCode::OK, flavor.clone(), String::new()),
        (StatusCode::OK, flavor.clone(), "proj-1".to_owned()),
        json_answer(&json!({"email": "machine@proj-1.iam.gserviceaccount.com"})),
        token("t-1"),
        token("t-2"),
    ];
    let env = environment(&[], &[]);
    let run = run(&env, answers, None).await;
    assert_eq!(
        run.identity.access_token().await.unwrap().expose_secret(),
        "t-1"
    );
    let got = run.fake.got.lock().unwrap().clone();
    let asked: Vec<&str> = got.iter().map(|got| got.target.as_str()).collect();
    assert_eq!(
        asked,
        [
            "/",
            "/computeMetadata/v1/project/project-id",
            "/computeMetadata/v1/instance/service-accounts/default/?recursive=true",
            "/computeMetadata/v1/instance/service-accounts/default/token?scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform",
        ]
    );
    assert!(
        got.iter()
            .all(|got| got.flavor.as_deref() == Some("Google"))
    );
}

#[tokio::test]
async fn a_machine_that_is_none_has_no_credentials() {
    let refused = (StatusCode::NOT_FOUND, Vec::new(), String::new());
    let env = environment(&[], &[]);
    // A ping answered, but not as Google's: the machine is none, at once.
    let run_once = run(&env, vec![refused], None).await;
    assert_eq!(
        run_once.identity.access_token().await.unwrap_err(),
        Error::NoCredentials
    );
    assert_eq!(run_once.fake.got.lock().unwrap().len(), 1);
    // NO_GCE_CHECK says the machine is none: nothing is asked.
    let env = environment(&[("NO_GCE_CHECK", "true")], &[]);
    let unchecked = run(&env, Vec::new(), None).await;
    assert_eq!(
        unchecked.identity.access_token().await.unwrap_err(),
        Error::NoCredentials
    );
    assert!(unchecked.fake.got.lock().unwrap().is_empty());
    assert!(unchecked.waits.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_file_that_cannot_be_read_fails_the_first_token() {
    let external = json!({"type": "external_account", "audience": "a"}).to_string();
    for (files, failure) in [
        (vec![], Error::Configuration),
        (
            vec![("/adc.json", "not json".to_owned())],
            Error::Configuration,
        ),
        (
            vec![("/adc.json", json!({"client_email": "a"}).to_string())],
            Error::Configuration,
        ),
        (vec![("/adc.json", external)], Error::Unsupported),
    ] {
        let env = environment(&[("GOOGLE_APPLICATION_CREDENTIALS", "/adc.json")], &files);
        let run = run(&env, Vec::new(), None).await;
        assert_eq!(run.identity.access_token().await.unwrap_err(), failure);
        assert!(run.fake.got.lock().unwrap().is_empty());
    }
}

#[test]
fn an_identity_shows_no_user_secret() {
    let env = environment(
        &[("GOOGLE_APPLICATION_CREDENTIALS", "/adc.json")],
        &[("/adc.json", user(None))],
    );
    let identity = GoogleCloud::application_default_in(&env, "fixture-client/1").unwrap();
    let shown = format!("{identity:?}");
    assert!(
        !shown.contains("secret-1") && !shown.contains("refresh-1"),
        "{shown}"
    );
}
