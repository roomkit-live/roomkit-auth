#![expect(clippy::unwrap_used, reason = "failed fixtures fail the test")]
use crate::*;
use axum::{
    Form, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header::ACCEPT_ENCODING},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

const SCOPE: &str = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
#[derive(Default)]
struct Wire {
    queries: Vec<BTreeMap<String, String>>,
    forms: Vec<BTreeMap<String, String>>,
    claims: BTreeMap<String, Value>,
    scope: Option<String>,
    refresh_error: bool,
    bad_signature: bool,
    revocation_error: bool,
    compressed: bool,
}
#[derive(Clone)]
struct Peer {
    issuer: String,
    wire: Arc<Mutex<Wire>>,
    refreshes: Arc<AtomicUsize>,
}
struct Fixture {
    _directory: tempfile::TempDir,
    server: tokio::task::JoinHandle<()>,
    auth: ChatGpt,
    peer: Peer,
    browser: reqwest::Client,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let peer = Peer {
            issuer: issuer.clone(),
            wire: Arc::default(),
            refreshes: Arc::default(),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route(
                "/jwks",
                get(|| async {
                    Json(
                        serde_json::from_str::<Value>(include_str!("../tests/fixtures/jwks.json"))
                            .unwrap(),
                    )
                }),
            )
            .route("/api/accounts/oauth/token", post(token))
            .route("/revoke", post(revoke))
            .route(
                "/v1/models",
                get(|| async {
                    Json(json!({"models":[
                        {"slug":"preferred","display_name":"Preferred model","visibility":"list"},
                        {"slug":"hidden","visibility":"hide"},
                        {"slug":"second","display_name":"Second model","visibility":"list"}
                    ]}))
                }),
            )
            .with_state(peer.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut auth = ChatGpt::new(directory.path().join("auth"), "Example App").unwrap();
        let inner = Arc::get_mut(&mut auth.inner).unwrap();
        inner.http.issuer = issuer.clone();
        inner.http.resource = format!("{issuer}/v1");
        Self {
            _directory: directory,
            server,
            auth,
            peer,
            browser: reqwest::Client::builder()
                .tls_backend_preconfigured(crate::http::tls_config().unwrap())
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }
    async fn start(&self, account: Option<&str>) -> (SignIn, BTreeMap<String, String>) {
        let pending = self.auth.sign_in(account).await.unwrap();
        assert!(!format!("{pending:?}").contains("http"));
        let response = self
            .browser
            .get(pending.url().clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 302);
        let location = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
        let query: BTreeMap<_, _> = location
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        self.peer.wire.lock().unwrap().queries.push(query.clone());
        (pending, query)
    }
    async fn callback(
        &self,
        query: &BTreeMap<String, String>,
        parameters: &[(&str, &str)],
    ) -> reqwest::Response {
        let mut callback = url::Url::parse(&query["redirect_uri"]).unwrap();
        callback.query_pairs_mut().extend_pairs(parameters);
        self.browser.get(callback).send().await.unwrap()
    }
    async fn login(&self) -> Account {
        let (pending, query) = self.start(None).await;
        self.callback(
            &query,
            &[
                ("state", &query["state"]),
                ("code", "code"),
                ("client_id", "issued-client"),
            ],
        )
        .await;
        pending.wait().await.unwrap()
    }
    async fn expire(&self, id: &str) {
        let _lease = self.auth.inner.store.lock().await.unwrap();
        let mut data = self.auth.inner.store.read().unwrap();
        data.accounts
            .get_mut(id)
            .unwrap()
            .tokens
            .as_mut()
            .unwrap()
            .expires_at = 1;
        self.auth.inner.store.write(&data).unwrap();
    }
}
async fn discovery(State(peer): State<Peer>) -> Json<Value> {
    Json(
        json!({"issuer":peer.issuer, "authorization_endpoint":format!("{}/authorize",peer.issuer), "token_endpoint":format!("{}/token",peer.issuer), "jwks_uri":format!("{}/jwks",peer.issuer), "revocation_endpoint":format!("{}/revoke",peer.issuer)}),
    )
}
async fn token(
    State(peer): State<Peer>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    let wire = &mut *peer.wire.lock().unwrap();
    wire.forms.push(form.clone());
    wire.compressed |= headers.contains_key(ACCEPT_ENCODING);
    if form["grant_type"] == "refresh_token" {
        peer.refreshes.fetch_add(1, Ordering::SeqCst);
        if wire.refresh_error {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_grant", "error_description":"secret-echo"})),
            )
                .into_response();
        }
        assert_eq!(form["refresh_token"], "refresh-initial");
        assert!(!form.contains_key("scope"));
        let mut response = json!({"access_token":"access-rotated","refresh_token":"refresh-rotated","token_type":"Bearer","expires_in":3600});
        if let Some(scope) = &wire.scope {
            response["scope"] = scope.clone().into();
        }
        return Json(response).into_response();
    }
    let query = wire.queries.last().unwrap();
    assert_eq!(
        query["code_challenge"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(&form["code_verifier"]))
    );
    assert_eq!(form["redirect_uri"], query["redirect_uri"]);
    assert_eq!(form["resource"], format!("{}/v1", peer.issuer));
    assert_ne!(form["client_id"], "dynamic_agent_client");
    let mut claims = json!({"iss":peer.issuer, "sub":"account-one", "aud":form["client_id"], "exp": now().unwrap()+3600, "nonce":query["nonce"], "email":"person@example.test"});
    for (k, v) in &wire.claims {
        claims[k] = v.clone();
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("fixture".into());
    let mut id = jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/test-only-rsa.der")),
    )
    .unwrap();
    if wire.bad_signature {
        let dot = id.rfind('.').unwrap() + 1;
        let replacement = if &id[dot..dot + 1] == "A" { "B" } else { "A" };
        id.replace_range(dot..dot + 1, replacement);
    }
    Json(json!({"access_token":"access-initial","refresh_token":"refresh-initial","id_token":id,"token_type":"Bearer","expires_in":3600,"scope":wire.scope.as_deref().unwrap_or(SCOPE)})).into_response()
}
async fn revoke(State(peer): State<Peer>, Form(form): Form<BTreeMap<String, String>>) -> Response {
    let wire = &mut *peer.wire.lock().unwrap();
    wire.forms.push(form);
    if wire.revocation_error {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    }
    .into_response()
}

#[tokio::test]
async fn consent_is_verified_stored_privately_and_resumes_after_restart() {
    let f = Fixture::new().await;
    let (pending, query) = f.start(None).await;
    assert_eq!(query["client_id"], "dynamic_agent_client");
    assert_eq!(query["agent_name_hint"], "Example App");
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["scope"], SCOPE);
    assert!(query["ext_agent_host_id"].starts_with("urn:uuid:"));
    assert_eq!(
        f.callback(&query, &[("state", "wrong"), ("code", "code")])
            .await
            .status(),
        400
    );
    assert!(f.peer.wire.lock().unwrap().forms.is_empty());
    f.callback(
        &query,
        &[
            ("state", &query["state"]),
            ("code", "code"),
            ("client_id", "issued-client"),
        ],
    )
    .await;
    let account = pending.wait().await.unwrap();
    assert!(account.connected && account.plan_usage);
    // Uncompressed even though the test build enables reqwest's gzip.
    assert!(!f.peer.wire.lock().unwrap().compressed);
    assert_eq!(
        f.auth
            .access_token(&account.id)
            .await
            .unwrap()
            .expose_secret(),
        "access-initial"
    );
    let reopened = ChatGpt::new(f._directory.path().join("auth"), "Example App").unwrap();
    assert_eq!(reopened.accounts().unwrap(), std::slice::from_ref(&account));
    assert_eq!(
        reopened
            .access_token(&account.id)
            .await
            .unwrap()
            .expose_secret(),
        "access-initial"
    );
    assert_eq!(
        f.auth
            .models(&account.id)
            .await
            .unwrap()
            .iter()
            .map(|m| m.id.as_str())
            .collect::<Vec<_>>(),
        ["preferred", "second"]
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(f._directory.path().join("auth/accounts.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let (pending, returning) = f.start(Some(&account.id)).await;
    assert_eq!(returning["ext_agent_host_id"], query["ext_agent_host_id"]);
    assert_eq!(returning["client_id"], "issued-client");
    assert!(!returning.contains_key("agent_name_hint"));
    assert!(returning.contains_key("id_token_hint"));
    f.callback(
        &returning,
        &[("state", &returning["state"]), ("code", "code")],
    )
    .await;
    assert_eq!(pending.wait().await.unwrap().id, account.id);
}

#[tokio::test]
async fn independent_managers_serialize_refresh_and_atomically_keep_rotating_credentials() {
    let f = Fixture::new().await;
    let account = f.login().await;
    f.expire(&account.id).await;
    let mut another = ChatGpt::new(f._directory.path().join("auth"), "Example App").unwrap();
    Arc::get_mut(&mut another.inner).unwrap().http = f.auth.inner.http.clone();
    let (a, b) = tokio::join!(
        f.auth.access_token(&account.id),
        another.access_token(&account.id)
    );
    assert_eq!(a.unwrap().expose_secret(), "access-rotated");
    assert_eq!(b.unwrap().expose_secret(), "access-rotated");
    assert_eq!(f.peer.refreshes.load(Ordering::SeqCst), 1);
    let data = f.auth.inner.store.read().unwrap();
    let tokens = data.accounts[&account.id].tokens.as_ref().unwrap();
    assert_eq!(tokens.refresh.expose_secret(), "refresh-rotated");
    assert!(tokens.plan_usage());
}

#[tokio::test]
async fn identity_only_consent_never_returns_an_inference_token() {
    let f = Fixture::new().await;
    f.peer.wire.lock().unwrap().scope = Some("openid profile email".into());
    let account = f.login().await;
    assert!(!account.plan_usage);
    assert_eq!(
        f.auth.access_token(&account.id).await.unwrap_err(),
        Error::PlanUsageRequired
    );
    assert_eq!(f.peer.refreshes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_grants_disconnect_without_echoing_service_errors() {
    let f = Fixture::new().await;
    let account = f.login().await;
    f.expire(&account.id).await;
    f.peer.wire.lock().unwrap().refresh_error = true;
    let error = f.auth.access_token(&account.id).await.unwrap_err();
    assert_eq!(error, Error::SignInRequired);
    assert!(!error.to_string().contains("secret-echo"));
    assert!(!f.auth.accounts().unwrap()[0].connected);
}

#[tokio::test]
async fn logout_revokes_then_clears_and_reauthorization_keeps_the_registration() {
    let f = Fixture::new().await;
    let account = f.login().await;
    assert_eq!(
        f.auth.sign_out(&account.id).await.unwrap(),
        SignOut::Revoked
    );
    assert_eq!(
        f.auth.access_token(&account.id).await.unwrap_err(),
        Error::SignInRequired
    );
    let (pending, query) = f.start(Some(&account.id)).await;
    assert_eq!(query["client_id"], "issued-client");
    assert!(!query.contains_key("id_token_hint"));
    drop(pending);
    let form = f.peer.wire.lock().unwrap().forms.last().unwrap().clone();
    assert_eq!(form["token_type_hint"], "refresh_token");
    assert_eq!(form["token"], "refresh-initial");
}

#[tokio::test]
async fn local_logout_reports_unconfirmed_revocation() {
    let f = Fixture::new().await;
    let account = f.login().await;
    f.peer.wire.lock().unwrap().revocation_error = true;
    assert_eq!(
        f.auth.sign_out(&account.id).await.unwrap(),
        SignOut::LocalOnly
    );
    assert!(!f.auth.accounts().unwrap()[0].connected);
}

#[tokio::test]
async fn untrusted_identity_claims_never_create_an_account() {
    for (key, value) in [
        ("iss", json!("https://wrong.example")),
        ("aud", json!("wrong-client")),
        ("nonce", json!("wrong-nonce")),
        ("exp", json!(1)),
        ("azp", json!("wrong-client")),
    ] {
        let f = Fixture::new().await;
        f.peer.wire.lock().unwrap().claims.insert(key.into(), value);
        let (pending, query) = f.start(None).await;
        f.callback(
            &query,
            &[
                ("state", &query["state"]),
                ("code", "code"),
                ("client_id", "issued-client"),
            ],
        )
        .await;
        assert_eq!(pending.wait().await.unwrap_err(), Error::Identity, "{key}");
        assert!(f.auth.accounts().unwrap().is_empty());
    }
}

#[tokio::test]
async fn reauthorization_cannot_replace_another_identity_or_registration() {
    let f = Fixture::new().await;
    let account = f.login().await;
    let (pending, query) = f.start(Some(&account.id)).await;
    f.callback(
        &query,
        &[
            ("state", &query["state"]),
            ("code", "code"),
            ("client_id", "different-client"),
        ],
    )
    .await;
    assert_eq!(pending.wait().await.unwrap_err(), Error::Identity);
    f.peer
        .wire
        .lock()
        .unwrap()
        .claims
        .insert("sub".into(), json!("different-account"));
    let (pending, query) = f.start(Some(&account.id)).await;
    f.callback(&query, &[("state", &query["state"]), ("code", "code")])
        .await;
    assert_eq!(pending.wait().await.unwrap_err(), Error::Identity);
    assert_eq!(f.auth.accounts().unwrap(), [account]);
}

#[tokio::test]
async fn declining_or_cancelling_never_exchanges_a_code() {
    let f = Fixture::new().await;
    let (pending, query) = f.start(None).await;
    f.callback(
        &query,
        &[("state", &query["state"]), ("error", "access_denied")],
    )
    .await;
    assert_eq!(pending.wait().await.unwrap_err(), Error::Denied);
    let (pending, query) = f.start(None).await;
    let listener = pending.url().clone();
    drop(pending);
    tokio::task::yield_now().await;
    assert!(f.browser.get(listener).send().await.is_err());
    assert!(f.peer.wire.lock().unwrap().forms.is_empty());
    assert!(!query["state"].is_empty());
}

#[tokio::test]
async fn symlinks_and_public_credential_files_are_refused() {
    let f = Fixture::new().await;
    let _ = f.login().await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let path = f._directory.path().join("auth/accounts.json");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(f.auth.accounts().unwrap_err(), Error::Storage);
        std::fs::rename(&path, path.with_extension("old")).unwrap();
        symlink(path.with_extension("old"), &path).unwrap();
        assert_eq!(f.auth.accounts().unwrap_err(), Error::Storage);
    }
}

#[tokio::test]
async fn a_forged_signature_is_rejected_even_with_valid_claims() {
    let f = Fixture::new().await;
    f.peer.wire.lock().unwrap().bad_signature = true;
    let (pending, query) = f.start(None).await;
    f.callback(
        &query,
        &[
            ("state", &query["state"]),
            ("code", "code"),
            ("client_id", "issued-client"),
        ],
    )
    .await;
    assert_eq!(pending.wait().await.unwrap_err(), Error::Identity);
    assert!(f.auth.accounts().unwrap().is_empty());
}
#[tokio::test]
async fn accounts_keep_independent_registrations_and_logout_is_local_to_one() {
    let f = Fixture::new().await;
    let first = f.login().await;
    f.peer
        .wire
        .lock()
        .unwrap()
        .claims
        .insert("sub".into(), json!("account-two"));
    let (pending, query) = f.start(None).await;
    f.callback(
        &query,
        &[
            ("state", &query["state"]),
            ("code", "code"),
            ("client_id", "second-client"),
        ],
    )
    .await;
    let second = pending.wait().await.unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(f.auth.accounts().unwrap().len(), 2);
    f.auth.sign_out(&first.id).await.unwrap();
    assert_eq!(
        f.auth.access_token(&first.id).await.unwrap_err(),
        Error::SignInRequired
    );
    assert_eq!(
        f.auth
            .access_token(&second.id)
            .await
            .unwrap()
            .expose_secret(),
        "access-initial"
    );
}
#[tokio::test]
async fn a_refresh_scope_downgrade_is_persisted_without_returning_access() {
    let f = Fixture::new().await;
    let account = f.login().await;
    f.expire(&account.id).await;
    f.peer.wire.lock().unwrap().scope = Some("openid email".into());
    assert_eq!(
        f.auth.access_token(&account.id).await.unwrap_err(),
        Error::PlanUsageRequired
    );
    assert!(!f.auth.accounts().unwrap()[0].plan_usage);
    assert_eq!(
        f.auth.inner.store.read().unwrap().accounts[&account.id]
            .tokens
            .as_ref()
            .unwrap()
            .refresh
            .expose_secret(),
        "refresh-rotated"
    );
}
