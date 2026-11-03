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
    jwks_down: bool,
    refresh_returns_identity: bool,
    refresh_failure: Option<Value>,
    discovery_issuer: Option<String>,
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
                get(|State(peer): State<Peer>| async move {
                    if peer.wire.lock().unwrap().jwks_down {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    Json(
                        serde_json::from_str::<Value>(include_str!("../tests/fixtures/jwks.json"))
                            .unwrap(),
                    )
                    .into_response()
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
    async fn finish(
        &self,
        pending: SignIn,
        query: &BTreeMap<String, String>,
        client: &str,
    ) -> Result<Account, Error> {
        // The token endpoint checks the latest authorization request.
        self.peer.wire.lock().unwrap().queries.push(query.clone());
        self.callback(
            query,
            &[
                ("state", &query["state"]),
                ("code", "code"),
                ("client_id", client),
            ],
        )
        .await;
        pending.wait().await
    }
    fn set_subject(&self, subject: &str) {
        self.peer
            .wire
            .lock()
            .unwrap()
            .claims
            .insert("sub".into(), json!(subject));
    }
    fn revocations(&self) -> Vec<BTreeMap<String, String>> {
        let wire = self.peer.wire.lock().unwrap();
        wire.forms
            .iter()
            .filter(|form| form.contains_key("token_type_hint"))
            .cloned()
            .collect()
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
    let issuer = peer.wire.lock().unwrap().discovery_issuer.clone();
    Json(
        json!({"issuer":issuer.as_ref().unwrap_or(&peer.issuer), "authorization_endpoint":format!("{}/authorize",peer.issuer), "token_endpoint":format!("{}/token",peer.issuer), "jwks_uri":format!("{}/jwks",peer.issuer), "revocation_endpoint":format!("{}/revoke",peer.issuer)}),
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
        if let Some(body) = &wire.refresh_failure {
            return (StatusCode::BAD_REQUEST, Json(body.clone())).into_response();
        }
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
        if wire.refresh_returns_identity {
            let mut claims = json!({"iss":peer.issuer, "sub":"account-one", "aud":form["client_id"], "exp": now().unwrap()+3600});
            for (k, v) in &wire.claims {
                claims[k] = v.clone();
            }
            response["id_token"] = signed(&claims).into();
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
    let mut id = signed(&claims);
    if wire.bad_signature {
        let dot = id.rfind('.').unwrap() + 1;
        let replacement = if &id[dot..dot + 1] == "A" { "B" } else { "A" };
        id.replace_range(dot..dot + 1, replacement);
    }
    Json(json!({"access_token":"access-initial","refresh_token":"refresh-initial","id_token":id,"token_type":"Bearer","expires_in":3600,"scope":wire.scope.as_deref().unwrap_or(SCOPE)})).into_response()
}
fn signed(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("fixture".into());
    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/test-only-rsa.der")),
    )
    .unwrap()
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
#[tokio::test]
async fn a_signing_key_outage_leaves_the_refresh_token_unspent() {
    let f = Fixture::new().await;
    let account = f.login().await;
    f.expire(&account.id).await;
    {
        let mut wire = f.peer.wire.lock().unwrap();
        wire.refresh_returns_identity = true;
        wire.jwks_down = true;
    }
    assert_eq!(
        f.auth.access_token(&account.id).await.unwrap_err(),
        Error::Http(503)
    );
    // The service rotates on use: spending the token here would lose it.
    assert_eq!(f.peer.refreshes.load(Ordering::SeqCst), 0);
    f.peer.wire.lock().unwrap().jwks_down = false;
    assert_eq!(
        f.auth
            .access_token(&account.id)
            .await
            .unwrap()
            .expose_secret(),
        "access-rotated"
    );
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
#[tokio::test]
async fn a_refresh_cannot_change_the_account_identity() {
    let f = Fixture::new().await;
    let account = f.login().await;
    f.expire(&account.id).await;
    {
        let mut wire = f.peer.wire.lock().unwrap();
        wire.refresh_returns_identity = true;
        wire.claims.insert("sub".into(), json!("account-two"));
    }
    assert_eq!(
        f.auth.access_token(&account.id).await.unwrap_err(),
        Error::Identity
    );
}
#[tokio::test]
async fn signing_in_again_with_a_saved_account_updates_its_entry() {
    let f = Fixture::new().await;
    let first = f.login().await;
    f.expire(&first.id).await;
    let second = f.login().await;
    assert_eq!(second.id, first.id);
    assert_eq!(f.auth.accounts().unwrap(), [second]);
    // The new tokens replaced the expired ones, so nothing needs refreshing,
    // and the same registration leaves no other grant to end.
    assert_eq!(
        f.auth
            .access_token(&first.id)
            .await
            .unwrap()
            .expose_secret(),
        "access-initial"
    );
    assert_eq!(f.peer.refreshes.load(Ordering::SeqCst), 0);
    assert!(f.revocations().is_empty());
}
#[tokio::test]
async fn another_registration_of_one_login_keeps_its_own_entry() {
    let f = Fixture::new().await;
    let first = f.login().await;
    let (pending, query) = f.start(None).await;
    let second = f.finish(pending, &query, "second-client").await.unwrap();
    assert_ne!(second.id, first.id);
    assert_eq!(f.auth.accounts().unwrap().len(), 2);
    let data = f.auth.inner.store.read().unwrap();
    assert_eq!(data.accounts[&first.id].client_id, "issued-client");
    assert_eq!(data.accounts[&second.id].client_id, "second-client");
    assert!(data.accounts[&first.id].tokens.is_some());
    assert!(f.revocations().is_empty());
    // Signing out of one ends its own grant and leaves the other connected.
    f.auth.sign_out(&first.id).await.unwrap();
    assert_eq!(f.revocations()[0]["client_id"], "issued-client");
    assert!(f.auth.access_token(&second.id).await.is_ok());
}
#[tokio::test]
async fn removing_an_account_revokes_it_and_forgets_its_identity() {
    let f = Fixture::new().await;
    let account = f.login().await;
    let (pending, query) = f.start(Some(&account.id)).await;
    assert_eq!(
        f.auth.remove_account(&account.id).await.unwrap(),
        SignOut::Revoked
    );
    assert_eq!(f.revocations()[0]["token"], "refresh-initial");
    assert!(f.auth.accounts().unwrap().is_empty());
    let stored = std::fs::read_to_string(f._directory.path().join("auth/accounts.json")).unwrap();
    for forgotten in [
        "person@example.test",
        "account-one",
        "issued-client",
        "refresh-initial",
    ] {
        assert!(!stored.contains(forgotten), "{forgotten}");
    }
    assert_eq!(
        f.auth.access_token(&account.id).await.unwrap_err(),
        Error::SignInRequired
    );
    assert_eq!(
        f.auth.remove_account(&account.id).await.unwrap_err(),
        Error::SignInRequired
    );
    // A sign-in already under way cannot bring the account back.
    let result = f.finish(pending, &query, "issued-client").await;
    assert_eq!(result.unwrap_err(), Error::Cancelled);
    assert!(f.auth.accounts().unwrap().is_empty());
}
#[tokio::test]
async fn removal_reports_an_unconfirmed_revocation_and_still_deletes() {
    let f = Fixture::new().await;
    let connected = f.login().await;
    f.set_subject("account-two");
    let signed_out = f.login().await;
    f.auth.sign_out(&signed_out.id).await.unwrap();
    f.peer.wire.lock().unwrap().revocation_error = true;
    assert_eq!(
        f.auth.remove_account(&connected.id).await.unwrap(),
        SignOut::LocalOnly
    );
    assert_eq!(
        f.auth.remove_account(&signed_out.id).await.unwrap(),
        SignOut::Revoked
    );
    assert!(f.auth.accounts().unwrap().is_empty());
}
#[tokio::test]
async fn the_account_limit_is_reported_and_only_removal_frees_a_place() {
    let f = Fixture::new().await;
    let mut accounts = Vec::new();
    for number in 0..63 {
        f.set_subject(&format!("account-{number}"));
        accounts.push(f.login().await);
    }
    // Under the limit when it starts, over it when it ends.
    let (late, late_query) = f.start(None).await;
    f.set_subject("account-63");
    accounts.push(f.login().await);
    f.set_subject("account-64");
    let error = f
        .finish(late, &late_query, "late-client")
        .await
        .unwrap_err();
    assert_eq!(error, Error::AccountLimit);
    assert_eq!(f.auth.accounts().unwrap().len(), 64);

    assert_eq!(f.auth.sign_in(None).await.unwrap_err(), Error::AccountLimit);
    let last = &accounts[63].id;
    f.auth.sign_out(last).await.unwrap();
    assert_eq!(f.auth.sign_in(None).await.unwrap_err(), Error::AccountLimit);
    f.auth.remove_account(last).await.unwrap();
    assert!(f.auth.sign_in(None).await.is_ok());
}
#[tokio::test]
async fn a_store_written_by_an_earlier_version_still_opens() {
    let f = Fixture::new().await;
    let path = f._directory.path().join("auth/accounts.json");
    let stored = json!({"version":1, "host":"urn:uuid:9a1c5a0e-5d1b-4e2a-8c3f-0d6f2b7e4a11", "accounts":{"local-id":{
        "id":"local-id", "client_id":"issued-client", "issuer":f.peer.issuer, "subject":"account-one",
        "email":"person@example.test", "revision":"first",
        "tokens":{"access":"stored-access", "refresh":"stored-refresh", "id":"stored-id",
            "expires_at":now().unwrap()+3600, "scopes":SCOPE.split(' ').collect::<Vec<_>>()},
    }}});
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    serde_json::to_writer(options.open(&path).unwrap(), &stored).unwrap();
    assert_eq!(f.auth.accounts().unwrap()[0].id, "local-id");
    assert_eq!(
        f.auth
            .access_token("local-id")
            .await
            .unwrap()
            .expose_secret(),
        "stored-access"
    );
    // Writing keeps that format: the file reads back with its values in clear.
    f.auth.sign_in(Some("local-id")).await.unwrap();
    let written: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(written, stored);
}
#[tokio::test]
async fn a_signing_key_outage_during_sign_in_exchanges_no_code() {
    let f = Fixture::new().await;
    let (pending, query) = f.start(None).await;
    f.peer.wire.lock().unwrap().jwks_down = true;
    let result = f.finish(pending, &query, "issued-client").await;
    assert_eq!(result.unwrap_err(), Error::Http(503));
    assert!(f.peer.wire.lock().unwrap().forms.is_empty());
    assert!(f.auth.accounts().unwrap().is_empty());
}
#[tokio::test]
async fn every_documented_unusable_refresh_token_asks_for_a_new_sign_in() {
    for code in [
        "invalid_grant",
        "invalid_refresh_token",
        "token_expired",
        "refresh_token_expired",
        "refresh_token_invalidated",
        "refresh_token_reused",
    ] {
        // OpenAI lists the codes without the JSON around them.
        for body in [
            json!({"error": code}),
            json!({"error": {"code": code, "message": "secret-echo"}}),
        ] {
            let f = Fixture::new().await;
            let account = f.login().await;
            f.expire(&account.id).await;
            f.peer.wire.lock().unwrap().refresh_failure = Some(body);
            let error = f.auth.access_token(&account.id).await.unwrap_err();
            assert_eq!(error, Error::SignInRequired, "{code}");
            assert!(!f.auth.accounts().unwrap()[0].connected, "{code}");
        }
    }
}
#[tokio::test]
async fn other_refresh_failures_keep_the_credentials() {
    for body in [
        json!({"error": "invalid_client"}),
        json!({"error": {"code": "server_error"}}),
        json!("not an object"),
    ] {
        let f = Fixture::new().await;
        let account = f.login().await;
        f.expire(&account.id).await;
        f.peer.wire.lock().unwrap().refresh_failure = Some(body.clone());
        let error = f.auth.access_token(&account.id).await.unwrap_err();
        assert_eq!(error, Error::Http(400), "{body}");
        assert!(f.auth.accounts().unwrap()[0].connected, "{body}");
    }
}
#[tokio::test]
async fn a_failed_identity_check_after_a_refresh_never_replays_the_spent_token() {
    for (claim, value) in [("sub", json!("account-two")), ("exp", json!(1))] {
        let f = Fixture::new().await;
        let account = f.login().await;
        f.expire(&account.id).await;
        {
            let mut wire = f.peer.wire.lock().unwrap();
            wire.refresh_returns_identity = true;
            wire.claims.insert(claim.into(), value);
        }
        let error = f.auth.access_token(&account.id).await.unwrap_err();
        assert_eq!(error, Error::Identity, "{claim}");
        assert!(!f.auth.accounts().unwrap()[0].connected, "{claim}");
        let error = f.auth.access_token(&account.id).await.unwrap_err();
        assert_eq!(error, Error::SignInRequired, "{claim}");
        assert_eq!(f.peer.refreshes.load(Ordering::SeqCst), 1, "{claim}");
    }
}
#[tokio::test]
async fn an_identity_error_before_the_refresh_keeps_the_unspent_token() {
    let f = Fixture::new().await;
    let account = f.login().await;
    f.expire(&account.id).await;
    f.peer.wire.lock().unwrap().discovery_issuer = Some("https://wrong.example".into());
    let error = f.auth.access_token(&account.id).await.unwrap_err();
    assert_eq!(error, Error::Identity);
    assert_eq!(f.peer.refreshes.load(Ordering::SeqCst), 0);
    assert!(f.auth.accounts().unwrap()[0].connected);
}
