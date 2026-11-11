use super::*;

async fn start(f: &Fixture, account: Option<&str>) -> (SignIn, RemoteSignIn, url::Url) {
    let pending = f.auth.sign_in(account).await.unwrap();
    let remote = pending.remote();
    let query: BTreeMap<String, String> = remote
        .url()
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    f.peer.wire.lock().unwrap().queries.push(query.clone());
    let mut callback = url::Url::parse(&query["redirect_uri"]).unwrap();
    callback.query_pairs_mut().extend_pairs([
        ("state", query["state"].as_str()),
        ("code", "code"),
        ("client_id", "issued-client"),
    ]);
    (pending, remote, callback)
}

#[tokio::test]
async fn a_remote_browser_completes_sign_in_without_reaching_the_loopback_listener() {
    let f = Fixture::new().await;
    let (pending, remote, callback) = start(&f, None).await;
    assert!(remote.url().as_str().starts_with(&f.peer.issuer));
    assert!(!format!("{remote:?}").contains("http"));
    remote.submit_callback(callback.as_str()).unwrap();
    assert_eq!(
        remote.submit_callback(callback.as_str()),
        Err(Error::Cancelled)
    );
    let account = pending.wait().await.unwrap();
    assert!(account.connected && account.plan_usage);
    let reopened = ChatGpt::new(f._directory.path().join("auth"), "Example App").unwrap();
    assert_eq!(reopened.accounts().unwrap(), [account]);
    // The fake token endpoint verifies the original PKCE, nonce and redirect URI.
    assert_eq!(f.peer.wire.lock().unwrap().forms.len(), 1);
}

#[tokio::test]
async fn invalid_remote_callbacks_leave_the_attempt_open_without_exchanging_a_code() {
    let f = Fixture::new().await;
    let (pending, remote, callback) = start(&f, None).await;
    let valid = callback.as_str();
    let invalid = [
        "code".to_owned(),
        valid.replace("state=", "wrong_state="),
        valid.replace("127.0.0.1", "localhost"),
        valid.replace("http:", "https:"),
        valid.replace("/auth/callback", "/callback"),
        valid.replace("code=code", "code="),
        valid.replace("127.0.0.1", "user@127.0.0.1"),
        format!("{valid}#fragment"),
        format!("{valid}&state=duplicate"),
        format!("{valid}&code=duplicate"),
        format!("{valid}&error=access_denied"),
        format!("{valid}&extra={}", "x".repeat(16_384)),
        valid.replace("/auth/", "/auth/\n"),
    ];
    for value in invalid {
        assert_eq!(remote.submit_callback(&value), Err(Error::InvalidCallback));
        assert!(f.peer.wire.lock().unwrap().forms.is_empty());
    }
    remote.submit_callback(valid).unwrap();
    assert!(pending.wait().await.is_ok());
}

#[tokio::test]
async fn remote_reauthorization_omits_identity_hints_and_keeps_the_registration() {
    let f = Fixture::new().await;
    let first = f.login().await;
    let (pending, remote, callback) = start(&f, Some(&first.id)).await;
    let query: BTreeMap<_, _> = remote.url().query_pairs().collect();
    assert_eq!(query["client_id"], "issued-client");
    assert!(!query.contains_key("id_token_hint") && !query.contains_key("login_hint"));
    remote.submit_callback(callback.as_str()).unwrap();
    assert_eq!(pending.wait().await.unwrap().id, first.id);
    assert_eq!(f.auth.accounts().unwrap().len(), 1);
}

#[tokio::test]
async fn remote_reauthorization_cannot_replace_the_selected_account_or_client() {
    for changed_client in [false, true] {
        let f = Fixture::new().await;
        let first = f.login().await;
        let (pending, remote, callback) = start(&f, Some(&first.id)).await;
        let callback = if changed_client {
            callback.as_str().replace("issued-client", "another-client")
        } else {
            f.set_subject("another-subject");
            callback.to_string()
        };
        remote.submit_callback(&callback).unwrap();
        assert_eq!(pending.wait().await.unwrap_err(), Error::Identity);
        assert_eq!(f.auth.accounts().unwrap(), [first]);
    }
}

#[tokio::test]
async fn a_remote_denial_ends_the_attempt_without_exchanging_a_code() {
    let f = Fixture::new().await;
    let (pending, remote, callback) = start(&f, None).await;
    let denied = callback
        .as_str()
        .replace("code=code", "error=access_denied");
    remote.submit_callback(&denied).unwrap();
    assert_eq!(pending.wait().await.unwrap_err(), Error::Denied);
    assert!(f.peer.wire.lock().unwrap().forms.is_empty());
    assert!(f.auth.accounts().unwrap().is_empty());
}

#[tokio::test]
async fn dropping_sign_in_invalidates_every_remote_handle() {
    let f = Fixture::new().await;
    let (pending, remote, callback) = start(&f, None).await;
    let clone = remote.clone();
    drop(pending);
    for remote in [remote, clone] {
        assert_eq!(
            remote.submit_callback(callback.as_str()),
            Err(Error::Cancelled)
        );
    }
    assert!(f.peer.wire.lock().unwrap().forms.is_empty());
}

#[tokio::test]
async fn remote_callbacks_still_require_a_signed_identity_with_the_original_nonce() {
    for bad_signature in [false, true] {
        let f = Fixture::new().await;
        let (pending, remote, callback) = start(&f, None).await;
        {
            let mut wire = f.peer.wire.lock().unwrap();
            if bad_signature {
                wire.bad_signature = true;
            } else {
                wire.claims.insert("nonce".into(), json!("another-attempt"));
            }
        }
        remote.submit_callback(callback.as_str()).unwrap();
        assert_eq!(pending.wait().await.unwrap_err(), Error::Identity);
        assert!(f.auth.accounts().unwrap().is_empty());
    }
}
