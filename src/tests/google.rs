use super::*;

const CLOUD: &str = "https://www.googleapis.com/auth/cloud-platform";

async fn consent(f: &Fixture, google: &Google, id: Option<&str>) -> Result<GoogleAccount, Error> {
    let sign_in = google.sign_in(id).await?;
    let remote = sign_in.remote();
    let query: BTreeMap<String, String> = remote.url().query_pairs().into_owned().collect();
    assert_eq!(query["access_type"], "offline");
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(query["scope"].split_whitespace().any(|s| s == CLOUD));
    assert!(!query.contains_key("client_secret"));
    let mut callback = url::Url::parse(&query["redirect_uri"]).unwrap();
    callback
        .query_pairs_mut()
        .append_pair("state", &query["state"])
        .append_pair("code", "fixture");
    f.peer.wire.lock().unwrap().queries.push(query);
    remote.submit_callback(callback.as_str())?;
    sign_in.wait().await
}

#[tokio::test]
async fn google_grants_are_bound_to_the_registered_client_subject_and_scopes() {
    let f = Fixture::new().await;
    let google = Google::fixture(f._directory.path(), &f.peer.issuer).unwrap();
    assert!(matches!(
        consent(&f, &google, None).await,
        Err(Error::GoogleScopeRequired)
    ));
    f.peer.wire.lock().unwrap().scope = Some(CLOUD.into());
    let account = consent(&f, &google, None).await.unwrap();
    assert!(account.connected);
    assert_eq!(account.email.as_deref(), Some("person@example.test"));
    assert_eq!(consent(&f, &google, None).await.unwrap(), account);
    assert_eq!(google.accounts().unwrap(), vec![account.clone()]);
    assert!(f.auth.accounts().unwrap().is_empty());
    f.peer
        .wire
        .lock()
        .unwrap()
        .claims
        .insert("sub".into(), "another-user".into());
    assert!(matches!(
        consent(&f, &google, Some(&account.id)).await,
        Err(Error::Identity)
    ));
    assert_eq!(
        google
            .access_token(&account.id)
            .await
            .unwrap()
            .expose_secret(),
        "access-initial"
    );
    assert_eq!(
        google.sign_out(&account.id).await.unwrap(),
        SignOut::Revoked
    );
    assert_eq!(
        f.peer.wire.lock().unwrap().forms.last().unwrap()["token"],
        "refresh-initial"
    );
    assert!(matches!(
        google.access_token(&account.id).await,
        Err(Error::SignInRequired)
    ));
}

#[tokio::test]
async fn google_refreshes_once_and_revokes_the_rotated_grant() {
    let f = Fixture::new().await;
    let google = Google::fixture(f._directory.path(), &f.peer.issuer).unwrap();
    f.peer.wire.lock().unwrap().scope = Some(CLOUD.into());
    let id = consent(&f, &google, None).await.unwrap().id;
    let store = Store::new(&f._directory.path().join("google")).unwrap();
    let mut data = store.read().unwrap();
    data.accounts
        .get_mut(&id)
        .unwrap()
        .tokens
        .as_mut()
        .unwrap()
        .expires_at = 1;
    store.write(&data).unwrap();
    let (a, b) = tokio::join!(google.access_token(&id), google.access_token(&id));
    assert_eq!(a.unwrap().expose_secret(), "access-rotated");
    assert_eq!(b.unwrap().expose_secret(), "access-rotated");
    assert_eq!(f.peer.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(google.sign_out(&id).await.unwrap(), SignOut::Revoked);
    assert_eq!(
        f.peer.wire.lock().unwrap().forms.last().unwrap()["token"],
        "refresh-rotated"
    );
}
