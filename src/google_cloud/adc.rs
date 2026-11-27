//! Application Default Credentials, found as google-auth finds them
//! (`google.auth.default`): the file `GOOGLE_APPLICATION_CREDENTIALS` names,
//! else gcloud's file, else the machine's metadata server.
//!
//! A file is read when the identity is built, by its `type`: a service
//! account's key, a user's credentials (`authorized_user`), or a service
//! account borrowed with either (`impersonated_service_account`). The other
//! types google-auth takes (`external_account`,
//! `external_account_authorized_user`, `gdch_service_account`) are not
//! taken yet. A file that cannot be read fails the first token asked, as
//! google-auth fails then; the metadata server is asked then too.

use std::path::Path;

use serde_json::Value;

use super::Identity;
use super::borrowed::Borrowing;
use super::environment::Environment;
use super::key::Key;
use super::metadata::Machine;
use super::user::User;
use crate::Error;

/// The identity `environment` holds.
pub(super) fn found(environment: &Environment) -> Identity {
    let gcloud = environment.gcloud_file();
    let named = environment.set("GOOGLE_APPLICATION_CREDENTIALS");
    if let Some(named) = named {
        // The file gcloud writes, named as it is, is read as gcloud's.
        if gcloud.as_deref() != Some(Path::new(&named)) {
            return read(environment, Path::new(&named)).unwrap_or_else(Identity::Unresolved);
        }
    }
    if let Some(contents) = gcloud.and_then(|gcloud| (environment.file)(&gcloud)) {
        return of_contents(&contents).unwrap_or_else(Identity::Unresolved);
    }
    Identity::Machine(Machine::of(environment))
}

/// The identity of the file at `path`.
fn read(environment: &Environment, path: &Path) -> Result<Identity, Error> {
    let contents = (environment.file)(path).ok_or(Error::Configuration)?;
    of_contents(&contents)
}

/// The identity a file's `contents` hold, by their type.
fn of_contents(contents: &str) -> Result<Identity, Error> {
    let written: Value = serde_json::from_str(contents).map_err(|_| Error::Configuration)?;
    of_value(&written, contents)
}

fn of_value(written: &Value, contents: &str) -> Result<Identity, Error> {
    match written.get("type").and_then(Value::as_str) {
        Some("service_account") => Ok(Identity::Key(Box::new(Key::read(contents)?))),
        Some("authorized_user") => Ok(Identity::User(User::read(written)?)),
        Some("impersonated_service_account") => {
            let source = written
                .get("source_credentials")
                .ok_or(Error::Configuration)?;
            let source = match source.get("type").and_then(Value::as_str) {
                Some("service_account" | "authorized_user") => {
                    of_value(source, &source.to_string())?
                }
                Some(_) => return Err(Error::Unsupported),
                None => return Err(Error::Configuration),
            };
            let quota_project = written
                .get("quota_project_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            Ok(Identity::Borrowed {
                source: Box::new(source),
                borrowing: Borrowing::read(written)?,
                quota_project,
            })
        }
        Some("external_account" | "external_account_authorized_user" | "gdch_service_account") => {
            Err(Error::Unsupported)
        }
        Some(_) | None => Err(Error::Configuration),
    }
}
