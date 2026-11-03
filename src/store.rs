use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::{Account, Error, Secret, secret::plain};

/// Accounts one directory can hold.
pub(crate) const MAX_ACCOUNTS: usize = 64;

#[derive(Clone, Debug)]
pub(crate) struct Store(PathBuf);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Data {
    version: u32,
    pub host: String,
    pub accounts: BTreeMap<String, Record>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub id: String,
    pub client_id: String,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub revision: String,
    pub tokens: Option<Tokens>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Tokens {
    #[serde(with = "plain")]
    pub access: Secret,
    #[serde(with = "plain")]
    pub refresh: Secret,
    #[serde(with = "plain")]
    pub id: Secret,
    pub expires_at: u64,
    pub scopes: Vec<String>,
}

impl Data {
    /// Find the entry for a new sign-in: the one its registration already has,
    /// which keeps its local ID, or a new one if there is room. A registration
    /// is the verified subject with the issued client ID: a subject does not
    /// identify a workspace, so one login can hold several.
    pub fn place(&self, mut record: Record) -> Result<Record, Error> {
        let saved = self.accounts.values().find(|saved| {
            saved.issuer == record.issuer
                && saved.subject == record.subject
                && saved.client_id == record.client_id
        });
        match saved {
            Some(saved) => record.id = saved.id.clone(),
            None if self.accounts.len() >= MAX_ACCOUNTS => return Err(Error::AccountLimit),
            None => {}
        }
        Ok(record)
    }
}

impl Record {
    pub fn account(&self) -> Account {
        Account {
            id: self.id.clone(),
            email: self.email.clone(),
            connected: self.tokens.is_some(),
            plan_usage: self.tokens.as_ref().is_some_and(Tokens::plan_usage),
        }
    }
}

impl Tokens {
    pub fn plan_usage(&self) -> bool {
        ["resource.invoke", "chatgpt.tokens.use.direct"]
            .iter()
            .all(|required| self.scopes.iter().any(|scope| scope == required))
    }
}

/// Holding the file keeps the OS advisory lock, including across processes.
pub(crate) struct Lease {
    _file: fs::File,
}

impl Store {
    pub fn new(path: &Path) -> Result<Self, Error> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path).map_err(|_| Error::Storage)?;
        let metadata = fs::symlink_metadata(path).map_err(|_| Error::Storage)?;
        if !metadata.is_dir() || !private(&metadata) {
            return Err(Error::Storage);
        }
        Ok(Self(path.into()))
    }

    pub async fn lock(&self) -> Result<Lease, Error> {
        let path = self.0.join("accounts.lock");
        check_file(&path)?;
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|_| Error::Storage)?;
        if !private(&file.metadata().map_err(|_| Error::Storage)?) {
            return Err(Error::Storage);
        }
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match file.try_lock_exclusive() {
                    Ok(()) => return Ok(Lease { _file: file }),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(_) => return Err(Error::Storage),
                }
            }
        })
        .await
        .map_err(|_| Error::Busy)?
    }

    pub fn read(&self) -> Result<Data, Error> {
        let path = self.0.join("accounts.json");
        if !check_file(&path)? {
            return Ok(Data {
                version: 1,
                host: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                accounts: BTreeMap::new(),
            });
        }
        let file = fs::File::open(path).map_err(|_| Error::Storage)?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        file.take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Storage)?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(Error::Storage);
        }
        let data: Data = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
        if data.version != 1
            || data.accounts.len() > MAX_ACCOUNTS
            || !data.host.starts_with("urn:uuid:")
        {
            return Err(Error::Storage);
        }
        Ok(data)
    }

    /// Call only while holding the lease; readers see either complete version.
    pub fn write(&self, data: &Data) -> Result<(), Error> {
        let path = self.0.join("accounts.json");
        check_file(&path)?;
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(data).map_err(|_| Error::Storage)?);
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(Error::Storage);
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&self.0).map_err(|_| Error::Storage)?;
        temporary.write_all(&bytes).map_err(|_| Error::Storage)?;
        temporary.as_file().sync_all().map_err(|_| Error::Storage)?;
        temporary.persist(path).map_err(|_| Error::Storage)?;
        fs::File::open(&self.0)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Storage)?;
        Ok(())
    }
}

fn check_file(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file() && private(&metadata) && metadata.len() <= 2 * 1024 * 1024 =>
        {
            Ok(true)
        }
        Ok(_) => Err(Error::Storage),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(Error::Storage),
    }
}

fn private(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}
