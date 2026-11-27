//! What Application Default Credentials are read from: the variables of the
//! process and its files, as google-auth reads them (`_default`,
//! `_cloud_sdk`). A replay or a test gives its own.

use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A variable of the environment.
#[doc(hidden)]
pub type Variable = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The contents of a file, if it holds text.
#[doc(hidden)]
pub type File = Arc<dyn Fn(&Path) -> Option<String> + Send + Sync>;

/// The variables and the files Application Default Credentials are read
/// from, and whether the system is Windows, whose gcloud keeps its files
/// elsewhere.
#[derive(Clone)]
#[doc(hidden)]
pub struct Environment {
    /// A variable of the environment, unset or empty alike.
    pub variable: Variable,
    /// A file's contents.
    pub file: File,
    /// Whether the system is Windows.
    pub windows: bool,
}

impl Environment {
    /// The process's own: its variables, its files, its system.
    #[must_use]
    pub fn of_the_process() -> Self {
        Self {
            variable: Arc::new(|name| std::env::var(name).ok()),
            file: Arc::new(|path| std::fs::read_to_string(path).ok()),
            windows: cfg!(windows),
        }
    }

    /// The variable `name`, when it is set and not empty.
    pub(super) fn set(&self, name: &str) -> Option<String> {
        (self.variable)(name).filter(|value| !value.is_empty())
    }

    /// The file gcloud writes its Application Default Credentials in
    /// (`get_application_default_credentials_path`): in `CLOUDSDK_CONFIG`,
    /// else in gcloud's directory of the user's.
    pub(super) fn gcloud_file(&self) -> Option<PathBuf> {
        let directory = if let Some(directory) = self.set("CLOUDSDK_CONFIG") {
            PathBuf::from(directory)
        } else if self.windows {
            match self.set("APPDATA") {
                Some(root) => Path::new(&root).join("gcloud"),
                None => {
                    let drive = self.set("SystemDrive").unwrap_or_else(|| "C:".to_owned());
                    Path::new(&format!("{drive}\\")).join("gcloud")
                }
            }
        } else {
            Path::new(&self.set("HOME")?).join(".config").join("gcloud")
        };
        Some(directory.join("application_default_credentials.json"))
    }
}

impl std::fmt::Debug for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Environment")
            .field("windows", &self.windows)
            .finish_non_exhaustive()
    }
}
