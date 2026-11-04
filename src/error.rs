//! Errors never include URLs, tokens or remote response bodies.

/// A safe, actionable authentication failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Local configuration is invalid.
    #[error("Invalid authentication configuration")]
    Configuration,
    /// Private storage could not be read or written safely.
    #[error(
        "Cannot use the authentication directory: it must be accessible only by its owner (mode 0700), with intact files"
    )]
    Storage,
    /// Another process kept the credential lock too long.
    #[error("Authentication storage is busy; try again")]
    Busy,
    /// An HTTP operation failed, without disclosing its URL or body.
    #[error("Cannot reach the authentication service; check your connection")]
    Network,
    /// The remote service refused an operation.
    #[error("Authentication service returned HTTP {0}")]
    Http(u16),
    /// A bounded response did not match the expected protocol.
    #[error("Invalid response from the authentication service")]
    Protocol,
    /// The ID token failed cryptographic or identity validation.
    #[error("The account identity could not be verified; sign in again")]
    Identity,
    /// The browser did not finish in time.
    #[error("Sign-in timed out; start a new attempt")]
    Timeout,
    /// Authorization was declined in the browser.
    #[error("Sign-in was declined in the browser")]
    Denied,
    /// A pending operation was cancelled or superseded.
    #[error("Sign-in was cancelled or superseded")]
    Cancelled,
    /// No connected credential exists or its refresh grant expired.
    #[error("This account needs to sign in again")]
    SignInRequired,
    /// The directory holds the maximum number of accounts. Signing out keeps an
    /// account; [`ChatGpt::remove_account`](crate::ChatGpt::remove_account) frees its place.
    #[error("Too many saved accounts; remove one and try again")]
    AccountLimit,
    /// Identity was granted but plan usage was not.
    #[error("ChatGPT plan usage is not enabled for this account; sign in to authorize it")]
    PlanUsageRequired,
}
