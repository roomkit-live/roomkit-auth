# Security policy

## Supported versions

RoomKit Auth is in early development. Security fixes land on the `main` branch
and in the next release; there are no maintained release branches yet.

## Reporting a vulnerability

Please do not report security issues in public issues, discussions or pull
requests. Report them privately through GitHub's
[private vulnerability reporting](https://github.com/roomkit-live/roomkit-auth/security/advisories/new).

Include what you can of the following, and never a real token, code or account:

- the affected version or commit;
- a description of the issue and its impact;
- the steps, or a minimal program, that reproduce it.

We will acknowledge the report, keep you informed while we work on a fix, and
credit you in the advisory unless you prefer otherwise.

## Scope

The authentication service's responses and anything reaching the loopback
listener are treated as untrusted. Reports of particular interest include:

- a token, authorization code or PKCE verifier appearing in an error, a log, the
  URL handed to the host, or any file other than the private store;
- a credential sent to a host other than the issuer or `CHATGPT_API_ROOT`;
- an account accepted without a verified ID token, or one account's credentials
  replaced by another's;
- the loopback listener completing a sign-in from a forged callback;
- credentials readable by another user, through permissions or symlinks;
- a credential lost or reused because of concurrent refreshes, across processes
  or after a cancelled operation.

Some limits are known and are not vulnerabilities by themselves. Credentials are
stored unencrypted, so any process running as the same user can read them. Any
local process can delay a sign-in by holding connections open on the listener.
The URL from `SignIn::url` can be replayed while its attempt is pending and
reveals the attempt's state and ID token hint, so a local process that reads it,
for example from a browser's command line, can tamper with that attempt.
Protecting the machine and the state directory is the host application's
responsibility.
