# Changelog

## Unreleased

- Update reqwest to 0.13, sha2 to 0.11 and base64 to 0.23, the versions
  roomkit-rs and roomkit-tools use. HTTPS keeps rustls with the ring provider
  and the webpki roots, now given to reqwest as a configuration, offers
  HTTP/1.1 by ALPN and asks for uncompressed answers, even in a host that
  enables reqwest's gzip.

- Initial Sign in with ChatGPT support for local applications.
