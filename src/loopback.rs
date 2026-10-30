//! A bounded loopback-only redirect listener. The terminal sees only the local
//! start URL, never authorization parameters or retained identity tokens.
use std::collections::BTreeMap;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{Error, http::text};

pub(crate) struct Callback {
    pub code: String,
    pub client_id: Option<String>,
}

pub(crate) async fn receive(
    listener: TcpListener,
    start: &url::Url,
    authorization: &url::Url,
    state: &str,
) -> Result<Callback, Error> {
    let authority = start
        .as_str()
        .split('/')
        .nth(2)
        .ok_or(Error::Configuration)?;
    loop {
        let (mut stream, peer) = listener.accept().await.map_err(|_| Error::Network)?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let request =
            tokio::time::timeout(std::time::Duration::from_secs(3), request(&mut stream)).await;
        let Ok(Ok(request)) = request else {
            continue;
        };
        let mut lines = request.split("\r\n");
        let Some(first) = lines.next() else {
            continue;
        };
        let parts: Vec<_> = first.split_whitespace().collect();
        let hosts: Vec<_> = lines
            .filter_map(|line| line.split_once(':'))
            .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.trim())
            .collect();
        if parts.len() != 3
            || parts[0] != "GET"
            || !parts[1].starts_with('/')
            || hosts != [authority]
        {
            respond(&mut stream, "400 Bad Request", "Invalid request.", None).await;
            continue;
        }
        let Ok(url) = start.join(parts[1]) else {
            continue;
        };
        if url.origin() != start.origin() {
            continue;
        }
        if url.path() == start.path() && url.query().is_none() {
            respond(
                &mut stream,
                "302 Found",
                "Continue in your browser.",
                Some(authorization.as_str()),
            )
            .await;
            continue;
        }
        if url.path() != "/auth/callback" {
            respond(&mut stream, "404 Not Found", "Not found.", None).await;
            continue;
        }
        let mut values = BTreeMap::new();
        let duplicate = url
            .query_pairs()
            .any(|(k, v)| values.insert(k.into_owned(), v.into_owned()).is_some());
        if duplicate || values.get("state").map(String::as_str) != Some(state) {
            respond(
                &mut stream,
                "400 Bad Request",
                "Invalid sign-in state. Return to the application.",
                None,
            )
            .await;
            continue;
        }
        let result = if let Some(error) = values.get("error") {
            Err(if error == "access_denied" {
                Error::Denied
            } else {
                Error::Protocol
            })
        } else {
            values
                .remove("code")
                .filter(|c| text(c, 8192))
                .ok_or(Error::Protocol)
                .map(|code| Callback {
                    code,
                    client_id: values.remove("client_id"),
                })
        };
        respond(
            &mut stream,
            "200 OK",
            "You can return to the application. Account verification continues there.",
            None,
        )
        .await;
        return result;
    }
}

async fn request(stream: &mut TcpStream) -> Result<String, Error> {
    let mut buffer = Vec::new();
    let mut chunk = [0; 1024];
    while buffer.len() <= 16_384 {
        let read = stream.read(&mut chunk).await.map_err(|_| Error::Network)?;
        if read == 0 {
            return Err(Error::Protocol);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            return String::from_utf8(buffer).map_err(|_| Error::Protocol);
        }
    }
    Err(Error::Protocol)
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str, location: Option<&str>) {
    let location = location
        .map(|url| format!("Location: {url}\r\n"))
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\nConnection: close\r\n{location}\r\n{body}",
        body.len()
    );
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        stream.write_all(response.as_bytes()),
    )
    .await;
}
