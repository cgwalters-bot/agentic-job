//! Loopback GraphQL API shared by the GitLab poller and session tests.
//! Like an egress proxy that lets reads alone through, it refuses any
//! request but a GET.

#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio_rustls::rustls::{ServerConfig, ServerConnection, StreamOwned};

pub struct Stub {
    pub api: String,
    pub requests: Arc<Mutex<Vec<Request>>>,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub head: String,
    pub query: String,
    pub variables: Value,
    pub offset: u32,
    pub last: u32,
}

#[derive(Clone)]
#[allow(dead_code)] // Some answers are only used by the poller tests.
pub enum Answer {
    Page(Vec<Value>, bool),
    Issue {
        visibility: &'static str,
        confidential: bool,
        notes: Vec<Value>,
    },
    Http(u16, Vec<(&'static str, String)>),
}

impl Answer {
    fn response(self, request: &Request) -> (u16, Vec<(&'static str, String)>, String) {
        let (visibility, confidential, nodes, more) = match self {
            Self::Page(nodes, more) => ("public", false, nodes, more),
            Self::Issue {
                visibility,
                confidential,
                notes,
            } => (visibility, confidential, notes, false),
            Self::Http(status, headers) => return (status, headers, String::new()),
        };
        let mut notes = json!({"pageInfo": {
            "startCursor": (request.offset + request.last).to_string(),
            "hasPreviousPage": more,
        }});
        if request.variables["body"] == true {
            notes["nodes"] = json!(nodes);
        }
        let body = json!({"data": {"project": {"visibility": visibility,
            "issue": {"confidential": confidential, "notes": notes}}}});
        (200, vec![], body.to_string())
    }
}

/// TEXT, a query string's value, decoded.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

/// Serves ANSWER over plain HTTP.
#[allow(dead_code)] // The session tests speak TLS alone.
pub fn serve(answer: impl FnMut(&Request) -> Answer + Send + 'static) -> Stub {
    serve_on(None, answer)
}

/// Serves ANSWER over TLS with CONFIG's certificate.
#[allow(dead_code)] // Only the session tests speak TLS.
pub fn serve_tls(
    config: Arc<ServerConfig>,
    answer: impl FnMut(&Request) -> Answer + Send + 'static,
) -> Stub {
    serve_on(Some(config), answer)
}

fn serve_on(
    tls: Option<Arc<ServerConfig>>,
    mut answer: impl FnMut(&Request) -> Answer + Send + 'static,
) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let scheme = if tls.is_some() { "https" } else { "http" };
    let api = format!("{scheme}://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            match &tls {
                Some(config) => {
                    let connection = ServerConnection::new(config.clone()).unwrap();
                    let mut stream = StreamOwned::new(connection, stream);
                    exchange(&mut stream, &recorded, &mut answer);
                    stream.conn.send_close_notify();
                    let _ = stream.flush();
                }
                None => exchange(&mut &stream, &recorded, &mut answer),
            }
        }
    });
    Stub { api, requests }
}

/// Reads one request from STREAM and answers it.
fn exchange(
    stream: &mut (impl Read + Write),
    recorded: &Mutex<Vec<Request>>,
    answer: &mut impl FnMut(&Request) -> Answer,
) {
    let mut reader = BufReader::new(&mut *stream);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        head.push_str(&line);
    }
    drop(reader);
    let (status, headers, body) = match head
        .strip_prefix("GET ")
        .and_then(|rest| rest.split_once(' '))
        .and_then(|(target, _)| target.split_once('?'))
    {
        Some((_, query)) => {
            let mut params = query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .map(|(k, v)| (k.to_owned(), decode(v)))
                .collect::<std::collections::HashMap<_, _>>();
            let variables: Value =
                serde_json::from_str(&params.remove("variables").unwrap()).unwrap();
            let request = Request {
                head,
                query: params.remove("query").unwrap(),
                last: variables["last"].as_u64().unwrap().try_into().unwrap(),
                offset: variables["before"]
                    .as_str()
                    .map_or(0, |cursor| cursor.parse().unwrap()),
                variables,
            };
            recorded.lock().unwrap().push(request.clone());
            answer(&request).response(&request)
        }
        None => (403, vec![], String::new()),
    };
    let mut out = format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let _ = stream
        .write_all(out.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .and_then(|()| stream.flush());
}
