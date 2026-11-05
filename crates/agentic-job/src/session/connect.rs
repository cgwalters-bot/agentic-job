//! `session connect`: a terminal's, or another agent's, client of a
//! session run's bridge (specs/session.md). It does what the bridge
//! serves: `initialize`, `session/new`, then each line of standard input
//! as a `session/prompt`, one turn at a time, and prints what the agent
//! says. With `--json`, each message from the bridge is printed as one
//! line of JSON instead, for a program to read.
//!
//! The endpoint is `wss://`, with serve's public certificate checked
//! against Mozilla's roots; plain `ws://` only to loopback, where nothing
//! on the path can read or change the conversation.

use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use super::bridge::{MAX_MESSAGE_BYTES, MAX_QUEUED_BYTES};
use super::driver::TURN_RUNNING;
use crate::exit::Exit;

/// How long a prompt refused while a turn runs, such as the task's, waits
/// before it is sent again.
const RETRY: Duration = Duration::from_secs(1);
/// How long the connection and its handshake may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const INITIALIZE_ID: u64 = 1;
const NEW_ID: u64 = 2;

#[derive(Debug, Parser)]
pub struct Args {
    /// The session's endpoint, `wss://NAME/` as setup printed it; `ws://`
    /// only to loopback
    pub endpoint: String,
    /// Print each JSON-RPC message from the bridge as one line, for
    /// another program to drive the session
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &Args) -> Result<Exit> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the client's runtime")?;
    runtime.block_on(connect(args))
}

async fn connect(args: &Args) -> Result<Exit> {
    let request = args
        .endpoint
        .as_str()
        .into_client_request()
        .with_context(|| format!("{:?} is not a WebSocket URL", args.endpoint))?;
    let uri = request.uri().clone();
    let host = uri.host().context("the endpoint names no host")?;
    let tls = match uri.scheme_str() {
        Some("wss") => true,
        Some("ws") => {
            ensure!(
                is_loopback(host),
                "ws:// is only for loopback: use the session's wss:// endpoint"
            );
            false
        }
        _ => bail!("{:?} is not a ws:// or wss:// URL", args.endpoint),
    };
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_QUEUED_BYTES))
        .max_frame_size(Some(MAX_QUEUED_BYTES));
    let opened = tokio::time::timeout(CONNECT_TIMEOUT, async {
        let stream = TcpStream::connect((bare, port))
            .await
            .with_context(|| format!("connecting to {host}:{port}"))?;
        if !tls {
            // Whatever the name resolved to.
            ensure!(
                stream.peer_addr()?.ip().is_loopback(),
                "ws:// is only for loopback"
            );
            let (socket, _) =
                tokio_tungstenite::client_async_with_config(request, stream, Some(config))
                    .await
                    .context("the WebSocket handshake")?;
            return Ok(Converse::Plain(Box::new(socket)));
        }
        use secure_host::proxy::tls;
        let connector = tokio_rustls::TlsConnector::from(tls::client_config(tls::mozilla_roots())?);
        let stream = connector
            .connect(tls::server_name(host)?, stream)
            .await
            .with_context(|| format!("TLS with {host}"))?;
        let (socket, _) =
            tokio_tungstenite::client_async_with_config(request, stream, Some(config))
                .await
                .context("the WebSocket handshake")?;
        Ok(Converse::Tls(Box::new(socket)))
    })
    .await
    .context("connecting to the session timed out")??;
    let lines = read_stdin();
    let out = std::io::stdout();
    match opened {
        Converse::Plain(socket) => converse(*socket, lines, args.json, out).await,
        Converse::Tls(socket) => converse(*socket, lines, args.json, out).await,
    }
}

enum Converse {
    Plain(Box<WebSocketStream<TcpStream>>),
    Tls(Box<WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>>),
}

/// Whether HOST, as a URL names it, is this machine.
fn is_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost" || bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Standard input's lines, as they come; an error ends them.
fn read_stdin() -> mpsc::Receiver<Result<String>> {
    let (tx, rx) = mpsc::channel(1);
    // A thread, not the runtime's: a read that never ends must not keep
    // the process from exiting.
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();
        loop {
            let Some(line) = read_line(&mut stdin).transpose() else {
                return;
            };
            if tx.blocking_send(line).is_err() {
                return;
            }
        }
    });
    rx
}

/// The next line of INPUT, without its end; `None` at its end. A line no
/// prompt could carry is an error, read no further than that.
fn read_line(input: &mut impl BufRead) -> Result<Option<String>> {
    let mut line = Vec::new();
    let limit = MAX_MESSAGE_BYTES as u64;
    std::io::Read::take(input, limit + 1)
        .read_until(b'\n', &mut line)
        .context("reading standard input")?;
    if line.is_empty() {
        return Ok(None);
    }
    ensure!(
        line.len() as u64 <= limit,
        "a line of standard input is over {limit} bytes"
    );
    if line.ends_with(b"\n") {
        line.pop();
        if line.ends_with(b"\r") {
            line.pop();
        }
    }
    String::from_utf8(line)
        .map(Some)
        .context("a line of standard input is not UTF-8")
}

/// Holds the conversation on SOCKET: attaches, then sends each of LINES
/// as a prompt once the one before it is answered. Ends at their end, or
/// when the session does.
async fn converse<S: AsyncRead + AsyncWrite + Unpin>(
    socket: WebSocketStream<S>,
    mut lines: mpsc::Receiver<Result<String>>,
    json: bool,
    mut out: impl Write,
) -> Result<Exit> {
    let (mut write, mut read) = socket.split();
    let mut send = async |msg: Value| -> Result<()> {
        let text = msg.to_string();
        // The bridge would end the connection on a longer one.
        ensure!(
            text.len() <= MAX_MESSAGE_BYTES,
            "a prompt is over the bridge's {MAX_MESSAGE_BYTES} bytes"
        );
        write
            .send(Message::text(text))
            .await
            .context("sending to the session")
    };
    let params = json!({"protocolVersion": 1});
    send(request(INITIALIZE_ID, "initialize", params)).await?;
    let params = json!({"cwd": "/", "mcpServers": []});
    send(request(NEW_ID, "session/new", params)).await?;
    let mut session_id = None;
    // The prompt waiting for its answer: its id and its text, to send
    // again while another turn runs.
    let mut turn: Option<(u64, String)> = None;
    let mut next_id = NEW_ID + 1;
    let mut stdin_open = true;
    let mut retry_at = None;
    loop {
        if !stdin_open && turn.is_none() && session_id.is_some() {
            break;
        }
        let take_line = stdin_open && turn.is_none() && session_id.is_some();
        tokio::select! {
            msg = read.next() => {
                let text = match msg {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Close(_))) | None => {
                        eprintln!("session: the session ended");
                        return Ok(Exit::Failure);
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(e).context("reading from the session"),
                };
                let msg: Value = serde_json::from_str(&text)
                    .context("a message from the session is not JSON")?;
                if json {
                    // Parsed and printed again: one line, whatever was sent.
                    writeln!(out, "{msg}")?;
                    out.flush()?;
                }
                match msg["id"].as_u64() {
                    Some(INITIALIZE_ID) | None => {}
                    Some(NEW_ID) => {
                        let id = msg["result"]["sessionId"].as_str().with_context(|| {
                            format!("the session refused to attach: {}", msg["error"])
                        })?;
                        session_id = Some(id.to_owned());
                    }
                    Some(id) if turn.as_ref().is_some_and(|(sent, _)| *sent == id) => {
                        if msg["error"]["message"].as_str() == Some(TURN_RUNNING) {
                            // The task's turn, most likely: wait for it.
                            retry_at = Some(tokio::time::Instant::now() + RETRY);
                        } else {
                            turn = None;
                            if !json {
                                match msg["error"]["message"].as_str() {
                                    Some(why) => eprintln!("session: {}", printable(why)),
                                    None => writeln!(out)?,
                                }
                            }
                        }
                    }
                    Some(_) => {}
                }
                if !json && let Some(text) = chunk(&msg) {
                    write!(out, "{}", printable(text))?;
                    out.flush()?;
                }
            }
            () = async {
                match retry_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {
                retry_at = None;
                let (_, text) = turn.take().context("a retry without a prompt")?;
                let id = next_id;
                next_id += 1;
                send(prompt(id, session_id.as_deref().unwrap_or_default(), &text)).await?;
                turn = Some((id, text));
            }
            line = lines.recv(), if take_line => match line {
                None => stdin_open = false,
                Some(line) => {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let id = next_id;
                    next_id += 1;
                    send(prompt(id, session_id.as_deref().unwrap_or_default(), &line)).await?;
                    turn = Some((id, line));
                }
            },
        }
    }
    // Leaving ends the session.
    let _ = write.close().await;
    Ok(Exit::Success)
}

fn request(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn prompt(id: u64, session_id: &str, text: &str) -> Value {
    request(
        id,
        "session/prompt",
        json!({"sessionId": session_id, "prompt": [{"type": "text", "text": text}]}),
    )
}

/// The text of MSG where it is a chunk of the agent's message.
fn chunk(msg: &Value) -> Option<&str> {
    let update = &msg["params"]["update"];
    if msg["method"] != "session/update" || update["sessionUpdate"] != "agent_message_chunk" {
        return None;
    }
    update["content"]["text"].as_str()
}

/// TEXT without control characters but for line ends and tabs: the agent
/// must not drive the operator's terminal with escape sequences, such as
/// one that sets the clipboard.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\n' | '\t' => c,
            c if c.is_control() => char::REPLACEMENT_CHARACTER,
            c => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_is_plain() {
        for (host, loopback) in [
            ("127.0.0.1", true),
            ("127.1.2.3", true),
            ("[::1]", true),
            ("localhost", true),
            ("10.0.0.1", false),
            ("runner.example.ts.net", false),
            ("localhost.example", false),
            ("[::2]", false),
        ] {
            assert_eq!(is_loopback(host), loopback, "{host}");
        }
    }

    #[test]
    fn only_loopback_is_refused_plain() {
        let args = Args {
            endpoint: "ws://runner.example.ts.net/".to_owned(),
            json: false,
        };
        let err = format!("{:#}", run(&args).unwrap_err());
        assert!(err.contains("ws:// is only for loopback"), "{err}");
        for endpoint in ["http://127.0.0.1/", "runner.example.ts.net"] {
            let args = Args {
                endpoint: endpoint.to_owned(),
                json: false,
            };
            assert!(run(&args).is_err(), "{endpoint}");
        }
    }

    #[test]
    fn lines_are_bounded() {
        let mut input = std::io::Cursor::new(b"one\r\ntwo\n\nlast".to_vec());
        let mut got = Vec::new();
        while let Some(line) = read_line(&mut input).unwrap() {
            got.push(line);
        }
        assert_eq!(got, ["one", "two", "", "last"]);
        let mut long = std::io::Cursor::new(vec![b'x'; MAX_MESSAGE_BYTES + 1]);
        assert!(read_line(&mut long).is_err());
        let mut exact = std::io::Cursor::new(vec![b'x'; MAX_MESSAGE_BYTES]);
        let exact = read_line(&mut exact).unwrap().unwrap();
        assert_eq!(exact.len(), MAX_MESSAGE_BYTES);
        let mut binary = std::io::Cursor::new(vec![0xff, b'\n']);
        assert!(read_line(&mut binary).is_err());
    }

    #[test]
    fn only_the_agents_words_are_printed() {
        let said = json!({"jsonrpc": "2.0", "method": "session/update", "params": {
            "sessionId": "s", "update": {"sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": "Hi\u{1b}]52;c;eA==\u{7}\n"}}}});
        assert_eq!(
            chunk(&said).map(printable).as_deref(),
            Some("Hi\u{fffd}]52;c;eA==\u{fffd}\n")
        );
        let thought = json!({"method": "session/update", "params": {"update": {
            "sessionUpdate": "agent_thought_chunk", "content": {"type": "text", "text": "hm"}}}});
        assert_eq!(chunk(&thought), None);
        assert_eq!(chunk(&json!({"id": 3, "result": {}})), None);
    }
}
