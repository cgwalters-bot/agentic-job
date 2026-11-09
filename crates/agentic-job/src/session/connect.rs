//! `session connect`: a terminal's, or another agent's, client of a
//! session run's bridge (specs/session.md). It does what the bridge
//! serves: `initialize`, `session/new`, then each line of standard input
//! as a `session/prompt`, one turn at a time, and prints what the agent
//! says and a line for each tool call it finishes. With `--json`, each
//! message from the bridge is printed as one line of JSON instead, for a
//! program to read.
//!
//! It attaches with a replay of what the agent said since a cursor
//! (`--since`, everything the session kept by default), so a client that
//! comes late sees the task's turn. When the connection drops, it
//! connects again with the cursor it last saw, a bounded number of times,
//! so a laptop's sleep or a tailnet hiccup does not end the session or
//! lose a word of it. The end of its input ends the session; Ctrl-C only
//! detaches, and says which cursor a later `connect --since` resumes
//! from.
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
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{self, Message};

use super::bridge::{MAX_MESSAGE_BYTES, MAX_QUEUED_BYTES, META_KEY, SILENCE};
use super::digest::{Digest, Dir};
use super::driver::TURN_RUNNING;
use crate::exit::Exit;

/// How long a prompt refused while a turn runs, such as the task's, waits
/// before it is sent again.
const RETRY: Duration = Duration::from_secs(1);
/// How long the connection and its handshake may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long after a dropped connection the next is tried, and how many
/// times in all: a minute of outage, then the operator connects again
/// with the cursor printed.
const RECONNECT_WAIT: Duration = Duration::from_secs(2);
const RECONNECTS: u32 = 30;

#[derive(Debug, Parser)]
pub struct Args {
    /// The session's endpoint, `wss://NAME/` as setup printed it; `ws://`
    /// only to loopback
    pub endpoint: String,
    /// Print each JSON-RPC message from the bridge as one line, for
    /// another program to drive the session
    #[arg(long)]
    pub json: bool,
    /// Replay what the agent said after this cursor on attaching: 0 for
    /// everything the session kept, or the cursor printed when a client
    /// detached
    #[arg(long, default_value_t = 0)]
    pub since: u64,
}

pub fn run(args: &Args) -> Result<Exit> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the client's runtime")?;
    runtime.block_on(session(
        args,
        read_stdin(),
        std::io::stdout(),
        detach_signal(),
    ))
}

/// A handshake the bridge refused: trying again would not help.
#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// The whole conversation: connects, converses, and connects again with
/// the cursor last seen when the connection drops. DETACH is the
/// operator's Ctrl-C.
async fn session(
    args: &Args,
    mut lines: mpsc::Receiver<Result<String>>,
    mut out: impl Write,
    detach: impl Future<Output = ()>,
) -> Result<Exit> {
    let mut detach = std::pin::pin!(detach);
    let mut state = State {
        json: args.json,
        since: args.since,
        session_id: None,
        next_id: 1,
        turn: None,
        waiting: None,
        drops: 0,
        stdin_open: true,
        at_line_start: true,
        digest: Digest::new(),
    };
    loop {
        // Ctrl-C detaches while connecting and between tries too.
        let opened = tokio::select! {
            opened = open(args) => opened,
            () = detach.as_mut() => {
                state.detached();
                return Ok(Exit::Success);
            }
        };
        let ended = match opened {
            Ok(Converse::Plain(socket)) => {
                converse(*socket, &mut state, &mut lines, &mut out, detach.as_mut()).await?
            }
            Ok(Converse::Tls(socket)) => {
                converse(*socket, &mut state, &mut lines, &mut out, detach.as_mut()).await?
            }
            // The first connection fails for good, as does one the bridge
            // refused; a later one is tried again.
            Err(e) if state.drops == 0 || e.is::<Refused>() => return Err(e),
            Err(e) => {
                eprintln!("session: {e:#}");
                Ended::Dropped
            }
        };
        match ended {
            Ended::Done | Ended::Detached => return Ok(Exit::Success),
            Ended::Session => {
                eprintln!("session: the session ended");
                return Ok(Exit::Failure);
            }
            Ended::Dropped => tokio::select! {
                again = state.again() => again?,
                () = detach.as_mut() => {
                    state.detached();
                    return Ok(Exit::Success);
                }
            },
        }
    }
}

/// Connects to the endpoint, through the handshake.
async fn open(args: &Args) -> Result<Converse> {
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
    tokio::time::timeout(CONNECT_TIMEOUT, async {
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
                    .map_err(handshake_error)?;
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
                .map_err(handshake_error)?;
        Ok(Converse::Tls(Box::new(socket)))
    })
    .await
    .context("connecting to the session timed out")?
}

/// Why the handshake failed: the bridge's own words where it refused the
/// client (403), which it does for good. A server error is serve's,
/// while the bridge has not noticed the dropped connection yet, say: that
/// passes.
fn handshake_error(e: tungstenite::Error) -> anyhow::Error {
    match e {
        tungstenite::Error::Http(response) => {
            let body = response
                .body()
                .as_deref()
                .map(|b| String::from_utf8_lossy(b).trim().to_owned())
                .unwrap_or_default();
            let status = response.status();
            let why = format!("the handshake was answered with HTTP {status}: {body}");
            if status.is_client_error() {
                anyhow::Error::new(Refused(why))
            } else {
                anyhow::anyhow!(why)
            }
        }
        e => anyhow::Error::new(e).context("the WebSocket handshake"),
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

/// What the client knows across its connections.
struct State {
    json: bool,
    /// The cursor to attach since: `--since`, then the last one seen.
    since: u64,
    session_id: Option<String>,
    next_id: u64,
    /// The prompt sent and not yet answered: its id and its text.
    turn: Option<(u64, String)>,
    /// A prompt the bridge refused while a turn ran, to send again: the
    /// agent never had it, so a dropped connection does not lose it.
    waiting: Option<String>,
    /// Connections that dropped or could not be made since the last
    /// attach.
    drops: u32,
    stdin_open: bool,
    /// Whether what was printed last ended its line.
    at_line_start: bool,
    /// Condenses the agent's tool calls to a line each, as the job's log
    /// does.
    digest: Digest,
}

impl State {
    fn id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Whether a prompt can be taken: none in hand.
    fn free(&self) -> bool {
        self.turn.is_none() && self.waiting.is_none()
    }

    /// Says how to resume where the operator detached.
    fn detached(&self) {
        eprintln!(
            "session: detached at cursor {}; the session goes on until its idle timeout: \
             `agentic-job session connect --since {} ENDPOINT` resumes it",
            self.since, self.since
        );
    }

    /// Counts a connection that dropped or could not be made, and waits
    /// before the next; or why there is none.
    async fn again(&mut self) -> Result<()> {
        self.drops += 1;
        ensure!(
            self.drops <= RECONNECTS,
            "the connection dropped {RECONNECTS} times: run connect again --since {}",
            self.since
        );
        eprintln!(
            "session: connecting again since cursor {} ({} of {RECONNECTS})",
            self.since, self.drops
        );
        tokio::time::sleep(RECONNECT_WAIT).await;
        Ok(())
    }
}

/// How a connection's conversation ended.
enum Ended {
    /// At the end of the input: the client left, which ends the session.
    Done,
    /// The bridge closed normally: the session has ended.
    Session,
    /// The operator detached (Ctrl-C): the session goes on.
    Detached,
    /// The connection dropped, or the bridge hung up: it is made again.
    Dropped,
}

/// Holds the conversation on SOCKET: attaches since the cursor, then
/// sends each of LINES as a prompt once the one before it is answered.
async fn converse<S: AsyncRead + AsyncWrite + Unpin>(
    socket: WebSocketStream<S>,
    state: &mut State,
    lines: &mut mpsc::Receiver<Result<String>>,
    out: &mut impl Write,
    mut detach: std::pin::Pin<&mut impl Future<Output = ()>>,
) -> Result<Ended> {
    let (mut write, mut read) = socket.split();
    // A prompt may have reached the agent even if its write failed. Never
    // resend it, and do not let EOF close normally until the driver is idle.
    let recovering = state.turn.is_some();
    if let Some((_, text)) = &state.turn {
        eprintln!(
            "session: the connection dropped during the prompt {:?}: the agent may be answering \
             it, and what it says still arrives",
            cut(text)
        );
    }
    let initialize_id = state.id();
    let params = json!({"protocolVersion": 1});
    if !send(&mut write, request(initialize_id, "initialize", params)).await? {
        return Ok(Ended::Dropped);
    }
    let mut new_id = state.id();
    if !send(&mut write, attach(new_id, state.since)).await? {
        return Ok(Ended::Dropped);
    }
    let mut attached = false;
    let mut retry_at = None;
    let mut status_id = None;
    let mut status_at = None;
    loop {
        if !state.stdin_open && state.free() && attached {
            // Leaving on purpose ends the session.
            let frame = CloseFrame {
                code: CloseCode::Normal,
                reason: "the client left".into(),
            };
            let _ = write.send(Message::Close(Some(frame))).await;
            let _ = write.close().await;
            return Ok(Ended::Done);
        }
        let take_line = state.stdin_open && state.free() && attached;
        tokio::select! {
            // The bridge pings every 20 seconds. TCP need not notice a
            // blackholed tunnel: expire it ourselves so recovery can start.
            msg = tokio::time::timeout(SILENCE, read.next()) => {
                let Ok(msg) = msg else {
                    eprintln!("session: no traffic from the bridge for {} seconds", SILENCE.as_secs());
                    return Ok(Ended::Dropped);
                };
                let text = match msg {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Close(Some(frame)))) if frame.code == CloseCode::Normal => {
                        return Ok(Ended::Session);
                    }
                    Some(Ok(Message::Close(frame))) => {
                        if let Some(frame) = frame {
                            eprintln!("session: the bridge hung up: {}", printable(frame.reason.as_str()));
                        }
                        return Ok(Ended::Dropped);
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => {
                        eprintln!("session: reading from the session: {e}");
                        return Ok(Ended::Dropped);
                    }
                    None => return Ok(Ended::Dropped),
                };
                let msg: Value = serde_json::from_str(&text)
                    .context("a message from the session is not JSON")?;
                if state.json {
                    // Parsed and printed again: one line, whatever was sent.
                    writeln!(out, "{msg}")?;
                    out.flush()?;
                }
                if let Some(cursor) = msg["params"]["_meta"][META_KEY]["cursor"].as_u64() {
                    state.since = state.since.max(cursor);
                }
                match msg["id"].as_u64() {
                    Some(id) if id == initialize_id => {}
                    None => {}
                    Some(id) if id == new_id => {
                        if let Some(sid) = msg["result"]["sessionId"].as_str() {
                            // An endpoint can be reused by a later run. Neither
                            // queued input nor a normal EOF close belongs to it.
                            ensure!(
                                state.session_id.as_deref().is_none_or(|had| had == sid),
                                "attached to another session; refusing to continue"
                            );
                            state.session_id = Some(sid.to_owned());
                            if let Some(cursor) = msg["result"]["_meta"][META_KEY]["cursor"].as_u64() {
                                state.since = state.since.max(cursor);
                            }
                            attached = true;
                            state.drops = 0;
                            if recovering {
                                status_at = Some(tokio::time::Instant::now());
                            }
                            // A prompt refused before the drop goes again.
                            if state.waiting.is_some() {
                                retry_at = Some(tokio::time::Instant::now() + RETRY);
                            }
                        } else if let Some(since) = msg["error"]["data"]["since"].as_u64() {
                            // Not what was asked for, but what there is.
                            eprintln!("session: {}", printable(msg["error"]["message"].as_str().unwrap_or("?")));
                            state.since = since;
                            new_id = state.id();
                            if !send(&mut write, attach(new_id, since)).await? {
                                return Ok(Ended::Dropped);
                            }
                        } else {
                            bail!("the session refused to attach: {}", msg["error"]);
                        }
                    }
                    Some(id) if Some(id) == status_id => {
                        status_id = None;
                        match msg["result"]["running"].as_bool() {
                            Some(true) => status_at = Some(tokio::time::Instant::now() + RETRY),
                            Some(false) => state.turn = None,
                            None => bail!("cannot establish whether the unanswered turn ended: {msg}"),
                        }
                    }
                    Some(id) if state.turn.as_ref().is_some_and(|(sent, _)| *sent == id) => {
                        if msg["error"]["message"].as_str() == Some(TURN_RUNNING) {
                            // The task's turn, most likely: wait for it.
                            state.waiting = state.turn.take().map(|(_, text)| text);
                            retry_at = Some(tokio::time::Instant::now() + RETRY);
                        } else {
                            state.turn = None;
                            if !state.json {
                                match msg["error"]["message"].as_str() {
                                    Some(why) => eprintln!("session: {}", printable(why)),
                                    None => {
                                        writeln!(out)?;
                                        state.at_line_start = true;
                                    }
                                }
                            }
                        }
                    }
                    Some(_) => {}
                }
                if !state.json {
                    show(state, &msg, out)?;
                }
            }
            () = async {
                match status_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {
                status_at = None;
                let id = state.id();
                status_id = Some(id);
                let sid = state.session_id.clone().unwrap_or_default();
                if !send(&mut write, request(id, "_session/status", json!({"sessionId": sid}))).await? {
                    return Ok(Ended::Dropped);
                }
            }
            () = async {
                match retry_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {
                retry_at = None;
                let text = state.waiting.take().context("a retry without a prompt")?;
                let id = state.id();
                let sid = state.session_id.clone().unwrap_or_default();
                let sent = send(&mut write, prompt(id, &sid, &text)).await?;
                state.turn = Some((id, text));
                if !sent {
                    return Ok(Ended::Dropped);
                }
            }
            line = lines.recv(), if take_line => match line {
                None => state.stdin_open = false,
                Some(line) => {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let id = state.id();
                    let sid = state.session_id.clone().unwrap_or_default();
                    let sent = send(&mut write, prompt(id, &sid, &line)).await?;
                    state.turn = Some((id, line));
                    if !sent {
                        return Ok(Ended::Dropped);
                    }
                }
            },
            () = &mut detach => {
                state.detached();
                return Ok(Ended::Detached);
            }
        }
    }
}

/// Sends MSG; false where the connection does not take it, which ends
/// the connection, not the conversation: it goes on over the next.
async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    write: &mut futures::stream::SplitSink<WebSocketStream<S>, Message>,
    msg: Value,
) -> Result<bool> {
    let text = msg.to_string();
    // The bridge would end the connection on a longer one.
    ensure!(
        text.len() <= MAX_MESSAGE_BYTES,
        "a prompt is over the bridge's {MAX_MESSAGE_BYTES} bytes"
    );
    Ok(write.send(Message::text(text)).await.is_ok())
}

/// Ctrl-C, once; never, where it cannot be taken.
async fn detach_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Prints what MSG shows the operator: the agent's words as they come,
/// and a line for each tool call that finished, as the job's log has it.
fn show(state: &mut State, msg: &Value, out: &mut impl Write) -> Result<()> {
    if let Some(text) = chunk(msg) {
        if !text.is_empty() {
            write!(out, "{}", printable(text))?;
            state.at_line_start = text.ends_with('\n');
            out.flush()?;
        }
        return Ok(());
    }
    if msg["method"] != "session/update" {
        return Ok(());
    }
    for line in state.digest.feed(super::transcript::now(), Dir::Recv, msg) {
        if !state.at_line_start {
            writeln!(out)?;
        }
        writeln!(out, "{}", printable(&line))?;
        state.at_line_start = true;
    }
    out.flush()?;
    Ok(())
}

/// TEXT shortened for a line of the log.
fn cut(text: &str) -> String {
    super::digest::cut(text)
}

fn request(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

/// The `session/new` that attaches to the running session, with a replay
/// of what the agent said after SINCE.
fn attach(id: u64, since: u64) -> Value {
    request(
        id,
        "session/new",
        json!({"cwd": "/", "mcpServers": [], "_meta": {META_KEY: {"since": since}}}),
    )
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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

    fn args(endpoint: &str) -> Args {
        Args {
            endpoint: endpoint.to_owned(),
            json: false,
            since: 0,
        }
    }

    #[test]
    fn only_loopback_is_refused_plain() {
        let err = format!(
            "{:#}",
            run(&args("ws://runner.example.ts.net/")).unwrap_err()
        );
        assert!(err.contains("ws:// is only for loopback"), "{err}");
        for endpoint in ["http://127.0.0.1/", "runner.example.ts.net"] {
            assert!(run(&args(endpoint)).is_err(), "{endpoint}");
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

    /// A stand-in for the bridge on one connection.
    type Server = WebSocketStream<TcpStream>;

    async fn next_request(server: &mut Server) -> Value {
        loop {
            match server.next().await.expect("the client hung up").unwrap() {
                Message::Text(text) => return serde_json::from_str(&text).unwrap(),
                Message::Close(frame) => panic!("the client closed: {frame:?}"),
                _ => {}
            }
        }
    }

    async fn reply(server: &mut Server, msg: Value) {
        server.send(Message::text(msg.to_string())).await.unwrap();
    }

    fn update(cursor: u64, update: Value) -> Value {
        json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s",
               "update": update, "_meta": {META_KEY: {"cursor": cursor}}}})
    }

    fn said(cursor: u64, text: &str) -> Value {
        update(
            cursor,
            json!({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": text}}),
        )
    }

    /// The client attaches since its cursor, prints the replay and the
    /// tool calls, comes back with the cursor it last saw when the
    /// connection drops, takes the cursor the bridge can replay from when
    /// its own is no longer kept, and leaves with a normal close at the
    /// end of its input, which ends the session.
    #[tokio::test]
    async fn a_dropped_connection_is_made_again_since_the_cursor() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}/", listener.local_addr().unwrap());
        let bridge = tokio::spawn(async move {
            // The first connection: attached since 0 with a replay, then
            // dropped without a close frame.
            let (stream, _) = listener.accept().await.unwrap();
            let mut server = tokio_tungstenite::accept_async(stream).await.unwrap();
            let init = next_request(&mut server).await;
            assert_eq!(init["method"], "initialize");
            reply(
                &mut server,
                json!({"jsonrpc": "2.0", "id": init["id"], "result": {}}),
            )
            .await;
            let new = next_request(&mut server).await;
            assert_eq!(new["method"], "session/new");
            assert_eq!(new["params"]["_meta"][META_KEY]["since"], 0, "{new}");
            reply(&mut server, said(1, "Task ")).await;
            reply(
                &mut server,
                update(
                    2,
                    json!({"sessionUpdate": "tool_call", "toolCallId": "t1",
                    "title": "Bash", "kind": "execute", "status": "completed",
                    "rawInput": {"command": "true"}}),
                ),
            )
            .await;
            let result = json!({"sessionId": "s", "_meta": {META_KEY: {"cursor": 2}}});
            reply(
                &mut server,
                json!({"jsonrpc": "2.0", "id": new["id"], "result": result}),
            )
            .await;
            reply(&mut server, said(3, "done.\n")).await;
            // The first prompt is taken, and the connection dropped with
            // it unanswered: read first, so that the close does not reset
            // the connection with the prompt unread and lose the client
            // what was sent before.
            let lost = next_request(&mut server).await;
            assert_eq!(lost["params"]["prompt"][0]["text"], "first", "{lost}");
            drop(server);
            // Serve's answer while the bridge has not noticed the drop:
            // tried again, unlike the bridge's own refusal.
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0; 4096];
            let _ = stream.read(&mut head).await;
            stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            drop(stream);
            // The second: since 3, which is no longer kept; then since 4,
            // and a prompt answered.
            let (stream, _) = listener.accept().await.unwrap();
            let mut server = tokio_tungstenite::accept_async(stream).await.unwrap();
            let init = next_request(&mut server).await;
            reply(
                &mut server,
                json!({"jsonrpc": "2.0", "id": init["id"], "result": {}}),
            )
            .await;
            let new = next_request(&mut server).await;
            assert_eq!(new["params"]["_meta"][META_KEY]["since"], 3, "{new}");
            let error = json!({"code": -32602, "message": "the 1 notifications after cursor 3 are gone",
                               "data": {"since": 4}});
            reply(
                &mut server,
                json!({"jsonrpc": "2.0", "id": new["id"], "error": error}),
            )
            .await;
            let again = next_request(&mut server).await;
            assert_eq!(again["method"], "session/new");
            assert_eq!(again["params"]["_meta"][META_KEY]["since"], 4, "{again}");
            assert_ne!(again["id"], new["id"]);
            let result = json!({"sessionId": "s", "_meta": {META_KEY: {"cursor": 4}}});
            reply(
                &mut server,
                json!({"jsonrpc": "2.0", "id": again["id"], "result": result}),
            )
            .await;
            let prompt = next_request(&mut server).await;
            assert_eq!(prompt["method"], "_session/status");
            reply(
                &mut server,
                json!({"jsonrpc": "2.0", "id": prompt["id"], "result": {"running": false}}),
            )
            .await;
            let prompt = next_request(&mut server).await;
            assert_eq!(prompt["method"], "session/prompt");
            assert_eq!(prompt["params"]["sessionId"], "s");
            assert_eq!(prompt["params"]["prompt"][0]["text"], "second");
            reply(&mut server, said(5, "Hi!")).await;
            reply(
                &mut server,
                json!({"jsonrpc": "2.0", "id": prompt["id"], "result": {"stopReason": "end_turn"}}),
            )
            .await;
            // The end of its input: a normal close.
            loop {
                match server.next().await.expect("the client hung up").unwrap() {
                    Message::Close(Some(frame)) => {
                        assert_eq!(frame.code, CloseCode::Normal);
                        break;
                    }
                    Message::Close(None) => panic!("closed without a code"),
                    _ => {}
                }
            }
        });
        let (tx, rx) = mpsc::channel(2);
        // The first line goes before the drop, and is lost with it; the
        // second after.
        tx.send(Ok("first".to_owned())).await.unwrap();
        tx.send(Ok("second".to_owned())).await.unwrap();
        drop(tx);
        let mut out = Vec::new();
        let exit = session(&args(&endpoint), rx, &mut out, std::future::pending())
            .await
            .unwrap();
        assert_eq!(exit, Exit::Success);
        bridge.await.unwrap();
        let printed = String::from_utf8(out).unwrap();
        assert_eq!(printed, "Task \n▶ Bash: true (ok, 0s)\ndone.\nHi!\n");
    }

    /// Attaches the client of SERVER, replaying one line of the task's
    /// turn, and returns the attached client's first prompt.
    async fn attach_and_take_a_prompt(server: &mut Server) -> Value {
        let init = next_request(server).await;
        assert_eq!(init["method"], "initialize");
        reply(
            server,
            json!({"jsonrpc": "2.0", "id": init["id"], "result": {}}),
        )
        .await;
        let new = next_request(server).await;
        assert_eq!(new["method"], "session/new");
        reply(server, said(1, "Task done.\n")).await;
        let result = json!({"sessionId": "s", "_meta": {META_KEY: {"cursor": 1}}});
        reply(
            server,
            json!({"jsonrpc": "2.0", "id": new["id"], "result": result}),
        )
        .await;
        let prompt = next_request(server).await;
        assert_eq!(prompt["method"], "session/prompt");
        prompt
    }

    /// Ctrl-C during a turn detaches: the client ends well, with its
    /// input still open, and its connection ends without the normal close
    /// that would end the session; one is not tried again either.
    #[tokio::test]
    async fn ctrl_c_detaches_without_ending_the_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}/", listener.local_addr().unwrap());
        let (detach_tx, detach_rx) = tokio::sync::oneshot::channel::<()>();
        let bridge = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut server = tokio_tungstenite::accept_async(stream).await.unwrap();
            let prompt = attach_and_take_a_prompt(&mut server).await;
            assert_eq!(prompt["params"]["prompt"][0]["text"], "first", "{prompt}");
            // The operator presses Ctrl-C with the prompt unanswered.
            detach_tx.send(()).unwrap();
            loop {
                match server.next().await {
                    Some(Ok(Message::Close(frame))) => {
                        let code = frame.as_ref().map(|f| f.code);
                        assert_ne!(code, Some(CloseCode::Normal), "left, not detached");
                    }
                    Some(Ok(msg)) => panic!("sent after detaching: {msg:?}"),
                    Some(Err(_)) | None => break,
                }
            }
            // Nobody connects again.
            let again = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
            assert!(again.is_err(), "connected again after detaching");
        });
        let (tx, rx) = mpsc::channel(1);
        tx.send(Ok("first".to_owned())).await.unwrap();
        let mut out = Vec::new();
        let detach = async {
            let _ = detach_rx.await;
        };
        let exit = session(&args(&endpoint), rx, &mut out, detach)
            .await
            .unwrap();
        assert_eq!(exit, Exit::Success);
        // The input was open throughout: the end of it, not Ctrl-C, leaves.
        drop(tx);
        bridge.await.unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "Task done.\n");
    }

    /// The bridge's normal close is the session's end: the client fails,
    /// as the conversation is over, rather than connecting again.
    #[tokio::test]
    async fn the_sessions_end_is_not_a_drop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}/", listener.local_addr().unwrap());
        let bridge = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut server = tokio_tungstenite::accept_async(stream).await.unwrap();
            attach_and_take_a_prompt(&mut server).await;
            let frame = CloseFrame {
                code: CloseCode::Normal,
                reason: "the session ended".into(),
            };
            server.send(Message::Close(Some(frame))).await.unwrap();
            let again = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
            assert!(again.is_err(), "connected again after the session's end");
        });
        let (tx, rx) = mpsc::channel(1);
        tx.send(Ok("first".to_owned())).await.unwrap();
        let mut out = Vec::new();
        let exit = session(&args(&endpoint), rx, &mut out, std::future::pending())
            .await
            .unwrap();
        assert_eq!(exit, Exit::Failure);
        bridge.await.unwrap();
    }
}
