//! The bridge: how a client reaches a session on a machine that takes no
//! inbound connection (specs/session.md). `run` dials out to a relay,
//! sends it one hello line, and from then on the connection carries
//! ACP's newline-delimited JSON-RPC, with the session in the agent's role
//! toward the client at the relay's far end.
//!
//! The client gets a narrow part of ACP: `initialize`; `session/new`,
//! which attaches it to the session already running instead of starting
//! another; `session/prompt` and `session/cancel`. Every other request is
//! refused. So a client cannot have a program started (`mcpServers` is
//! never passed on), load another session, or change the session's mode
//! or model: what the agent may do was fixed before it started, and a
//! client is only another source of prompts. The agent's notifications
//! reach the client once it has attached, with the run's secrets
//! replaced; its permission requests stay with the session's policy.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};

use crate::config;

/// The first line `run` sends the relay, before any of ACP's.
pub const HELLO_SCHEMA: &str = "agentic-job-relay/v1";
/// How long the session waits for a prompt unless `session.idle-minutes`
/// says otherwise: a runner waiting for nobody still costs its minutes.
const DEFAULT_IDLE_MINUTES: u64 = 10;
const MAX_IDLE_MINUTES: u64 = 60;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long what is left to send the client gets once the session ended.
const CLOSE_GRACE: Duration = Duration::from_secs(5);
/// The longest line taken from the client: a prompt as large as the
/// largest task, with room for its JSON. A longer one ends the bridge.
const MAX_LINE_BYTES: u64 = 2 * crate::run::MAX_TASK_BYTES;
/// The client's requests that wait for the session at once: the reading
/// stops beyond them.
const INBOX: usize = 4;
/// The answers to the client's prompts that wait to be sent at once: the
/// reading stops beyond them.
const PENDING_ANSWERS: usize = INBOX;
/// The most bytes queued for the client at once. A client that does not
/// read is not to fill the memory of the process that holds the run: an
/// agent's notification that finds no room hangs up on the client, and a
/// response to the client waits for room, which stops the reading.
const MAX_QUEUED_BYTES: usize = 8 << 20;
const PROTOCOL_VERSION: u64 = 1;
const PARSE_ERROR: i64 = -32700;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

/// Replaces the run's secrets in a string sent to the client.
pub type Redact = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// The relay of a run's configuration, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    /// `HOST:PORT`.
    pub address: String,
    pub audience: Option<String>,
    pub idle: Duration,
}

impl Relay {
    /// `None` where `session.relay` is not set: a task run.
    pub fn from_config(table: &config::Session) -> Result<Option<Self>> {
        let config::Session {
            relay,
            audience,
            idle_minutes,
        } = table;
        if relay.is_empty() {
            ensure!(
                audience.is_none() && *idle_minutes == 0,
                "session.audience and session.idle-minutes mean nothing without session.relay"
            );
            return Ok(None);
        }
        let port = relay
            .rsplit_once(':')
            .filter(|(host, _)| {
                // A name, an IPv4 address, or an IPv6 one in brackets.
                let (host, extra) = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
                    Some(v6) => (v6, b":".as_slice()),
                    None => (*host, b".-".as_slice()),
                };
                !host.is_empty()
                    && host
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
            })
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .filter(|port| *port != 0);
        ensure!(port.is_some(), "session.relay: {relay:?} is not HOST:PORT");
        if let Some(audience) = audience {
            // It goes into the query of the token request as it is.
            ensure!(
                !audience.is_empty()
                    && audience
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b)),
                "session.audience: {audience:?} is not letters, digits and ._:/-"
            );
        }
        let minutes = match *idle_minutes {
            0 => DEFAULT_IDLE_MINUTES,
            n => n,
        };
        ensure!(
            minutes <= MAX_IDLE_MINUTES,
            "session.idle-minutes = {minutes} is over {MAX_IDLE_MINUTES}"
        );
        Ok(Some(Self {
            address: relay.clone(),
            audience: audience.clone(),
            idle: Duration::from_secs(minutes * 60),
        }))
    }
}

/// What a session is given to reach its client.
pub struct Bridge {
    pub relay: Relay,
    /// The first line: [`hello`].
    pub hello: Value,
    pub redact: Redact,
}

/// The hello for the run NAME, with TOKEN, the job's identity token for
/// the relay's audience, where it has one. The relay decides from it
/// whether this run is one it expects; nothing else on the connection
/// says who is at this end.
pub fn hello(name: &str, token: Option<&str>) -> Value {
    json!({"schema": HELLO_SCHEMA, "run": name, "token": token})
}

/// What the client asks of the session.
pub(super) enum FromClient {
    /// A prompt turn, with the prompt's content blocks as the client sent
    /// them; the turn's response, or why there is none, goes to ANSWER.
    Prompt {
        prompt: Value,
        answer: oneshot::Sender<Result<Value, String>>,
    },
    Cancel,
}

/// A line for the client, with the room it takes until it is written.
struct Line {
    text: String,
    _room: OwnedSemaphorePermit,
}

/// Ends the connection: whichever half learns first that the client is
/// gone, or must be, tells the other, and nothing more is queued.
#[derive(Clone)]
struct HangUp {
    room: Arc<Semaphore>,
    gone: Arc<watch::Sender<bool>>,
}

impl HangUp {
    fn now(&self) {
        self.room.close();
        self.gone.send_replace(true);
    }
}

/// Waits until the connection is hung up.
async fn hung_up(gone: &mut watch::Receiver<bool>) {
    let _ = gone.wait_for(|gone| *gone).await;
}

/// What goes to the client, in order, held to `MAX_QUEUED_BYTES`.
#[derive(Clone)]
struct Outbox {
    lines: mpsc::UnboundedSender<Line>,
    hang_up: HangUp,
    /// Set once the response that attaches the client is queued: the
    /// agent's notifications are sent only after it.
    attached: Arc<AtomicBool>,
    redact: Redact,
}

impl Outbox {
    /// MSG as a line, with the room it takes; none for a line that could
    /// never fit.
    fn line(&self, msg: Value) -> (String, Option<u32>) {
        let text = redacted(msg, &self.redact).to_string() + "\n";
        let size = u32::try_from(text.len())
            .ok()
            .filter(|n| *n as usize <= MAX_QUEUED_BYTES);
        (text, size)
    }

    /// Queues a notification of the agent's, or hangs up on a client
    /// that leaves no room for it: the agent is not held up by a client.
    fn notify(&self, msg: Value) {
        if !self.attached.load(Ordering::Acquire) || self.hang_up.room.is_closed() {
            return;
        }
        let (text, size) = self.line(msg);
        let room = size.and_then(|n| self.hang_up.room.clone().try_acquire_many_owned(n).ok());
        match room {
            Some(room) => {
                let _ = self.lines.send(Line { text, _room: room });
            }
            None => self.hang_up.now(),
        }
    }

    /// Queues a response once there is room for it; false once the
    /// client is gone.
    async fn send(&self, msg: Value) -> bool {
        let (text, size) = self.line(msg);
        let Some(size) = size else {
            self.hang_up.now();
            return false;
        };
        match self.hang_up.room.clone().acquire_many_owned(size).await {
            Ok(room) => self.lines.send(Line { text, _room: room }).is_ok(),
            Err(_) => false,
        }
    }
}

/// A bridge that is connected.
pub(super) struct Connected {
    /// Passes a notification of the agent's on to the client.
    pub send: Box<dyn Fn(Value) + Send + Sync>,
    pub from_client: mpsc::Receiver<FromClient>,
    pub idle: Duration,
    pub close: Close,
}

/// Hangs up on the client once the session has ended: the relay learns
/// of the end at once, not when `run` exits after its hand-back.
pub(super) struct Close {
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
    done: oneshot::Sender<()>,
}

impl Close {
    pub(super) async fn close(self) {
        self.reader.abort();
        // The writer sends what was queued for the client, and hangs up.
        let _ = self.done.send(());
        let mut writer = self.writer;
        if tokio::time::timeout(CLOSE_GRACE, &mut writer)
            .await
            .is_err()
        {
            writer.abort();
        }
    }
}

impl Bridge {
    /// Dials the relay and sends the hello. SESSION_ID is the agent's
    /// session, once there is one: the client attaches to it.
    pub(super) async fn connect(
        self,
        session_id: watch::Receiver<Option<String>>,
    ) -> Result<Connected> {
        let address = &self.relay.address;
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
            .await
            .ok()
            .with_context(|| format!("connecting to the relay at {address}: timed out"))?
            .with_context(|| format!("connecting to the relay at {address}"))?;
        let (read, mut write) = stream.into_split();
        // Not redacted: the token in it is for the relay.
        let hello = serde_json::to_string(&self.hello)? + "\n";
        write
            .write_all(hello.as_bytes())
            .await
            .with_context(|| format!("greeting the relay at {address}"))?;
        let (lines, outgoing) = mpsc::unbounded_channel();
        let (gone, _) = watch::channel(false);
        let hang_up = HangUp {
            room: Arc::new(Semaphore::new(MAX_QUEUED_BYTES)),
            gone: Arc::new(gone),
        };
        let out = Outbox {
            lines,
            hang_up: hang_up.clone(),
            attached: Arc::new(AtomicBool::new(false)),
            redact: self.redact,
        };
        let (inbox, from_client) = mpsc::channel(INBOX);
        let (done, closing) = oneshot::channel();
        let writer = tokio::spawn(write_lines(write, outgoing, closing, hang_up));
        let reader = tokio::spawn(read_lines(read, out.clone(), inbox, session_id));
        Ok(Connected {
            // A client that went away is no reason to stop the agent.
            send: Box::new(move |msg| out.notify(msg)),
            from_client,
            idle: self.relay.idle,
            close: Close {
                reader,
                writer,
                done,
            },
        })
    }
}

/// VALUE with SECRETS replaced in each of its strings: in the line as a
/// whole, a replacement could cut through JSON's escapes.
fn redacted(value: Value, redact: &Redact) -> Value {
    match value {
        Value::String(s) => Value::String(redact(&s)),
        Value::Array(items) => items.into_iter().map(|v| redacted(v, redact)).collect(),
        Value::Object(map) => map
            .into_iter()
            .map(|(k, v)| (redact(&k), redacted(v, redact)))
            .collect(),
        other => other,
    }
}

/// Writes the client's lines until the session has ended and they are
/// all sent, the connection fails or it is hung up.
async fn write_lines(
    mut write: OwnedWriteHalf,
    mut outgoing: mpsc::UnboundedReceiver<Line>,
    mut closing: oneshot::Receiver<()>,
    hang_up: HangUp,
) {
    let mut gone = hang_up.gone.subscribe();
    let mut closed = false;
    loop {
        let line = if closed {
            outgoing.try_recv().ok()
        } else {
            tokio::select! {
                line = outgoing.recv() => line,
                _ = &mut closing => {
                    closed = true;
                    continue;
                }
                () = hung_up(&mut gone) => None,
            }
        };
        let Some(line) = line else {
            break;
        };
        // A write the client does not take is no reason to wait past a
        // hang-up.
        let written = tokio::select! {
            r = write.write_all(line.text.as_bytes()) => r.is_ok(),
            () = hung_up(&mut gone) => false,
        };
        if !written {
            break;
        }
    }
    hang_up.now();
    let _ = write.shutdown().await;
}

fn response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Reads the client's messages until the relay closes the connection,
/// sends a line too long or the session stops listening; returning closes
/// the session's inbox, which ends the conversation.
async fn read_lines(
    read: OwnedReadHalf,
    out: Outbox,
    inbox: mpsc::Sender<FromClient>,
    mut session_id: watch::Receiver<Option<String>>,
) {
    let mut gone = out.hang_up.gone.subscribe();
    let pending = Arc::new(Semaphore::new(PENDING_ANSWERS));
    let mut reader = BufReader::new(read);
    let mut line = Vec::new();
    let mut attached = None;
    loop {
        line.clear();
        let mut limited = (&mut reader).take(MAX_LINE_BYTES);
        let read = tokio::select! {
            read = limited.read_until(b'\n', &mut line) => read,
            () = hung_up(&mut gone) => return,
        };
        // Closed, failed, or a line without its end within the limit.
        if !matches!(read, Ok(1..)) || line.last() != Some(&b'\n') {
            return;
        }
        let Ok(msg) = serde_json::from_slice::<Value>(&line) else {
            if !out.send(error(Value::Null, PARSE_ERROR, "not JSON")).await {
                return;
            }
            continue;
        };
        let id = msg.get("id").cloned();
        let params = &msg["params"];
        let ours = attached.is_some() && params["sessionId"].as_str() == attached.as_deref();
        let sent = match (id, msg["method"].as_str()) {
            (Some(id), Some("initialize")) => {
                out.send(response(
                id,
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "agentCapabilities": {},
                    "authMethods": [],
                    "agentInfo": {"name": env!("CARGO_PKG_NAME"), "version": env!("CARGO_PKG_VERSION")},
                }),
                ))
                .await
            }
            (Some(id), Some("session/new")) => {
                let Ok(sid) = session_id
                    .wait_for(Option::is_some)
                    .await
                    .map(|sid| sid.clone())
                else {
                    return;
                };
                attached.clone_from(&sid);
                let sent = out.send(response(id, json!({"sessionId": sid}))).await;
                out.attached.store(true, Ordering::Release);
                sent
            }
            (Some(id), Some("session/prompt")) if ours => {
                let Ok(slot) = pending.clone().acquire_owned().await else {
                    return;
                };
                let (tx, rx) = oneshot::channel();
                let prompt = params["prompt"].clone();
                if inbox
                    .send(FromClient::Prompt { prompt, answer: tx })
                    .await
                    .is_err()
                {
                    return;
                }
                let out = out.clone();
                tokio::spawn(async move {
                    let msg = match rx.await {
                        Ok(Ok(result)) => response(id, result),
                        Ok(Err(why)) => error(id, INTERNAL_ERROR, &why),
                        Err(_) => error(id, INTERNAL_ERROR, "the session has ended"),
                    };
                    out.send(msg).await;
                    drop(slot);
                });
                true
            }
            (Some(id), Some("session/prompt")) => {
                out.send(error(
                    id,
                    INVALID_PARAMS,
                    "no such session: session/new first",
                ))
                .await
            }
            (None, Some("session/cancel")) if ours => {
                if inbox.send(FromClient::Cancel).await.is_err() {
                    return;
                }
                true
            }
            (Some(id), method) => {
                out.send(error(
                    id,
                    METHOD_NOT_FOUND,
                    &format!("{} is not served over the relay", method.unwrap_or("?")),
                ))
                .await
            }
            // The client's other notifications, and responses: the bridge
            // sends it no request.
            (None, _) => true,
        };
        if !sent {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(relay: &str, audience: Option<&str>, idle_minutes: u64) -> config::Session {
        config::Session {
            relay: relay.to_owned(),
            audience: audience.map(str::to_owned),
            idle_minutes,
        }
    }

    #[test]
    fn relays_that_are_taken() {
        assert_eq!(Relay::from_config(&table("", None, 0)).unwrap(), None);
        let cases = [
            (table("relay.example.ts.net:7000", None, 0), 10 * 60),
            (table("100.64.0.9:7000", Some("review-relay"), 3), 3 * 60),
            (table("[fd7a::1]:7000", None, MAX_IDLE_MINUTES), 60 * 60),
        ];
        for (table, idle_s) in cases {
            let relay = Relay::from_config(&table).unwrap().unwrap();
            assert_eq!(relay.address, table.relay);
            assert_eq!(relay.audience, table.audience);
            assert_eq!(relay.idle, Duration::from_secs(idle_s));
        }
    }

    #[test]
    fn relays_that_are_refused() {
        let cases = [
            (
                table("", Some("x"), 0),
                "mean nothing without session.relay",
            ),
            (table("", None, 5), "mean nothing without session.relay"),
            (table("relay", None, 0), "is not HOST:PORT"),
            (table(":7000", None, 0), "is not HOST:PORT"),
            (table("relay:0", None, 0), "is not HOST:PORT"),
            (table("relay:http", None, 0), "is not HOST:PORT"),
            (table("relay:7000:7001", None, 0), "is not HOST:PORT"),
            (table("[]:7000", None, 0), "is not HOST:PORT"),
            (table("http://relay:7000", None, 0), "is not HOST:PORT"),
            (table("relay:7000", Some(""), 0), "session.audience"),
            (table("relay:7000", Some("a&b"), 0), "session.audience"),
            (table("relay:7000", None, MAX_IDLE_MINUTES + 1), "is over"),
        ];
        for (table, expected) in cases {
            let err = format!("{:#}", Relay::from_config(&table).unwrap_err());
            assert!(err.contains(expected), "{table:?}: {err}");
        }
    }

    #[test]
    fn secrets_are_replaced_in_every_string() {
        let redact: Redact = Arc::new(|s: &str| s.replace("sekrit", "[REDACTED]"));
        let msg = json!({"a": ["sekrit \"quoted\"", 1, {"sekrit": "x"}], "b": null});
        assert_eq!(
            redacted(msg, &redact),
            json!({"a": ["[REDACTED] \"quoted\"", 1, {"[REDACTED]": "x"}], "b": null})
        );
    }
}
