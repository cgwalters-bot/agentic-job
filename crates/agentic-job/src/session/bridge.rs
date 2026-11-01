//! The bridge: how an operator reaches a session (specs/session.md).
//! `run` listens on a loopback port, which its root helper exposes on
//! the runner's tailnet name with `tailscale serve`, as HTTPS. A client
//! opens a WebSocket there, and each of its text messages is one of
//! ACP's JSON-RPC messages, with the session in the agent's role toward
//! it.
//!
//! Who connects is decided at the handshake, from what `tailscale serve`
//! adds: `Tailscale-User-Login`, the tailnet login of the person at the
//! other end, which serve sets for a user's device and strips from what
//! the client sent, must be one of `session.operators`. `Origin` must be
//! one of `session.origins`, so that a page of another site the
//! operator's browser has open cannot use the operator's tailnet identity
//! to attach (cross-site WebSocket hijacking). A tagged device has no
//! login; it is let in instead where `session.capability` is set and
//! serve, which then forwards it, names that app capability among the
//! node's in `Tailscale-App-Capabilities`. Such a client need not send an
//! `Origin`, since it is no browser, but one it sends must be allowed: a
//! browser on that device would otherwise lend the capability to any
//! site. The tailnet policy's grant, not this repository, then decides
//! which nodes may attach. A refused handshake leaves
//! the bridge listening; the first client let in is the only one, and
//! when it leaves the session ends.
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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::config;

/// The loopback port `run` listens on and its root helper serves: fixed,
/// so that both know it, and below Linux's ephemeral range, so that no
/// outgoing connection holds it.
pub const PORT: u16 = 7790;
/// Where `sandbox setup` leaves the address the client connects to,
/// `wss://NAME/` for the runner's tailnet name, for the job to publish:
/// secure-host's setup writes it for [`PORT`], which it keeps from the
/// sandbox user.
pub use ::secure_host::setup::SERVE_ENDPOINT as ENDPOINT_FILE;
/// What `tailscale serve` sets to the tailnet login of a user's device
/// (`tailscale serve --help`); it drops one the client sent.
pub const LOGIN_HEADER: &str = "Tailscale-User-Login";
/// What `tailscale serve --accept-app-caps` sets to a JSON object of the
/// connecting node's capabilities among those accepted; it drops one the
/// client sent. Tailscale encodes a value that is not ASCII as RFC 2047,
/// which is never decoded here: it is refused as not JSON.
pub const CAPABILITIES_HEADER: &str = "Tailscale-App-Capabilities";
/// The longest `Tailscale-App-Capabilities` taken, in bytes: serve
/// forwards only the one accepted capability, with the grant's values.
const MAX_CAPABILITIES_BYTES: usize = 4096;
const NO_LOGIN: &str = "no tailnet login: not through tailscale serve, or from a tagged device";
const NO_CAPABILITY: &str = "no tailnet login or app capability: not through tailscale serve, \
                             or the tailnet policy grants this device no session.capability";
const CAPABILITIES_TWICE: &str = "Tailscale-App-Capabilities more than once";
const CAPABILITIES_NOT_ASCII: &str =
    "Tailscale-App-Capabilities is not plain ASCII within its limit";
const CAPABILITIES_NOT_OBJECT: &str = "Tailscale-App-Capabilities is not a JSON object";
const CAPABILITY_NOT_GRANTED: &str = "the app capabilities do not include session.capability";
/// How long the session waits for a prompt unless `session.idle-minutes`
/// says otherwise: a runner waiting for nobody still costs its minutes.
const DEFAULT_IDLE_MINUTES: u64 = 10;
const MAX_IDLE_MINUTES: u64 = 60;
/// The most operators and origins: a few people and pages, not a
/// directory.
const MAX_ALLOWED: usize = 16;
/// The longest login or origin taken, in bytes.
const MAX_NAME_BYTES: usize = 256;
/// How long a connection has to finish its handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HANDSHAKES: usize = 16;
/// How long what is left to send the client gets once the session ended.
const CLOSE_GRACE: Duration = Duration::from_secs(5);
/// The longest message taken from the client: a prompt as large as the
/// largest task, with room for its JSON. A longer one ends the bridge.
pub(super) const MAX_MESSAGE_BYTES: usize = 2 * crate::run::MAX_TASK_BYTES as usize;
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
pub(super) const MAX_QUEUED_BYTES: usize = 8 << 20;
const PROTOCOL_VERSION: u64 = 1;
const PARSE_ERROR: i64 = -32700;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

/// Replaces the run's secrets in a string sent to the client.
pub type Redact = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// The session of a run's configuration, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listen {
    pub operators: Vec<String>,
    pub origins: Vec<String>,
    /// The Tailscale app capability that lets a node in without a login.
    pub capability: Option<String>,
    pub idle: Duration,
}

impl Listen {
    /// `None` where `session.listen` is not set: a task run.
    pub fn from_config(table: &config::Session) -> Result<Option<Self>> {
        let config::Session {
            listen,
            operators,
            origins,
            capability,
            idle_minutes,
            ..
        } = table;
        // The rest is inert without it: a caller's file names who may
        // attach once, and the workflow's `session` input turns it on per
        // run.
        if !listen {
            return Ok(None);
        }
        let capability = (!capability.is_empty()).then(|| capability.clone());
        if let Some(capability) = &capability {
            ensure!(
                is_capability(capability),
                "session.capability: {capability:?} is not a Tailscale app capability: \
                 DOMAIN/cap/NAME, with DOMAIN in lower case"
            );
        }
        // Empty would let nobody in: a session nobody can reach is a
        // runner spent for nothing. Operators may be empty where the
        // capability lets someone in; origins still bound browsers on
        // either path.
        let fewest_operators = usize::from(capability.is_none());
        for (key, list, fewest) in [
            ("operators", operators, fewest_operators),
            ("origins", origins, 1),
        ] {
            ensure!(
                (fewest..=MAX_ALLOWED).contains(&list.len()),
                "session.{key} needs {fewest} to {MAX_ALLOWED} entries with session.listen"
            );
        }
        for login in operators {
            // Compared as it is with the header: something like
            // `name@github` or `name@example.com`.
            ensure!(
                login.len() <= MAX_NAME_BYTES
                    && login.contains('@')
                    && login.bytes().all(|b| b.is_ascii_graphic()),
                "session.operators: {login:?} is not a tailnet login"
            );
        }
        for origin in origins {
            ensure!(
                origin.len() <= MAX_NAME_BYTES && is_origin(origin),
                "session.origins: {origin:?} is not an origin: https://HOST[:PORT], with HOST \
                 in lower case, or http:// for localhost"
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
            operators: operators.clone(),
            origins: origins.clone(),
            capability,
            idle: Duration::from_secs(minutes * 60),
        }))
    }

    /// Why REQUEST, a client's handshake, is refused; `None` to let it
    /// in. Each header must be there once, so that no proxy and no
    /// client can disagree about which counts. A client is let in by its
    /// login or, where `session.capability` is set, by its capability;
    /// the capability's refusal is the one given once serve sent it.
    fn refusal(&self, request: &Request) -> Option<&'static str> {
        // None: let in by its login.
        let by_login = self.login_refusal(request)?;
        match &self.capability {
            Some(capability) if request.headers().contains_key(CAPABILITIES_HEADER) => {
                self.capability_refusal(capability, request)
            }
            Some(_) if by_login == NO_LOGIN => Some(NO_CAPABILITY),
            _ => Some(by_login),
        }
    }

    /// Why REQUEST is not let in by its tailnet login.
    fn login_refusal(&self, request: &Request) -> Option<&'static str> {
        match (one(request, LOGIN_HEADER), one(request, "Origin")) {
            (None, _) => Some(NO_LOGIN),
            (Some(login), _) if !self.operators.iter().any(|o| o == login) => {
                Some("the tailnet login is not one of session.operators")
            }
            (_, None) => Some("no Origin"),
            (_, Some(origin)) if !self.origins.iter().any(|o| o == origin) => {
                Some("the Origin is not one of session.origins")
            }
            _ => None,
        }
    }

    /// Why REQUEST is not let in by CAPABILITY, which serve names among
    /// the node's: a JSON object keyed by capability, with the grant's
    /// values, which are not looked at.
    fn capability_refusal(&self, capability: &str, request: &Request) -> Option<&'static str> {
        let mut values = request.headers().get_all(CAPABILITIES_HEADER).iter();
        let (Some(value), None) = (values.next(), values.next()) else {
            return Some(CAPABILITIES_TWICE);
        };
        let bytes = value.as_bytes();
        if bytes.len() > MAX_CAPABILITIES_BYTES
            || !bytes.iter().all(|b| *b == b' ' || b.is_ascii_graphic())
        {
            return Some(CAPABILITIES_NOT_ASCII);
        }
        let Ok(Value::Object(granted)) = serde_json::from_slice::<Value>(bytes) else {
            return Some(CAPABILITIES_NOT_OBJECT);
        };
        if !granted.contains_key(capability) {
            return Some(CAPABILITY_NOT_GRANTED);
        }
        // No Origin is a client that is no browser. A browser always
        // sends one, so a page of another site is still kept out.
        let allowed = |origin: &[u8]| self.origins.iter().any(|o| o.as_bytes() == origin);
        let mut origins = request.headers().get_all("Origin").iter();
        match (origins.next(), origins.next()) {
            (None, _) => None,
            (Some(origin), None) if allowed(origin.as_bytes()) => None,
            (Some(_), None) => Some("the Origin is not one of session.origins"),
            (Some(_), Some(_)) => Some("Origin more than once"),
        }
    }
}

/// The value of REQUEST's header NAME where it is there once.
fn one<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    let mut values = request.headers().get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok(),
        _ => None,
    }
}

/// Whether TEXT is a Tailscale app capability name, `DOMAIN/cap/NAME`
/// (`example.com/cap/agentic-job-session`), narrowly enough that it is
/// one argument of `tailscale serve --accept-app-caps`, which takes a
/// comma-separated list.
fn is_capability(text: &str) -> bool {
    let mut parts = text.split('/');
    let (Some(domain), Some("cap"), Some(name), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let domain_ok = domain.contains('.')
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b));
    let name_ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    text.len() <= MAX_NAME_BYTES && domain_ok && name_ok
}

/// Whether TEXT is an origin as a browser sends it: a scheme, a host and
/// a port where it is not the scheme's, and nothing after them. Plain
/// HTTP only for a page on the operator's own machine: anyone on the path
/// to another could put script in it, which would then connect with the
/// operator's tailnet identity.
fn is_origin(text: &str) -> bool {
    let (local, authority) = match text.strip_prefix("https://") {
        Some(authority) => (false, authority),
        None => match text.strip_prefix("http://") {
            Some(authority) => (true, authority),
            None => return false,
        },
    };
    let (host, port) = authority.split_once(':').unwrap_or((authority, "80"));
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b));
    let port_ok = port.parse::<u16>().is_ok_and(|p| p != 0) && !port.starts_with('0');
    host_ok && port_ok && (!local || matches!(host, "localhost" | "127.0.0.1"))
}

/// What a session is given to reach its client.
pub struct Bridge {
    pub listen: Listen,
    /// Bound already, on loopback, so that a port that is taken stops
    /// the run before the agent starts.
    pub listener: std::net::TcpListener,
    pub redact: Redact,
}

impl Bridge {
    /// Binds [`PORT`] on loopback, where the root helper's `tailscale serve` passes
    /// connections on. Loopback alone: the tailnet's peers come through
    /// serve, which names them; the sandbox user is kept from this port
    /// by the network rules (`sandbox::network`).
    pub fn bind(listen: Listen, redact: Redact) -> Result<Self> {
        let address = (std::net::Ipv4Addr::LOCALHOST, PORT);
        let listener = std::net::TcpListener::bind(address)
            .with_context(|| format!("listening on 127.0.0.1:{PORT} for the session's client"))?;
        Ok(Self {
            listen,
            listener,
            redact,
        })
    }
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
    /// MSG as a message's text, with the room it takes; none for one
    /// that could never fit.
    fn line(&self, msg: Value) -> (String, Option<u32>) {
        let text = redacted(msg, &self.redact).to_string();
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

/// A bridge that is listening.
pub(super) struct Connected {
    /// Passes a notification of the agent's on to the client.
    pub send: Box<dyn Fn(Value) + Send + Sync>,
    pub from_client: mpsc::Receiver<FromClient>,
    pub idle: Duration,
    pub close: Close,
}

/// Stops listening, and hangs up on the client once the session has
/// ended: the client learns of the end at once, not when `run` exits
/// after its hand-back.
pub(super) struct Close {
    guard: Option<crate::sandbox::session::Guard>,
    /// Listens, and then reads the client's messages.
    reader: tokio::task::JoinHandle<()>,
    /// The writer, once a client was let in.
    writer: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    done: oneshot::Sender<()>,
}

impl Close {
    pub(super) async fn close(self) -> Result<()> {
        // Root retains its duplicate even if revocation fails or this future
        // is cancelled. Release our listener only after requesting teardown.
        let revoked = match self.guard {
            Some(guard) => guard.close().await,
            None => Ok(()),
        };
        self.reader.abort();
        // The writer sends what was queued for the client, and hangs up.
        let _ = self.done.send(());
        let writer = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(mut writer) = writer else {
            return revoked;
        };
        if tokio::time::timeout(CLOSE_GRACE, &mut writer)
            .await
            .is_err()
        {
            writer.abort();
        }
        revoked
    }
}

type Socket = WebSocketStream<TcpStream>;

/// What waits for the client to be let in.
struct Waiting {
    listener: TcpListener,
    listen: Listen,
    out: Outbox,
    inbox: mpsc::Sender<FromClient>,
    session_id: watch::Receiver<Option<String>>,
    closing: oneshot::Receiver<()>,
    writer: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl Bridge {
    /// Starts listening for the client. SESSION_ID is the agent's
    /// session, once there is one: the client attaches to it.
    pub(super) fn start(self, session_id: watch::Receiver<Option<String>>) -> Result<Connected> {
        let guard = if std::path::Path::new(ENDPOINT_FILE).exists() {
            Some(crate::sandbox::session::Guard::start(&self.listener)?)
        } else {
            // Unprepared hosts are used by the loopback-only protocol tests.
            None
        };
        self.listener
            .set_nonblocking(true)
            .context("listening for the session's client")?;
        let listener =
            TcpListener::from_std(self.listener).context("listening for the session's client")?;
        let (lines, outgoing) = mpsc::unbounded_channel();
        let (gone, _) = watch::channel(false);
        let hang_up = HangUp {
            room: Arc::new(Semaphore::new(MAX_QUEUED_BYTES)),
            gone: Arc::new(gone),
        };
        let out = Outbox {
            lines,
            hang_up,
            attached: Arc::new(AtomicBool::new(false)),
            redact: self.redact,
        };
        let (inbox, from_client) = mpsc::channel(INBOX);
        let (done, closing) = oneshot::channel();
        let writer = Arc::new(Mutex::new(None));
        let idle = self.listen.idle;
        let waiting = Waiting {
            listener,
            listen: self.listen,
            out: out.clone(),
            inbox,
            session_id,
            closing,
            writer: writer.clone(),
        };
        let reader = tokio::spawn(serve(waiting, outgoing));
        Ok(Connected {
            // A client that went away, or has not come yet, is no reason
            // to stop the agent.
            send: Box::new(move |msg| out.notify(msg)),
            from_client,
            idle,
            close: Close {
                guard,
                reader,
                writer,
                done,
            },
        })
    }
}

/// Takes connections until one is let in, and then serves it alone: a
/// later connection is closed unanswered, and the session ends when this
/// client leaves.
async fn serve(waiting: Waiting, outgoing: mpsc::UnboundedReceiver<Line>) {
    let Waiting {
        listener,
        listen,
        out,
        inbox,
        session_id,
        closing,
        writer,
    } = waiting;
    let socket = admit(&listener, &listen).await;
    eprintln!("session: a client is attached");
    let (sink, stream) = socket.split();
    let hang_up = out.hang_up.clone();
    *writer.lock().unwrap_or_else(PoisonError::into_inner) =
        Some(tokio::spawn(write_lines(sink, outgoing, closing, hang_up)));
    // The port stays owned until serve is revoked, even if reaping fails:
    // an agent that bound it once
    // it was free would be handed every later connection through serve,
    // with the operator's login on it.
    tokio::select! {
        () = read_lines(stream, out, inbox, session_id) => {}
        () = refuse_all(&listener) => {}
    }
    refuse_all(&listener).await;
}

/// A stalled unauthenticated connection cannot occupy the only admission
/// slot. Bound both the number of pending upgrades and their lifetime.
async fn admit(listener: &TcpListener, listen: &Listen) -> Socket {
    let mut pending = Vec::new();
    loop {
        tokio::select! {
            stream = accept(listener) => {
                if pending.len() == MAX_HANDSHAKES {
                    // Do not let parked unauthenticated sockets reserve all
                    // slots: a newcomer displaces the oldest pending upgrade.
                    drop(pending.remove(0));
                }
                pending.push(Box::pin(tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(stream, listen))));
            }
            (result, index, _) = async { futures::future::select_all(pending.iter_mut()).await }, if !pending.is_empty() => {
                drop(pending.remove(index));
                match result {
                    Ok(Ok(socket)) => return socket,
                    Ok(Err(why)) => eprintln!("session: refused a connection: {why}"),
                    Err(_) => eprintln!("session: refused a connection: handshake timed out"),
                }
            }
        }
    }
}

/// The next connection on LISTENER.
async fn accept(listener: &TcpListener) -> TcpStream {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => return stream,
            // Out of descriptors, for one: not a reason to stop, nor to
            // spin.
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

/// Closes every connection on LISTENER as it comes; never returns.
async fn refuse_all(listener: &TcpListener) {
    loop {
        drop(accept(listener).await);
    }
}

/// The WebSocket handshake on STREAM, refused unless LISTEN lets the
/// client in; why it was refused otherwise.
// The refusal's type is tungstenite's `Callback`'s.
#[allow(clippy::result_large_err)]
async fn handshake(stream: TcpStream, listen: &Listen) -> Result<Socket, String> {
    let mut refused = None;
    let check = |request: &Request, response: Response| match listen.refusal(request) {
        None => Ok(response),
        Some(why) => {
            refused = Some(why);
            let mut answer = ErrorResponse::new(Some(format!("{why}\n")));
            *answer.status_mut() = StatusCode::FORBIDDEN;
            Err(answer)
        }
    };
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
    let socket = tokio_tungstenite::accept_hdr_async_with_config(stream, check, Some(config)).await;
    match (socket, refused) {
        (_, Some(why)) => Err(why.to_owned()),
        (Ok(socket), None) => Ok(socket),
        (Err(e), None) => Err(format!("not a WebSocket handshake: {e}")),
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

/// Writes the client's messages until the session has ended and they are
/// all sent, the connection fails or it is hung up.
async fn write_lines(
    mut write: SplitSink<Socket, Message>,
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
            r = write.send(Message::text(line.text)) => r.is_ok(),
            () = hung_up(&mut gone) => false,
        };
        if !written {
            break;
        }
    }
    hang_up.now();
    let _ = write.close().await;
}

fn response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Reads the client's messages until it closes the connection, sends
/// one too long or the session stops listening; returning closes the
/// session's inbox, which ends the conversation.
async fn read_lines(
    mut read: SplitStream<Socket>,
    out: Outbox,
    inbox: mpsc::Sender<FromClient>,
    mut session_id: watch::Receiver<Option<String>>,
) {
    let mut gone = out.hang_up.gone.subscribe();
    let pending = Arc::new(Semaphore::new(PENDING_ANSWERS));
    let mut attached = None;
    loop {
        let read = tokio::select! {
            read = read.next() => read,
            () = hung_up(&mut gone) => return,
        };
        let parsed = match read {
            // Each text message is one of ACP's.
            Some(Ok(Message::Text(text))) => serde_json::from_str::<Value>(&text).ok(),
            Some(Ok(Message::Binary(_))) => None,
            // Answered by the library, or nothing.
            Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
            // Closed, failed, or a message over the limit.
            Some(Ok(Message::Close(_)) | Err(_)) | None => return,
        };
        let Some(msg) = parsed else {
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
                    &format!("{} is not served to the session's client", method.unwrap_or("?")),
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
    use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};

    use super::*;

    const OPERATOR: &str = "operator@github";
    const ORIGIN: &str = "https://review.example.ts.net";
    const CAPABILITY: &str = "example.com/cap/agentic-job-session";

    #[tokio::test]
    async fn stalled_handshake_does_not_block_the_operator() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let listen = Listen::from_config(&table(true, &[OPERATOR], &[ORIGIN], 0))
            .unwrap()
            .unwrap();
        let mut stalled = Vec::new();
        for _ in 0..MAX_HANDSHAKES {
            stalled.push(TcpStream::connect(address).await.unwrap());
        }
        let mut request = format!("ws://{address}/").into_client_request().unwrap();
        request
            .headers_mut()
            .insert(LOGIN_HEADER, OPERATOR.parse().unwrap());
        request
            .headers_mut()
            .insert("Origin", ORIGIN.parse().unwrap());
        tokio::time::timeout(Duration::from_secs(2), async {
            let client = async {
                let stream = TcpStream::connect(address).await.unwrap();
                tokio_tungstenite::client_async(request, stream).await
            };
            let (server, client) = tokio::join!(admit(&listener, &listen), client);
            client.unwrap();
            drop(server);
        })
        .await
        .expect("one stalled handshake must not hold up an operator for ten seconds");
        drop(stalled);
    }

    fn table(
        listen: bool,
        operators: &[&str],
        origins: &[&str],
        idle_minutes: u64,
    ) -> config::Session {
        let owned = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect();
        config::Session {
            listen,
            operators: owned(operators),
            origins: owned(origins),
            idle_minutes,
            ..config::Session::default()
        }
    }

    /// TABLE with `session.capability = CAPABILITY`.
    fn with_capability(table: config::Session, capability: &str) -> config::Session {
        config::Session {
            capability: capability.to_owned(),
            ..table
        }
    }

    #[test]
    fn sessions_that_are_taken() {
        for off in [
            table(false, &[], &[], 0),
            table(false, &[OPERATOR], &[ORIGIN], 5),
        ] {
            assert_eq!(Listen::from_config(&off).unwrap(), None);
        }
        let cases = [
            (table(true, &[OPERATOR], &[ORIGIN], 0), 10 * 60),
            (
                table(
                    true,
                    &[OPERATOR, "a.b@example.com"],
                    &["http://localhost:5173", ORIGIN],
                    3,
                ),
                3 * 60,
            ),
            (
                table(
                    true,
                    &[OPERATOR],
                    &[
                        "https://review.example.ts.net:8443",
                        "http://127.0.0.1:8080",
                    ],
                    MAX_IDLE_MINUTES,
                ),
                60 * 60,
            ),
            // The capability lets nodes in with no operator listed.
            (
                with_capability(table(true, &[], &[ORIGIN], 0), CAPABILITY),
                10 * 60,
            ),
            (
                with_capability(
                    table(true, &[OPERATOR], &[ORIGIN], 0),
                    "tailscale.example/cap/Agent_job.2",
                ),
                10 * 60,
            ),
        ];
        for (table, idle_s) in cases {
            let listen = Listen::from_config(&table).unwrap().unwrap();
            assert_eq!(listen.operators, table.operators);
            assert_eq!(listen.origins, table.origins);
            assert_eq!(
                listen.capability.unwrap_or_default(),
                table.capability,
                "{table:?}"
            );
            assert_eq!(listen.idle, Duration::from_secs(idle_s));
        }
    }

    #[test]
    fn sessions_that_are_refused() {
        let many: Vec<String> = (0..=MAX_ALLOWED).map(|i| format!("u{i}@github")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let cases = [
            (
                table(true, &[], &[ORIGIN], 0),
                "session.operators needs 1 to",
            ),
            (
                table(true, &[OPERATOR], &[], 0),
                "session.origins needs 1 to",
            ),
            (
                table(true, &many, &[ORIGIN], 0),
                "session.operators needs 1 to",
            ),
            (
                table(true, &["operator"], &[ORIGIN], 0),
                "is not a tailnet login",
            ),
            (
                table(true, &["a b@github"], &[ORIGIN], 0),
                "is not a tailnet login",
            ),
            (table(true, &[""], &[ORIGIN], 0), "is not a tailnet login"),
            (table(true, &[OPERATOR], &["*"], 0), "is not an origin"),
            (
                table(true, &[OPERATOR], &["https://"], 0),
                "is not an origin",
            ),
            (
                table(true, &[OPERATOR], &["review.example.ts.net"], 0),
                "is not an origin",
            ),
            (
                table(true, &[OPERATOR], &["https://review.example.ts.net/"], 0),
                "is not an origin",
            ),
            (
                table(true, &[OPERATOR], &["https://Review.example.ts.net"], 0),
                "is not an origin",
            ),
            (table(true, &[OPERATOR], &["null"], 0), "is not an origin"),
            (
                table(true, &[OPERATOR], &["http://review.example.ts.net"], 0),
                "is not an origin",
            ),
            (
                table(true, &[OPERATOR], &["https://a:b:c"], 0),
                "is not an origin",
            ),
            (
                table(true, &[OPERATOR], &["https://]"], 0),
                "is not an origin",
            ),
            (
                table(true, &[OPERATOR], &["https://review:0"], 0),
                "is not an origin",
            ),
            (
                table(true, &[OPERATOR], &["https://review:"], 0),
                "is not an origin",
            ),
            (
                table(true, &[OPERATOR], &["https://review:65536"], 0),
                "is not an origin",
            ),
            (
                table(true, &[OPERATOR], &[ORIGIN], MAX_IDLE_MINUTES + 1),
                "is over",
            ),
            (
                with_capability(table(true, &many, &[ORIGIN], 0), CAPABILITY),
                "session.operators needs 0 to",
            ),
            (
                with_capability(table(true, &[], &[], 0), CAPABILITY),
                "session.origins needs 1 to",
            ),
        ];
        let long = format!("example.com/cap/{}", "x".repeat(MAX_NAME_BYTES));
        let mut cases = Vec::from(cases);
        for capability in [
            "agentic-job-session",
            "example.com/agentic-job-session",
            "example.com/caps/session",
            "example.com/cap/",
            "/cap/session",
            "localhost/cap/session",
            "Example.com/cap/session",
            "example.com/cap/a/b",
            "example.com/cap/a,example.com/cap/b",
            "example.com/cap/a b",
            "example.com/cap/sessi\u{f6}n",
            " example.com/cap/session",
            long.as_str(),
        ] {
            cases.push((
                with_capability(table(true, &[], &[ORIGIN], 0), capability),
                "is not a Tailscale app capability",
            ));
        }
        for (table, expected) in cases {
            let err = format!("{:#}", Listen::from_config(&table).unwrap_err());
            assert!(err.contains(expected), "{table:?}: {err}");
        }
    }

    /// The handshake's headers, as `tailscale serve` passes them on, to
    /// a session that also takes CAPABILITY.
    #[test]
    fn who_is_let_in() {
        let config = with_capability(table(true, &[OPERATOR], &[ORIGIN], 0), CAPABILITY);
        let listen = Listen::from_config(&config).unwrap().unwrap();
        let granted = format!(r#"{{"{CAPABILITY}":[{{"to":"any"}}]}}"#);
        let granted = granted.as_str();
        let other = r#"{"example.com/cap/other":[{}]}"#;
        let long = format!(
            r#"{{"{CAPABILITY}":["{}"]}}"#,
            "x".repeat(MAX_CAPABILITIES_BYTES)
        );
        let not_ascii = format!(r#"{{"{CAPABILITY}":["café"]}}"#);
        type Headers<'a> = &'a [(&'a str, &'a str)];
        let cases: &[(Headers, Option<&str>)] = &[
            (&[(LOGIN_HEADER, OPERATOR), ("Origin", ORIGIN)], None),
            (&[("Origin", ORIGIN)], Some("no tailnet login")),
            (
                &[(LOGIN_HEADER, "other@github"), ("Origin", ORIGIN)],
                Some("not one of session.operators"),
            ),
            (
                &[(LOGIN_HEADER, "OPERATOR@github"), ("Origin", ORIGIN)],
                Some("not one of session.operators"),
            ),
            (
                &[
                    (LOGIN_HEADER, "other@github"),
                    (LOGIN_HEADER, OPERATOR),
                    ("Origin", ORIGIN),
                ],
                Some("no tailnet login"),
            ),
            (&[(LOGIN_HEADER, OPERATOR)], Some("no Origin")),
            (
                &[(LOGIN_HEADER, OPERATOR), ("Origin", "https://evil.example")],
                Some("not one of session.origins"),
            ),
            (
                &[
                    (LOGIN_HEADER, OPERATOR),
                    ("Origin", ORIGIN),
                    ("Origin", ORIGIN),
                ],
                Some("no Origin"),
            ),
            // A node the tailnet policy grants the capability: no
            // browser, or a browser at an allowed page.
            (&[(CAPABILITIES_HEADER, granted)], None),
            (&[(CAPABILITIES_HEADER, granted), ("Origin", ORIGIN)], None),
            (
                &[
                    (CAPABILITIES_HEADER, granted),
                    ("Origin", "https://evil.example"),
                ],
                Some("not one of session.origins"),
            ),
            (
                &[
                    (CAPABILITIES_HEADER, granted),
                    ("Origin", ORIGIN),
                    ("Origin", ORIGIN),
                ],
                Some("Origin more than once"),
            ),
            (&[], Some("no tailnet login or app capability")),
            (
                &[(CAPABILITIES_HEADER, other)],
                Some("do not include session.capability"),
            ),
            (
                &[(CAPABILITIES_HEADER, "{}")],
                Some("do not include session.capability"),
            ),
            (
                &[
                    (CAPABILITIES_HEADER, granted),
                    (CAPABILITIES_HEADER, granted),
                ],
                Some("more than once"),
            ),
            (
                &[(CAPABILITIES_HEADER, "not json")],
                Some("not a JSON object"),
            ),
            (
                &[(CAPABILITIES_HEADER, &format!("[{granted}]"))],
                Some("not a JSON object"),
            ),
            (
                &[(CAPABILITIES_HEADER, &format!(r#""{CAPABILITY}""#))],
                Some("not a JSON object"),
            ),
            // How serve would encode a value that is not ASCII: not
            // decoded.
            (
                &[(CAPABILITIES_HEADER, "=?utf-8?q?=7B=7D?=")],
                Some("not a JSON object"),
            ),
            (
                &[(CAPABILITIES_HEADER, &not_ascii)],
                Some("not plain ASCII"),
            ),
            (
                &[(CAPABILITIES_HEADER, &format!("{granted}\t"))],
                Some("not plain ASCII"),
            ),
            (&[(CAPABILITIES_HEADER, &long)], Some("not plain ASCII")),
            // The login path is as it was: a login with no Origin is
            // refused, whether or not the node also has the capability.
            (&[(LOGIN_HEADER, OPERATOR)], Some("no Origin")),
            (
                &[(LOGIN_HEADER, OPERATOR), (CAPABILITIES_HEADER, granted)],
                None,
            ),
            (
                &[(LOGIN_HEADER, OPERATOR), (CAPABILITIES_HEADER, other)],
                Some("do not include session.capability"),
            ),
        ];
        fn request(headers: Headers) -> Request {
            let mut request = Request::new(());
            for (name, value) in headers {
                // Bytes, so that a value need not be visible ASCII.
                let value = HeaderValue::from_bytes(value.as_bytes()).unwrap();
                let name = HeaderName::try_from(*name).unwrap();
                request.headers_mut().append(name, value);
            }
            request
        }
        for &(headers, expected) in cases {
            let refusal = listen.refusal(&request(headers));
            match expected {
                None => assert_eq!(refusal, None, "{headers:?}"),
                Some(why) => assert!(
                    refusal.is_some_and(|r| r.contains(why)),
                    "{headers:?}: {refusal:?}"
                ),
            }
        }
        // Without session.capability, the header lets nobody in, and the
        // refusal is the login's.
        let logins = Listen::from_config(&table(true, &[OPERATOR], &[ORIGIN], 0))
            .unwrap()
            .unwrap();
        assert_eq!(
            logins.refusal(&request(&[(CAPABILITIES_HEADER, granted)])),
            Some(NO_LOGIN)
        );
        assert_eq!(
            logins.refusal(&request(&[(LOGIN_HEADER, OPERATOR), ("Origin", ORIGIN)])),
            None
        );
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
