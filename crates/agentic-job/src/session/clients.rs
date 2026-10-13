//! The clients attached to a session.
//!
//! A session is the agent-facing half of an ACP proxy: it is the agent's
//! client, and what it does not answer itself it can pass on. Who it
//! passes things on to is this list. For a task run the list is empty:
//! the session's own prompt is the only one, and the turn's end is the
//! session's. With a relay (`bridge`, specs/session.md) the list holds
//! the one client at its far end, attached before the agent starts, and
//! the session goes on after the task's turn to that client's prompts.
//!
//! Every message from the agent passes the transcript's tap, and the tap
//! hands its notifications to this list. Requests stay with the session:
//! its policy answers permission requests whether or not a person is
//! watching. Still open (docs/interactive.md): several clients, and one
//! that joins a session already running.
//!
//! The SDK's `Proxy` role is not what this is built on: it speaks
//! `_proxy/*` to a conductor that owns both of its connections, and a
//! task run has no client side for one to own. The session holds the
//! `Client` role toward the agent, which is the half a proxy and a task
//! run share; the bridge plays the `Agent` role toward its client.

use serde_json::Value;

/// One attached client: what passes the agent's messages on to it.
type Attached = Box<dyn Fn(Value) + Send + Sync>;

/// The attached clients of one session.
#[derive(Default)]
pub struct Clients {
    attached: Vec<Attached>,
}

impl std::fmt::Debug for Clients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Clients")
            .field("attached", &self.attached.len())
            .finish()
    }
}

impl Clients {
    /// No client: a task run.
    pub fn none() -> Self {
        Self::default()
    }

    /// Passes a notification from the agent on to every client. Requests
    /// stay with the session, which answers them from its policy.
    pub(super) fn relay(&self, msg: &Value) {
        if self.attached.is_empty() || !msg["id"].is_null() || msg["method"].is_null() {
            return;
        }
        for send in &self.attached {
            send(msg.clone());
        }
    }

    /// Attaches a client: SEND passes a notification on to it.
    pub(super) fn attach(&mut self, send: Attached) {
        self.attached.push(send);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tokio::sync::mpsc;

    use super::*;

    #[test]
    fn a_task_run_relays_to_nobody() {
        Clients::none().relay(&json!({"method": "session/update", "params": {}}));
    }

    #[test]
    fn notifications_reach_every_client() {
        let mut clients = Clients::none();
        let mut receivers = [(), ()].map(|()| {
            let (to_client, from_session) = mpsc::unbounded_channel();
            clients.attach(Box::new(move |msg| {
                let _ = to_client.send(msg);
            }));
            from_session
        });
        let update = json!({"jsonrpc": "2.0", "method": "session/update", "params": {"n": 1}});
        let messages = [
            update.clone(),
            // A request, and a response: the session's to deal with.
            json!({"jsonrpc": "2.0", "id": 1, "method": "session/request_permission"}),
            json!({"jsonrpc": "2.0", "id": 2, "result": {}}),
        ];
        for msg in &messages {
            clients.relay(msg);
        }
        for rx in &mut receivers {
            assert_eq!(rx.try_recv().ok(), Some(update.clone()));
            assert!(rx.try_recv().is_err());
        }
    }
}
