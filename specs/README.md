# A first TLA+ model: proposal → check → apply

> This text is LLM generated.

`Pipeline.cfg` checks five properties of the pipeline: apply consumes the
immutable contents check accepted (`AcceptedOnly`), the writer does not execute
producer code (`CredentialIsolation`), an existing run-named branch blocks
another patch push (`BranchOnce`), a re-run of apply posts no accepted proposal
a second time (`AtMostOnce`), and apply leaves a proposal out only if it was
posted (`NoFalseSkip`). Each has a broken variant that TLC must reject.

`AtMostOnce` was false before apply had its guard: re-running apply on an
accepted comment posted the comment again, as
[issue 300](https://github.com/cgwalters-forge/agentic-job/issues/300) saw on
the forge. `BrokenGuard` keeps that pipeline as the negative control.

## Start with a state, then take a step

Open [Pipeline.tla](Pipeline.tla). A *state* is one value for every `VARIABLE`:
for example, an uploaded comment, an accepted artifact, and an empty history.
An *action* describes allowed changes from one state to the next. A prime means
the next value (`phase'`); `UNCHANGED` lists values that must stay put. `/\`
means “and”, `\/` means “or”, and `\E` means “there exists”. An action can choose
any value satisfying its conditions: TLC explores all those choices, not just
the happy path. `Init` defines the starting state; `Next` lists possible actions.

`Spec` allows these steps forever, including doing nothing (“stuttering”).
An *invariant* is a statement that must be true in every reachable state.
TLC searches the finite state graph breadth-first and stops with a trace when
an invariant becomes false. There is no fairness or liveness claim here.
`CHECK_DEADLOCK FALSE` permits terminal/refused/blocked runs; getting stuck is
not the security property we are checking.

## Where the model meets the code

`uploads` maps two immutable producer IDs to representative proposals:
`comment`, `patch`, `invalid`, or `marked`: a proposal holding the name apply
hides in what it posts. Each ID denotes a distinct payload, even if
both payloads have the same kind. `latest` is the ID currently under the same
artifact name. `Upload` represents hand-back from
[`run/handback.rs`](../crates/agentic-job/src/run/handback.rs), or a proposals-only
producer, and the upload action in
[`agentic-job.yml`](../.github/workflows/agentic-job.yml). A same-name upload
without deletion/overwrite conflicts and does not change the state. Successful
replacement has a fresh ID; it cannot mutate the old one. Missing/deleted IDs
fail downloads in reality rather than authorizing different bytes.

`accepted` identifies the checked copy of a proposal, with zero meaning no
applicable artifact. Producer IDs and checked IDs are different namespaces in
the workflow; the model labels a checked copy with its producer index, not with
a claim that the numeric IDs are equal. `Check` abstracts the collector plus
[`check/mod.rs`](../crates/agentic-job/src/check/mod.rs) and
[`check.yml`](../.github/workflows/check.yml): invalid proposals are refused,
and only accepted proposals are uploaded as `checked-outputs`. A `marked`
proposal is refused too. The legacy
proposals selector uses a name **before** validation; apply still uses check's
returned ID. Choosing any existing producer ID covers both selector routes.

`phase` is the check/apply job gate, not every workflow step. `Apply` abstracts
the writer's immutable-ID download and pinned gh-aw handlers in
[`agentic-job.yml`](../.github/workflows/agentic-job.yml). `history` records
successful effects as `(checked ID, used ID, kind)`: the forge's comments,
issues and pull requests. Apply's guard reads it as the implementation reads the
forge, for the name hidden in what the bot posted (`Evidence`). Only the bot's
posts count, so a commenter's is not in `history`; a posted `marked` proposal
is the bot's, and may name any proposal. `skipped` records what the guard left
out.
`branch` represents the persistent `agent-run-RUNID` branch: another patch push
cannot overwrite it. `Retry` represents re-running apply with its old accepted
artifact or re-running check (assuming its upload succeeds). Neither erases
forge effects. Conflicting checked-artifact uploads can instead fail without
another effect.

`credential` and `executes` describe the current writer step: apply holds the
write token but treats producer files as data. Applying a patch is not running
its code. Trusted workflow scripts, pinned handlers and Git are assumed to
interpret that data safely; this model does not verify their implementations.
Separate machines, read-only check permissions, and apply-only token placement
are documented in [the workflow guide](../docs/workflow.md).

Why the guard is apply's and not the handlers': the pinned
[add-comment handler](https://github.com/github/gh-aw/blob/462ed682857c4ab64d40f2c85e3738fa27834839/actions/setup/js/add_comment.cjs)
calls `issues.createComment` with a `processedCount` local to a new handler
instance, and comment-only apply has no checkout or existing-branch gate. The
pull request handler fails on an existing branch, but once a merged pull
request's branch is deleted it opens another.

## Run it

Install Java (21 works), Rust and curl, then from the repository root:

```sh
bash specs/check.sh
```

`JAVA_BIN` can name a non-default Java executable. The shell launcher runs
[specs-check](../crates/agentic-job/src/bin/specs-check.rs) to download the official
`tla2tools.jar` v1.7.4 and verify the SHA-256 pinned in source before execution.
The pin is the SHA-256 of the download whose SHA-1 the release notes publish; downloads and TLC state files stay in a temporary
directory printed at the start. `TMPDIR` can move it outside the checkout.
The script prints full TLC output and keeps each report there. No jar, generated
trace module, or state database is committed.

It checks [Session.tla](#writes-during-a-session-sessiontla) the same way.
The good config must exit 0 with TLC's completion message. Each negative control
must exit **12** and name its expected invariant; parse errors, Java failures,
unexpected successes and other failures fail the script. This follows gh-aw's
[negative-control pattern](https://github.com/github/gh-aw/blob/main/specs/work-queue/check.sh).

`BrokenName` resolves the artifact name again at apply, allowing a different
upload to replace what check accepted. It deliberately collapses producer and
checked-artifact names to demonstrate substitution, rather than literally
modeling both name registries. `BrokenWiring` lets apply take the ID a
caller wired, which may be a producer upload's, instead of looking it up as
check's upload of this run; the model labels a checked copy by its producer
index, so only wiring to another upload shows. `BrokenCredential` runs producer code in
the credential-bearing step. `BrokenBranch` permits overwriting the run branch.
These are at least one deliberately broken variant per **passing** invariant,
selected by constants in the same small module. `BrokenGuard` applies without looking
for what was posted, as apply did before issue 300. `BrokenMarker` lets check
accept a proposal holding the name, so that a posted proposal makes another
look applied.

The independent [specs CI workflow](../.github/workflows/specs.yml) runs this
command with `contents: read`, no secrets, the existing full checkout action
pin and `persist-credentials: false`. It runs repository model/checker code only
on a read-only machine; it neither depends on nor changes the e2e jobs, production
permissions, handler pins or token placement. It is not added to the aggregate
`ci` job or branch-required checks in this change.

## Reading a real counterexample

With TLC v1.8.0, Java 21, one worker, seed 1 and fingerprint 0, the passing
model reported:

```text
Model checking completed. No error has been found.
879 states generated, 501 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 10.
```

`BrokenGuard` exited 12 with `Error: Invariant AtMostOnce is violated.`
Its first three states initialize, upload a comment under ID 1, then accept it.
Here are the last three states from that actual trace (action locations omitted):

```text
State 4: <Apply>
/\ skipped = {}
/\ credential = TRUE
/\ history = <<[kind |-> "comment", used |-> 1, checked |-> 1]>>
/\ phase = "done"
/\ accepted = 1
/\ uploads = <<"comment", "absent">>
/\ executes = FALSE
/\ branch = FALSE
/\ latest = 1

State 5: <Retry>
/\ skipped = {}
/\ credential = FALSE
/\ history = <<[kind |-> "comment", used |-> 1, checked |-> 1]>>
/\ phase = "apply"
/\ accepted = 1
/\ uploads = <<"comment", "absent">>
/\ executes = FALSE
/\ branch = FALSE
/\ latest = 1

State 6: <Apply>
/\ skipped = {}
/\ credential = TRUE
/\ history = << [kind |-> "comment", used |-> 1, checked |-> 1],
   [kind |-> "comment", used |-> 1, checked |-> 1] >>
/\ phase = "done"
/\ accepted = 1
/\ uploads = <<"comment", "absent">>
/\ executes = FALSE
/\ branch = FALSE
/\ latest = 1
```

Read adjacent states as a diff: `Retry` resets job-local credential state but
keeps the prior effect. The second `Apply` appends a second effect for ID 1.
Nothing was swapped and no untrusted code ran, yet `AtMostOnce` is false.
TLC reported 317 generated states, 190 distinct states, and depth 6 before
stopping at this counterexample. With the guard, the same second `Apply` finds
ID 1 in `history` and adds it to `skipped` instead.

`BrokenMarker` exited 12 with `Error: Invariant NoFalseSkip is violated.` after
eight states: a comment is uploaded under ID 1 and a `marked` proposal under
ID 2; check accepts ID 2 and apply posts it; a re-run of check accepts ID 1,
and apply finds the posted name and leaves ID 1 out, never posted:

```text
State 8: <Apply>
/\ skipped = {1}
/\ history = <<[kind |-> "marked", used |-> 2, checked |-> 2]>>
```

These are model traces, not live forge re-runs.

## Writes during a session: Session.tla

[Session.tla](Session.tla) models
[writes during a session](session.md#writes-during-a-session-specified-not-built),
where apply runs during the session as well as at its end. `file` is what `run`
has read of the agent's outputs, append-only, up to three requests against an
output ceiling `Max` of two. `Write` is the agent writing one more, a `comment`
or an `invalid` one, while `phase` is `session`. The upload for request `n` is
`SubSeq(file, 1, n)`: it cannot change, since `file` only grows.

That assumes only `run` uploads to the run, which rested on the removed
sandbox user. Since [#2989](https://github.com/cgwalters-forge/agentic-job/issues/2989)
the agent is the runner's user and could upload any content under that name,
so the model no longer matches a session run. It is kept unchanged as the
design for a replacement premise, and its results do not hold today
([session.md](session.md#writes-during-a-session-specified-not-built)).

`InSession` is one dispatch of tracker's session apply workflow, for any
request, at any time, during the session or after it, any number of times:
whether the operator confirmed it does not matter to these properties. It
checks the whole upload, adds `n` to `accepted`, and appends the request to
`history` unless the guard finds its name there. `Stop`, `EndCheck`,
`EndApply` and `Retry` are the end of the run, as in `Pipeline.tla`: check all
of `file`, then apply what the guard does not find, and maybe apply again.
Each effect in `history` is one request posted with its name, `Name(p, end)`:
its position, since `file` is append-only, and the digest of what check
accepted. Applies are atomic steps, as the concurrency group makes them.

`Session.cfg` checks four properties: each effect is a request a check
accepted, as `run` read it (`AcceptedOnly`); no request is applied twice across
the session and the end (`AtMostOnce`); all effects together stay within the
ceiling (`Ceiling`); and no writer runs the agent's code
(`CredentialIsolation`). Each has a broken variant TLC must reject:

- `BrokenSessionInputs` applies the request the dispatch inputs carry, which
  may be anything, instead of fetching it from the run and checking it.
- `BrokenSessionGuard` lets the end-of-run apply post again what the session
  already posted: a comment is applied during the session, then at the end.
- `BrokenSessionName` names a request at the end after putting a partial run's
  note in its body, as apply's guard does today: the end does not find the
  comment the session posted, and posts it again.
- `BrokenSessionCeiling` checks request `n` alone instead of the upload ending
  at it. Three comments each pass, and the session applies all three.
- `BrokenSessionCredential` runs producer code in the writer.

With TLC v1.7.4 the passing model reported 228 states generated, 100 distinct,
depth 8. The negative controls fail at depths 3, 6, 6, 7 and 3.

As in `Pipeline.tla`, `CredentialIsolation` holds by construction unless its
constant breaks it; it records the claim rather than finding a path. The model
does not exercise the append-only read: `file` only grows by definition, and a
hand-back that differed from what `run` read would break `Ceiling` and
`AtMostOnce`. It leaves out what the workflow checks before it reaches
`check`'s code (the run's workflow, event, branch and attempt, the upload's
name and digest), and requests with a patch or `create_issue`, which wait for
the end. It assumes the guard sees every earlier post: the forge's search lag
for issues, and an apply token the guard cannot name, break that, as they do
for `Pipeline.tla`'s re-runs. Applies are atomic, so it does not show what
the concurrency group's cancellations do, which only delays or loses writes.

## Honest scope

This is a bounded model beside the code, **not a proof of the code**. It explores
two producer uploads, one proposal per upload and at most two successful effects
in one workflow run. It abstracts validation into valid/invalid, assumes trusted
policy/binary/handler source selection and immutable artifact IDs, and omits
network failures, Git hooks, sandbox exploits, partial multi-output application,
concurrent apply jobs, the forge's search lag, artifact expiry, branch deletion and forge/API retries.
Branch persistence is an assumption: deleting the branch removes that guard.
`Check` refusing every `marked` proposal is an assumption too: the handlers
decode entities and drop invisible characters after check, so the code also
counts only the first name in a body, the one apply puts before the request's
text (`a name the handlers decoded into a posted body` in `apply.test.cjs`).
A pull request whose branch was pushed without being opened is not completed
by a re-run; the model's `Apply` posts or skips as a whole.
Identical text uploaded under a new ID is not deduplicated by this model either.
Each upload stands for one proposal, so a half-applied attempt, posting some of a
run's proposals and not the rest, is not modelled: `workflow/apply.test.cjs`
covers it with `a re-run after a half-applied attempt applies only what was not`,
and that only the bot's posts count with the `a comment named by …` cases. The
bot is apply's token's principal (`github-actions[bot]` for the job token, the
PAT's user), not any bot; and a pull request's name covers its checked patch,
so a different patch is a different proposal (`a different patch with the same
request is not taken for the open pull request`).

`AcceptedOnly` is artifact/proposal identity, not byte-for-byte equality of final
forge text: trusted partial markers, sanitization, handler footers and caller-fixed
destinations may change its presentation. The model does not establish that a
patch changes only its checked paths; the trial/file-list checks and local
`workflow/apply.test.cjs` tests cover that separate implementation boundary.
There is no liveness, TLAPS or generated code.

When changing artifact selectors, check/upload gates, the pinned handlers,
branch behavior or token-bearing steps, review this model's corresponding
action and assumptions too. TLC cannot detect drift in workflow/Rust code it
does not execute; the negative controls test model assertions, not that mapping.
