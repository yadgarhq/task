//! `TaskService`. Business rules here; storage over the `-db` API, never directly.

use tonic::Status;
use yadgar_dial::Deadline;

use crate::pb::yadgar::task::v1 as db;
use crate::pb::yadgar::task::v1::task_db_service_client::TaskDbServiceClient;
use crate::pb::yadgar::taskapi::v1 as api;
use crate::rules;

/// THE `TaskService` IMPLEMENTATION, AND NOTHING ELSE.
///
/// **The rule that decides what is in which file is mechanical, so a reader
/// never has to guess and a later change never has to negotiate.** The six
/// trait methods are in `handlers`. Everything they CALL is here: `tel_scope`,
/// which carries a request's scope into telemetry's shape; `passthrough`, which
/// maps a `-db` failure into the code and the words a public caller is allowed
/// to see; `Task` itself and its inherent methods. So the handlers read as the
/// six things this service answers, and this file reads as what answering one
/// costs — each half stands up on its own.
///
/// PRIVATE, so the public surface is exactly what it was. `Task` and its trait
/// implementation are reached at `yadgar_task::service` as before — a trait impl
/// is visible wherever the trait and the type are, whatever file it sits in.
/// Being a CHILD module is also what lets it reach `Task`'s private `db` field,
/// `tel_scope` and `passthrough` without any of them widening.
mod handlers;

/// Keyed retries (ADR-1051): the lookup ahead of the read, and what a hit
/// replays. A child for the same reason `handlers` is one.
mod keyed;

/// KNOWN LIMITATION, recorded rather than hidden: an error path returns via `?`,
/// which drops the `Call`, and a dropped call records `UNRECORDED` rather than the
/// real gRPC status. So failures are counted but not yet classified.
///
/// Fixing it means threading the status through every `?` site, which is a
/// restructure rather than an addition — deliberately not done in the same change
/// that established the coverage.
///
/// Copy the scope fields a record needs, before the request is consumed.
///
/// An absent scope yields empty strings rather than an error: the call is refused
/// on its own merits with INVALID_ARGUMENT, and telemetry must never be the thing
/// that fails a request (D67).
fn tel_scope(
    scope: Option<&crate::pb::yadgar::common::v1::Scope>,
) -> yadgar_telemetry::observe::Scope {
    yadgar_telemetry::observe::Scope {
        request_id: scope.map(|s| s.request_id.clone()).unwrap_or_default(),
        instance_id: scope.map(|s| s.instance_id.clone()).unwrap_or_default(),
        user_id: scope.map(|s| s.user_id.clone()).unwrap_or_default(),
        project_id: scope.map(|s| s.project_id.clone()).unwrap_or_default(),
    }
}

#[derive(Clone)]
pub struct Task {
    db: TaskDbServiceClient<tonic::transport::Channel>,
    /// The `-db` request timeout the channel was dialled with (ADR-1019): the
    /// CEILING on every `-db` call. The effective bound is the smaller of this
    /// and what the caller's own deadline has left.
    ceiling: std::time::Duration,
}

impl Task {
    pub fn new(channel: tonic::transport::Channel, ceiling: std::time::Duration) -> Self {
        Self {
            db: TaskDbServiceClient::new(channel),
            ceiling,
        }
    }

    /// The TransitionTask write, after the rule has allowed it. Moved here
    /// from `transition_task` for the file ceiling, with its reasoning.
    ///
    /// A store FAILED_PRECONDITION after a read that showed another version
    /// is VERSION_MISMATCH (ADR-1050), by [`version_refused`]'s mechanics.
    ///
    /// THE WRITE CARRIES `req.expect_version`, NOT
    /// `current.meta.version`, AND THAT IS DELIBERATE. A scanner reads
    /// the read-then-check-then-write in `transition_task` as a race and proposes
    /// substituting the version just read. Doing so would introduce a
    /// real defect, so the reasoning is recorded here rather than left
    /// to be rediscovered.
    ///
    /// `expect_version` is the CALLER'S claim about what it saw. It is
    /// the compare half of a compare-and-set, and it exists to refuse a
    /// caller that acted on a stale read. Replacing it with a version
    /// this service read microseconds ago launders a stale expectation
    /// into a fresh one: a write that must be refused would then
    /// succeed, and the caller would never learn it had overwritten
    /// somebody else's change.
    ///
    /// THERE IS NO ARM THAT SKIPS THE COMPARE. `task-db`'s
    /// `write.rs::update` binds `expect_version` into the WHERE clause
    /// of every UPDATE — `WHERE id = ? AND version = ? AND deleted_at
    /// IS NULL AND <reach>` — and a mismatch makes `rows_affected()`
    /// zero, which it turns into FAILED_PRECONDITION. Zero is not a
    /// wildcard there; it is simply a version no row holds.
    ///
    /// A SECOND CHECK HERE WOULD CATCH NOTHING. Only the comparison
    /// inside the store's transaction is atomic with the write. One
    /// added here passes in exactly the cases the CAS passes, and in
    /// the racing case — a writer committing between this read and that
    /// UPDATE — it passes too, because it is reading the same stale row.
    ///
    /// THE CAS IS ALSO WHAT MAKES THE RULE CHECK ABOVE SOUND. Any
    /// change that could invalidate `may_transition(from, to)` is a
    /// change of STATUS, a status change is a write, and every write
    /// bumps `version` — so the racing writer this handler cannot see
    /// is one the CAS refuses on its behalf.
    ///
    /// ONE LOOSE END, AND IT IS IN EXACTLY ONE PLACE. A review claimed
    /// `expect_version + 1` is live code both here and in
    /// `task-db/src/write.rs`. IT IS NOT. In THIS crate the expression
    /// survives only as the WORDS of the last paragraph below, which
    /// describes what the handler used to do and no longer does;
    /// there is no such arithmetic on any executable line here.
    ///
    /// In `task-db/src/write.rs` it IS live: the SQL sets `version =
    /// version + 1`, and the response's `Meta.version` is then computed
    /// as `req.expect_version + 1` rather than read back. That is
    /// correct only BECAUSE the CAS guarantees the stored version
    /// equalled `expect_version`. If that side is ever changed to read
    /// the version back, the change belongs there alone — this
    /// repository holds no second copy to keep in step.
    ///
    /// The STORE'S meta, as `edit_task` already does. This used to
    /// discard the response and synthesise one from the request —
    /// `id` from `req.id`, `version` from `expect_version + 1` — which
    /// asserted two things this service cannot know: that `-db`
    /// increments by exactly one, and that no other Meta field the
    /// store fills in differs from the zero value. On a replay the
    /// second is plainly false, since the version is the ORIGINAL
    /// write's and the project comes from the scope. A synthesised
    /// envelope is a guess wearing the shape of an answer.
    async fn write_transition(
        &self,
        req: api::TransitionTaskRequest,
        current: &db::Task,
        to: db::TaskStatus,
        caller_fingerprint: Vec<u8>,
        deadline: Deadline,
    ) -> Result<db::UpdateTaskResponse, Status> {
        let read_version = current.meta.as_ref().map_or(0, |m| m.version);
        let expect_version = req.expect_version;
        deadline
            .call(
                self.ceiling,
                tonic::Request::new(crate::writes::transition_request(
                    req,
                    current,
                    to,
                    caller_fingerprint,
                )),
                |r| {
                    let mut db = self.db.clone();
                    async move { db.update_task(r).await }
                },
            )
            .await
            .map_err(|e| {
                version_refused(
                    e,
                    "transition",
                    "transition",
                    Some(read_version),
                    expect_version,
                )
            })
            .map(tonic::Response::into_inner)
    }

    /// WHAT A TRANSITION MUST SETTLE FROM THE STORE BEFORE ANYTHING IS
    /// WRITTEN: the task as the store holds it now, the status that task is
    /// in, and the rule's verdict on moving from it to `to`.
    ///
    /// The request-only half, the read key and the target, is
    /// [`transition_target`]. It was part of this helper until ADR-1051 put the
    /// keyed lookup between the two: the lookup runs after the request-only
    /// checks and before any read, so this runs only after a miss.
    ///
    /// The seam it leaves behind in `transition_task` is the real one: what may
    /// happen, and then what happens. The long `expect_version` commentary
    /// stayed with the write it is about.
    ///
    /// Returns the task as it stands. The status it was in is NOT returned:
    /// `from` is the store's recorded `previous_status` (ADR-1051 rule 7), and
    /// this read's status is used only for the rule.
    ///
    /// THE REQUEST IS BORROWED, because `transition_task` still consumes it
    /// afterwards, on the write.
    async fn decide_transition(
        &self,
        req: &api::TransitionTaskRequest,
        key: db::get_task_request::Key,
        to: db::TaskStatus,
        deadline: Deadline,
    ) -> Result<db::Task, Status> {
        let current = deadline
            .call(
                self.ceiling,
                tonic::Request::new(db::GetTaskRequest {
                    scope: req.scope.clone(),
                    key: Some(key),
                }),
                |r| {
                    let mut db = self.db.clone();
                    async move { db.get_task(r).await }
                },
            )
            .await
            .map_err(|e| passthrough(e, "transition-read"))?
            .into_inner()
            .task
            .ok_or_else(|| Status::not_found("no such task in this scope"))?;

        let from = db::TaskStatus::try_from(current.status)
            .map_err(|_| Status::internal("the stored status is not a known value"))?;

        // THE RULE. Checked here, in the logic tier, because -db owns the
        // boundary and not the rules.
        //
        // INVALID_ARGUMENT, not FAILED_PRECONDITION. `passthrough`
        // documents the latter as a refusal a re-read may clear, and
        // there is nothing to re-read: DROPPED -> OPEN is refused by the rule
        // itself and will be refused identically forever. A code that
        // invites a retry which can never succeed is worse than a plain
        // refusal — a client obeying the contract loops.
        rules::may_transition(from, to).map_err(|e| Status::invalid_argument(e.to_string()))?;

        Ok(current)
    }
}

/// The request-only half of an edit: the paths it writes and the read key,
/// after every check that needs nothing but the request. They run before the
/// keyed lookup (ADR-1051) and before any read, so a malformed request costs
/// no store call. Moved out of `edit_task` with its reasoning, unchanged.
fn edit_target(
    req: &api::EditTaskRequest,
) -> Result<(Vec<&'static str>, db::get_task_request::Key), Status> {
    // THE MASK FIRST, before the store is touched at all. Resolving it
    // is a pure decision about the request, so a mask naming a field
    // no edit may write is refused here rather than after a `get_task`
    // round trip whose answer was always going to be discarded.
    let paths = crate::writes::requested_paths(req.update_mask.as_ref())?;
    // The key, the patch's shape (including `expect_new_sha256`,
    // checked in full) and the body digest are decisions about the
    // request alone too, so they are settled before the read as
    // well. In patch mode the digest is over the PRE-edit
    // body, so only its length is settled here; `writes::patched`
    // compares it after the read (ADR-1008).
    let key = crate::writes::target_key(&req.id, req.number)?;
    crate::writes::check_patch(req, &paths)?;
    crate::writes::check_body_digest(req, &paths)?;

    // THE TITLE RULE, and it applies only to an edit that WRITES a
    // title. It used to run before the mask was resolved, which made a
    // body-only edit impossible: `EditTaskRequest.title` is empty when
    // a caller does not intend to change it, and this refused the call
    // over a value it was never going to store. The rule itself is
    // unchanged — an untitled task is unfindable by the humans who
    // have to triage it — it simply now applies where a title is
    // actually at stake.
    if paths.contains(&"title") && req.title.trim().is_empty() {
        return Err(Status::invalid_argument("a task needs a title"));
    }
    // The bound, on the same condition: only a title being written.
    if paths.contains(&"title") {
        rules::title_fits(&req.title).map_err(Status::invalid_argument)?;
    }
    Ok((paths, key))
}

/// The request-only half of a transition: the read key and the target status.
/// Both are decisions about the request alone, so they run before the keyed
/// lookup and cost no store call.
fn transition_target(
    req: &api::TransitionTaskRequest,
) -> Result<(db::get_task_request::Key, db::TaskStatus), Status> {
    let key = crate::writes::target_key(&req.id, req.number)?;
    let to = db::TaskStatus::try_from(req.to)
        .map_err(|_| Status::invalid_argument("unknown target status"))?;
    Ok((key, to))
}

/// A `-db` failure is passed through with its CODE intact but not its message.
///
/// The code is the caller's contract — `FAILED_PRECONDITION` means a refusal a
/// re-read MAY clear, `NOT_FOUND` means what it says — and collapsing everything
/// to `INTERNAL` would destroy that. The word "may" is load-bearing and the arm
/// below carries why. The message is not passed through: it may name
/// tables and columns, and a client of the public API has no business seeing the
/// storage layer's vocabulary.
///
/// It IS logged, and that is not in tension with withholding it. Keeping the
/// message out of the RESPONSE is the point; discarding it altogether leaves the
/// operator with a code and no reason, and the log is the only place the reason
/// survives at all. There is no redaction concern in doing so — the log never
/// reaches the client.
///
/// The field is `db_message` rather than `message` because the event's own text
/// is already emitted under `message`. Naming it that a second time produces a
/// JSON object carrying the key TWICE, and no parser preserves a duplicate — each
/// keeps one value and drops the other, so an operator loses either the store's
/// reason or the words that say what the event is, with nothing to indicate
/// which. Verified against the JSON formatter this binary installs, not assumed.
fn passthrough(status: Status, op: &str) -> Status {
    tracing::warn!(
        op,
        code = ?status.code(),
        db_message = status.message(),
        "task-db returned an error"
    );
    match status.code() {
        tonic::Code::NotFound => Status::not_found("no such task in this scope"),
        // THE ADVICE IS CONDITIONAL ON WHAT THE CALLER CAN OBSERVE, and it has
        // to be. This used to say "re-read and retry" unconditionally, which was
        // followable only while the causes agreed: a caller who could not edit a
        // record could not read it either, so the re-read failed and the caller
        // stopped. ADR-0522 grants an owner who left a team the READ of their own
        // TEAM-visible record and deliberately does not widen the edit — so the
        // re-read now SUCCEEDS and returns the same version, and a client obeying
        // the old advice re-sent a byte-identical request for ever. The rule this
        // broke is stated a hundred lines below, at the `may_transition` refusal:
        // a code that invites a retry which can never succeed is worse than a
        // plain refusal.
        //
        // THREE DISJUNCTS DISCLOSE NO MORE THAN TWO DID. A caller who reaches the
        // record already knows it exists; one who cannot gets NOT_FOUND from the
        // re-read and learns nothing it could not learn anyway. Whether a row is
        // there is not decidable from this string.
        //
        // `task-db`'s own refusal was fixed to the same shape in task-db#33. This
        // is NOT that message forwarded — see the paragraph above on why the
        // store's text never reaches a caller — it is the same defect fixed
        // independently at the boundary that owns the words an end caller sees.
        tonic::Code::FailedPrecondition => Status::failed_precondition(
            "a version mismatch, no such task in this scope, or a task you may read but not \
             modify. Re-read: if the version has moved, retry with the new one. If the read \
             returns the same version, or returns nothing, retrying will fail identically.",
        ),
        tonic::Code::InvalidArgument => Status::invalid_argument("invalid request"),
        // The store could not serialise this write against a concurrent one, and
        // said so specifically. Folding it into INTERNAL here would undo the
        // reason `-db` distinguishes it at all: this is the one storage failure
        // a caller can act on, and the action is to send the request again.
        tonic::Code::Aborted => Status::aborted("the write raced another one — retry"),
        // THE STORE WAS UNREACHABLE, WHICH IS THE ONE FAILURE THIS SERVICE
        // ALREADY PROMISES TO REPORT AS ITSELF.
        //
        // Three places state the contract, and none of them was true: `main.rs`'s
        // module doc ("Failing a request with UNAVAILABLE is recoverable"),
        // `README.md`'s "It does not wait for task-db to be ready", and the
        // readiness-probe comment in `chart/templates/deployment.yaml`. All three
        // rest on the same design — this service deliberately does NOT block its
        // boot on the twin (D69), and the whole justification for that is that a
        // request arriving before `task-db` is reachable fails RECOVERABLY. The
        // `_ =>` arm below collapsed it into INTERNAL, so the recoverable failure
        // was indistinguishable from a bug and no client would retry it.
        tonic::Code::Unavailable => {
            Status::unavailable("the task store could not be reached in time — retry")
        }
        // ADR-1019: the caller's own deadline ran out on the `-db` hop (or the
        // `-db` request ceiling did). That is DEADLINE_EXCEEDED to the caller,
        // not UNAVAILABLE: a caller that already gave up has nothing to retry
        // against, and one with time left sees the true cause.
        tonic::Code::DeadlineExceeded => {
            Status::deadline_exceeded("the task store did not answer in time")
        }
        _ => Status::internal("the task store is unavailable"),
    }
}

/// A write the store refused, mapped as [`passthrough`] maps it under `op`,
/// with one exception: VERSION_MISMATCH (ADR-1042 rule 10, which ADR-1050
/// extends from EditTask to TransitionTask and RemoveTask).
///
/// **THE TOKEN FOLLOWS THE STORE'S REFUSAL, NEVER PRECEDES IT.** It is added
/// only when the store refused with FAILED_PRECONDITION AND this service's own
/// read already showed a version other than `expect_version`. A check ahead of
/// the store would refuse a same-key retry that `task-db` replays (D9): the
/// store claims the key before its compare-and-set, so a replay never reaches
/// the refusal this function names.
///
/// When the read matched, or there was no read to compare (`read_version` is
/// `None`: RemoveTask's read found nothing and the call went on to the store),
/// the store's refusal stays untokened: a writer landed between the read and
/// the write, or the task is out of reach or read-only for this caller, and
/// the store does not say which.
///
/// The message says "when read", because the task may have moved again
/// between this service's read and the store's compare-and-set. `noun` names
/// the write in it: "edit", "transition" or "removal".
fn version_refused(
    status: Status,
    op: &str,
    noun: &str,
    read_version: Option<u64>,
    expect_version: u64,
) -> Status {
    let mapped = passthrough(status, op);
    let Some(read_version) = read_version else {
        return mapped;
    };
    if mapped.code() != tonic::Code::FailedPrecondition || read_version == expect_version {
        return mapped;
    }
    Status::failed_precondition(format!(
        "VERSION_MISMATCH: the task was at version {read_version} when read, not the \
         expect_version {expect_version} this {noun} names; nothing was written. Re-read the \
         task and retry with the version you then see"
    ))
}
