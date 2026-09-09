//! `TaskService`. Business rules here; storage over the `-db` API, never directly.

use tonic::Status;

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
/// that fails a request (D25).
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
}

impl Task {
    pub fn new(channel: tonic::transport::Channel) -> Self {
        Self {
            db: TaskDbServiceClient::new(channel),
        }
    }

    /// EVERYTHING A TRANSITION MUST SETTLE BEFORE ANYTHING IS WRITTEN, in the
    /// order it has to be settled in: the target status the request names, the
    /// task as the store holds it now, the status that task is in, and the
    /// rule's verdict on moving between the two.
    ///
    /// It is one helper rather than three because it is one decision. Each step
    /// is the input to the next — there is no reading of the store without a
    /// target to read it for, and no rule to apply without both ends of the
    /// move — so cutting between them would leave parts that only make sense
    /// read together, which is the split a line ceiling is there to discourage
    /// rather than to cause.
    ///
    /// The seam it leaves behind in `transition_task` is the real one: what may
    /// happen, and then what happens. The long `expect_version` commentary
    /// stayed with the write it is about.
    ///
    /// Returns the task as it stands, the status it is in, and the status it is
    /// moving to — `(current, from, to)`, in that order.
    ///
    /// THE REQUEST IS BORROWED. Both fields read below were already cloned at
    /// this point before the split, and `transition_task` still consumes the
    /// request afterwards, on the write.
    async fn decide_transition(
        &self,
        req: &api::TransitionTaskRequest,
    ) -> Result<(db::Task, db::TaskStatus, db::TaskStatus), Status> {
        let to = db::TaskStatus::try_from(req.to)
            .map_err(|_| Status::invalid_argument("unknown target status"))?;

        let current = self
            .db
            .clone()
            .get_task(db::GetTaskRequest {
                scope: req.scope.clone(),
                key: Some(db::get_task_request::Key::Id(req.id.clone())),
            })
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

        Ok((current, from, to))
    }
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
        //
        // DEADLINE_EXCEEDED belongs with it rather than with the opaque arm: the
        // store did not refuse the work, it did not answer in time — which is a
        // transient condition of the same shape, and one a caller can act on
        // identically.
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded => {
            Status::unavailable("the task store could not be reached in time — retry")
        }
        _ => Status::internal("the task store is unavailable"),
    }
}
