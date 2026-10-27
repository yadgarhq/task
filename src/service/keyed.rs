//! Keyed retries (ADR-1051), and RemoveTask's pre-write read (ADR-1050).
//!
//! **WHY THE LOOKUP RUNS BEFORE THE READ.** This service reads a task before
//! it writes it. A same-key retry whose first attempt was applied can then
//! fail that read (the task was removed or left the caller's reach), fail a
//! rule checked on what the read returned, or build a different store payload
//! from fields a concurrent writer changed, all before `task-db` ever sees the
//! key. D9 says a repeated key is a replay. So when `idempotency.key` is
//! non-empty, EditTask, TransitionTask and RemoveTask ask `task-db`'s claim
//! ledger first, after their request-only checks and before anything else.
//!
//! A LOOKUP FAILURE FAILS THE CALL through [`passthrough`]. There is no
//! fallback to the unlooked-up path, UNIMPLEMENTED included: `task-db` 0.11.8
//! deploys first (ADR-1051 rule 11), and a store outage must stay visible.

use tonic::Status;
use yadgar_dial::Deadline;

use super::{passthrough, version_refused, Task};
use crate::fingerprint;
use crate::pb::yadgar::common::v1 as common;
use crate::pb::yadgar::task::v1 as db;
use crate::pb::yadgar::task::v1::lookup_write_response::Outcome;
use crate::pb::yadgar::taskapi::v1 as api;

/// What a keyed write does next.
pub(super) enum Lookup {
    /// The key is claimed: the outcome the first attempt recorded, to be
    /// returned without a read, a rule check or a write, and so with no reason
    /// token.
    ///
    /// BOXED because a recorded `UpdateTaskResponse` is far larger than a
    /// fingerprint, and the miss is the common path.
    Hit(Box<Outcome>),
    /// The key is not claimed, or there is no key: the caller fingerprint the
    /// write carries. EMPTY WHEN THERE IS NO KEY, which the store reads as
    /// absent; with a key, the same 32 bytes the lookup sent.
    Miss(Vec<u8>),
}

impl Task {
    /// RemoveTask's work, under the handler's telemetry: the request-only
    /// check, the keyed lookup (a hit replays the recorded delete), the
    /// pre-write read that supplies VERSION_MISMATCH (ADR-1050), and the
    /// delete. Here rather than in `handlers` because every step but the
    /// delete is about keyed retries and the token.
    pub(super) async fn remove(
        &self,
        req: api::RemoveTaskRequest,
        deadline: Deadline,
    ) -> Result<api::RemoveTaskResponse, Status> {
        // The read below needs an id, so a request without one is
        // refused here, before the lookup.
        if req.id.is_empty() {
            return Err(Status::invalid_argument("an id is required"));
        }
        let caller_fingerprint = match self
            .look_up(
                deadline,
                &req.scope,
                &req.idempotency,
                db::WriteRpc::DeleteTask,
                || fingerprint::remove_task(&req),
            )
            .await?
        {
            Lookup::Hit(outcome) => {
                replayed_delete(outcome)?;
                return Ok(api::RemoveTaskResponse {});
            }
            Lookup::Miss(caller_fingerprint) => caller_fingerprint,
        };
        let read_version = self.remove_read(deadline, &req.scope, &req.id).await?;
        let expect_version = req.expect_version;
        deadline
            .call(
                self.ceiling,
                tonic::Request::new(db::DeleteTaskRequest {
                    idempotency: req.idempotency,
                    scope: req.scope,
                    id: req.id,
                    expect_version: req.expect_version,
                    caller_fingerprint,
                }),
                |r| {
                    let mut db = self.db.clone();
                    async move { db.delete_task(r).await }
                },
            )
            .await
            .map_err(|e| version_refused(e, "remove", "removal", read_version, expect_version))?;
        // No payload to measure: RemoveTaskResponse is empty. Recording it
        // anyway matters — a call that returns nothing still costs time and still
        // belongs in the count, and omitting it would make deletes invisible.
        Ok(api::RemoveTaskResponse {})
    }

    /// Look the key up, or, with no key, do nothing and miss.
    ///
    /// `fingerprint` is called only with a key, after the caller's
    /// request-only checks, because that is where the derivation says it is
    /// computed.
    pub(super) async fn look_up(
        &self,
        deadline: Deadline,
        scope: &Option<common::Scope>,
        idempotency: &Option<common::Idempotency>,
        rpc: db::WriteRpc,
        fingerprint: impl FnOnce() -> Vec<u8>,
    ) -> Result<Lookup, Status> {
        if idempotency.as_ref().is_none_or(|i| i.key.is_empty()) {
            return Ok(Lookup::Miss(Vec::new()));
        }
        let caller_fingerprint = fingerprint();
        let found = deadline
            .call(
                self.ceiling,
                tonic::Request::new(db::LookupWriteRequest {
                    scope: scope.clone(),
                    idempotency: idempotency.clone(),
                    rpc: rpc as i32,
                    caller_fingerprint: caller_fingerprint.clone(),
                }),
                |r| {
                    let mut db = self.db.clone();
                    async move { db.lookup_write(r).await }
                },
            )
            .await
            .map_err(|e| passthrough(e, "lookup"))?
            .into_inner();
        Ok(match found.outcome {
            Some(outcome) => Lookup::Hit(Box::new(outcome)),
            None => Lookup::Miss(caller_fingerprint),
        })
    }

    /// RemoveTask's pre-write read (ADR-1050), run only after a miss. It
    /// exists ONLY to supply VERSION_MISMATCH: the version it saw, or `None`
    /// when the task is not there to read. A NOT_FOUND does not refuse the
    /// call, which goes on to the store; the store decides. Any other failure
    /// fails the call, as every other read here does.
    pub(super) async fn remove_read(
        &self,
        deadline: Deadline,
        scope: &Option<common::Scope>,
        id: &str,
    ) -> Result<Option<u64>, Status> {
        let read = deadline
            .call(
                self.ceiling,
                tonic::Request::new(db::GetTaskRequest {
                    scope: scope.clone(),
                    key: Some(db::get_task_request::Key::Id(id.to_string())),
                }),
                |r| {
                    let mut db = self.db.clone();
                    async move { db.get_task(r).await }
                },
            )
            .await;
        match read {
            Ok(got) => Ok(got
                .into_inner()
                .task
                .map(|t| t.meta.map_or(0, |m| m.version))),
            Err(e) if e.code() == tonic::Code::NotFound => Ok(None),
            Err(e) => Err(passthrough(e, "remove-read")),
        }
    }
}

/// A hit in the arm the lookup did not ask for. `task-db` sets the arm that
/// matches the request's `rpc`, so this is a store fault. It is NEVER a miss:
/// that would write a second time under a key the store says it holds.
fn wrong_arm(rpc: &str) -> Status {
    tracing::error!(
        rpc,
        "task-db answered a lookup with another write's outcome"
    );
    Status::internal("the task store replayed an outcome for another write")
}

/// The recorded `UpdateTask` outcome of a hit.
pub(super) fn replayed_update(outcome: Box<Outcome>) -> Result<db::UpdateTaskResponse, Status> {
    match *outcome {
        Outcome::Update(recorded) => Ok(recorded),
        _ => Err(wrong_arm("UpdateTask")),
    }
}

/// The recorded `DeleteTask` outcome of a hit.
pub(super) fn replayed_delete(outcome: Box<Outcome>) -> Result<db::DeleteTaskResponse, Status> {
    match *outcome {
        Outcome::Delete(recorded) => Ok(recorded),
        _ => Err(wrong_arm("DeleteTask")),
    }
}
