//! `TaskService`. Business rules here; storage over the `-db` API, never directly.

use tonic::{Request, Response, Status};
use yadgar_telemetry::estimator::Class;
use yadgar_telemetry::grpc::status_name;
use yadgar_telemetry::observe::{Call, Outcome};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::pb::yadgar::task::v1 as db;
use crate::pb::yadgar::task::v1::task_db_service_client::TaskDbServiceClient;
use crate::pb::yadgar::taskapi::v1 as api;
use crate::pb::yadgar::taskapi::v1::task_service_server::TaskService;
use crate::rules;
use crate::writes;

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
}

/// A `-db` failure is passed through with its CODE intact but not its message.
///
/// The code is the caller's contract — `FAILED_PRECONDITION` means "re-read and
/// retry", `NOT_FOUND` means what it says — and collapsing everything to
/// `INTERNAL` would destroy that. The message is not passed through: it may name
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
        tonic::Code::FailedPrecondition => Status::failed_precondition(
            "the task changed since you read it, or you may not modify it — re-read and retry",
        ),
        tonic::Code::InvalidArgument => Status::invalid_argument("invalid request"),
        // The store could not serialise this write against a concurrent one, and
        // said so specifically. Folding it into INTERNAL here would undo the
        // reason `-db` distinguishes it at all: this is the one storage failure
        // a caller can act on, and the action is to send the request again.
        tonic::Code::Aborted => Status::aborted("the write raced another one — retry"),
        _ => Status::internal("the task store is unavailable"),
    }
}

#[tonic::async_trait]
impl TaskService for Task {
    async fn create_task(
        &self,
        request: Request<api::CreateTaskRequest>,
    ) -> Result<Response<api::CreateTaskResponse>, Status> {
        let req = request.into_inner();
        // Started BEFORE the work, so the duration covers the handler and the
        // scope is captured before the request is consumed by the -db call.
        let call = Call::start(
            "task",
            "CreateTask",
            Kind::Write,
            tel_scope(req.scope.as_ref()),
        );

        call.run(
            async move {
                if req.title.trim().is_empty() {
                    // A rule, not a storage constraint: an untitled task is unfindable by
                    // the humans who have to triage it. The column would happily take it.
                    return Err(Status::invalid_argument("a task needs a title"));
                }

                let created = self
                    .db
                    .clone()
                    .create_task(db::CreateTaskRequest {
                        idempotency: req.idempotency,
                        scope: req.scope,
                        task: Some(db::Task {
                            title: req.title,
                            body: req.body,
                            status: db::TaskStatus::Open as i32,
                            tags: req.tags,
                            links: req.links,
                            ..Default::default()
                        }),
                    })
                    .await
                    .map_err(|e| passthrough(e, "create"))?
                    .into_inner();

                let response = api::CreateTaskResponse {
                    meta: created.meta,
                    number: created.number,
                };

                Ok(response)
            },
            |r| Outcome {
                status: "OK",
                payload: format!("{r:?}"),
                encoded_bytes: Some(prost::Message::encoded_len(r) as u64),
                class: Class::Envelope,
                rows: 1,
                ..Default::default()
            },
            status_name,
        )
        .await
        .map(Response::new)
    }

    async fn read_task(
        &self,
        request: Request<api::ReadTaskRequest>,
    ) -> Result<Response<api::ReadTaskResponse>, Status> {
        let req = request.into_inner();
        let call = Call::start(
            "task",
            "ReadTask",
            Kind::Read,
            tel_scope(req.scope.as_ref()),
        );

        call.run(
            async move {
                let key = match req.key {
                    Some(api::read_task_request::Key::Id(id)) => db::get_task_request::Key::Id(id),
                    Some(api::read_task_request::Key::Number(n)) => {
                        db::get_task_request::Key::Number(n)
                    }
                    None => {
                        return Err(Status::invalid_argument("one of id or number is required"))
                    }
                };

                let got = self
                    .db
                    .clone()
                    .get_task(db::GetTaskRequest {
                        scope: req.scope,
                        key: Some(key),
                    })
                    .await
                    .map_err(|e| passthrough(e, "read"))?
                    .into_inner();

                let response = api::ReadTaskResponse { task: got.task };
                Ok(response)
            },
            |r| Outcome {
                status: "OK",
                payload: format!("{r:?}"),
                encoded_bytes: Some(prost::Message::encoded_len(r) as u64),
                class: Class::Envelope,
                rows: 1,
                ..Default::default()
            },
            status_name,
        )
        .await
        .map(Response::new)
    }

    async fn find_tasks(
        &self,
        request: Request<api::FindTasksRequest>,
    ) -> Result<Response<api::FindTasksResponse>, Status> {
        let req = request.into_inner();
        let call = Call::start(
            "task",
            "FindTasks",
            Kind::Read,
            tel_scope(req.scope.as_ref()),
        );

        call.run(
            async move {
                let found = self
                    .db
                    .clone()
                    .list_tasks(db::ListTasksRequest {
                        scope: req.scope,
                        statuses: req.statuses,
                        page_size: req.page_size,
                        page_token: req.page_token,
                    })
                    .await
                    .map_err(|e| passthrough(e, "find"))?
                    .into_inner();

                let response = api::FindTasksResponse {
                    tasks: found.tasks,
                    next_page_token: found.next_page_token,
                };
                Ok(response)
            },
            |r| Outcome {
                status: "OK",
                payload: format!("{r:?}"),
                encoded_bytes: Some(prost::Message::encoded_len(r) as u64),
                class: Class::Envelope,
                // The row count for a list is the LIST, not one.
                rows: r.tasks.len() as u32,
                ..Default::default()
            },
            status_name,
        )
        .await
        .map(Response::new)
    }

    async fn edit_task(
        &self,
        request: Request<api::EditTaskRequest>,
    ) -> Result<Response<api::EditTaskResponse>, Status> {
        let req = request.into_inner();
        let call = Call::start(
            "task",
            "EditTask",
            Kind::Write,
            tel_scope(req.scope.as_ref()),
        );

        call.run(
            async move {
                if req.title.trim().is_empty() {
                    return Err(Status::invalid_argument("a task needs a title"));
                }

                // The read is kept for what it actually provides: NOT_FOUND for a
                // task that is not there or not visible, before anything is
                // written. Its STATUS is no longer what keeps an edit from
                // changing one — `writes::edit_request` masks the column out, so
                // the rule is in the request rather than in this handler's
                // discipline.
                let current = self
                    .db
                    .clone()
                    .get_task(db::GetTaskRequest {
                        scope: req.scope.clone(),
                        key: Some(db::get_task_request::Key::Id(req.id.clone())),
                    })
                    .await
                    .map_err(|e| passthrough(e, "edit-read"))?
                    .into_inner()
                    .task
                    .ok_or_else(|| Status::not_found("no such task in this scope"))?;

                let updated = self
                    .db
                    .clone()
                    .update_task(writes::edit_request(req, current.status)?)
                    .await
                    .map_err(|e| passthrough(e, "edit"))?
                    .into_inner();

                let response = api::EditTaskResponse { meta: updated.meta };
                Ok(response)
            },
            |r| Outcome {
                status: "OK",
                payload: format!("{r:?}"),
                encoded_bytes: Some(prost::Message::encoded_len(r) as u64),
                class: Class::Envelope,
                rows: 1,
                ..Default::default()
            },
            status_name,
        )
        .await
        .map(Response::new)
    }

    /// KNOWN CONTRACT GAP, recorded here rather than papered over: on an
    /// IDEMPOTENT REPLAY, `from` reports the status the task is already in.
    ///
    /// The read below runs before the write. On the retry of a transition that
    /// was already applied, it returns the NEW status; `rules::may_transition`
    /// waves `(to, to)` through as an identity no-op; `task-db` replays the
    /// recorded response without writing; and `from` comes back equal to `to`.
    ///
    /// That is exactly the guarantee the field exists to give. `taskapi.proto`
    /// says `from` is there "so a caller that raced another writer sees what
    /// actually happened rather than assuming its own read was current" — and on
    /// this path it carries no information at all.
    ///
    /// IT CANNOT BE FIXED HERE. Nothing this service can reach holds the prior
    /// status. `UpdateTaskResponse` carries `meta` and nothing else, identically
    /// at proto v1.2.0 and v1.6.0, and `task-db`'s idempotency row persists that
    /// same response — so even a change confined to `-db` has nowhere to put the
    /// answer. Closing it needs a new field on `UpdateTaskResponse` in
    /// yadgarhq/proto first, after which the store's replay carries the true
    /// predecessor and this handler reports it instead of its own read.
    ///
    /// Deriving one instead would be worse than the gap: several statuses lead to
    /// any given target, so a guess is indistinguishable from an answer.
    async fn transition_task(
        &self,
        request: Request<api::TransitionTaskRequest>,
    ) -> Result<Response<api::TransitionTaskResponse>, Status> {
        let req = request.into_inner();
        let call = Call::start(
            "task",
            "TransitionTask",
            Kind::Write,
            tel_scope(req.scope.as_ref()),
        );

        call.run(
            async move {
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
                // documents the latter as "re-read and retry", and there is
                // nothing to re-read: DROPPED -> OPEN is refused by the rule
                // itself and will be refused identically forever. A code that
                // invites a retry which can never succeed is worse than a plain
                // refusal — a client obeying the contract loops.
                rules::may_transition(from, to)
                    .map_err(|e| Status::invalid_argument(e.to_string()))?;

                // The STORE'S meta, as `edit_task` already does. This used to
                // discard the response and synthesise one from the request —
                // `id` from `req.id`, `version` from `expect_version + 1` — which
                // asserted two things this service cannot know: that `-db`
                // increments by exactly one, and that no other Meta field the
                // store fills in differs from the zero value. On a replay the
                // second is plainly false, since the version is the ORIGINAL
                // write's and the project comes from the scope. A synthesised
                // envelope is a guess wearing the shape of an answer.
                let updated = self
                    .db
                    .clone()
                    .update_task(writes::transition_request(req, &current, to))
                    .await
                    .map_err(|e| passthrough(e, "transition"))?
                    .into_inner();

                let response = api::TransitionTaskResponse {
                    meta: updated.meta,
                    from: from as i32,
                };
                Ok(response)
            },
            |r| Outcome {
                status: "OK",
                payload: format!("{r:?}"),
                encoded_bytes: Some(prost::Message::encoded_len(r) as u64),
                class: Class::Envelope,
                rows: 1,
                ..Default::default()
            },
            status_name,
        )
        .await
        .map(Response::new)
    }

    async fn remove_task(
        &self,
        request: Request<api::RemoveTaskRequest>,
    ) -> Result<Response<api::RemoveTaskResponse>, Status> {
        let req = request.into_inner();
        let call = Call::start(
            "task",
            "RemoveTask",
            Kind::Write,
            tel_scope(req.scope.as_ref()),
        );

        call.run(
            async move {
                self.db
                    .clone()
                    .delete_task(db::DeleteTaskRequest {
                        idempotency: req.idempotency,
                        scope: req.scope,
                        id: req.id,
                        expect_version: req.expect_version,
                    })
                    .await
                    .map_err(|e| passthrough(e, "remove"))?;
                // No payload to measure: RemoveTaskResponse is empty. Recording it
                // anyway matters — a call that returns nothing still costs time and still
                // belongs in the count, and omitting it would make deletes invisible.
                Ok(api::RemoveTaskResponse {})
            },
            |_| Outcome {
                status: "OK",
                // RemoveTaskResponse is empty — nothing to measure. Recorded
                // anyway: a delete costs time and belongs in the count.
                rows: 1,
                ..Default::default()
            },
            status_name,
        )
        .await
        .map(Response::new)
    }
}
