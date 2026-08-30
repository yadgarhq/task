//! `TaskService`. Business rules here; storage over the `-db` API, never directly.

use tonic::{Request, Response, Status};
use yadgar_telemetry::estimator::Class;
use yadgar_telemetry::observe::{Call, Outcome};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::pb::yadgar::task::v1 as db;
use crate::pb::yadgar::task::v1::task_db_service_client::TaskDbServiceClient;
use crate::pb::yadgar::taskapi::v1 as api;
use crate::pb::yadgar::taskapi::v1::task_service_server::TaskService;
use crate::rules;

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
fn passthrough(status: Status, op: &str) -> Status {
    tracing::warn!(op, code = ?status.code(), "task-db returned an error");
    match status.code() {
        tonic::Code::NotFound => Status::not_found("no such task in this scope"),
        tonic::Code::FailedPrecondition => Status::failed_precondition(
            "the task changed since you read it, or you may not modify it — re-read and retry",
        ),
        tonic::Code::InvalidArgument => Status::invalid_argument("invalid request"),
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

        call.finish(Outcome {
            status: "OK",
            payload: format!("{response:?}"),
            // A response STRUCTURE containing one URN, not a list of URNs — the
            // first real record corrected this from Identifiers, which
            // over-estimated it threefold.
            class: Class::Envelope,
            rows: 1,
            ..Default::default()
        });

        Ok(Response::new(response))
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
        let key = match req.key {
            Some(api::read_task_request::Key::Id(id)) => db::get_task_request::Key::Id(id),
            Some(api::read_task_request::Key::Number(n)) => db::get_task_request::Key::Number(n),
            None => return Err(Status::invalid_argument("one of id or number is required")),
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
        call.finish(Outcome {
            status: "OK",
            payload: format!("{response:?}"),
            class: Class::Envelope,
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(response))
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
        call.finish(Outcome {
            status: "OK",
            payload: format!("{response:?}"),
            class: Class::Envelope,
            rows: response.tasks.len() as u32,
            ..Default::default()
        });
        Ok(Response::new(response))
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
        if req.title.trim().is_empty() {
            return Err(Status::invalid_argument("a task needs a title"));
        }

        // Status is NOT read from this request — the API has no such field, and
        // that is the point. Reading the current status and writing it back keeps
        // the -db call's shape without letting an edit change it.
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
            .update_task(db::UpdateTaskRequest {
                idempotency: req.idempotency,
                scope: req.scope,
                id: req.id,
                expect_version: req.expect_version,
                task: Some(db::Task {
                    title: req.title,
                    body: req.body,
                    status: current.status,
                    ..Default::default()
                }),
                update_mask: req.update_mask,
            })
            .await
            .map_err(|e| passthrough(e, "edit"))?
            .into_inner();

        let response = api::EditTaskResponse { meta: updated.meta };
        call.finish(Outcome {
            status: "OK",
            payload: format!("{response:?}"),
            class: Class::Envelope,
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(response))
    }

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
        rules::may_transition(from, to).map_err(|e| Status::failed_precondition(e.to_string()))?;

        self.db
            .clone()
            .update_task(db::UpdateTaskRequest {
                idempotency: req.idempotency,
                scope: req.scope,
                id: req.id.clone(),
                expect_version: req.expect_version,
                task: Some(db::Task {
                    title: current.title,
                    body: current.body,
                    status: to as i32,
                    ..Default::default()
                }),
                update_mask: None,
            })
            .await
            .map_err(|e| passthrough(e, "transition"))?;

        let response = api::TransitionTaskResponse {
            meta: Some(crate::pb::yadgar::common::v1::Meta {
                id: req.id,
                version: req.expect_version + 1,
                ..Default::default()
            }),
            from: from as i32,
        };
        call.finish(Outcome {
            status: "OK",
            payload: format!("{response:?}"),
            class: Class::Envelope,
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(response))
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
        call.finish(Outcome {
            status: "OK",
            rows: 1,
            ..Default::default()
        });
        Ok(Response::new(api::RemoveTaskResponse {}))
    }
}
