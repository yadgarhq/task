//! `TaskService`. Business rules here; storage over the `-db` API, never directly.

use std::time::Instant;

use tonic::{Request, Response, Status};
use yadgar_telemetry::estimator::Class;
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;
use yadgar_telemetry::record;

use crate::pb::yadgar::task::v1 as db;
use crate::pb::yadgar::task::v1::task_db_service_client::TaskDbServiceClient;
use crate::pb::yadgar::taskapi::v1 as api;
use crate::pb::yadgar::taskapi::v1::task_service_server::TaskService;
use crate::rules;

/// The scope fields a record needs, copied before the request is consumed.
///
/// A small struct rather than four loose strings because they are always used
/// together and mixing up two of them produces telemetry that is wrong in a way
/// no test would catch.
struct Telemetry {
    request_id: String,
    instance_id: String,
    user_id: String,
    project_id: String,
}

impl From<Option<&crate::pb::yadgar::common::v1::Scope>> for Telemetry {
    fn from(scope: Option<&crate::pb::yadgar::common::v1::Scope>) -> Self {
        // An absent scope is refused later with INVALID_ARGUMENT; here it simply
        // yields empty strings, because telemetry must never be the thing that
        // fails a call (D25).
        Self {
            request_id: scope.map(|s| s.request_id.clone()).unwrap_or_default(),
            instance_id: scope.map(|s| s.instance_id.clone()).unwrap_or_default(),
            user_id: scope.map(|s| s.user_id.clone()).unwrap_or_default(),
            project_id: scope.map(|s| s.project_id.clone()).unwrap_or_default(),
        }
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
        let started = Instant::now();
        let req = request.into_inner();
        // Captured BEFORE the request is consumed by the -db call. The gateway
        // attests these; this service only carries them through (D12).
        let tel = Telemetry::from(req.scope.as_ref());
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

        // D67, on the one path this service fully owns. The payload here is a URN
        // and a number — the IDENTIFIER class, which is exactly the case a
        // word count under-reports and the reason both features are recorded.
        record::emit(
            &record::Builder::new("task", "CreateTask", Kind::Write)
                .scope(
                    &tel.request_id,
                    &tel.instance_id,
                    &tel.user_id,
                    &tel.project_id,
                )
                .outcome("OK")
                .duration(started.elapsed())
                .payload(&format!("{response:?}"), Class::Identifiers)
                .rows_returned(1)
                .build(),
        );

        Ok(Response::new(response))
    }

    async fn read_task(
        &self,
        request: Request<api::ReadTaskRequest>,
    ) -> Result<Response<api::ReadTaskResponse>, Status> {
        let req = request.into_inner();
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

        Ok(Response::new(api::ReadTaskResponse { task: got.task }))
    }

    async fn find_tasks(
        &self,
        request: Request<api::FindTasksRequest>,
    ) -> Result<Response<api::FindTasksResponse>, Status> {
        let req = request.into_inner();
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

        Ok(Response::new(api::FindTasksResponse {
            tasks: found.tasks,
            next_page_token: found.next_page_token,
        }))
    }

    async fn edit_task(
        &self,
        request: Request<api::EditTaskRequest>,
    ) -> Result<Response<api::EditTaskResponse>, Status> {
        let req = request.into_inner();
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

        Ok(Response::new(api::EditTaskResponse { meta: updated.meta }))
    }

    async fn transition_task(
        &self,
        request: Request<api::TransitionTaskRequest>,
    ) -> Result<Response<api::TransitionTaskResponse>, Status> {
        let req = request.into_inner();
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

        Ok(Response::new(api::TransitionTaskResponse {
            meta: Some(crate::pb::yadgar::common::v1::Meta {
                id: req.id,
                version: req.expect_version + 1,
                ..Default::default()
            }),
            from: from as i32,
        }))
    }

    async fn remove_task(
        &self,
        request: Request<api::RemoveTaskRequest>,
    ) -> Result<Response<api::RemoveTaskResponse>, Status> {
        let req = request.into_inner();
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
        Ok(Response::new(api::RemoveTaskResponse {}))
    }
}
