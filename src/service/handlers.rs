//! The six `TaskService` handlers.
//!
//! Split out of `service.rs` for the file ceiling, along the seam its parent's
//! `mod handlers;` documents: the trait implementation is here, and everything
//! it calls — `tel_scope`, `passthrough`, `Task`'s own methods — stayed there.
//! Nothing about what any of them does changed in the move.

use tonic::{Request, Response, Status};
use yadgar_dial::Deadline;
use yadgar_telemetry::estimator::Class;
use yadgar_telemetry::grpc::status_name;
use yadgar_telemetry::observe::{Call, Outcome};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use super::keyed::{self, Lookup};
use super::{edit_target, passthrough, tel_scope, transition_target, version_refused, Task};
use crate::pb::yadgar::task::v1 as db;
use crate::pb::yadgar::taskapi::v1 as api;
use crate::pb::yadgar::taskapi::v1::task_service_server::TaskService;
use crate::{fingerprint, rules, writes};

#[tonic::async_trait]
impl TaskService for Task {
    async fn create_task(
        &self,
        request: Request<api::CreateTaskRequest>,
    ) -> Result<Response<api::CreateTaskResponse>, Status> {
        let deadline = Deadline::of(&request);
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
                rules::title_fits(&req.title).map_err(Status::invalid_argument)?;

                let created = deadline
                    .call(
                        self.ceiling,
                        tonic::Request::new(db::CreateTaskRequest {
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
                        }),
                        |r| {
                            let mut db = self.db.clone();
                            async move { db.create_task(r).await }
                        },
                    )
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
        let deadline = Deadline::of(&request);
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

                let got = deadline
                    .call(
                        self.ceiling,
                        tonic::Request::new(db::GetTaskRequest {
                            scope: req.scope,
                            key: Some(key),
                        }),
                        |r| {
                            let mut db = self.db.clone();
                            async move { db.get_task(r).await }
                        },
                    )
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
        let deadline = Deadline::of(&request);
        let req = request.into_inner();
        let call = Call::start(
            "task",
            "FindTasks",
            Kind::Read,
            tel_scope(req.scope.as_ref()),
        );

        call.run(
            async move {
                let found = deadline
                    .call(
                        self.ceiling,
                        tonic::Request::new(db::ListTasksRequest {
                            scope: req.scope,
                            statuses: req.statuses,
                            page_size: req.page_size,
                            page_token: req.page_token,
                        }),
                        |r| {
                            let mut db = self.db.clone();
                            async move { db.list_tasks(r).await }
                        },
                    )
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
        let deadline = Deadline::of(&request);
        let req = request.into_inner();
        let call = Call::start(
            "task",
            "EditTask",
            Kind::Write,
            tel_scope(req.scope.as_ref()),
        );

        call.run(
            async move {
                // EVERY REQUEST-ONLY CHECK, before the store is touched at all:
                // see `edit_target`. They run ahead of the keyed lookup too.
                let (paths, key) = edit_target(&req)?;

                // THE KEYED LOOKUP (ADR-1051), after every request-only check and
                // before the read: a hit replays the recorded outcome, with no
                // read, no patch and no write; a miss writes with the
                // fingerprint the lookup sent. See `keyed`.
                let caller_fingerprint = match self
                    .look_up(
                        deadline,
                        &req.scope,
                        &req.idempotency,
                        db::WriteRpc::UpdateTask,
                        || fingerprint::edit_task(&req),
                    )
                    .await?
                {
                    Lookup::Hit(outcome) => {
                        let recorded = keyed::replayed_update(outcome)?;
                        return Ok(api::EditTaskResponse {
                            meta: recorded.meta,
                        });
                    }
                    Lookup::Miss(caller_fingerprint) => caller_fingerprint,
                };

                // The read is kept for what it actually provides: NOT_FOUND for a
                // task that is not there or not visible, before anything is
                // written. Its STATUS is no longer what keeps an edit from
                // changing one — `writes::edit_request` masks the column out, so
                // the rule is in the request rather than in this handler's
                // discipline. It now also supplies the fields the mask does NOT
                // name, for the rollout reason `edit_request` documents.
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
                    .map_err(|e| passthrough(e, "edit-read"))?
                    .into_inner()
                    .task
                    .ok_or_else(|| Status::not_found("no such task in this scope"))?;

                // A patch becomes a whole-body edit here, against the body
                // just read (ADR-1008); any other edit passes through as sent.
                let (req, paths) = writes::patched(req, &current, &paths)?;

                // Both versions, before the request is consumed: a refusal of
                // the write is named VERSION_MISMATCH only when they differ
                // (ADR-1042), and only after the store has refused.
                let read_version = current.meta.as_ref().map_or(0, |m| m.version);
                let expect_version = req.expect_version;
                let updated = deadline
                    .call(
                        self.ceiling,
                        tonic::Request::new(writes::edit_request(
                            req,
                            &current,
                            &paths,
                            caller_fingerprint,
                        )),
                        |r| {
                            let mut db = self.db.clone();
                            async move { db.update_task(r).await }
                        },
                    )
                    .await
                    .map_err(|e| {
                        version_refused(e, "edit", "edit", Some(read_version), expect_version)
                    })?
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

    /// `from` IS THE STORE'S RECORDED PRIOR STATUS (ADR-1051 rule 7):
    /// `UpdateTaskResponse.previous_status`, on a fresh transition and on a
    /// replay alike, never this service's own read. On a replay that read
    /// returns the status the first attempt already wrote, so a `from` taken
    /// from it would equal `to` and tell a racing caller nothing (ledger 508).
    /// TASK_STATUS_UNSPECIFIED is carried through as the store sent it: it
    /// means the prior status is unknown, and a guess would be worse.
    async fn transition_task(
        &self,
        request: Request<api::TransitionTaskRequest>,
    ) -> Result<Response<api::TransitionTaskResponse>, Status> {
        let deadline = Deadline::of(&request);
        let req = request.into_inner();
        let call = Call::start(
            "task",
            "TransitionTask",
            Kind::Write,
            tel_scope(req.scope.as_ref()),
        );

        call.run(
            async move {
                // The request-only checks, then the keyed lookup (ADR-1051):
                // a hit replays with no read and no rule check, so a retry
                // whose `to` is no longer legal is still replayed.
                let (key, to) = transition_target(&req)?;
                let caller_fingerprint = match self
                    .look_up(
                        deadline,
                        &req.scope,
                        &req.idempotency,
                        db::WriteRpc::UpdateTask,
                        || fingerprint::transition_task(&req),
                    )
                    .await?
                {
                    Lookup::Hit(outcome) => {
                        let recorded = keyed::replayed_update(outcome)?;
                        return Ok(api::TransitionTaskResponse {
                            meta: recorded.meta,
                            from: recorded.previous_status,
                        });
                    }
                    Lookup::Miss(caller_fingerprint) => caller_fingerprint,
                };

                // THE DECISION, ALL OF IT, BEFORE THE WRITE. See
                // `Task::decide_transition` for what it settles, and for why
                // the refusal it can raise is INVALID_ARGUMENT. The rule is
                // decided before the version: an illegal `to` is refused here,
                // whatever the read's version.
                let current = self.decide_transition(&req, key, to, deadline).await?;

                // THE WRITE, and why it carries `req.expect_version` rather than
                // the version just read: see `Task::write_transition`.
                let updated = self
                    .write_transition(req, &current, to, caller_fingerprint, deadline)
                    .await?;

                let response = api::TransitionTaskResponse {
                    meta: updated.meta,
                    from: updated.previous_status,
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
        let deadline = Deadline::of(&request);
        let req = request.into_inner();
        let call = Call::start(
            "task",
            "RemoveTask",
            Kind::Write,
            tel_scope(req.scope.as_ref()),
        );

        call.run(
            async move {
                // See `Task::remove` (in `keyed`): the request-only check, the
                // keyed lookup, the pre-write read and the delete.
                self.remove(req, deadline).await
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
