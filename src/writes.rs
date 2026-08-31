//! How a public API write becomes a `-db` write.
//!
//! Separated from the handlers because this is where the module's rules stop
//! being advice and become the request that is actually sent. A handler that
//! assembles its own `UpdateTaskRequest` inline can quietly include a field the
//! API does not have — which is exactly what `EditTask` was doing with `status`.

use prost_types::FieldMask;
use tonic::Status;

use crate::pb::yadgar::task::v1 as db;
use crate::pb::yadgar::taskapi::v1 as api;

/// What an EDIT is allowed to write. `status` is deliberately absent: a status
/// change is a REQUEST that `rules::may_transition` answers, never a field
/// write, and the API carries no such field.
const EDITABLE: [&str; 2] = ["title", "body"];

fn mask(paths: &[&str]) -> Option<FieldMask> {
    Some(FieldMask {
        paths: paths.iter().map(|p| (*p).to_string()).collect(),
    })
}

/// The `-db` write an `EditTask` becomes.
///
/// TWO THINGS KEEP STATUS OUT, and they are not redundant.
///
/// The MASK is the mechanism: it names `title` and `body`, so a `-db` that
/// honours it writes nothing else. `current_status` is still carried in the
/// message because a `-db` that does NOT yet honour the mask writes every field
/// it is given, and sending `TASK_STATUS_UNSPECIFIED` to one of those would set
/// the stored status to zero on every edit — a worse bug than the one being
/// fixed, reachable during any rollout where the two services are not upgraded
/// together.
///
/// The caller's own `update_mask` is INTERSECTED with the editable set rather
/// than forwarded. Forwarding it would let a client name `status` and reopen a
/// DONE task through an RPC whose whole purpose is that it cannot.
pub fn edit_request(
    req: api::EditTaskRequest,
    current_status: i32,
) -> Result<db::UpdateTaskRequest, Status> {
    let paths = requested_paths(req.update_mask.as_ref())?;
    Ok(db::UpdateTaskRequest {
        idempotency: req.idempotency,
        scope: req.scope,
        id: req.id,
        expect_version: req.expect_version,
        task: Some(db::Task {
            title: req.title,
            body: req.body,
            status: current_status,
            ..Default::default()
        }),
        update_mask: mask(&paths),
    })
}

/// A caller may narrow an edit, never widen it.
fn requested_paths(requested: Option<&FieldMask>) -> Result<Vec<&'static str>, Status> {
    let Some(requested) = requested.filter(|m| !m.paths.is_empty()) else {
        return Ok(EDITABLE.to_vec());
    };
    requested
        .paths
        .iter()
        .map(|path| {
            EDITABLE
                .into_iter()
                .find(|editable| editable == path)
                .ok_or_else(|| {
                    Status::invalid_argument(format!(
                        "an edit may write {}, not `{path}`",
                        EDITABLE.join(" and ")
                    ))
                })
        })
        .collect()
}

/// The `-db` write a `TransitionTask` becomes, once the rule has allowed it.
///
/// The mask names `status` alone. Without it the request would carry an empty
/// `tags` and `links` — the zero value of a message this handler never
/// populated — and a `-db` that writes every field would erase them.
pub fn transition_request(
    req: api::TransitionTaskRequest,
    current: &db::Task,
    to: db::TaskStatus,
) -> db::UpdateTaskRequest {
    db::UpdateTaskRequest {
        idempotency: req.idempotency,
        scope: req.scope,
        id: req.id,
        expect_version: req.expect_version,
        // title and body are carried for the same rollout reason as above: a
        // -db that ignores the mask writes them, and writing back what was just
        // read is what that -db already did.
        task: Some(db::Task {
            title: current.title.clone(),
            body: current.body.clone(),
            status: to as i32,
            ..Default::default()
        }),
        update_mask: mask(&["status"]),
    }
}
