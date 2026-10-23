//! How a public API write becomes a `-db` write.
//!
//! Separated from the handlers because this is where the module's rules stop
//! being advice and become the request that is actually sent. A handler that
//! assembles its own `UpdateTaskRequest` inline can quietly include a field the
//! API does not have — which is exactly what `EditTask` was doing with `status`.

use prost_types::FieldMask;
use sha2::{Digest, Sha256};
use tonic::Status;

use crate::pb::yadgar::task::v1 as db;
use crate::pb::yadgar::taskapi::v1 as api;

/// The read key for a write to an existing task: exactly one of `id` or
/// `number` (yaadgaar #397).
///
/// **PURE, AND RUN BEFORE THE STORE IS TOUCHED.** Both and neither are
/// decisions about the request alone, so they cost no read.
///
/// `number` 0 is absent: the per-project counter hands out 1 first. The key
/// goes to `GetTask` with the caller's scope unchanged, and `task-db`'s number
/// arm matches the project by EQUALITY, so a number resolves in the caller's
/// exact project and never in another one.
pub fn target_key(id: &str, number: u32) -> Result<db::get_task_request::Key, Status> {
    match (id.is_empty(), number) {
        (false, 0) => Ok(db::get_task_request::Key::Id(id.to_string())),
        (true, 0) => Err(Status::invalid_argument("one of id or number is required")),
        (true, n) => Ok(db::get_task_request::Key::Number(n)),
        (false, _) => Err(Status::invalid_argument("give id or number, not both")),
    }
}

/// The id the WRITE names: the caller's when it sent one, otherwise the id the
/// read resolved its number to.
///
/// The caller's id is kept rather than replaced by the read's, so an edit by
/// id sends exactly what it sent before this function existed.
fn write_id(req_id: String, current: &db::Task) -> String {
    if !req_id.is_empty() {
        return req_id;
    }
    current
        .meta
        .as_ref()
        .map(|m| m.id.clone())
        .unwrap_or_default()
}

/// The length of a SHA-256 digest in bytes.
const SHA256_LEN: usize = 32;

/// `expect_body_sha256`: refuse a body that is not the one the caller hashed
/// (yaadgaar #394).
///
/// THE CASE IT EXISTS FOR: a model's tool call cut off mid-body still arrives
/// as a well-formed request, and without this the cut body is stored and the
/// version moves. The caller hashes the body it MEANT to send, so a body
/// shortened anywhere in transit no longer matches.
///
/// Empty is no guard, which is what every caller predating the field sends.
/// Present, it must be 32 bytes and the mask must write `body`; a digest on an
/// edit that writes no body guards nothing, and the caller believes it does.
/// The digest is over the exact UTF-8 bytes of `body`, with no normalisation.
pub fn check_body_digest(req: &api::EditTaskRequest, paths: &[&'static str]) -> Result<(), Status> {
    let expected = &req.expect_body_sha256;
    if expected.is_empty() {
        return Ok(());
    }
    if expected.len() != SHA256_LEN {
        return Err(Status::invalid_argument(format!(
            "expect_body_sha256 must be a {SHA256_LEN}-byte SHA-256 digest, not {} bytes",
            expected.len()
        )));
    }
    if !paths.contains(&"body") {
        return Err(Status::invalid_argument(
            "expect_body_sha256 was sent, but this edit does not write `body`",
        ));
    }
    if Sha256::digest(req.body.as_bytes()).as_slice() != expected.as_slice() {
        return Err(Status::invalid_argument(
            "the body does not match expect_body_sha256; it may have been cut off in \
             transit, so nothing was written. Re-send the whole body",
        ));
    }
    Ok(())
}

/// What an EDIT is allowed to write. `status` is deliberately absent: a status
/// change is a REQUEST that `rules::may_transition` answers, never a field
/// write, and the API carries no such field.
const EDITABLE: [&str; 2] = ["title", "body"];

fn mask(paths: &[&'static str]) -> Option<FieldMask> {
    Some(FieldMask {
        paths: paths.iter().map(|p| (*p).to_string()).collect(),
    })
}

/// The `-db` write an `EditTask` becomes, given the paths it may write and the
/// task as it stands.
///
/// TWO THINGS KEEP STATUS OUT, and they are not redundant.
///
/// The MASK is the mechanism: it names only what `paths` holds, so a `-db` that
/// honours it writes nothing else. The CURRENT VALUES are still carried in the
/// message because a `-db` that does NOT yet honour the mask writes every field
/// it is given, and sending `TASK_STATUS_UNSPECIFIED` to one of those would set
/// the stored status to zero on every edit — a worse bug than the one being
/// fixed, reachable during any rollout where the two services are not upgraded
/// together.
///
/// **THE SAME ARGUMENT APPLIES TO A FIELD THE MASK LEAVES OUT, and this function
/// used to make it only for `status`.** It set `title: req.title, body: req.body`
/// unconditionally, so a title-only edit still put the request's EMPTY body on
/// the wire — and a `-db` ignoring the mask would write it, erasing the stored
/// body. [`transition_request`] already defends this way, naming the hazard in a
/// comment; this now defends identically. `task-db` does honour the mask today
/// (`fields_of` in its `write.rs`), so the exposure is the rollout window in
/// which the two services disagree, not the steady state.
///
/// The caller's own `update_mask` is INTERSECTED with the editable set rather
/// than forwarded, by [`requested_paths`]. Forwarding it would let a client name
/// `status` and reopen a DONE task through an RPC whose whole purpose is that it
/// cannot.
pub fn edit_request(
    req: api::EditTaskRequest,
    current: &db::Task,
    paths: &[&'static str],
) -> db::UpdateTaskRequest {
    let writes = |field| paths.contains(&field);
    db::UpdateTaskRequest {
        idempotency: req.idempotency,
        scope: req.scope,
        id: write_id(req.id, current),
        expect_version: req.expect_version,
        task: Some(db::Task {
            title: if writes("title") {
                req.title
            } else {
                current.title.clone()
            },
            body: if writes("body") {
                req.body
            } else {
                current.body.clone()
            },
            status: current.status,
            ..Default::default()
        }),
        update_mask: mask(paths),
    }
}

/// A caller may narrow an edit, never widen it.
///
/// **PUBLIC, and resolved by the handler BEFORE it reads.** Two rules depend on
/// knowing which fields an edit actually writes, and both used to run in the
/// wrong place: a mask naming an unknown field was refused only after a
/// `get_task` round trip, and the empty-title check ran before this had said
/// whether `title` was being written at all — so an edit naming only `body` was
/// rejected for an empty title it was never going to store.
pub fn requested_paths(requested: Option<&FieldMask>) -> Result<Vec<&'static str>, Status> {
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
        id: write_id(req.id, current),
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
