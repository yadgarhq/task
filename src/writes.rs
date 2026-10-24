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
/// Present, it must be 32 bytes and the mask must write `body` or name
/// `patch`; a digest on an edit that writes no body guards nothing, and the
/// caller believes it does. In patch mode only the length is checked here.
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
    // IN PATCH MODE THE DIGEST IS OVER THE PRE-EDIT BODY (ADR-1008), which only
    // the read supplies: [`patched`] compares it. The length is settled here.
    if paths.contains(&PATCH) {
        return Ok(());
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

/// The mask path that selects patch mode (ADR-1008). It names the request's
/// `patch` field, not a column: [`patched`] turns it into a `body` write.
///
/// A task that predates patch mode refuses this path in [`requested_paths`],
/// so a newer caller's patch is refused there rather than silently dropped.
const PATCH: &str = "patch";

/// The most bytes `old` or `new` may each carry.
pub const PATCH_SIDE_MAX: usize = 65536;

/// The most bytes a patched body may have: the gateway's request cap
/// (`MAX_BODY_BYTES`), so a patch never stores a body that no whole-body edit
/// through the MCP surface could have sent.
pub const PATCH_RESULT_MAX: usize = 1_048_576;

/// The rules a patch is held to before anything is read (ADR-1008): the mask
/// and the message agree, `patch` excludes `body`, `old` is non-empty,
/// `expect_count` is at least 1, and each side fits [`PATCH_SIDE_MAX`].
///
/// **RUN BEFORE [`check_body_digest`]**, whose answer depends on whether the
/// edit is a patch.
pub fn check_patch(req: &api::EditTaskRequest, paths: &[&'static str]) -> Result<(), Status> {
    let names_patch = paths.contains(&PATCH);
    let Some(patch) = req.patch.as_ref() else {
        if names_patch {
            return Err(Status::invalid_argument(
                "the mask names `patch`, but no patch was sent",
            ));
        }
        return Ok(());
    };
    if paths.contains(&"body") && names_patch {
        return Err(Status::invalid_argument(
            "`patch` and `body` are mutually exclusive; send one",
        ));
    }
    if !names_patch {
        return Err(Status::invalid_argument(
            "a patch was sent, but the mask does not name `patch`",
        ));
    }
    if patch.old.is_empty() {
        return Err(Status::invalid_argument(
            "a patch's `old` must not be empty",
        ));
    }
    if patch.expect_count == 0 {
        return Err(Status::invalid_argument(
            "a patch's `expect_count` must be at least 1",
        ));
    }
    for (side, text) in [("old", &patch.old), ("new", &patch.new)] {
        if text.len() > PATCH_SIDE_MAX {
            return Err(Status::invalid_argument(format!(
                "a patch's `{side}` is at most {PATCH_SIDE_MAX} bytes; this one has {}",
                text.len()
            )));
        }
    }
    Ok(())
}

/// Apply a patch to the body as stored, and turn the edit into a whole-body
/// one: THE ONE PLACE A PATCH IS COMPUTED (ADR-1008), so no caller can compute
/// a different result. An edit that is not a patch passes through unchanged.
///
/// Matching is literal over UTF-8 bytes, with no regex and no normalisation.
/// Occurrences are counted non-overlapping, left to right (`str::matches`),
/// and `str::replace` replaces exactly those. Both strings are valid UTF-8, so
/// a match always starts and ends on a character boundary.
///
/// Each refusal here depends on the stored task, so it is FAILED_PRECONDITION,
/// as a stale version is. A refusal over the body starts with a reason token
/// listed on `EditTaskRequest.patch`; a stale version carries none, as it
/// carries none in whole-body mode.
///
/// **THE READ MUST BE THE VERSION THE CALLER EXPECTS**, checked here and not
/// left to the store. A patch is computed on the body READ. With
/// `expect_version` read+1, the patch would be computed on the older body, and
/// the store's compare-and-set would pass if another writer landed read+1 in
/// between: a lost update. A whole-body edit carries its own body, so it needs
/// no such check and gets none. The write still carries the caller's
/// `expect_version`, so a body that moves after this read is refused by the
/// compare-and-set.
///
/// **THE RESULT'S SIZE IS DECIDED BEFORE IT IS BUILT**, by arithmetic. A
/// 1 MiB body of one-byte occurrences, each grown to 64 KiB, is a 64 GiB
/// string; building it first and measuring after would exhaust memory.
///
/// KNOWN CONTRACT GAP, recorded here rather than papered over: an IDEMPOTENT
/// REPLAY of an applied patch is refused, not replayed.
///
/// The read below runs before the write. On the retry of a patch that was
/// already applied, it returns the PATCHED body at the NEW version, so this
/// function refuses the retry as a stale version before `task-db` is reached. `task-db` would have
/// replayed the recorded response for the same key, and its fingerprint of the
/// request covers the body THIS service computed, which a retry cannot
/// reproduce from the new body anyway.
///
/// IT IS NOT FIXED HERE, because nothing this service can reach tells it that
/// a key was already applied before it reads. Through the gateway the gap is
/// unreachable: every gateway call mints a fresh idempotency key. A direct
/// gRPC caller that retries with the same key after a lost response sees the
/// refusal and must re-read, which is safe — the patch is applied once.
pub fn patched(
    mut req: api::EditTaskRequest,
    current: &db::Task,
    paths: &[&'static str],
) -> Result<(api::EditTaskRequest, Vec<&'static str>), Status> {
    let Some(patch) = req.patch.take() else {
        return Ok((req, paths.to_vec()));
    };
    let read_version = current.meta.as_ref().map_or(0, |m| m.version);
    if read_version != req.expect_version {
        return Err(Status::failed_precondition(format!(
            "the task is at version {read_version}, not the expect_version {} this patch \
             names; nothing was written. Re-read the task",
            req.expect_version
        )));
    }
    if !req.expect_body_sha256.is_empty()
        && Sha256::digest(current.body.as_bytes()).as_slice() != req.expect_body_sha256.as_slice()
    {
        return Err(Status::failed_precondition(
            "BODY_SHA256_MISMATCH: the stored body does not match expect_body_sha256, so \
             it is not the body you read; nothing was written. Re-read the task",
        ));
    }
    let found = current.body.matches(patch.old.as_str()).count();
    if found != patch.expect_count as usize {
        return Err(Status::failed_precondition(format!(
            "PATCH_COUNT_MISMATCH: `old` occurs {found} times in the stored body, not the {} \
             expect_count names; nothing was written. Re-read the task",
            patch.expect_count
        )));
    }
    // Checked, in usize. `found * old.len()` never exceeds the body's length,
    // so the subtraction cannot underflow; an overflow of the growth term means
    // a result no machine could hold, which is over the bound by definition.
    let result_len = found
        .checked_mul(patch.new.len())
        .and_then(|grown| (current.body.len() - found * patch.old.len()).checked_add(grown));
    let Some(_) = result_len.filter(|n| *n <= PATCH_RESULT_MAX) else {
        return Err(Status::failed_precondition(format!(
            "PATCH_RESULT_TOO_LARGE: the patched body would be {} bytes; a body is \
             at most {PATCH_RESULT_MAX}. Nothing was written",
            result_len.map_or_else(|| "more than usize::MAX".to_string(), |n| n.to_string())
        )));
    };
    let body = current.body.replace(patch.old.as_str(), &patch.new);
    req.body = body;
    let paths = paths
        .iter()
        .map(|p| if *p == PATCH { "body" } else { *p })
        .collect();
    Ok((req, paths))
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
                .chain([PATCH])
                .find(|editable| editable == path)
                .ok_or_else(|| {
                    Status::invalid_argument(format!(
                        "an edit may write {}, or apply a `{PATCH}`, not `{path}`",
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
