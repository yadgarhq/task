//! What an API write turns into on the wire to `task-db`.
//!
//! These assert the SHAPE of the request rather than the effect of sending it,
//! and that is the point: `EditTask` used to read the current status and write
//! it back, which meant the one RPC that must not change a status was the one
//! writing the status column on every call. Whether that particular value
//! happened to be correct is not the property worth testing — whether an edit
//! can reach the column at all is.

use prost_types::FieldMask;
use yadgar_task::pb::yadgar::task::v1 as db;
use yadgar_task::pb::yadgar::taskapi::v1 as api;
use yadgar_task::writes::{edit_request, requested_paths, transition_request};

/// The task as the STORE holds it. Every value here is one no request below
/// carries, so a field that arrives unchanged was read rather than echoed.
const STORED_TITLE: &str = "the title the store already held";
const STORED_BODY: &str = "octarine wombat 8823, the body the store already held";

fn an_edit(mask: Option<Vec<&str>>) -> api::EditTaskRequest {
    api::EditTaskRequest {
        idempotency: None,
        scope: None,
        id: "yadgar:task:x".into(),
        expect_version: 3,
        title: "new title".into(),
        body: "new body".into(),
        update_mask: mask.map(|paths| FieldMask {
            paths: paths.into_iter().map(String::from).collect(),
        }),
    }
}

fn stored(status: db::TaskStatus) -> db::Task {
    db::Task {
        title: STORED_TITLE.into(),
        body: STORED_BODY.into(),
        status: status as i32,
        ..Default::default()
    }
}

/// Resolve the mask the way the handler does, then build the request.
fn edit(
    req: api::EditTaskRequest,
    current: &db::Task,
) -> Result<db::UpdateTaskRequest, tonic::Status> {
    let paths = requested_paths(req.update_mask.as_ref())?;
    Ok(edit_request(req, current, &paths))
}

fn paths(req: &db::UpdateTaskRequest) -> Vec<String> {
    req.update_mask
        .clone()
        .expect("an edit is always masked")
        .paths
}

fn task_of(req: &db::UpdateTaskRequest) -> db::Task {
    req.task.clone().expect("an edit always carries a task")
}

/// The mutation this catches: deleting the mask, which restores an edit's reach
/// over the status column the moment `task-db` honours masks.
#[test]
fn an_edit_names_only_the_fields_an_edit_may_write() {
    let req = edit(an_edit(None), &stored(db::TaskStatus::Done)).expect("valid");
    assert_eq!(paths(&req), vec!["title", "body"]);
    assert!(
        !paths(&req).contains(&"status".to_string()),
        "status is not an editable field; that is why TransitionTask exists"
    );
}

/// The status is still CARRIED, and deliberately. A `-db` that does not yet
/// honour the mask writes every field it is given, so sending UNSPECIFIED would
/// zero the stored status on every edit during a rollout — a worse bug than the
/// one this fixes.
#[test]
fn an_edit_carries_the_current_status_unchanged_for_an_older_db() {
    let req = edit(an_edit(None), &stored(db::TaskStatus::Done)).expect("valid");
    assert_eq!(
        task_of(&req).status,
        db::TaskStatus::Done as i32,
        "an unmasked -db must write back what was already there, never zero"
    );
}

/// A caller may NARROW an edit.
#[test]
fn a_caller_may_ask_for_a_narrower_edit() {
    let req = edit(an_edit(Some(vec!["title"])), &stored(db::TaskStatus::Open)).expect("valid");
    assert_eq!(paths(&req), vec!["title"]);
}

/// **THE FIELD THE MASK LEAVES OUT CARRIES WHAT THE STORE ALREADY HELD.**
///
/// Asserting only that the mask was narrowed — which the test above does — passes
/// against the defect: `edit_request` set `body: req.body` unconditionally, so a
/// title-only edit put the request's EMPTY body on the wire under a mask that did
/// not name it. A `-db` ignoring the mask writes every field it is given, and the
/// stored body is gone. The mask is the mechanism; carrying the current value is
/// what survives a `-db` that has not caught up, which is exactly the argument
/// `transition_request` has always made for `title` and `body`.
///
/// `STORED_BODY` is a value no request in this file carries, so it can only have
/// reached the wire from `current`.
#[test]
fn a_title_only_edit_carries_the_stored_body_rather_than_an_empty_one() {
    let mut req = an_edit(Some(vec!["title"]));
    // What a title-only client actually sends: the field it does not intend to
    // write is left at its default.
    req.body = String::new();

    let built = edit(req, &stored(db::TaskStatus::Open)).expect("valid");

    assert_eq!(paths(&built), vec!["title"]);
    assert_eq!(
        task_of(&built).body,
        STORED_BODY,
        "a -db that ignores the mask writes this field, so it must be what was read"
    );
    assert_eq!(
        task_of(&built).title,
        "new title",
        "the field the mask DOES name must still be the caller's"
    );
}

/// The mirror, so neither direction can be satisfied by simply always sending
/// `current`.
#[test]
fn a_body_only_edit_carries_the_stored_title_rather_than_an_empty_one() {
    let mut req = an_edit(Some(vec!["body"]));
    req.title = String::new();

    let built = edit(req, &stored(db::TaskStatus::Open)).expect("valid");

    assert_eq!(paths(&built), vec!["body"]);
    assert_eq!(
        task_of(&built).title,
        STORED_TITLE,
        "a -db that ignores the mask writes this field, so it must be what was read"
    );
    assert_eq!(
        task_of(&built).body,
        "new body",
        "the field the mask DOES name must still be the caller's"
    );
}

/// A caller may not WIDEN one. Forwarding the caller's mask — which is what
/// happened before — let a client name `status` and reopen a DONE task through
/// the one RPC whose entire purpose is that it cannot.
#[test]
fn a_caller_may_not_widen_an_edit_to_the_status() {
    let err = requested_paths(an_edit(Some(vec!["status"])).update_mask.as_ref())
        .expect_err("`status` is not something an edit may name");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[test]
fn an_unknown_field_in_the_mask_is_refused() {
    let err = requested_paths(an_edit(Some(vec!["owner_user_id"])).update_mask.as_ref())
        .expect_err("not editable");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

/// A transition writes the status and nothing else. Without the mask the request
/// also carries an empty `tags` and `links` — the zero value of a message this
/// handler never populated — and a `-db` that writes every field would erase
/// them on every status change.
#[test]
fn a_transition_names_the_status_alone() {
    let current = db::Task {
        title: "kept".into(),
        body: "also kept".into(),
        status: db::TaskStatus::Open as i32,
        tags: vec!["important".into()],
        ..Default::default()
    };
    let req = transition_request(
        api::TransitionTaskRequest {
            idempotency: None,
            scope: None,
            id: "yadgar:task:x".into(),
            expect_version: 1,
            to: db::TaskStatus::Done as i32,
        },
        &current,
        db::TaskStatus::Done,
    );

    assert_eq!(
        req.update_mask.expect("a transition is masked").paths,
        vec!["status"]
    );
    let task = req.task.expect("task");
    assert_eq!(task.status, db::TaskStatus::Done as i32);
    assert_eq!(
        task.title, "kept",
        "an unmasked -db writes the title too, so it must be the one just read"
    );
}
