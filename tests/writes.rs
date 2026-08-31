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
use yadgar_task::writes::{edit_request, transition_request};

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

fn paths(req: &db::UpdateTaskRequest) -> Vec<String> {
    req.update_mask
        .clone()
        .expect("an edit is always masked")
        .paths
}

/// The mutation this catches: deleting the mask, which restores an edit's reach
/// over the status column the moment `task-db` honours masks.
#[test]
fn an_edit_names_only_the_fields_an_edit_may_write() {
    let req = edit_request(an_edit(None), db::TaskStatus::Done as i32).expect("valid");
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
    let req = edit_request(an_edit(None), db::TaskStatus::Done as i32).expect("valid");
    assert_eq!(
        req.task.expect("task").status,
        db::TaskStatus::Done as i32,
        "an unmasked -db must write back what was already there, never zero"
    );
}

/// A caller may NARROW an edit.
#[test]
fn a_caller_may_ask_for_a_narrower_edit() {
    let req = edit_request(an_edit(Some(vec!["title"])), 0).expect("valid");
    assert_eq!(paths(&req), vec!["title"]);
}

/// A caller may not WIDEN one. Forwarding the caller's mask — which is what
/// happened before — let a client name `status` and reopen a DONE task through
/// the one RPC whose entire purpose is that it cannot.
#[test]
fn a_caller_may_not_widen_an_edit_to_the_status() {
    let err = edit_request(an_edit(Some(vec!["status"])), 0)
        .expect_err("`status` is not something an edit may name");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[test]
fn an_unknown_field_in_the_mask_is_refused() {
    let err = edit_request(an_edit(Some(vec!["owner_user_id"])), 0).expect_err("not editable");
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
