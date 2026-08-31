//! The transition rules. Pure logic, no engine and no `-db` — this is the one
//! part of the module that is genuinely testable in isolation, and it is also
//! the part that justifies the service existing.

use yadgar_task::pb::yadgar::task::v1::TaskStatus::*;
use yadgar_task::rules::may_transition;

#[test]
fn ordinary_work_moves_freely() {
    for (from, to) in [
        (Open, InProgress),
        (InProgress, Blocked),
        (Blocked, InProgress),
        (InProgress, Done),
        (Open, Done),
    ] {
        assert!(
            may_transition(from, to).is_ok(),
            "{from:?} -> {to:?} should be allowed"
        );
    }
}

/// Finishing something and later reopening it is ordinary.
#[test]
fn done_can_be_reopened() {
    assert!(may_transition(Done, Open).is_ok());
    assert!(may_transition(Done, InProgress).is_ok());
}

/// Abandoning something and quietly resurrecting it loses the fact that it was
/// abandoned, which is exactly what someone reading the history wants to see.
#[test]
fn dropped_is_terminal() {
    for to in [Open, InProgress, Blocked, Done] {
        let err = may_transition(Dropped, to).expect_err("nothing may come back from DROPPED");
        let message = err.to_string();
        assert!(
            message.contains("terminal"),
            "the error must say why, not just refuse: {err}"
        );
        // Naming the status it is talking about is what makes this assertion
        // discriminating. `contains("terminal")` on its own passed for EVERY
        // refusal, because one message was returned for all of them.
        assert!(
            message.contains("TASK_STATUS_DROPPED"),
            "the error must name the rule it is applying: {err}"
        );
    }
}

/// The table refuses both and nothing asserted it, so there was no way to tell a
/// deliberate rule from a typo in the row.
///
/// A finished task is REOPENED before it moves anywhere else. Blocking something
/// already done is meaningless, and dropping it erases that it was completed —
/// either way the intermediate state is the record of what actually happened.
#[test]
fn a_done_task_must_be_reopened_before_it_moves_anywhere_else() {
    for to in [Blocked, Dropped] {
        let err = may_transition(Done, to).expect_err("the transition table refuses this");
        let message = err.to_string();
        assert!(
            message.contains("TASK_STATUS_DONE"),
            "the error must name what is being moved: {err}"
        );
        // This refusal has nothing to do with DROPPED being terminal, and saying
        // so sends the reader off to the wrong rule.
        assert!(
            !message.contains("terminal"),
            "DONE -> {to:?} is not the DROPPED rule: {err}"
        );
        assert!(
            message.contains("TASK_STATUS_OPEN") && message.contains("TASK_STATUS_IN_PROGRESS"),
            "a refusal must name the legal targets, or the caller is guessing: {err}"
        );
    }
}

/// A retry, or two clients agreeing. Rejecting it would fail an
/// idempotent-looking call for no useful reason — including Dropped -> Dropped,
/// which must not be caught by the terminal rule.
#[test]
fn a_no_op_transition_is_allowed_including_from_dropped() {
    for s in [Open, InProgress, Blocked, Done, Dropped] {
        assert!(
            may_transition(s, s).is_ok(),
            "{s:?} -> {s:?} is a no-op and must be accepted"
        );
    }
}

/// The proto zero value. A caller that forgot to set the field must be told,
/// not silently moved to a status nobody chose.
#[test]
fn unspecified_is_never_a_target() {
    for from in [Open, InProgress, Blocked, Done, Dropped] {
        assert!(
            may_transition(from, Unspecified).is_err(),
            "UNSPECIFIED must never be a transition target, from {from:?}"
        );
    }
}

/// A task read back before any status was written decodes as Unspecified. It
/// must still be movable, or such a row would be permanently stuck.
#[test]
fn a_task_with_no_status_yet_can_still_be_moved() {
    for to in [Open, InProgress, Blocked, Done, Dropped] {
        assert!(may_transition(Unspecified, to).is_ok());
    }
}
