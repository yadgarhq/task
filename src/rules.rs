//! The business rules. This is what the logic service exists for — everything
//! else here is plumbing.

use crate::pb::yadgar::task::v1::TaskStatus;

/// Which status transitions are legal.
///
/// This lives HERE rather than in `task-db` because it is a business rule, and
/// `-db` owns the boundary rather than the rules (D4). It also cannot live in the
/// caller: `EditTask` deliberately cannot write status, so the only way to change
/// one is `TransitionTask`, and the legal set is therefore a property of the
/// contract rather than a convention each client re-implements.
///
/// **`DROPPED` is terminal and `DONE` is not.** Finishing something and later
/// reopening it is ordinary; abandoning something and then quietly resurrecting
/// it loses the fact that it was abandoned, which is the thing anyone reviewing
/// the history wants to see. Undoing a drop means creating a new task that links
/// to it.
pub fn may_transition(from: TaskStatus, to: TaskStatus) -> Result<(), TransitionError> {
    use TaskStatus::*;

    if to == Unspecified {
        return Err(TransitionError::Unspecified);
    }
    if from == to {
        // Not an error: a retry, or two clients agreeing. Rejecting it would make
        // an idempotent-looking call fail for no useful reason.
        return Ok(());
    }

    let allowed: &[TaskStatus] = match from {
        Unspecified => &[Open, InProgress, Blocked, Done, Dropped],
        Open => &[InProgress, Blocked, Done, Dropped],
        InProgress => &[Open, Blocked, Done, Dropped],
        Blocked => &[Open, InProgress, Done, Dropped],
        Done => &[Open, InProgress],
        Dropped => &[],
    };

    if allowed.contains(&to) {
        Ok(())
    } else {
        Err(TransitionError::Illegal { from, to })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransitionError {
    #[error(
        "cannot move a task from {from:?} to {to:?}. DROPPED is terminal by \
         design: undoing it would erase the fact that the task was abandoned. \
         Create a new task linking to this one instead."
    )]
    Illegal { from: TaskStatus, to: TaskStatus },

    #[error("a transition must name a target status; TASK_STATUS_UNSPECIFIED is not one")]
    Unspecified,
}
