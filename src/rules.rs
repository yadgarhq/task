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
        return Ok(());
    }
    // WHY TWO VARIANTS. There used to be one, and its message explained DROPPED
    // — so a caller refused DONE -> BLOCKED was told that dropping is terminal,
    // which is true, unrelated, and says nothing about the transition it asked
    // for. An error that explains the WRONG rule is worse than one that explains
    // none: it sends the reader off to fix something that is not broken.
    if from == Dropped {
        return Err(TransitionError::Terminal { to });
    }
    Err(TransitionError::Illegal {
        from,
        to,
        legal: allowed
            .iter()
            .map(|s| s.as_str_name())
            .collect::<Vec<_>>()
            .join(", "),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum TransitionError {
    #[error(
        "cannot move a task from TASK_STATUS_DROPPED to {}. DROPPED is terminal \
         by design: undoing it would erase the fact that the task was abandoned. \
         Create a new task linking to this one instead.",
        .to.as_str_name()
    )]
    Terminal { to: TaskStatus },

    /// Names the LEGAL TARGETS rather than a rationale, because the reason
    /// differs per pair while the caller's next move does not: pick one from the
    /// list. DONE refuses BLOCKED and DROPPED because a finished task is
    /// reopened first — the intermediate state is the record of what happened.
    #[error(
        "cannot move a task from {} to {}. The legal targets from {} are: {legal}.",
        .from.as_str_name(), .to.as_str_name(), .from.as_str_name()
    )]
    Illegal {
        from: TaskStatus,
        to: TaskStatus,
        legal: String,
    },

    #[error("a transition must name a target status; TASK_STATUS_UNSPECIFIED is not one")]
    Unspecified,
}
