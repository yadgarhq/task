//! The caller fingerprint (ADR-1051 rule 5): what a keyed `EditTask`,
//! `TransitionTask` or `RemoveTask` was, as 32 raw SHA-256 bytes.
//!
//! **THE DERIVATION IS NORMATIVE, AND IT IS STATED ON THE CONTRACT, NOT HERE.**
//! `yadgar.task.v1.LookupWriteRequest.caller_fingerprint` (proto v1.26.0) says
//! it once: SHA-256 over the fully-qualified gRPC method path as UTF-8, one
//! 0x00 byte, then the prost encoding of the decoded taskapi request with
//! `scope` and `idempotency` absent, an `update_mask` with no paths absent
//! (ADR-1052), and any other mask's paths sorted and deduplicated.
//!
//! **PURE, AND A COMPATIBILITY SURFACE.** `task-db` stores these bytes on the
//! claim and compares them on every same-key retry, so a change to any part of
//! the derivation needs a `task-db` migration that NULLs every stored caller
//! fingerprint; otherwise every retry across the deploy is refused as a
//! different request. `tests/fingerprint.rs` pins the bytes with known
//! answers computed outside this crate.
//!
//! The handlers compute it after their request-only checks and before any
//! read, so it is the same on every attempt whatever happened to the task.

use prost::Message;
use sha2::{Digest, Sha256};

use crate::pb::yadgar::taskapi::v1 as api;

/// The method path `EditTask` is served at.
pub const EDIT_TASK: &str = "/yadgar.taskapi.v1.TaskService/EditTask";
/// The method path `TransitionTask` is served at.
pub const TRANSITION_TASK: &str = "/yadgar.taskapi.v1.TaskService/TransitionTask";
/// The method path `RemoveTask` is served at.
pub const REMOVE_TASK: &str = "/yadgar.taskapi.v1.TaskService/RemoveTask";

/// SHA-256 over `path`, one 0x00 byte, then `encoded`.
fn digest(path: &str, encoded: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(path.as_bytes());
    hash.update([0u8]);
    hash.update(encoded);
    hash.finalize().to_vec()
}

/// The `EditTaskRequest` the fingerprint encodes: `scope` and `idempotency`
/// absent, an empty mask folded to absent, and any other mask's paths sorted
/// and deduplicated.
pub fn normalised_edit(req: &api::EditTaskRequest) -> api::EditTaskRequest {
    let mut req = req.clone();
    req.scope = None;
    req.idempotency = None;
    req.update_mask = req
        .update_mask
        .filter(|m| !m.paths.is_empty())
        .map(|mut m| {
            m.paths.sort();
            m.paths.dedup();
            m
        });
    req
}

/// The `TransitionTaskRequest` the fingerprint encodes: `scope` and
/// `idempotency` absent.
pub fn normalised_transition(req: &api::TransitionTaskRequest) -> api::TransitionTaskRequest {
    api::TransitionTaskRequest {
        scope: None,
        idempotency: None,
        ..req.clone()
    }
}

/// The `RemoveTaskRequest` the fingerprint encodes: `scope` and
/// `idempotency` absent.
pub fn normalised_remove(req: &api::RemoveTaskRequest) -> api::RemoveTaskRequest {
    api::RemoveTaskRequest {
        scope: None,
        idempotency: None,
        ..req.clone()
    }
}

/// The caller fingerprint of an `EditTask`.
pub fn edit_task(req: &api::EditTaskRequest) -> Vec<u8> {
    digest(EDIT_TASK, &normalised_edit(req).encode_to_vec())
}

/// The caller fingerprint of a `TransitionTask`.
pub fn transition_task(req: &api::TransitionTaskRequest) -> Vec<u8> {
    digest(TRANSITION_TASK, &normalised_transition(req).encode_to_vec())
}

/// The caller fingerprint of a `RemoveTask`.
pub fn remove_task(req: &api::RemoveTaskRequest) -> Vec<u8> {
    digest(REMOVE_TASK, &normalised_remove(req).encode_to_vec())
}
