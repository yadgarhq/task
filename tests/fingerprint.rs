//! Known answers for the caller fingerprint (ADR-1051 rule 5, ADR-1052).
//!
//! **EVERY CONSTANT BELOW WAS COMPUTED OUTSIDE THIS CRATE**, by a Python
//! script that hand-builds the protobuf bytes (tag = field << 3 | wire type,
//! varints, length prefixes; no protobuf library) and hashes them with
//! `hashlib.sha256`. The REMOVE digest was checked a second time with
//! `xxd -r -p` and `sha256sum`. The script is in the PR body. None of these
//! values was produced by the code under test.
//!
//! The ENCODED BYTES are pinned beside the digests, so an encoding fault and a
//! hashing fault red different assertions.

use prost::Message;
use prost_types::FieldMask;
use yadgar_task::fingerprint;
use yadgar_task::pb::yadgar::common::v1 as common;
use yadgar_task::pb::yadgar::task::v1 as db;
use yadgar_task::pb::yadgar::taskapi::v1 as api;

const ID: &str = "yadgar:task:kat";

const EDIT_BYTES: &str = "1a0f7961646761723a7461736b3a6b617420ac022a074772c3bcc39f653a0e0a057061\
                          7463680a057469746c65520c0a036f6c6412036e65771802";
const EDIT_SHA256: &str = "730941a99cbc6452dc2a97cc9025df47f685b7672623e612b93c4a6226459261";
const EDIT_NO_MASK_BYTES: &str =
    "1a0f7961646761723a7461736b3a6b617420ac022a074772c3bcc39f65520c0a036f6c6412036e65771802";
const EDIT_NO_MASK_SHA256: &str =
    "7dfabd108dbed8017088196754cca89d3ee3a0b4bc8d76efe21202408d0d471b";
const TRANSITION_BYTES: &str = "1a0f7961646761723a7461736b3a6b617420ac022804";
const TRANSITION_SHA256: &str = "200ec25084f8fef892aed75a7822fea8e0f2393e20b6a7691b97d05f2cd9f2a5";
const REMOVE_BYTES: &str = "1a0f7961646761723a7461736b3a6b617420ac02";
const REMOVE_SHA256: &str = "079d2f76e9d2792a8a21c3ed58358101a54756914e9de0489aba5567dcad77a8";
/// `{id, expect_version}` alone encodes to [`REMOVE_BYTES`] in all three
/// request types; only the method path tells the digests apart.
const COMMON_AS_EDIT_SHA256: &str =
    "4c33492b6c625304696e3cd8ee2f366cc1698993d1e2dfcd14f2e929d1169996";
const COMMON_AS_TRANSITION_SHA256: &str =
    "c95e3bdaae81954cac2db6fa2d23e4a2570db231694ae42fe72c7754d64a3ed6";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn scope() -> Option<common::Scope> {
    Some(common::Scope {
        project_id: "quinyx/qwfm".into(),
        user_id: "max".into(),
        request_id: "req-1".into(),
        ..Default::default()
    })
}

fn key(k: &str) -> Option<common::Idempotency> {
    Some(common::Idempotency { key: k.into() })
}

fn mask(paths: &[&str]) -> Option<FieldMask> {
    Some(FieldMask {
        paths: paths.iter().map(|p| (*p).to_string()).collect(),
    })
}

/// The edit the KAT script encodes: patch mode, a non-ASCII title, a
/// two-byte varint version, and a mask sent unsorted with a duplicate.
fn kat_edit() -> api::EditTaskRequest {
    api::EditTaskRequest {
        idempotency: key("k-1"),
        scope: scope(),
        id: ID.into(),
        expect_version: 300,
        title: "Grüße".into(),
        update_mask: mask(&["title", "patch", "title"]),
        patch: Some(api::BodyPatch {
            old: "old".into(),
            new: "new".into(),
            expect_count: 2,
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn an_edit_encodes_and_hashes_to_the_known_answer() {
    let req = kat_edit();
    assert_eq!(
        hex(&fingerprint::normalised_edit(&req).encode_to_vec()),
        EDIT_BYTES
    );
    assert_eq!(hex(&fingerprint::edit_task(&req)), EDIT_SHA256);
}

#[test]
fn a_transition_encodes_and_hashes_to_the_known_answer() {
    let req = api::TransitionTaskRequest {
        idempotency: key("k-1"),
        scope: scope(),
        id: ID.into(),
        expect_version: 300,
        to: db::TaskStatus::Done as i32,
        number: 0,
    };
    assert_eq!(
        hex(&fingerprint::normalised_transition(&req).encode_to_vec()),
        TRANSITION_BYTES
    );
    assert_eq!(hex(&fingerprint::transition_task(&req)), TRANSITION_SHA256);
}

#[test]
fn a_remove_encodes_and_hashes_to_the_known_answer() {
    let req = api::RemoveTaskRequest {
        idempotency: key("k-1"),
        scope: scope(),
        id: ID.into(),
        expect_version: 300,
    };
    assert_eq!(
        hex(&fingerprint::normalised_remove(&req).encode_to_vec()),
        REMOVE_BYTES
    );
    assert_eq!(hex(&fingerprint::remove_task(&req)), REMOVE_SHA256);
}

/// ADR-1052 rule 1: an absent mask and a present mask with no paths mean the
/// same edit, so they fingerprint the same. An empty `FieldMask` encodes as
/// `3a 00`, which is exactly what the fold removes.
#[test]
fn an_absent_mask_and_an_empty_mask_give_equal_digests() {
    let absent = api::EditTaskRequest {
        update_mask: None,
        ..kat_edit()
    };
    let empty = api::EditTaskRequest {
        update_mask: mask(&[]),
        ..kat_edit()
    };
    assert_eq!(
        hex(&fingerprint::normalised_edit(&empty).encode_to_vec()),
        EDIT_NO_MASK_BYTES
    );
    assert_eq!(hex(&fingerprint::edit_task(&absent)), EDIT_NO_MASK_SHA256);
    assert_eq!(hex(&fingerprint::edit_task(&empty)), EDIT_NO_MASK_SHA256);
}

/// A mask with paths is NOT folded to absent, even though it names more than
/// nothing: only the empty mask is (ADR-1052 rule 1).
#[test]
fn a_mask_with_paths_is_not_folded_to_absent() {
    assert_ne!(
        fingerprint::edit_task(&kat_edit()),
        fingerprint::edit_task(&api::EditTaskRequest {
            update_mask: None,
            ..kat_edit()
        })
    );
}

/// Unsorted, duplicated paths and their sorted, deduplicated form give one
/// digest. `["title","body","title"]` against `["body","title"]` reds a sort
/// without a dedup as well as no sort at all.
#[test]
fn unsorted_or_duplicated_paths_and_sorted_paths_give_equal_digests() {
    let with = |paths: &[&str]| {
        fingerprint::edit_task(&api::EditTaskRequest {
            update_mask: mask(paths),
            ..kat_edit()
        })
    };
    assert_eq!(with(&["title", "body", "title"]), with(&["body", "title"]));
    assert_eq!(with(&["title", "body"]), with(&["body", "title"]));
    assert_eq!(hex(&with(&["title", "patch", "title"])), EDIT_SHA256);
    assert_eq!(hex(&with(&["patch", "title"])), EDIT_SHA256);
}

/// `scope` and `idempotency` do not enter the digest: a retry is the same
/// request whatever its request id, and the key is what is looked up.
#[test]
fn scope_and_idempotency_do_not_affect_the_digest() {
    let bare = api::EditTaskRequest {
        scope: None,
        idempotency: None,
        ..kat_edit()
    };
    let other = api::EditTaskRequest {
        scope: Some(common::Scope {
            project_id: "another/project".into(),
            ..Default::default()
        }),
        idempotency: key("another-key"),
        ..kat_edit()
    };
    assert_eq!(hex(&fingerprint::edit_task(&bare)), EDIT_SHA256);
    assert_eq!(hex(&fingerprint::edit_task(&other)), EDIT_SHA256);

    let t = |scope, idempotency| {
        fingerprint::transition_task(&api::TransitionTaskRequest {
            idempotency,
            scope,
            id: ID.into(),
            expect_version: 300,
            to: db::TaskStatus::Done as i32,
            number: 0,
        })
    };
    assert_eq!(hex(&t(None, None)), TRANSITION_SHA256);
    assert_eq!(hex(&t(scope(), key("x"))), TRANSITION_SHA256);

    let r = |scope, idempotency| {
        fingerprint::remove_task(&api::RemoveTaskRequest {
            idempotency,
            scope,
            id: ID.into(),
            expect_version: 300,
        })
    };
    assert_eq!(hex(&r(None, None)), REMOVE_SHA256);
    assert_eq!(hex(&r(scope(), key("x"))), REMOVE_SHA256);
}

/// THE METHOD PATH SEPARATES THE THREE RPCs. `{id, expect_version}` encodes
/// to the same bytes in all three request types, so equal bytes and three
/// different digests prove the path is what tells them apart. EditTask and
/// TransitionTask both look up WRITE_RPC_UPDATE_TASK, so this is the only
/// thing that separates them under one key.
#[test]
fn the_three_method_paths_give_different_digests_for_equal_bytes() {
    let edit = api::EditTaskRequest {
        id: ID.into(),
        expect_version: 300,
        ..Default::default()
    };
    let transition = api::TransitionTaskRequest {
        id: ID.into(),
        expect_version: 300,
        ..Default::default()
    };
    let remove = api::RemoveTaskRequest {
        id: ID.into(),
        expect_version: 300,
        ..Default::default()
    };
    let bytes = [
        hex(&fingerprint::normalised_edit(&edit).encode_to_vec()),
        hex(&fingerprint::normalised_transition(&transition).encode_to_vec()),
        hex(&fingerprint::normalised_remove(&remove).encode_to_vec()),
    ];
    assert!(bytes.iter().all(|b| b == REMOVE_BYTES), "{bytes:?}");
    assert_eq!(hex(&fingerprint::edit_task(&edit)), COMMON_AS_EDIT_SHA256);
    assert_eq!(
        hex(&fingerprint::transition_task(&transition)),
        COMMON_AS_TRANSITION_SHA256
    );
    assert_eq!(hex(&fingerprint::remove_task(&remove)), REMOVE_SHA256);
}

/// The paths are the ones tonic serves the RPCs at, not a spelling of them.
#[test]
fn the_method_paths_are_the_served_ones() {
    use yadgar_task::pb::yadgar::taskapi::v1::task_service_server::SERVICE_NAME;
    assert_eq!(fingerprint::EDIT_TASK, format!("/{SERVICE_NAME}/EditTask"));
    assert_eq!(
        fingerprint::TRANSITION_TASK,
        format!("/{SERVICE_NAME}/TransitionTask")
    );
    assert_eq!(
        fingerprint::REMOVE_TASK,
        format!("/{SERVICE_NAME}/RemoveTask")
    );
}

/// Exactly 32 bytes, which is what LookupWrite and the writes require.
#[test]
fn a_fingerprint_is_32_bytes() {
    assert_eq!(fingerprint::edit_task(&kat_edit()).len(), 32);
}
