//! `task` — the task module's logic service.
//!
//! **It holds no store, and that absence is the design (D4).** There is no sqlx
//! and no `yadgar-store` in this crate's dependency tree: a logic service reaches
//! its data only over the `-db` API, which is what makes the twin a connection
//! concentrator rather than merely a boundary. N replicas of this service with
//! embedded pools would multiply connections against an engine with hard limits.

#![forbid(unsafe_code)]

pub mod rules;
pub mod serve;
pub mod service;
pub mod upstream;
pub mod writes;

/// Generated from the vendored contract (D16, D70). The module tree mirrors the
/// protobuf package path — generated cross-package references are emitted as
/// `super::super::common::v1::Meta`, so a flattened tree fails to compile.
pub mod pb {
    pub mod yadgar {
        pub mod common {
            pub mod v1 {
                tonic::include_proto!("yadgar.common.v1");
            }
        }
        pub mod task {
            pub mod v1 {
                tonic::include_proto!("yadgar.task.v1");
            }
        }
        pub mod taskapi {
            pub mod v1 {
                tonic::include_proto!("yadgar.taskapi.v1");
            }
        }
    }
}
