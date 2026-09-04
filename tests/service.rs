//! What a caller of the public API actually sees.
//!
//! `service.rs` had no tests at all, and `passthrough` decides every status code
//! this API ever returns. A handler could collapse `FAILED_PRECONDITION` — the
//! one code whose contract is a refusal a re-read may clear — into `INTERNAL`,
//! and nothing in the repository would have noticed.
//!
//! THESE RUN A REAL SERVER. The mock is a `TaskDbService` served over loopback,
//! not a hand-rolled stand-in for the client, because the properties under test
//! are wire properties: that a `-db` status code survives the hop with its code
//! intact and its MESSAGE dropped, and that what the store put in `meta` is what
//! the caller gets back. A fake that hands a `Status` over by value touches
//! neither the codec nor the trailers, so it could not tell either of those
//! apart from a handler that invents the answer.
//!
//! FIXTURE DISCIPLINE. Every value the store returns here is one the handler
//! could not plausibly have produced from its own inputs — version 41 against an
//! `expect_version` of 3, an id the caller never sent, a project the request does
//! not name. A fixture the implementation could have chosen proves nothing: the
//! assertion passes for the correct handler and for the one that echoes its own
//! request back.

use std::sync::{Arc, Mutex, OnceLock};

use tonic::{Code, Request, Response, Status};
use yadgar_task::pb::yadgar::common::v1 as common;
use yadgar_task::pb::yadgar::task::v1 as db;
use yadgar_task::pb::yadgar::task::v1::task_db_service_server::{
    TaskDbService, TaskDbServiceServer,
};
use yadgar_task::pb::yadgar::taskapi::v1 as api;
use yadgar_task::pb::yadgar::taskapi::v1::task_service_server::TaskService;
use yadgar_task::service::Task;

// ---------------------------------------------------------------------------
// Fixtures the implementation could not have chosen for itself.
// ---------------------------------------------------------------------------

/// The id the STORE assigns. Deliberately not the id any request below carries,
/// so a handler echoing `req.id` back fails rather than coincidentally passing.
const STORE_ID: &str = "yadgar:task:0192f3c1-assigned-by-the-store";
/// The version the STORE reports. Every request below sends `expect_version: 3`,
/// so a handler synthesising `expect_version + 1` produces 4 and is caught.
const STORE_VERSION: u64 = 41;
/// A project the requests do not name, so a synthesised `Meta` leaves it empty.
const STORE_PROJECT: &str = "quinyx/qwfm/assigned-by-the-store";

/// The id a CALLER sends. Never what the store returns.
const CALLER_ID: &str = "yadgar:task:the-id-the-caller-sent";

/// What `-db` says when it fails: storage vocabulary, exactly the kind the
/// module's doc comment says a public client has no business seeing.
const DB_DETAIL: &str = "column status of table task_0007 rejected 'mauve porcupine 4711'";

/// A second, distinct storage message used ONLY by the logging test, so a
/// `contains` assertion over the shared log buffer cannot be satisfied by some
/// other test's output arriving first.
const LOG_PROBE: &str = "constraint task_pkey violated by 'lilac wombat 8823'";

/// The envelope the WRITE answers with.
fn store_meta() -> common::Meta {
    common::Meta {
        id: STORE_ID.to_string(),
        version: STORE_VERSION,
        project_id: STORE_PROJECT.to_string(),
        ..Default::default()
    }
}

/// The envelope the READ answers with, and it is deliberately NOT the one above.
///
/// Both handlers that write read first, so a handler returning the meta it READ
/// rather than the one the write reported is a live mutation — and one the
/// mutation run caught, because these two fixtures were briefly identical and
/// the test could not tell them apart. The version here is the PRE-write one, so
/// it is also what a correct handler must not report.
fn read_meta() -> common::Meta {
    common::Meta {
        id: "yadgar:task:0192f3c1-as-it-was-before-the-write".to_string(),
        version: 3,
        project_id: "quinyx/qwfm/as-it-was-before-the-write".to_string(),
        ..Default::default()
    }
}

fn a_stored_task(status: i32) -> db::Task {
    db::Task {
        meta: Some(read_meta()),
        number: 4711,
        title: "the stored title".into(),
        body: "the stored body".into(),
        status,
        tags: vec!["stored-tag".into()],
        links: vec!["yadgar:adr:0004".into()],
    }
}

// ---------------------------------------------------------------------------
// The mock store.
// ---------------------------------------------------------------------------

/// A canned outcome. The error side is `(code, message)` rather than a `Status`
/// because the message has to be BUILT ON THE SERVER and cross the wire — that
/// journey is half of what the passthrough tests assert.
type Canned<T> = Result<T, (Code, &'static str)>;

/// Every request that reached the store. Assertions over this are what catch a
/// handler that talks to `-db` when it should have refused first, or that reads
/// twice when the contract only affords it one read.
#[derive(Default)]
struct Recorded {
    create: Vec<db::CreateTaskRequest>,
    update: Vec<db::UpdateTaskRequest>,
    get: Vec<db::GetTaskRequest>,
    list: Vec<db::ListTasksRequest>,
    delete: Vec<db::DeleteTaskRequest>,
}

/// One scripted outcome per RPC. No queue: no handler in this service calls any
/// `-db` RPC more than once, and a queue would quietly permit the second call
/// that several tests below exist to forbid.
#[derive(Default)]
struct MockDb {
    create: Option<Canned<db::CreateTaskResponse>>,
    update: Option<Canned<db::UpdateTaskResponse>>,
    get: Option<Canned<db::GetTaskResponse>>,
    list: Option<Canned<db::ListTasksResponse>>,
    delete: Option<Canned<db::DeleteTaskResponse>>,
    seen: Arc<Mutex<Recorded>>,
}

fn answer<T: Clone>(canned: &Option<Canned<T>>, rpc: &str) -> Result<Response<T>, Status> {
    match canned {
        Some(Ok(value)) => Ok(Response::new(value.clone())),
        Some(Err((code, message))) => Err(Status::new(*code, *message)),
        // Never scripted on purpose. Surfacing it as a status rather than a
        // panic keeps the failure inside the assertion the test already makes.
        None => Err(Status::unimplemented(format!(
            "the mock store has no scripted outcome for {rpc}"
        ))),
    }
}

#[tonic::async_trait]
impl TaskDbService for MockDb {
    async fn create_task(
        &self,
        request: Request<db::CreateTaskRequest>,
    ) -> Result<Response<db::CreateTaskResponse>, Status> {
        self.seen.lock().unwrap().create.push(request.into_inner());
        answer(&self.create, "CreateTask")
    }

    async fn update_task(
        &self,
        request: Request<db::UpdateTaskRequest>,
    ) -> Result<Response<db::UpdateTaskResponse>, Status> {
        self.seen.lock().unwrap().update.push(request.into_inner());
        answer(&self.update, "UpdateTask")
    }

    async fn get_task(
        &self,
        request: Request<db::GetTaskRequest>,
    ) -> Result<Response<db::GetTaskResponse>, Status> {
        self.seen.lock().unwrap().get.push(request.into_inner());
        answer(&self.get, "GetTask")
    }

    async fn list_tasks(
        &self,
        request: Request<db::ListTasksRequest>,
    ) -> Result<Response<db::ListTasksResponse>, Status> {
        self.seen.lock().unwrap().list.push(request.into_inner());
        answer(&self.list, "ListTasks")
    }

    async fn delete_task(
        &self,
        request: Request<db::DeleteTaskRequest>,
    ) -> Result<Response<db::DeleteTaskResponse>, Status> {
        self.seen.lock().unwrap().delete.push(request.into_inner());
        answer(&self.delete, "DeleteTask")
    }
}

/// Serve the mock on loopback and hand back a `Task` wired to it.
///
/// The server task is owned by the test's runtime and dies with it, so there is
/// nothing to reap: the runtime is dropped when the `#[tokio::test]` body
/// returns.
async fn wire(mock: MockDb) -> (Task, Arc<Mutex<Recorded>>) {
    let seen = mock.seen.clone();

    // Bind FIRST, then serve the bound listener. Picking a port and reopening it
    // leaves a window in which something else takes it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let addr = listener.local_addr().expect("the bound address");

    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(TaskDbServiceServer::new(mock))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await;
    });

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("a valid endpoint")
        .connect()
        .await
        .expect("the mock store accepted the connection");

    (Task::new(channel), seen)
}

// ---------------------------------------------------------------------------
// Log capture, for the one assertion that is about what an OPERATOR sees.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = LogBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The GLOBAL subscriber, installed once for the whole binary.
///
/// `set_default` would not do: it is thread-local, and the handler under test
/// runs on a tonic task on another thread, where a thread-local default does not
/// apply. So the buffer is shared by every test that logs, and the assertion
/// below looks for a probe string no other test emits.
///
/// `.json()` MIRRORS `main.rs`. It is not a formatting preference: JSON is what
/// the deployed binary emits and therefore what an operator greps, and the
/// property under test — that the store's message arrives as its own named
/// field — is one the two formatters answer differently.
fn logs() -> &'static LogBuffer {
    static LOGS: OnceLock<LogBuffer> = OnceLock::new();
    LOGS.get_or_init(|| {
        let buffer = LogBuffer::default();
        let _ = tracing_subscriber::fmt()
            .json()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .try_init();
        buffer
    })
}

// ---------------------------------------------------------------------------
// passthrough: the codes, and the message that must not escape.
// ---------------------------------------------------------------------------

async fn read_failing_with(code: Code, detail: &'static str) -> Status {
    let (svc, _) = wire(MockDb {
        get: Some(Err((code, detail))),
        ..Default::default()
    })
    .await;

    svc.read_task(Request::new(api::ReadTaskRequest {
        scope: None,
        key: Some(api::read_task_request::Key::Id(CALLER_ID.into())),
    }))
    .await
    .expect_err("the store failed, so the call must")
}

#[tokio::test]
async fn a_store_not_found_reaches_the_caller_as_not_found() {
    let status = read_failing_with(Code::NotFound, DB_DETAIL).await;
    assert_eq!(status.code(), Code::NotFound);
    assert_eq!(status.message(), "no such task in this scope");
}

/// The code a client is contractually told to retry on. Folding it into
/// `INTERNAL` would turn a recoverable conflict into an outage.
///
/// **AND THE ADVICE MUST BE FOLLOWABLE, WHICH IS WHY THIS ASSERTS THE WHOLE
/// STRING.** The old message said "re-read and retry" unconditionally. After
/// ADR-0522 enforcement landed in `task-db`, an owner who left a team can
/// `ReadTask` their own `TEAM`-visible record and is still refused the edit — so
/// the re-read SUCCEEDS and returns the same version, and a client obeying that
/// advice re-sends a byte-identical request for ever. `src/service.rs` already
/// refuses a forbidden status transition with `INVALID_ARGUMENT` for exactly
/// this reason: "A code that invites a retry which can never succeed is worse
/// than a plain refusal — a client obeying the contract loops."
///
/// The three re-read outcomes a caller can OBSERVE are what the advice now
/// branches on, and the three causes stay a disjunction so the string discloses
/// no more than the code does: a caller who reaches the record already knows it
/// exists, and one who cannot gets `NOT_FOUND` from the re-read. Whether a row
/// is there is not decidable from this message.
///
/// `assert_eq!` rather than `contains`: the message IS the contract here, so a
/// substring match would let half of it drift away.
#[tokio::test]
async fn a_version_conflict_reaches_the_caller_with_advice_it_can_follow() {
    let status = read_failing_with(Code::FailedPrecondition, DB_DETAIL).await;
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(
        status.message(),
        "a version mismatch, no such task in this scope, or a task you may read but not \
         modify. Re-read: if the version has moved, retry with the new one. If the read \
         returns the same version, or returns nothing, retrying will fail identically."
    );
}

#[tokio::test]
async fn a_store_invalid_argument_stays_invalid_argument() {
    let status = read_failing_with(Code::InvalidArgument, DB_DETAIL).await;
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(status.message(), "invalid request");
}

/// The one storage failure a caller can act on, and the action is to send the
/// request again. `passthrough` keeps it distinct for exactly that reason.
#[tokio::test]
async fn a_serialisation_failure_stays_aborted() {
    let status = read_failing_with(Code::Aborted, DB_DETAIL).await;
    assert_eq!(status.code(), Code::Aborted);
    assert!(
        status.message().contains("retry"),
        "ABORTED is kept distinct so the caller retries; the message must say so: {}",
        status.message()
    );
}

/// THE ONE FAILURE A CALLER IS SUPPOSED TO RETRY, and until now it was the one
/// this service hid.
///
/// Three places in this repository already promised `UNAVAILABLE`: `main.rs`'s
/// module doc, the "It does not wait for `task-db` to be ready" section of
/// `README.md`, and the readiness-probe comment in
/// `chart/templates/deployment.yaml`. They rest on one design — this service
/// deliberately does not block its boot on the twin (D69), because a request
/// arriving before `task-db` is reachable fails RECOVERABLY. `passthrough`'s
/// `_ =>` arm collapsed it into `INTERNAL`, so the recoverable failure was
/// indistinguishable from a bug and no client obeying the contract would retry.
///
/// The test that used to sit below asserted `UNAVAILABLE -> INTERNAL`, so the
/// repository's own suite defended the defect against the repository's own
/// documentation.
#[tokio::test]
async fn a_store_that_could_not_be_reached_stays_unavailable() {
    for code in [Code::Unavailable, Code::DeadlineExceeded] {
        let status = read_failing_with(code, DB_DETAIL).await;
        assert_eq!(
            status.code(),
            Code::Unavailable,
            "{code:?} is the store being unreachable, which is what this API promises to report"
        );
        assert!(
            status.message().contains("retry"),
            "the code invites a retry and the message must say so: {}",
            status.message()
        );
    }
}

/// **`UNAVAILABLE` AND `DEADLINE_EXCEEDED` ARE DELIBERATELY ABSENT from this
/// list** — see the test above for where they went. What remains is the genuine
/// residue: codes a caller can do nothing specific about, collapsed into one
/// opaque answer on purpose.
#[tokio::test]
async fn every_other_store_failure_becomes_one_opaque_internal() {
    for code in [
        Code::Internal,
        Code::Unknown,
        Code::ResourceExhausted,
        Code::PermissionDenied,
        Code::Unauthenticated,
        Code::Unimplemented,
    ] {
        let status = read_failing_with(code, DB_DETAIL).await;
        assert_eq!(
            status.code(),
            Code::Internal,
            "{code:?} must not reach the caller as itself"
        );
        assert_eq!(status.message(), "the task store is unavailable");
    }
}

/// The redaction half of `passthrough`, asserted on EVERY arm rather than the
/// default one — a new arm that forwards `e.message()` would otherwise leak
/// through whichever code it handles.
#[tokio::test]
async fn the_store_s_own_vocabulary_never_reaches_the_caller() {
    for code in [
        Code::NotFound,
        Code::FailedPrecondition,
        Code::InvalidArgument,
        Code::Aborted,
        Code::Internal,
        Code::Unavailable,
    ] {
        let message = read_failing_with(code, DB_DETAIL)
            .await
            .message()
            .to_string();
        assert!(
            !message.contains("mauve porcupine 4711"),
            "{code:?} leaked the store's message to the caller: {message}"
        );
        assert!(
            !message.contains("task_0007"),
            "{code:?} leaked a table name to the caller: {message}"
        );
    }
}

/// Redacting the message from the RESPONSE is right; dropping it entirely is
/// not. The operator diagnosing the failure has no other copy of it.
#[tokio::test]
async fn a_passed_through_failure_records_what_the_store_said() {
    let buffer = logs();
    let status = read_failing_with(Code::Aborted, LOG_PROBE).await;

    assert!(
        !status.message().contains("lilac wombat 8823"),
        "the message must still be kept from the caller"
    );

    let text = buffer.text();
    let line = text
        .lines()
        .find(|line| line.contains("lilac wombat 8823"))
        .unwrap_or_else(|| {
            panic!(
                "the store said why it failed and nothing wrote it down; \
                 the operator sees a code and no reason. captured log was:\n{text}"
            )
        });

    // Present is not the same as ATTRIBUTABLE, and only the second is useful.
    //
    // Recording the store's message under the key `message` also satisfies the
    // assertion above, and it is wrong: the event's own text already occupies
    // that key, so the JSON object comes out carrying `message` TWICE — once for
    // "task-db returned an error" and once for the store's text. Duplicate keys
    // are not something a parser preserves; every one of them keeps a single
    // value, so an operator loses one of the two and cannot tell which. That is
    // the mutation these three assertions exist to catch, and the reason the
    // field is named `db_message` in the first place.
    assert!(
        line.contains("\"db_message\":"),
        "the store's message is in the line but under no name of its own:\n{line}"
    );
    assert_eq!(
        line.matches("\"message\":").count(),
        1,
        "the line carries `message` more than once, so a parser keeps one value \
         and silently drops the other:\n{line}"
    );
    assert!(
        line.contains("\"message\":\"task-db returned an error\""),
        "the event lost the words that say what it is:\n{line}"
    );
    assert!(
        line.contains("\"op\":\"read\""),
        "the line says what the store said but no longer which call said it:\n{line}"
    );
}

// ---------------------------------------------------------------------------
// CreateTask
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_untitled_task_is_refused_before_the_store_is_touched() {
    let (svc, seen) = wire(MockDb::default()).await;

    let status = svc
        .create_task(Request::new(api::CreateTaskRequest {
            title: "   \t ".into(),
            ..Default::default()
        }))
        .await
        .expect_err("a whitespace title is not a title");

    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(status.message(), "a task needs a title");
    assert!(
        seen.lock().unwrap().create.is_empty(),
        "a rule the store cannot enforce was still sent to the store"
    );
}

#[tokio::test]
async fn a_created_task_carries_the_content_the_caller_sent_and_the_identity_the_store_assigned() {
    let (svc, seen) = wire(MockDb {
        create: Some(Ok(db::CreateTaskResponse {
            meta: Some(store_meta()),
            number: 4711,
        })),
        ..Default::default()
    })
    .await;

    let response = svc
        .create_task(Request::new(api::CreateTaskRequest {
            idempotency: None,
            scope: None,
            title: "a title".into(),
            body: "a body".into(),
            tags: vec!["one".into(), "two".into()],
            links: vec!["yadgar:adr:0004".into()],
        }))
        .await
        .expect("the store accepted it")
        .into_inner();

    assert_eq!(response.number, 4711);
    let meta = response.meta.expect("a created task has identity");
    assert_eq!(meta.id, STORE_ID);
    assert_eq!(meta.version, STORE_VERSION);

    let sent = seen.lock().unwrap().create[0].clone();
    let task = sent.task.expect("a create carries a task");
    assert_eq!(task.title, "a title");
    assert_eq!(task.body, "a body");
    assert_eq!(task.tags, vec!["one".to_string(), "two".to_string()]);
    assert_eq!(task.links, vec!["yadgar:adr:0004".to_string()]);
    // A new task starts OPEN, and the caller has no say in it.
    assert_eq!(task.status, db::TaskStatus::Open as i32);
    // D42: the caller supplies content, never identity.
    assert!(
        task.meta.is_none(),
        "the caller must not be able to set Meta"
    );
    assert_eq!(
        task.number, 0,
        "the caller must not be able to set a number"
    );
}

// ---------------------------------------------------------------------------
// ReadTask
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_read_naming_no_key_is_refused_before_the_store_is_touched() {
    let (svc, seen) = wire(MockDb::default()).await;

    let status = svc
        .read_task(Request::new(api::ReadTaskRequest {
            scope: None,
            key: None,
        }))
        .await
        .expect_err("a read has to say what to read");

    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(status.message(), "one of id or number is required");
    assert!(seen.lock().unwrap().get.is_empty());
}

/// Asserts WHICH key arm the store receives. The two arms are adjacent and
/// interchangeable to the type checker, so only this tells them apart.
#[tokio::test]
async fn a_read_by_number_reaches_the_store_as_a_number() {
    let (svc, seen) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse {
            task: Some(a_stored_task(db::TaskStatus::Blocked as i32)),
        })),
        ..Default::default()
    })
    .await;

    let response = svc
        .read_task(Request::new(api::ReadTaskRequest {
            scope: None,
            key: Some(api::read_task_request::Key::Number(4711)),
        }))
        .await
        .expect("the store had it")
        .into_inner();

    let task = response.task.expect("a found task");
    assert_eq!(task.status, db::TaskStatus::Blocked as i32);
    assert_eq!(task.title, "the stored title");

    assert_eq!(
        seen.lock().unwrap().get[0].key,
        Some(db::get_task_request::Key::Number(4711))
    );
}

#[tokio::test]
async fn a_read_by_id_reaches_the_store_as_an_id() {
    let (svc, seen) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse {
            task: Some(a_stored_task(db::TaskStatus::Open as i32)),
        })),
        ..Default::default()
    })
    .await;

    svc.read_task(Request::new(api::ReadTaskRequest {
        scope: None,
        key: Some(api::read_task_request::Key::Id(CALLER_ID.into())),
    }))
    .await
    .expect("the store had it");

    assert_eq!(
        seen.lock().unwrap().get[0].key,
        Some(db::get_task_request::Key::Id(CALLER_ID.to_string()))
    );
}

// ---------------------------------------------------------------------------
// FindTasks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_find_forwards_the_whole_filter_and_returns_the_page_the_store_gave() {
    let (svc, seen) = wire(MockDb {
        list: Some(Ok(db::ListTasksResponse {
            tasks: vec![
                a_stored_task(db::TaskStatus::InProgress as i32),
                a_stored_task(db::TaskStatus::Blocked as i32),
            ],
            next_page_token: "cursor-8823".into(),
        })),
        ..Default::default()
    })
    .await;

    let response = svc
        .find_tasks(Request::new(api::FindTasksRequest {
            scope: None,
            statuses: vec![
                db::TaskStatus::InProgress as i32,
                db::TaskStatus::Blocked as i32,
            ],
            page_size: 7,
            page_token: "cursor-4711".into(),
        }))
        .await
        .expect("the store answered")
        .into_inner();

    assert_eq!(response.tasks.len(), 2);
    // The store's cursor, not the caller's — a handler echoing the request back
    // would page forever on the same results.
    assert_eq!(response.next_page_token, "cursor-8823");

    let sent = seen.lock().unwrap().list[0].clone();
    assert_eq!(sent.page_size, 7);
    assert_eq!(sent.page_token, "cursor-4711");
    assert_eq!(
        sent.statuses,
        vec![
            db::TaskStatus::InProgress as i32,
            db::TaskStatus::Blocked as i32
        ]
    );
}

// ---------------------------------------------------------------------------
// EditTask
// ---------------------------------------------------------------------------

fn an_edit() -> api::EditTaskRequest {
    api::EditTaskRequest {
        idempotency: None,
        scope: None,
        id: CALLER_ID.into(),
        expect_version: 3,
        title: "an edited title".into(),
        body: "an edited body".into(),
        update_mask: None,
    }
}

#[tokio::test]
async fn an_edit_that_would_untitle_a_task_is_refused_before_anything_is_read() {
    let (svc, seen) = wire(MockDb::default()).await;

    let status = svc
        .edit_task(Request::new(api::EditTaskRequest {
            title: "  ".into(),
            ..an_edit()
        }))
        .await
        .expect_err("a whitespace title is not a title");

    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(status.message(), "a task needs a title");
    assert!(seen.lock().unwrap().get.is_empty());
    assert!(seen.lock().unwrap().update.is_empty());
}

/// **A BODY-ONLY EDIT WAS IMPOSSIBLE, and this is the shape every real caller
/// sends.** `EditTaskRequest.title` is empty when a client does not intend to
/// change the title, and the empty-title check ran BEFORE the mask was resolved —
/// so the call was refused over a value it was never going to store. The rule was
/// right; only the place it ran was wrong.
#[tokio::test]
async fn a_body_only_edit_is_not_refused_for_a_title_it_never_writes() {
    let (svc, seen) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse {
            task: Some(a_stored_task(db::TaskStatus::Open as i32)),
        })),
        update: Some(Ok(db::UpdateTaskResponse {
            meta: Some(store_meta()),
            // What the real store returns for this double: the task it holds is
            // OPEN, and an edit or a first transition displaces exactly that.
            previous_status: db::TaskStatus::Open as i32,
        })),
        ..Default::default()
    })
    .await;

    svc.edit_task(Request::new(api::EditTaskRequest {
        title: String::new(),
        body: "only the body is being changed".into(),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["body".to_string()],
        }),
        ..an_edit()
    }))
    .await
    .expect("an edit that writes no title is not an edit that empties one");

    let sent = seen.lock().unwrap().update[0].clone();
    assert_eq!(
        sent.update_mask.expect("an edit is always masked").paths,
        vec!["body"]
    );
}

/// **THE STORED BODY SURVIVES A TITLE-ONLY EDIT.**
///
/// Asserting only that the mask was narrowed passes against the defect —
/// `writes::edit_request` set `body: req.body` unconditionally, so the request's
/// EMPTY body went on the wire under a mask that did not name it, and a `-db`
/// ignoring the mask would write it. This asserts what actually reached the
/// store.
///
/// `a_stored_task`'s body is a value no request in this file carries, so it can
/// only have arrived from the read.
#[tokio::test]
async fn a_title_only_edit_sends_the_stored_body_rather_than_an_empty_one() {
    let (svc, seen) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse {
            task: Some(a_stored_task(db::TaskStatus::Open as i32)),
        })),
        update: Some(Ok(db::UpdateTaskResponse {
            meta: Some(store_meta()),
            // What the real store returns for this double: the task it holds is
            // OPEN, and an edit or a first transition displaces exactly that.
            previous_status: db::TaskStatus::Open as i32,
        })),
        ..Default::default()
    })
    .await;

    svc.edit_task(Request::new(api::EditTaskRequest {
        title: "a title-only edit".into(),
        // What a title-only client actually sends.
        body: String::new(),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["title".to_string()],
        }),
        ..an_edit()
    }))
    .await
    .expect("the edit applied");

    let sent = seen.lock().unwrap().update[0].clone();
    let task = sent.task.expect("an edit always carries a task");
    assert_eq!(
        task.body, "the stored body",
        "a -db that ignores the mask writes this field, so it must be what was read — an empty \
         body here erases the stored one during any rollout where the two services disagree"
    );
    assert_eq!(
        task.title, "a title-only edit",
        "the field the mask DOES name must still be the caller's"
    );
}

/// **A MASK NOBODY CAN HONOUR IS REFUSED BEFORE THE STORE IS TOUCHED.** The
/// decision is pure — it is about the request and nothing else — so the round
/// trip it used to cost was one whose answer was always going to be discarded.
#[tokio::test]
async fn a_mask_no_edit_may_name_is_refused_before_anything_is_read() {
    let (svc, seen) = wire(MockDb::default()).await;

    let status = svc
        .edit_task(Request::new(api::EditTaskRequest {
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["status".to_string()],
            }),
            ..an_edit()
        }))
        .await
        .expect_err("`status` is not something an edit may name");

    assert_eq!(status.code(), Code::InvalidArgument);
    assert!(
        seen.lock().unwrap().get.is_empty(),
        "the mask could never have been honoured, so the read was wasted work"
    );
    assert!(seen.lock().unwrap().update.is_empty());
}

/// A present response carrying an ABSENT task is not the same as `NOT_FOUND`
/// from the store, and both have to end the same way.
#[tokio::test]
async fn an_edit_of_a_task_the_store_does_not_hold_is_not_found_and_writes_nothing() {
    let (svc, seen) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse { task: None })),
        ..Default::default()
    })
    .await;

    let status = svc
        .edit_task(Request::new(an_edit()))
        .await
        .expect_err("there is nothing to edit");

    assert_eq!(status.code(), Code::NotFound);
    assert!(
        seen.lock().unwrap().update.is_empty(),
        "a task that is not there was written to anyway"
    );
}

/// The reference behaviour. `EditTask` returns the WRITE's `meta`, and
/// `TransitionTask` has to do the same thing.
///
/// The read in this handler answers with `read_meta`, which shares no field with
/// the write's — otherwise a handler returning the meta it read would pass.
#[tokio::test]
async fn an_edit_returns_the_meta_the_store_assigned() {
    let (svc, _) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse {
            task: Some(a_stored_task(db::TaskStatus::Open as i32)),
        })),
        update: Some(Ok(db::UpdateTaskResponse {
            meta: Some(store_meta()),
            // What the real store returns for this double: the task it holds is
            // OPEN, and an edit or a first transition displaces exactly that.
            previous_status: db::TaskStatus::Open as i32,
        })),
        ..Default::default()
    })
    .await;

    let meta = svc
        .edit_task(Request::new(an_edit()))
        .await
        .expect("the edit applied")
        .into_inner()
        .meta
        .expect("an applied write has a meta");

    assert_eq!(
        meta.id, STORE_ID,
        "the response carried the meta the handler READ rather than the one the write reported"
    );
    assert_eq!(meta.version, STORE_VERSION);
    assert_eq!(meta.project_id, STORE_PROJECT);
}

// ---------------------------------------------------------------------------
// TransitionTask
// ---------------------------------------------------------------------------

fn a_transition(to: i32) -> api::TransitionTaskRequest {
    api::TransitionTaskRequest {
        idempotency: None,
        scope: None,
        id: CALLER_ID.into(),
        expect_version: 3,
        to,
    }
}

#[tokio::test]
async fn a_target_outside_the_enum_is_refused_before_the_store_is_touched() {
    let (svc, seen) = wire(MockDb::default()).await;

    let status = svc
        .transition_task(Request::new(a_transition(99)))
        .await
        .expect_err("99 is not a status");

    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(status.message(), "unknown target status");
    assert!(seen.lock().unwrap().get.is_empty());
}

#[tokio::test]
async fn a_transition_of_a_task_the_store_does_not_hold_is_not_found_and_writes_nothing() {
    let (svc, seen) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse { task: None })),
        ..Default::default()
    })
    .await;

    let status = svc
        .transition_task(Request::new(a_transition(db::TaskStatus::Done as i32)))
        .await
        .expect_err("there is nothing to transition");

    assert_eq!(status.code(), Code::NotFound);
    assert!(seen.lock().unwrap().update.is_empty());
}

/// A stored value the enum does not name is a STORAGE fault, not the caller's.
/// Reporting it as `INVALID_ARGUMENT` would send the client to fix a request
/// that was correct.
#[tokio::test]
async fn a_stored_status_outside_the_enum_is_internal_rather_than_a_guess() {
    let (svc, seen) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse {
            task: Some(a_stored_task(99)),
        })),
        ..Default::default()
    })
    .await;

    let status = svc
        .transition_task(Request::new(a_transition(db::TaskStatus::Done as i32)))
        .await
        .expect_err("the stored status is not a status");

    assert_eq!(status.code(), Code::Internal);
    assert_eq!(status.message(), "the stored status is not a known value");
    assert!(seen.lock().unwrap().update.is_empty());
}

/// INVALID_ARGUMENT, not FAILED_PRECONDITION. There is nothing to re-read: the
/// rule refuses this pair forever, and a code inviting a retry would make a
/// contract-obeying client loop.
#[tokio::test]
async fn a_transition_the_rule_refuses_is_invalid_argument_and_writes_nothing() {
    let (svc, seen) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse {
            task: Some(a_stored_task(db::TaskStatus::Dropped as i32)),
        })),
        ..Default::default()
    })
    .await;

    let status = svc
        .transition_task(Request::new(a_transition(db::TaskStatus::Open as i32)))
        .await
        .expect_err("DROPPED is terminal");

    assert_eq!(status.code(), Code::InvalidArgument);
    assert!(
        status.message().contains("DROPPED is terminal"),
        "the refusal has to name the rule it applied: {}",
        status.message()
    );
    assert!(
        seen.lock().unwrap().update.is_empty(),
        "the rule refused it and the store was written anyway"
    );
}

/// THE FIX (ledger 510). The handler used to discard `UpdateTaskResponse` and
/// build a `Meta` out of its own request — `id` from `req.id` and `version` from
/// `expect_version + 1`.
///
/// Every field here is one the store chose and the request does not contain, so
/// a synthesised `Meta` cannot pass this by accident: it would carry the
/// caller's id, version 4, and an empty project.
#[tokio::test]
async fn a_transition_returns_the_meta_the_store_assigned_not_one_built_from_the_request() {
    let (svc, _) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse {
            task: Some(a_stored_task(db::TaskStatus::Open as i32)),
        })),
        update: Some(Ok(db::UpdateTaskResponse {
            meta: Some(store_meta()),
            // What the real store returns for this double: the task it holds is
            // OPEN, and an edit or a first transition displaces exactly that.
            previous_status: db::TaskStatus::Open as i32,
        })),
        ..Default::default()
    })
    .await;

    let response = svc
        .transition_task(Request::new(a_transition(db::TaskStatus::Done as i32)))
        .await
        .expect("the transition applied")
        .into_inner();

    let meta = response.meta.expect("an applied write has a meta");
    assert_eq!(
        meta.id, STORE_ID,
        "the response carried the id the caller sent rather than the one the store holds"
    );
    assert_eq!(
        meta.version, STORE_VERSION,
        "the response guessed expect_version + 1 rather than reporting the store's version"
    );
    assert_eq!(
        meta.project_id, STORE_PROJECT,
        "a synthesised Meta drops every field the store filled in"
    );
    assert_eq!(response.from, db::TaskStatus::Open as i32);
}

#[tokio::test]
async fn a_transition_writes_the_status_column_and_names_only_it() {
    let (svc, seen) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse {
            task: Some(a_stored_task(db::TaskStatus::Open as i32)),
        })),
        update: Some(Ok(db::UpdateTaskResponse {
            meta: Some(store_meta()),
            // What the real store returns for this double: the task it holds is
            // OPEN, and an edit or a first transition displaces exactly that.
            previous_status: db::TaskStatus::Open as i32,
        })),
        ..Default::default()
    })
    .await;

    svc.transition_task(Request::new(a_transition(db::TaskStatus::Done as i32)))
        .await
        .expect("the transition applied");

    let sent = seen.lock().unwrap().update[0].clone();
    assert_eq!(sent.id, CALLER_ID);
    assert_eq!(sent.expect_version, 3);
    assert_eq!(
        sent.update_mask.expect("a transition is masked").paths,
        vec!["status".to_string()]
    );
    assert_eq!(
        sent.task.expect("a transition carries a task").status,
        db::TaskStatus::Done as i32
    );
}

/// CHARACTERISATION, ledger 508 — and it PASSES ON UNFIXED CODE BY DESIGN.
/// There is no fix to make at this contract version, so this pins the gap rather
/// than pretending to close it.
///
/// THE TRACE. `transition_task` reads before it writes. On the retry of an
/// already-applied transition, the read returns the NEW status, `may_transition`
/// waves it through as an identity no-op, `task-db` replays the recorded
/// `UpdateTaskResponse` without writing, and `from` is reported as the status the
/// task is ALREADY in.
///
/// WHY THAT MATTERS. `taskapi.proto:91-93` says `from` exists "so a caller that
/// raced another writer sees what actually happened rather than assuming its own
/// read was current". On this path `from == to` always, so it carries no
/// information at all, which is precisely the guarantee it was added to provide.
///
/// WHAT CHANGED, AND WHAT DID NOT. The field this test was waiting for exists:
/// `UpdateTaskResponse.previous_status` arrived in proto v1.7.0, and
/// `yadgarhq/task-db` populates it on every update. So the answer now REACHES
/// this service — and this service still throws it away, which is the half that
/// is left. `from` is still read off the pre-write `GetTask`, so on a replay it
/// is still the post-transition status and still carries no information.
///
/// WHY IT IS NOT FIXED HERE. Wiring `from` to `previous_status` changes what
/// this service answers, which is a behaviour change to `TaskService` rather
/// than a consequence of the pin bump this commit carries. It is its own change
/// with its own reasoning, and this test is what will go red when it lands.
///
/// The store's double below now supplies `previous_status: BLOCKED`, a value
/// neither the read nor the request contains. The assertions pin BOTH halves:
/// `from` equals `to` (the gap), and `from` is not the value the store
/// supplied (the reason the gap survives). Wiring `from` correctly inverts the
/// second assertion, which is what makes this test a tripwire rather than a
/// comment.
#[tokio::test]
async fn a_replayed_transition_reports_a_from_that_carries_no_information() {
    // The store already holds DONE: this is the retry, after the first delivery
    // applied the transition.
    let (svc, seen) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse {
            task: Some(a_stored_task(db::TaskStatus::Done as i32)),
        })),
        // What `idem::claim` replays: the FIRST call's response, verbatim —
        // and at proto v1.7.1 that response CARRIES the prior status. BLOCKED
        // is deliberate: it is neither the status the read returns (DONE) nor
        // the target the request names (DONE), so a `from` carrying it could
        // only have come from the store. The handler discards it, and the
        // assertion below is what says so.
        update: Some(Ok(db::UpdateTaskResponse {
            meta: Some(store_meta()),
            previous_status: db::TaskStatus::Blocked as i32,
        })),
        ..Default::default()
    })
    .await;

    let request = a_transition(db::TaskStatus::Done as i32);
    let to = request.to;

    let response = svc
        .transition_task(Request::new(request))
        .await
        .expect("an identity transition is allowed, so the retry succeeds")
        .into_inner();

    assert_eq!(
        response.from, to,
        "THE GAP: on a replay `from` equals `to`, so the field the contract adds \
         for a racing caller tells that caller nothing"
    );
    assert_ne!(
        response.from,
        db::TaskStatus::Blocked as i32,
        "THE REASON THE GAP SURVIVES: the store supplied the prior status on \
         `UpdateTaskResponse.previous_status` and this service discarded it, \
         answering from its own pre-write read instead. Wiring `from` to that \
         field inverts this assertion, which is the point of writing it"
    );

    // The other half of the gap: there is no second place the prior status could
    // have come from. One read, one write, and the write carries only the target.
    let seen = seen.lock().unwrap();
    assert_eq!(seen.get.len(), 1, "the handler has exactly one read");
    assert_eq!(seen.update.len(), 1, "the handler has exactly one write");
    assert_eq!(
        seen.update[0]
            .task
            .as_ref()
            .expect("a transition carries a task")
            .status,
        to,
        "the write names the target, so nothing on the wire holds the predecessor"
    );
}

// ---------------------------------------------------------------------------
// RemoveTask
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_remove_forwards_the_compare_and_set_version() {
    let (svc, seen) = wire(MockDb {
        delete: Some(Ok(db::DeleteTaskResponse {})),
        ..Default::default()
    })
    .await;

    svc.remove_task(Request::new(api::RemoveTaskRequest {
        idempotency: Some(common::Idempotency {
            key: "idem-4711".into(),
        }),
        scope: None,
        id: CALLER_ID.into(),
        expect_version: 3,
    }))
    .await
    .expect("the store deleted it");

    let sent = seen.lock().unwrap().delete[0].clone();
    assert_eq!(sent.id, CALLER_ID);
    // Without this the delete stops being compare-and-set and races every
    // concurrent writer it was meant to lose to.
    assert_eq!(sent.expect_version, 3);
    assert_eq!(
        sent.idempotency.expect("a delete is idempotent").key,
        "idem-4711"
    );
}

#[tokio::test]
async fn a_remove_of_a_task_the_store_does_not_hold_is_not_found() {
    let (svc, _) = wire(MockDb {
        delete: Some(Err((Code::NotFound, DB_DETAIL))),
        ..Default::default()
    })
    .await;

    let status = svc
        .remove_task(Request::new(api::RemoveTaskRequest {
            id: CALLER_ID.into(),
            expect_version: 3,
            ..Default::default()
        }))
        .await
        .expect_err("there is nothing to remove");

    assert_eq!(status.code(), Code::NotFound);
    assert_eq!(status.message(), "no such task in this scope");
}

// ---------------------------------------------------------------------------
// Scope.owner_reads_own_record: the field this service must not lose (ADR-0522).
// ---------------------------------------------------------------------------

/// A team the requests below do not otherwise name, so an override keyed on it
/// cannot be produced by a handler reading its own inputs.
const SETTING_TEAM: &str = "yadgar:team:named-only-by-the-setting";

/// The setting as an organisation that has actually STATED one sends it.
///
/// Every field is deliberately away from its zero — `org_value` is a member
/// rather than `UNSPECIFIED`, the lock is engaged, and the map holds an entry —
/// so a handler that stamps `Some(InheritedSetting::default())` in place of what
/// it received fails the equality below rather than passing on the presence
/// check alone.
fn a_stated_setting() -> common::InheritedSetting {
    common::InheritedSetting {
        org_value: common::SettingValue::Off as i32,
        org_locked: true,
        team_override: std::collections::HashMap::from([(
            SETTING_TEAM.to_string(),
            common::SettingValue::On as i32,
        )]),
    }
}

/// A caller's scope, written EXHAUSTIVELY on purpose.
///
/// This is the first `common::Scope` literal in the repository, and it is the
/// tripwire the pin bump wanted and did not find: `task-db`'s equivalent fixture
/// broke with `E0063` when `Scope` grew field 6 and announced it, whereas this
/// repository held no literal to break and took the field in silence. Adding
/// `..Default::default()` here would restore that silence for the next field —
/// including one this hop must forward and does not.
fn a_caller_scope(setting: Option<common::InheritedSetting>) -> common::Scope {
    common::Scope {
        user_id: "yadgar:user:the-owner".into(),
        project_id: "quinyx/qwfm/named-by-the-caller".into(),
        team_ids: vec!["yadgar:team:the-caller-still-belongs-to".into()],
        instance_id: "instance-4711".into(),
        request_id: "request-4711".into(),
        owner_reads_own_record: setting,
    }
}

/// THE POINT OF THE PIN BUMP, ASSERTED ON THE WIRE.
///
/// The gateway attests this setting onto `Scope`; `task-db` resolves it; this
/// service is the hop in between and forwards `req.scope` whole. At proto
/// v1.7.1 `Scope` had no field 6 at all, so prost — which DISCARDS unknown
/// fields rather than round-tripping them — erased it here, and the two merged
/// cars either side of this hop were inert end to end.
///
/// The mock store is served over real loopback, so the assertion is on bytes
/// that were encoded and decoded rather than on a struct handed across by value.
/// That is the hop that used to drop the field.
#[tokio::test]
async fn a_stated_owner_reads_own_record_reaches_the_store() {
    let (svc, seen) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse {
            task: Some(a_stored_task(db::TaskStatus::Open as i32)),
        })),
        ..Default::default()
    })
    .await;

    svc.read_task(Request::new(api::ReadTaskRequest {
        scope: Some(a_caller_scope(Some(a_stated_setting()))),
        key: Some(api::read_task_request::Key::Id(CALLER_ID.into())),
    }))
    .await
    .expect("the store had it");

    let sent = seen.lock().unwrap().get[0]
        .scope
        .clone()
        .expect("the store is sent the caller's scope");

    // PRESENCE IS THE ASSERTION. A value assertion alone would be vacuous:
    // every field of `InheritedSetting::default()` equals the field an absent
    // message reads as through prost, so `org_value == UNSPECIFIED` is true
    // whether the setting arrived or was silently dropped.
    assert!(
        sent.owner_reads_own_record.is_some(),
        "the setting the caller stated was erased on the hop to the store"
    );
    // And having established presence, that it is the caller's setting rather
    // than a freshly minted empty one.
    assert_eq!(sent.owner_reads_own_record, Some(a_stated_setting()));
}

/// THE OTHER HALF, AND WITHOUT IT THE TEST ABOVE PROVES NOTHING.
///
/// A handler that unconditionally stamps `Some(InheritedSetting::default())`
/// would satisfy an `is_some` check. What the contract needs is that the two
/// states stay TOLD APART — `common.proto` says an absent message and a present
/// one holding the zero are one case and both are REFUSED by an enforcing
/// `-db`, and a hop that manufactures presence turns a refusal into an answer.
#[tokio::test]
async fn a_scope_that_states_no_setting_reaches_the_store_still_stating_none() {
    let (svc, seen) = wire(MockDb {
        get: Some(Ok(db::GetTaskResponse {
            task: Some(a_stored_task(db::TaskStatus::Open as i32)),
        })),
        ..Default::default()
    })
    .await;

    svc.read_task(Request::new(api::ReadTaskRequest {
        scope: Some(a_caller_scope(None)),
        key: Some(api::read_task_request::Key::Id(CALLER_ID.into())),
    }))
    .await
    .expect("the store had it");

    let sent = seen.lock().unwrap().get[0]
        .scope
        .clone()
        .expect("the store is sent the caller's scope");

    assert!(
        sent.owner_reads_own_record.is_none(),
        "the hop invented a setting the caller never stated"
    );
    // The rest of the scope still arrives, so the assertion above is about the
    // one field rather than about a scope that went missing entirely.
    assert_eq!(sent.user_id, "yadgar:user:the-owner");
}
