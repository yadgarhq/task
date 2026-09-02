# task

The `task` module's **logic service**: business rules, no store.

Decisions in [`yadgarhq/docs`](https://github.com/yadgarhq/docs): D4 (the twin
split), D23 (client-side balancing), D70 (how the protos get here).

## It holds no store, and that absence is the design

There is no `sqlx` and no `yadgar-store` in this crate's dependency tree. A logic
service reaches its data only over the `-db` API — which is what makes the twin a
**connection concentrator** rather than merely a boundary. N replicas of this
service with embedded pools would multiply connections against an engine with
hard limits (D4).

`proto-contract-design.md` keeps a per-repo check that the binary has no store
SDK in its dependency tree, for exactly this reason.

## What it adds over `task-db`

Rules the storage layer has no business enforcing:

- **Which status transitions are legal.** `DROPPED` is terminal; `DONE` is not.
  Finishing something and later reopening it is ordinary; abandoning something
  and quietly resurrecting it loses the fact that it was abandoned, which is what
  anyone reading the history wants to see. Undoing a drop means creating a new
  task that links to it.
- **Status is not writable through `EditTask`.** A field write cannot express
  which transitions are legal, so the rule would have to live in every caller —
  which is how it stops being a rule. `TransitionTask` makes the legal set a
  property of the contract.
- **A task needs a title.** The column would happily take an empty one; the
  humans who triage tasks cannot find it.

## Client-side balancing, and the part that gets forgotten

gRPC holds **one** long-lived HTTP/2 connection. A normal Service balances at
connection time, so a client would open one connection, get one pod, and send
everything there for the life of the process — the other replicas idle while
looking healthy, and D68's autoscaler responding to the latency by adding more
pods that also receive nothing.

So `task-db`'s Service is **headless**: DNS returns every pod address and this
service balances across them itself.

**Re-resolution is the half that must not be forgotten**, and it is wired up: a
background task re-resolves every 5s and applies the difference to the channel's
endpoint set. Resolving once at startup would pin the client to whichever pods
existed then — new replicas getting no traffic, and a rolling update leaving it
talking to addresses that no longer exist.

Two things the loop deliberately does not do:

- **It never acts on an empty resolution.** A headless Service briefly returns
  nothing during some rollouts, and removing every endpoint on that basis is a
  self-inflicted outage from a transient DNS answer.
- **It never tears down a working channel because DNS failed.** A blip is not a
  reason to stop using endpoints that currently work.

**The balancing itself is no longer in this repository.** It began here as
`src/balance.rs`; the gateway needed the identical logic, and anything every
service needs is implemented once — so it lives in the
[`yadgar-dial`](https://github.com/yadgarhq/dial) crate, pinned by revision in
`Cargo.toml`. What remains here is `src/upstream.rs`: this service's decision
about which transport to reach `task-db` over, handed to `yadgar_dial::connect`
or `yadgar_dial::connect_tls`.

## It does not wait for `task-db` to be ready

Deliberately. The twin gates its own boot — probe, migrate, then listen (D69) — so
a `-db` that is not ready has no endpoint behind the headless Service and
`upstream::connect` fails loudly. Blocking this service's startup on that would
turn one module's slow migration into a cascading outage, and under D68 a pod
stuck in startup is one the autoscaler cannot help. A request that cannot reach
the store fails with `UNAVAILABLE`, which is recoverable; refusing to start is
not.

That last sentence is a CONTRACT rather than a description, and `passthrough` in
`src/service.rs` is where it is kept: a `-db` answering `UNAVAILABLE` or
`DEADLINE_EXCEEDED` reaches the caller as `UNAVAILABLE`. It used to be folded
into `INTERNAL`, which made the one recoverable storage failure
indistinguishable from a bug.

## SIGTERM, not SIGINT

Kubernetes ends a pod by sending **SIGTERM**, then waits out
`terminationGracePeriodSeconds` before SIGKILL. It never sends SIGINT. So
`serve::shutdown` listens for both, and it installs the handlers when it is
CALLED rather than when the future is first polled — a signal arriving in that
window would otherwise take SIGTERM's default disposition and kill the process
mid-request.

D23 sets the blast radius. Each caller holds ONE long-lived HTTP/2 connection, so
what a skipped drain loses is not a slice of traffic but everything that
connection was carrying.

## Local development

```bash
make proto     # refresh the vendored protos from PROTO_VERSION (D70)
cargo test     # the rules; they need no engine and no -db
```

`protoc` must be on `PATH` — types are generated, never hand-written (D16).

## Configuration

| variable                        | default             |                                                |
| ------------------------------- | ------------------- | ---------------------------------------------- |
| `TASK_DB_HOST` / `TASK_DB_PORT` | `task-db` / `50051` | the twin's headless Service                    |
| `LISTEN`                        | `0.0.0.0:50052`     | the gRPC address this service binds            |
| `METRICS_LISTEN`                | `0.0.0.0:9090`      | the Prometheus endpoint (D67)                  |
| `RUST_LOG`                      | `info`              | a DEFAULT, not `from_default_env`'s silence    |
| `LISTEN_TLS_ENABLED`            | unset               | exactly `1` to serve TLS; anything else is off |
| `LISTEN_TLS_CERT_FILE`          | unset               | PEM certificate this service PRESENTS          |
| `LISTEN_TLS_KEY_FILE`           | unset               | its private key                                |
| `TASK_DB_TLS_ENABLED`           | unset               | exactly `1` to dial `task-db` over TLS         |
| `TASK_DB_TLS_CA_FILE`           | unset               | PEM bundle `task-db` is VERIFIED against       |
| `TASK_DB_TLS_DOMAIN`            | unset               | only when the certificate names something else |

**Two directions, and the prefix says which.** `LISTEN_TLS_*` configures the
listener — `LISTEN` is already the variable naming the address it binds.
`TASK_DB_TLS_*` configures the dial, and a dial is named for the upstream it
reaches. The same rule holds across every service: `iam` reads `LISTEN_TLS_*`
and `IAM_DB_TLS_*`.

Both groups are **opt-in and off**, and every enable flag is exactly the string
`1` — a permissive parse is how a setting meant to be off ends up on, and how a
revert lever stops moving. A flag that is on with a file that is missing,
unreadable or unusable **refuses the boot naming the file**. It never falls back
to cleartext.

`RUST_LOG` is listed because the default is this binary's own, not the library's:
`EnvFilter::from_default_env()` with `RUST_LOG` unset enables NOTHING, and a
service nobody can observe is one D67 cannot measure either.
