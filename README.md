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

`balance::diff` is a pure function over two address sets, extracted so the part
that is easy to get silently wrong is testable: re-inserting an unchanged
endpoint churns connections every tick and looks like working code.

## It does not wait for `task-db` to be ready

Deliberately. The twin gates its own boot — probe, migrate, then listen (D69) — so
a `-db` that is not ready has no endpoint behind the headless Service and
`balance::connect` fails loudly. Blocking this service's startup on that would
turn one module's slow migration into a cascading outage, and under D68 a pod
stuck in startup is one the autoscaler cannot help. A request that cannot reach
the store fails with `UNAVAILABLE`, which is recoverable; refusing to start is
not.

## Local development

```bash
make proto     # refresh the vendored protos from PROTO_VERSION (D70)
cargo test     # the rules; they need no engine and no -db
```

`protoc` must be on `PATH` — types are generated, never hand-written (D16).

## Configuration

| variable                        | default             |                             |
| ------------------------------- | ------------------- | --------------------------- |
| `TASK_DB_HOST` / `TASK_DB_PORT` | `task-db` / `50051` | the twin's headless Service |
| `LISTEN`                        | `0.0.0.0:50052`     |                             |
