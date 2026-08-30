//! Client-side load balancing over a headless Service (D23).
//!
//! **The problem this solves is not obvious and is easy to declare solved.** gRPC
//! runs on HTTP/2 and holds ONE long-lived connection. A normal Kubernetes
//! Service balances at L4 — at connection time — so a client opens one connection,
//! gets one pod, and sends every request there for the life of the process. The
//! other replicas sit idle while looking healthy, and D68's autoscaler responds
//! to the resulting latency by adding more pods that also receive nothing.
//!
//! So the Service is HEADLESS: DNS returns every pod address rather than one
//! virtual IP, and the client balances across them itself.
//!
//! **Re-resolution is the part that must not be forgotten.** Resolving once at
//! startup pins the client to whichever pods existed then — new replicas get no
//! traffic, and a rolling update leaves the client talking to addresses that no
//! longer exist. That is the failure D68 calls self-amplifying, and it is a
//! property of D23 rather than of the autoscaler.

use std::time::Duration;

use tonic::transport::{Channel, Endpoint};

/// How often the endpoint set is re-resolved.
///
/// Kubernetes headless DNS has a short TTL, and pods come and go on deploys and
/// autoscaling events. Five seconds is well inside a rolling update's window;
/// resolving once at startup is what this constant exists to prevent.
const RERESOLVE: Duration = Duration::from_secs(5);

/// Resolve every A record behind `host` and build a balanced channel.
///
/// `tonic`'s `Channel::balance_list` round-robins across the endpoints it is
/// given, so the work here is producing that list from DNS and refreshing it.
pub async fn connect(host: &str, port: u16) -> Result<Channel, BalanceError> {
    let addrs = resolve(host, port).await?;
    if addrs.is_empty() {
        return Err(BalanceError::NoEndpoints {
            host: host.to_string(),
        });
    }
    tracing::info!(
        host,
        count = addrs.len(),
        "balancing across task-db replicas"
    );

    let endpoints = addrs.into_iter().map(|addr| {
        Endpoint::from_shared(format!("http://{addr}"))
            .expect("a socket address always forms a valid authority")
            // A dead pod must not hold a request open until the caller's deadline.
            .connect_timeout(Duration::from_secs(2))
            // HTTP/2 keepalive is what notices a pod that vanished without
            // closing its connection — the common case when a node goes away.
            .http2_keep_alive_interval(Duration::from_secs(10))
            .keep_alive_timeout(Duration::from_secs(3))
    });

    Ok(Channel::balance_list(endpoints))
}

async fn resolve(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, BalanceError> {
    let target = format!("{host}:{port}");
    let addrs = tokio::net::lookup_host(target.clone())
        .await
        .map_err(|source| BalanceError::Dns {
            host: target,
            source,
        })?;
    Ok(addrs.collect())
}

/// The interval at which a caller should re-resolve. Exposed rather than applied
/// internally because the refresh loop belongs to whoever owns the channel's
/// lifetime, and hiding it would make "did anyone actually re-resolve?"
/// unanswerable from the outside.
pub const fn reresolve_interval() -> Duration {
    RERESOLVE
}

#[derive(Debug, thiserror::Error)]
pub enum BalanceError {
    #[error(
        "DNS returned no addresses for {host}. For a headless Service this means \
         no ready endpoints — the -db replicas are down or failing readiness, \
         which under D69 includes failing their capability probe or migrations."
    )]
    NoEndpoints { host: String },

    #[error("could not resolve {host}: {source}")]
    Dns {
        host: String,
        #[source]
        source: std::io::Error,
    },
}
