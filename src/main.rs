//! Wiring, and one decision worth naming: this service does NOT wait for
//! `task-db` to be reachable before reporting ready.
//!
//! The twin's own boot is gated — probe, migrate, then listen (D69) — so a
//! `-db` that is not ready has no DNS endpoint behind the headless Service, and
//! `balance::connect` fails loudly. Blocking this service's startup on that would
//! turn one module's slow migration into a cascading outage across everything
//! that depends on it, and under D68 a pod stuck in startup is one the autoscaler
//! cannot help. Failing a request with UNAVAILABLE is recoverable; refusing to
//! start is not.

use std::net::SocketAddr;

use yadgar_task::balance;
use yadgar_task::pb::yadgar::taskapi::v1::task_service_server::TaskServiceServer;
use yadgar_task::service::Task;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // The HEADLESS Service name (D23). Resolving it yields every ready pod
    // address rather than one virtual IP.
    let db_host = env_or("TASK_DB_HOST", "task-db");
    let db_port: u16 = env_or("TASK_DB_PORT", "50051").parse()?;

    let channel = balance::connect(&db_host, db_port).await?;
    tracing::info!(
        reresolve_secs = balance::reresolve_interval().as_secs(),
        "connected to task-db"
    );

    let addr: SocketAddr = env_or("LISTEN", "0.0.0.0:50052").parse()?;
    tracing::info!(%addr, "task listening");
    tonic::transport::Server::builder()
        .add_service(TaskServiceServer::new(Task::new(channel)))
        .serve_with_shutdown(addr, async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;

    Ok(())
}
