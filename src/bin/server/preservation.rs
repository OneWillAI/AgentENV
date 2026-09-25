//! Local administrative socket. Filesystem permissions, not the public API,
//! restrict promotion preparation to the service account and root.
use agentenv::orchestrator::Orchestrator;
use std::{os::unix::fs::PermissionsExt, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
};

pub async fn start(orchestrator: Arc<Orchestrator>) -> anyhow::Result<()> {
    let Some(path) = std::env::var_os("AENV_PRESERVATION_SOCKET") else {
        return Ok(());
    };
    let path = std::path::PathBuf::from(path);
    if path.exists() {
        match tokio::net::UnixStream::connect(&path).await {
            Ok(_) => anyhow::bail!("preservation socket is already in use"),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                tokio::fs::remove_file(&path).await?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let listener = UnixListener::bind(&path)?;
    tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::error!(%error, "preservation socket accept failed");
                    break;
                }
            };
            let orchestrator = Arc::clone(&orchestrator);
            // Disconnecting a client must not cancel an in-progress checkpoint.
            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader.take(33));
                let mut command = String::new();
                if !matches!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        reader.read_line(&mut command)
                    )
                    .await,
                    Ok(Ok(1..=32))
                ) {
                    return;
                }
                let result = match command.trim() {
                    "prepare" => orchestrator.shutdown().await.map_err(|e| e.to_string()),
                    "status" => Ok(()),
                    _ => Err("expected prepare or status".to_string()),
                };
                let (guests, inventory_error) = match orchestrator.list_sandboxes().await {
                    Ok(guests) => (guests.into_iter().map(|guest| serde_json::json!({
                        "id": guest.id, "state": guest.state.to_string(),
                        "safely_checkpointed": guest.paused_runtime_stopped && !guest.resume_recovery_pending,
                        "requires_intervention": guest.resume_recovery_pending,
                    })).collect::<Vec<_>>(), None),
                    Err(error) => (Vec::new(), Some(error.to_string())),
                };
                let response = serde_json::json!({
                    "protocol": 1, "ok": result.is_ok() && inventory_error.is_none(),
                    "error": result.err(), "inventory_error": inventory_error, "guests": guests,
                });
                let _ = writer.write_all(format!("{response}\n").as_bytes()).await;
            });
        }
    });
    Ok(())
}
