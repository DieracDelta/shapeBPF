use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use shapebpf_common::ipc::{Request, Response};

pub struct IpcClient {
    stream: UnixStream,
}

impl IpcClient {
    pub async fn connect(socket_path: &str) -> Result<Self> {
        let stream = UnixStream::connect(socket_path)
            .await
            .context("connecting to shapebpf daemon")?;
        Ok(Self { stream })
    }

    pub async fn request(&mut self, req: &Request) -> Result<Response> {
        let bytes = bincode::serialize(req).context("serializing request")?;
        self.stream.write_u32(bytes.len() as u32).await?;
        self.stream.write_all(&bytes).await?;

        let len = self.stream.read_u32().await? as usize;
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        bincode::deserialize(&buf).context("deserializing response")
    }
}
