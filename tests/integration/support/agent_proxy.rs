//! An ssh-agent stand-in that hangs up on extension requests, as the OpenSSH agent on Windows
//! does, in front of a real agent that answers everything else.
use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

/// `SSH_AGENTC_EXTENSION`, which carries `session-bind@openssh.com`.
const EXTENSION_REQUEST: u8 = 27;

/// A proxy listening on [`AgentProxy::socket`]. It stops on drop.
pub struct AgentProxy {
    pub socket: PathBuf,
    task: JoinHandle<()>,
}

impl AgentProxy {
    /// Listen on `socket`, passing each request to the agent at `agent` except extension
    /// requests, on which the connection is closed.
    pub fn without_extensions(socket: PathBuf, agent: &Path) -> Self {
        let listener = UnixListener::bind(&socket).unwrap();
        let task = tokio::spawn(accept(listener, agent.to_path_buf()));
        Self { socket, task }
    }
}

impl Drop for AgentProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn accept(listener: UnixListener, agent: PathBuf) {
    while let Ok((client, _)) = listener.accept().await {
        tokio::spawn(serve(client, agent.clone()));
    }
}

/// Relay one client's requests to the agent, one frame at a time, until an extension request
/// or the end of the connection.
async fn serve(mut client: UnixStream, agent: PathBuf) {
    let Ok(mut upstream) = UnixStream::connect(&agent).await else {
        return;
    };
    while let Some(request) = read_frame(&mut client).await {
        if request.get(4) == Some(&EXTENSION_REQUEST) {
            return;
        }
        if upstream.write_all(&request).await.is_err() {
            return;
        }
        let Some(reply) = read_frame(&mut upstream).await else {
            return;
        };
        if client.write_all(&reply).await.is_err() {
            return;
        }
    }
}

/// One agent frame, its four length bytes included.
async fn read_frame(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut frame = vec![0; 4];
    stream.read_exact(&mut frame).await.ok()?;
    let length = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    frame.resize(4 + length, 0);
    stream.read_exact(&mut frame[4..]).await.ok()?;
    Some(frame)
}
