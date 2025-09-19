use std::process::Stdio;

use opcua::types::{BinaryEncodable, ByteString, Context, NodeId, Variant};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{ChildStdin, ChildStdout},
    select,
    sync::mpsc::{channel, Receiver, Sender},
};

pub struct ProcessWrapper {
    send: Sender<InMessage>,
    recv: Receiver<OutMessage>,
}

pub struct ProcessLoop {
    outgoing: Receiver<InMessage>,
    incoming: Sender<OutMessage>,
    proc: tokio::process::Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

pub fn spawn_proc(path: &str, config_path: &str) -> (ProcessWrapper, ProcessLoop) {
    println!(
        "Start at {}",
        std::path::absolute(path).unwrap().to_str().unwrap()
    );
    let mut child = tokio::process::Command::new(path)
        .arg(config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let stdout = child.stdout.take().expect("Failed to open stdout");
    let stdin = child.stdin.take().expect("Failed to open stdin");

    let (outsend, outrecv) = channel(100);
    let (insend, inrecv) = channel(100);

    (
        ProcessWrapper {
            send: insend,
            recv: outrecv,
        },
        ProcessLoop {
            outgoing: inrecv,
            incoming: outsend,
            proc: child,
            stdin,
            stdout,
        },
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum OutMessage {
    Log(LogMessage),
    Ready {},
    Error(LogMessage),
    Payload(GeneralMessage),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LogMessage {
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GeneralMessage {
    pub payload: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct UpdateValueMessage {
    pub node_id: String,
    pub value: String,
}

impl UpdateValueMessage {
    pub fn new(node_id: NodeId, value: Variant, ctx: &Context) -> Self {
        Self {
            node_id: node_id.to_string(),
            value: ByteString::from(value.encode_to_vec(ctx)).as_base64(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ReverseConnectMessage {
    pub url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum InMessage {
    Shutdown {},
    ChangeValue(UpdateValueMessage),
    ReverseConnect(ReverseConnectMessage),
}

impl ProcessLoop {
    pub async fn run(mut self) {
        let mut batch = Vec::new();
        let mut buf = [0u8; 1024];

        loop {
            let mut buf_mut = &mut buf[..];
            select! {
                len = self.stdout.read_buf(&mut buf_mut) => {
                    let Ok(len) = len else {
                        return;
                    };
                    batch.reserve(len);
                    for it in &buf[0..len] {
                        if *it == 0 {
                            let incoming: OutMessage = match serde_json::from_slice(&batch) {
                                Ok(v) => v,
                                Err(e) => {
                                    panic!("Failed to deserialize message from reader: {e}");
                                }
                            };
                            match incoming {
                                OutMessage::Log(msg) => {
                                    println!("Message from .NET: {}", msg.message);
                                }
                                OutMessage::Error(msg) => {
                                    eprintln!("Error message from .NET: {}", msg.message);
                                    panic!("Received error from .NET");
                                }
                                r => self.incoming.send(r).await.unwrap()
                            }
                            batch.clear();
                        } else {
                            batch.push(*it);
                        }
                    }
                }
                m = self.outgoing.recv() => {
                    let Some(m) = m else {
                        return;
                    };
                    self.stdin.write_all(&match serde_json::to_vec(&m) {
                        Ok(v) => v,
                        Err(e) => {
                            panic!("Failed to serialize message to send: {e}");
                        }
                    }).await.unwrap();
                    self.stdin.write_u8(0).await.unwrap();
                }
                r = self.proc.wait() => {
                    let r = r.unwrap();
                    if !r.success() {
                        panic!("Child excited with non-zero exit code");
                    }
                    return;
                }
            }
        }
    }
}

impl ProcessWrapper {
    pub async fn send_message(&self, msg: InMessage) {
        let _ = self.send.send(msg).await;
    }
    pub async fn receive_message(&mut self) -> Option<OutMessage> {
        self.recv.recv().await
    }
}
