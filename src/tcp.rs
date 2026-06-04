use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::context::RPCContext;
use crate::rpcwire::*;
use crate::transaction_tracker::TransactionTracker;
use crate::vfs::NFSFileSystem;

/// A NFS Tcp Connection Handler
pub struct NFSTcpListener<T: NFSFileSystem + Send + Sync + 'static> {
    listener: TcpListener,
    port: u16,
    arcfs: Arc<T>,
    mount_signal: Option<mpsc::Sender<bool>>,
    export_name: Arc<String>,
    transaction_tracker: Arc<TransactionTracker>,
}

pub fn generate_host_ip(hostnum: u16) -> String {
    format!("127.88.{}.{}", ((hostnum >> 8) & 0xFF) as u8, (hostnum & 0xFF) as u8)
}

/// Serve a single established connection. Generic over the stream so callers can
/// pass a plaintext `TcpStream` or an already-handshaked TLS stream
/// (e.g. `tokio_rustls::server::TlsStream`) — `nfsserve` stays TLS-agnostic.
///
/// `NFSTcpListener` uses this internally for plaintext TCP. To terminate TLS in
/// process, hand it an already-handshaked stream:
///
/// ```ignore
/// // `tls` is a `tokio_rustls::server::TlsStream<TcpStream>` after `acceptor.accept(tcp).await?`.
/// nfsserve::tcp::process_socket(tls, context).await?;
/// ```
pub async fn process_socket<S>(socket: S, context: RPCContext) -> Result<(), anyhow::Error>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut message_handler, mut socksend, mut msgrecvchan) = SocketMessageHandler::new(&context);
    let (mut reader, mut writer) = tokio::io::split(socket);

    tokio::spawn(async move {
        loop {
            if let Err(e) = message_handler.read().await {
                debug!("Message loop broken due to {:?}", e);
                break;
            }
        }
    });
    let mut buf = vec![0u8; 128000];
    loop {
        tokio::select! {
            res = reader.read(&mut buf) => {
                match res {
                    Ok(0) => return Ok(()),
                    Ok(n) => { let _ = socksend.write_all(&buf[..n]).await; }
                    Err(e) => {
                        debug!("Message handling closed : {:?}", e);
                        return Err(e.into());
                    }
                }
            },
            reply = msgrecvchan.recv() => {
                match reply {
                    Some(Err(e)) => {
                        debug!("Message handling closed : {:?}", e);
                        return Err(e);
                    }
                    Some(Ok(msg)) => {
                        if let Err(e) = write_fragment(&mut writer, &msg).await {
                            error!("Write error {:?}", e);
                        } else if let Err(e) = writer.flush().await {
                            error!("Flush error {:?}", e);
                        }
                    }
                    None => {
                        return Err(anyhow::anyhow!("Unexpected socket context termination"));
                    }
                }
            }
        }
    }
}

#[async_trait]
pub trait NFSTcp: Send + Sync {
    /// Gets the true listening port. Useful if the bound port number is 0
    fn get_listen_port(&self) -> u16;

    /// Gets the true listening IP. Useful on windows when the IP may be random
    fn get_listen_ip(&self) -> IpAddr;

    /// Sets a mount listener. A "true" signal will be sent on a mount
    /// and a "false" will be sent on an unmount
    fn set_mount_listener(&mut self, signal: mpsc::Sender<bool>);

    /// Loops forever and never returns handling all incoming connections.
    async fn handle_forever(&self) -> io::Result<()>;
}

impl<T: NFSFileSystem + Send + Sync + 'static> NFSTcpListener<T> {
    /// Binds to a ipstr of the form [ip address]:port. For instance
    /// "127.0.0.1:12000". fs is an instance of an implementation
    /// of NFSFileSystem.
    pub async fn bind(ipstr: &str, fs: T) -> io::Result<NFSTcpListener<T>> {
        let (ip, port) = ipstr
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "IP Address must be of form ip:port"))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::AddrNotAvailable, "Port not in range 0..=65535"))?;

        let arcfs: Arc<T> = Arc::new(fs);

        if ip == "auto" {
            let mut num_tries_left = 32;

            for try_ip in 1u16.. {
                let ip = generate_host_ip(try_ip);

                let result = NFSTcpListener::bind_internal(&ip, port, arcfs.clone()).await;

                match &result {
                    Err(_) => {
                        if num_tries_left == 0 {
                            return result;
                        } else {
                            num_tries_left -= 1;
                            continue;
                        }
                    },
                    Ok(_) => {
                        return result;
                    },
                }
            }
            unreachable!(); // Does not detect automatically that loop above never terminates.
        } else {
            // Otherwise, try this.
            NFSTcpListener::bind_internal(ip, port, arcfs).await
        }
    }

    async fn bind_internal(ip: &str, port: u16, arcfs: Arc<T>) -> io::Result<NFSTcpListener<T>> {
        let ipstr = format!("{ip}:{port}");
        let listener = TcpListener::bind(&ipstr).await?;
        info!("Listening on {:?}", &ipstr);

        let port = match listener.local_addr().unwrap() {
            SocketAddr::V4(s) => s.port(),
            SocketAddr::V6(s) => s.port(),
        };
        Ok(NFSTcpListener {
            listener,
            port,
            arcfs,
            mount_signal: None,
            export_name: Arc::from("/".to_string()),
            transaction_tracker: Arc::new(TransactionTracker::new(Duration::from_secs(60))),
        })
    }

    /// Sets an optional NFS export name.
    ///
    /// - `export_name`: The desired export name without slashes.
    ///
    /// Example: Name `foo` results in the export path `/foo`.
    /// Default path is `/` if not set.
    pub fn with_export_name<S: AsRef<str>>(&mut self, export_name: S) {
        self.export_name = Arc::new(format!("/{}", export_name.as_ref().trim_end_matches('/').trim_start_matches('/')))
    }
}

#[async_trait]
impl<T: NFSFileSystem + Send + Sync + 'static> NFSTcp for NFSTcpListener<T> {
    /// Gets the true listening port. Useful if the bound port number is 0
    fn get_listen_port(&self) -> u16 {
        let addr = self.listener.local_addr().unwrap();
        addr.port()
    }

    fn get_listen_ip(&self) -> IpAddr {
        let addr = self.listener.local_addr().unwrap();
        addr.ip()
    }

    /// Sets a mount listener. A "true" signal will be sent on a mount
    /// and a "false" will be sent on an unmount
    fn set_mount_listener(&mut self, signal: mpsc::Sender<bool>) {
        self.mount_signal = Some(signal);
    }

    /// Loops forever and never returns handling all incoming connections.
    async fn handle_forever(&self) -> io::Result<()> {
        loop {
            let (socket, _) = self.listener.accept().await?;
            let _ = socket.set_nodelay(true);
            let context = RPCContext {
                local_port: self.port,
                client_addr: socket.peer_addr().unwrap().to_string(),
                auth: crate::rpc::auth_unix::default(),
                vfs: self.arcfs.clone(),
                mount_signal: self.mount_signal.clone(),
                export_name: self.export_name.clone(),
                transaction_tracker: self.transaction_tracker.clone(),
            };
            info!("Accepting connection from {}", context.client_addr);
            debug!("Accepting socket {:?} {:?}", socket, context);
            tokio::spawn(async move {
                let _ = process_socket(socket, context).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::nfs::{fattr3, fileid3, filename3, nfspath3, nfsstat3, sattr3};
    use crate::rpc::{auth_unix, call_body, opaque_auth, reply_body, rpc_body, rpc_msg};
    use crate::vfs::{NFSFileSystem, ReadDirResult, VFSCapabilities};
    use crate::xdr::XDR;

    /// A do-nothing filesystem: enough to build an `RPCContext`. The NULL
    /// procedure exercised below never touches the VFS, so every data method
    /// just reports "not supported".
    struct NullFS;

    #[async_trait]
    impl NFSFileSystem for NullFS {
        fn capabilities(&self) -> VFSCapabilities {
            VFSCapabilities::ReadOnly
        }
        fn root_dir(&self) -> fileid3 {
            1
        }
        async fn lookup(&self, _: fileid3, _: &filename3) -> Result<fileid3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn getattr(&self, _: fileid3) -> Result<fattr3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn setattr(&self, _: fileid3, _: sattr3) -> Result<fattr3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn read(&self, _: fileid3, _: u64, _: u32) -> Result<(Vec<u8>, bool), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn write(&self, _: fileid3, _: u64, _: &[u8]) -> Result<fattr3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn create(&self, _: fileid3, _: &filename3, _: sattr3) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn create_exclusive(&self, _: fileid3, _: &filename3) -> Result<fileid3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn mkdir(&self, _: fileid3, _: &filename3) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn remove(&self, _: fileid3, _: &filename3) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn rename(&self, _: fileid3, _: &filename3, _: fileid3, _: &filename3) -> Result<(), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn readdir(&self, _: fileid3, _: fileid3, _: usize) -> Result<ReadDirResult, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn symlink(
            &self,
            _: fileid3,
            _: &filename3,
            _: &nfspath3,
            _: &sattr3,
        ) -> Result<(fileid3, fattr3), nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
        async fn readlink(&self, _: fileid3) -> Result<nfspath3, nfsstat3> {
            Err(nfsstat3::NFS3ERR_NOTSUPP)
        }
    }

    fn test_context() -> RPCContext {
        RPCContext {
            local_port: 2049,
            client_addr: "127.0.0.1:0".to_string(),
            auth: auth_unix::default(),
            vfs: Arc::new(NullFS),
            mount_signal: None,
            export_name: Arc::new("/".to_string()),
            transaction_tracker: Arc::new(TransactionTracker::new(Duration::from_secs(60))),
        }
    }

    /// Serialize an RPC record (4-byte last-fragment header + body), as
    /// `write_fragment` does on the wire.
    fn frame(body: &[u8]) -> Vec<u8> {
        let header = (body.len() as u32) | (1 << 31);
        let mut out = header.to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    /// Drive a single `MOUNTPROC3_NULL` call through `process_socket` over an
    /// in-memory `DuplexStream` (not a `TcpStream`) and assert a well-formed
    /// reply comes back. This proves the handler is genuinely transport-generic
    /// over `AsyncRead + AsyncWrite + Send + 'static` — the property TLS relies on.
    #[tokio::test]
    async fn process_socket_over_non_tcp_stream() {
        // server side is handed to process_socket; we drive the client side.
        let (server, mut client) = tokio::io::duplex(64 * 1024);

        let handle = tokio::spawn(async move {
            let _ = process_socket(server, test_context()).await;
        });

        // Build a MOUNTPROC3_NULL call (program 100005, version 3, procedure 0).
        let call = rpc_msg {
            xid: 0x1234_5678,
            body: rpc_body::CALL(call_body {
                rpcvers: 2,
                prog: crate::mount::PROGRAM,
                vers: crate::mount::VERSION,
                proc: 0,
                cred: opaque_auth::default(),
                verf: opaque_auth::default(),
            }),
        };
        let mut body = Vec::new();
        call.serialize(&mut body).unwrap();
        client.write_all(&frame(&body)).await.unwrap();
        client.flush().await.unwrap();

        // Read the reply record back: 4-byte fragment header, then the body.
        let mut header = [0u8; 4];
        client.read_exact(&mut header).await.unwrap();
        let len = (u32::from_be_bytes(header) & ((1 << 31) - 1)) as usize;
        let mut reply_buf = vec![0u8; len];
        client.read_exact(&mut reply_buf).await.unwrap();

        let mut reply = rpc_msg::default();
        reply.deserialize(&mut Cursor::new(&reply_buf)).unwrap();

        assert_eq!(reply.xid, 0x1234_5678);
        match reply.body {
            rpc_body::REPLY(reply_body::MSG_ACCEPTED(_)) => {},
            other => panic!("expected an accepted reply, got {other:?}"),
        }

        // Dropping the client closes the connection so process_socket returns.
        drop(client);
        handle.await.unwrap();
    }
}
