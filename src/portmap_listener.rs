//! Standalone portmapper listener for NFS clients that can't bypass portmapper.
//!
//! `NFSTcpListener` already serves portmap RPC on the same TCP port as NFS and
//! MOUNT (see [`crate::portmap_handlers`]); Linux/macOS clients pick that port
//! up via the `mountport=N` mount option and skip the portmapper round-trip.
//! The Windows "Client for NFS" has no equivalent: `mount.exe` always queries
//! portmapper at port 111 on the target host to discover MOUNT and NFS service
//! ports. Without a listener at 111, the mount fails with "network path not
//! found".
//!
//! [`spawn`] binds a TCP + UDP listener at a caller-chosen address (typically
//! `127.0.0.1:111`) and answers `PMAPPROC_GETPORT` queries with a fixed
//! `target_port` for the NFS (100003) and MOUNT (100005) program numbers. It
//! is intentionally minimal — no PMAPPROC_SET / DUMP / CALLIT — and exists
//! only to unblock Windows clients.
//!
//! Binding port 111 requires elevated privileges (Administrator on Windows,
//! root or `cap_net_bind_service` on Linux).

use std::io::Cursor;
use std::net::SocketAddr;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tracing::{debug, trace};

use crate::rpc::{
    make_success_reply, proc_unavail_reply_message, prog_mismatch_reply_message, prog_unavail_reply_message, rpc_body,
    rpc_msg,
};
use crate::rpcwire::write_fragment;
use crate::xdr::XDR;
use crate::{mount, nfs, portmap};

const PMAPPROC_NULL: u32 = 0;
const PMAPPROC_GETPORT: u32 = 3;

/// Bind a portmapper listener at `bind_addr` (typically `127.0.0.1:111`) and
/// spawn the UDP and TCP loops that answer `GETPORT` queries with `target_port`
/// for the NFS and MOUNT program numbers. Returns a handle that aborts the
/// listener loops on drop.
///
/// Errors propagate from the underlying socket binds (e.g. permission denied
/// on port 111, or address-in-use if another portmap is already running).
pub async fn spawn(bind_addr: SocketAddr, target_port: u16) -> std::io::Result<JoinHandle<()>> {
    let udp = UdpSocket::bind(bind_addr).await?;
    let tcp = TcpListener::bind(bind_addr).await?;
    debug!("portmap listener bound on {bind_addr} (target_port={target_port})");

    Ok(tokio::spawn(async move {
        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                if let Some(reply) = handle_message(&buf[..n], target_port) {
                    let _ = udp.send_to(&reply, peer).await;
                }
            }
        });

        let tcp_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = tcp.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    // ONC RPC over TCP: 4-byte fragment header (MSB = last fragment,
                    // lower 31 = length), then RPC message body. GETPORT replies
                    // never fragment, so we ignore the bit and read one frame.
                    loop {
                        let mut hdr = [0u8; 4];
                        if stream.read_exact(&mut hdr).await.is_err() {
                            return;
                        }
                        let len = (u32::from_be_bytes(hdr) & 0x7fff_ffff) as usize;
                        let mut body = vec![0u8; len];
                        if stream.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        if let Some(reply) = handle_message(&body, target_port) {
                            if write_fragment(&mut stream, &reply).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });

        let _ = tokio::join!(udp_task, tcp_task);
    }))
}

/// Parse a single RPC message and produce the reply payload (no fragment
/// header). Returns `None` for malformed input or non-CALL messages.
fn handle_message(buf: &[u8], target_port: u16) -> Option<Vec<u8>> {
    let mut cursor = Cursor::new(buf);
    let mut msg = rpc_msg::default();
    msg.deserialize(&mut cursor).ok()?;
    let xid = msg.xid;
    let call = match msg.body {
        rpc_body::CALL(c) => c,
        _ => return None,
    };

    let mut out = Vec::with_capacity(64);
    if call.prog != portmap::PROGRAM {
        prog_unavail_reply_message(xid).serialize(&mut out).ok()?;
        return Some(out);
    }
    if call.vers != portmap::VERSION {
        prog_mismatch_reply_message(xid, portmap::VERSION).serialize(&mut out).ok()?;
        return Some(out);
    }

    match call.proc {
        PMAPPROC_NULL => {
            make_success_reply(xid).serialize(&mut out).ok()?;
        },
        PMAPPROC_GETPORT => {
            let mut mapping = portmap::mapping::default();
            mapping.deserialize(&mut cursor).ok()?;
            let port: u32 = if mapping.prog == nfs::PROGRAM || mapping.prog == mount::PROGRAM {
                target_port as u32
            } else {
                0
            };
            trace!("GETPORT(prog={}, vers={}) -> {port}", mapping.prog, mapping.vers);
            make_success_reply(xid).serialize(&mut out).ok()?;
            port.serialize(&mut out).ok()?;
        },
        _ => {
            proc_unavail_reply_message(xid).serialize(&mut out).ok()?;
        },
    }
    Some(out)
}
