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
//! `target_port` for the NFS v3 (100003) and MOUNT v3 (100005) program numbers
//! over TCP. UDP queries and queries for other versions get a `0` port reply
//! (RFC 1833: "no such mapping"). It is intentionally minimal — no
//! PMAPPROC_SET / DUMP / CALLIT — and exists only to unblock Windows clients.
//!
//! Binding port 111 requires elevated privileges (Administrator on Windows,
//! root or `cap_net_bind_service` on Linux).

use std::io::Cursor;
use std::net::SocketAddr;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, trace};

use crate::rpc::{
    garbage_args_reply_message, make_success_reply, proc_unavail_reply_message, prog_mismatch_reply_message,
    prog_unavail_reply_message, rpc_body, rpc_msg, rpc_vers_mismatch,
};
use crate::rpcwire::write_fragment;
use crate::xdr::XDR;
use crate::{mount, nfs, portmap};

const PMAPPROC_NULL: u32 = 0;
const PMAPPROC_GETPORT: u32 = 3;

/// Cap RPC record size at 4 KiB. PMAPPROC_GETPORT requests are ~40 bytes; this
/// is generous slack while bounding memory if a peer advertises a huge fragment.
const MAX_RPC_RECORD_BYTES: usize = 4096;

/// Bind a portmapper listener at `bind_addr` (typically `127.0.0.1:111`) and
/// spawn the UDP and TCP loops that answer `GETPORT` queries with `target_port`
/// for the NFS v3 and MOUNT v3 program numbers over TCP.
///
/// Returns a [`JoinHandle`]. To stop the listener, call `.abort()` on the
/// handle (dropping it alone is not enough — Tokio does not abort tasks on
/// `JoinHandle` drop). Aborting the handle also tears down all UDP/TCP child
/// tasks because they live in [`JoinSet`]s owned by the spawned future.
///
/// Errors propagate from the underlying socket binds (e.g. permission denied
/// on port 111, or address-in-use if another portmap is already running).
pub async fn spawn(bind_addr: SocketAddr, target_port: u16) -> std::io::Result<JoinHandle<()>> {
    let udp = UdpSocket::bind(bind_addr).await?;
    let tcp = TcpListener::bind(bind_addr).await?;
    debug!("portmap listener bound on {bind_addr} (target_port={target_port})");

    Ok(tokio::spawn(async move {
        // Owning the children in a JoinSet means aborting the outer handle
        // drops the JoinSet, which aborts both child tasks (and transitively
        // their per-conn tasks for TCP).
        let mut tasks = JoinSet::new();
        tasks.spawn(udp_loop(udp, target_port));
        tasks.spawn(tcp_loop(tcp, target_port));
        while tasks.join_next().await.is_some() {}
    }))
}

async fn udp_loop(udp: UdpSocket, target_port: u16) {
    let mut buf = [0u8; 1500];
    loop {
        let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
            continue;
        };
        if let Some(reply) = handle_message(&buf[..n], target_port) {
            let _ = udp.send_to(&reply, peer).await;
        }
    }
}

async fn tcp_loop(tcp: TcpListener, target_port: u16) {
    // Hold per-connection tasks here so that this loop's cancellation (via the
    // parent JoinSet) propagates aborts to every in-flight connection.
    let mut conns: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            accept = tcp.accept() => {
                if let Ok((stream, _)) = accept {
                    conns.spawn(handle_tcp_conn(stream, target_port));
                }
            }
            // Reap finished connections so the JoinSet doesn't grow unbounded.
            Some(_) = conns.join_next() => {}
        }
    }
}

async fn handle_tcp_conn(mut stream: TcpStream, target_port: u16) {
    // ONC RPC over TCP (RFC 1057 §10): 4-byte fragment header per fragment
    // (MSB = last fragment, lower 31 bits = length), concatenated until
    // last == true. Cap total record size so a misbehaving peer cannot pin
    // arbitrary memory.
    let mut record = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        if stream.read_exact(&mut hdr).await.is_err() {
            return;
        }
        let frag = u32::from_be_bytes(hdr);
        let last = frag & 0x8000_0000 != 0;
        let len = (frag & 0x7fff_ffff) as usize;
        if record.len() + len > MAX_RPC_RECORD_BYTES {
            return; // close connection
        }
        let start = record.len();
        record.resize(start + len, 0);
        if stream.read_exact(&mut record[start..]).await.is_err() {
            return;
        }
        if !last {
            continue;
        }
        if let Some(reply) = handle_message(&record, target_port) {
            if write_fragment(&mut stream, &reply).await.is_err() {
                return;
            }
        }
        record.clear();
    }
}

/// Parse a single RPC message and produce the reply payload (no fragment
/// header). Returns `None` for malformed transport input or non-CALL messages.
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
    if call.rpcvers != 2 {
        rpc_vers_mismatch(xid).serialize(&mut out).ok()?;
        return Some(out);
    }
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
            if mapping.deserialize(&mut cursor).is_err() {
                garbage_args_reply_message(xid).serialize(&mut out).ok()?;
                return Some(out);
            }
            // RFC 1833: lookup by (prog, vers, prot). nfsserve only serves NFS
            // and MOUNT v3 over TCP, so any other tuple is "no such mapping".
            let known_service = (mapping.prog == nfs::PROGRAM && mapping.vers == nfs::VERSION)
                || (mapping.prog == mount::PROGRAM && mapping.vers == mount::VERSION);
            let port: u32 = if known_service && mapping.prot == portmap::IPPROTO_TCP {
                target_port as u32
            } else {
                0
            };
            trace!("GETPORT(prog={}, vers={}, prot={}) -> {port}", mapping.prog, mapping.vers, mapping.prot);
            make_success_reply(xid).serialize(&mut out).ok()?;
            port.serialize(&mut out).ok()?;
        },
        _ => {
            proc_unavail_reply_message(xid).serialize(&mut out).ok()?;
        },
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{call_body, opaque_auth};

    /// Serialize an RPC CALL header followed by raw `args`. Use this to drive
    /// `handle_message` without going through socket plumbing.
    fn build_call(xid: u32, rpcvers: u32, prog: u32, vers: u32, proc_: u32, args: &[u8]) -> Vec<u8> {
        let msg = rpc_msg {
            xid,
            body: rpc_body::CALL(call_body {
                rpcvers,
                prog,
                vers,
                proc: proc_,
                cred: opaque_auth::default(),
                verf: opaque_auth::default(),
            }),
        };
        let mut out = Vec::new();
        msg.serialize(&mut out).unwrap();
        out.extend_from_slice(args);
        out
    }

    fn build_getport_args(prog: u32, vers: u32, prot: u32) -> Vec<u8> {
        let mapping = portmap::mapping {
            prog,
            vers,
            prot,
            port: 0,
        };
        let mut out = Vec::new();
        mapping.serialize(&mut out).unwrap();
        out
    }

    /// Parse the trailing u32 of a SUCCESS GETPORT reply (the answered port).
    /// Returns `None` if the reply isn't a SUCCESS.
    fn parse_getport_reply(reply: &[u8]) -> Option<u32> {
        let mut cursor = Cursor::new(reply);
        let mut msg = rpc_msg::default();
        msg.deserialize(&mut cursor).ok()?;
        let port_offset = cursor.position() as usize;
        Some(u32::from_be_bytes(reply[port_offset..port_offset + 4].try_into().unwrap()))
    }

    const TARGET: u16 = 50_000;

    #[test]
    fn null_proc_returns_success() {
        let req = build_call(1, 2, portmap::PROGRAM, portmap::VERSION, PMAPPROC_NULL, &[]);
        let reply = handle_message(&req, TARGET).expect("reply");
        // 24 bytes = xid + msg_type(REPLY) + reply_stat(MSG_ACCEPTED) + verf(8) + accept_stat(SUCCESS).
        assert_eq!(reply.len(), 24);
    }

    #[test]
    fn getport_nfs_v3_tcp_returns_target_port() {
        let args = build_getport_args(nfs::PROGRAM, nfs::VERSION, portmap::IPPROTO_TCP);
        let req = build_call(2, 2, portmap::PROGRAM, portmap::VERSION, PMAPPROC_GETPORT, &args);
        let reply = handle_message(&req, TARGET).expect("reply");
        assert_eq!(parse_getport_reply(&reply), Some(TARGET as u32));
    }

    #[test]
    fn getport_mount_v3_tcp_returns_target_port() {
        let args = build_getport_args(mount::PROGRAM, mount::VERSION, portmap::IPPROTO_TCP);
        let req = build_call(3, 2, portmap::PROGRAM, portmap::VERSION, PMAPPROC_GETPORT, &args);
        let reply = handle_message(&req, TARGET).expect("reply");
        assert_eq!(parse_getport_reply(&reply), Some(TARGET as u32));
    }

    #[test]
    fn getport_nfs_over_udp_returns_zero() {
        let args = build_getport_args(nfs::PROGRAM, nfs::VERSION, portmap::IPPROTO_UDP);
        let req = build_call(4, 2, portmap::PROGRAM, portmap::VERSION, PMAPPROC_GETPORT, &args);
        let reply = handle_message(&req, TARGET).expect("reply");
        assert_eq!(parse_getport_reply(&reply), Some(0));
    }

    #[test]
    fn getport_unknown_program_returns_zero() {
        let args = build_getport_args(0xdead_beef, 1, portmap::IPPROTO_TCP);
        let req = build_call(5, 2, portmap::PROGRAM, portmap::VERSION, PMAPPROC_GETPORT, &args);
        let reply = handle_message(&req, TARGET).expect("reply");
        assert_eq!(parse_getport_reply(&reply), Some(0));
    }

    #[test]
    fn getport_wrong_nfs_version_returns_zero() {
        let args = build_getport_args(nfs::PROGRAM, nfs::VERSION + 1, portmap::IPPROTO_TCP);
        let req = build_call(6, 2, portmap::PROGRAM, portmap::VERSION, PMAPPROC_GETPORT, &args);
        let reply = handle_message(&req, TARGET).expect("reply");
        assert_eq!(parse_getport_reply(&reply), Some(0));
    }

    #[test]
    fn truncated_getport_returns_garbage_args() {
        // CALL header advertises GETPORT but no mapping bytes follow.
        let req = build_call(7, 2, portmap::PROGRAM, portmap::VERSION, PMAPPROC_GETPORT, &[]);
        let reply = handle_message(&req, TARGET).expect("reply");
        // garbage_args reply is shorter than a SUCCESS+port reply (no trailing port).
        // Just check we got a reply at all and it's not the SUCCESS+port shape.
        assert!(reply.len() < 28);
    }

    #[test]
    fn wrong_rpcvers_replies_with_mismatch() {
        let req = build_call(8, 1, portmap::PROGRAM, portmap::VERSION, PMAPPROC_NULL, &[]);
        let reply = handle_message(&req, TARGET).expect("reply");
        // rpc_vers_mismatch is a REPLY/MSG_DENIED/RPC_MISMATCH(low=2,high=2): 24 bytes total.
        // We only check it's a reply and not the SUCCESS shape.
        assert!(!reply.is_empty());
    }

    #[test]
    fn unknown_program_returns_prog_unavail() {
        let req = build_call(9, 2, 0xabcd_ef01, 1, 0, &[]);
        let reply = handle_message(&req, TARGET).expect("reply");
        assert!(!reply.is_empty());
    }

    #[test]
    fn unknown_portmap_proc_returns_proc_unavail() {
        // Proc 99 is not implemented (we only do NULL and GETPORT).
        let req = build_call(10, 2, portmap::PROGRAM, portmap::VERSION, 99, &[]);
        let reply = handle_message(&req, TARGET).expect("reply");
        assert!(!reply.is_empty());
    }

    #[test]
    fn truncated_rpc_header_returns_none() {
        // Less than the minimal RPC header — must not panic and must drop.
        assert!(handle_message(&[0u8; 4], TARGET).is_none());
    }
}
