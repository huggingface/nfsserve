// this is just a complete enumeration of everything in the RFC
#![allow(dead_code)]
// And its nice to keep the original RFC names and case
#![allow(non_camel_case_types)]

use crate::xdr::*;
use byteorder::{ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::cast::FromPrimitive;
use std::io::{Read, Write};

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum nlm4_stats {
    /// The call completed successfully.
    NLM4_GRANTED = 0,
    /// The call failed. For attempts to set a lock, this status implies that if the client retries the call later, it may succeed.
    NLM4_DENIED = 1,
    /// The call failed because the server could not allocate the necessary resources.
    NLM4_DENIED_NOLOCKS = 2,
    /// Indicates that a blocking request cannot be granted immediately. The server will issue an NLMPROC4_GRANTED callback to the client when the lock is granted.
    NLM4_BLOCKED = 3,
    /// The call failed because the server is reestablishing old locks after a reboot and is not yet ready to resume normal service.
    NLM4_DENIED_GRACE_PERIOD = 4,
    /// The request could not be granted and blocking would cause a deadlock.
    NLM4_DEADLCK = 5,
    /// The call failed because the remote file system is read-only. For example, some server implementations might not support exclusive locks on read-only file systems.
    NLM4_ROFS = 6,
    /// The call failed because it uses an invalid file handle. This can happen if the file has been removed or if access to the file has been revoked on the server.
    NLM4_STALE_FH = 7,
    /// The call failed because it specified a length or offset that exceeds the range supported by the server.
    NLM4_FBIG = 8,
    /// The call failed for some reason not already listed. The client should take this status as a strong hint not to retry the request.
    NLM4_FAILED = 9,
}
XDREnumSerde!(nlm4_stats);

/// The nlm_lock structure defines the information needed to uniquely specify a lock. The "caller_name" uniquely identifies the host making the call. The "fh" field identifies the file to lock. The "oh" field is an opaque object that identifies the host, or a process on the host, that is making the request. "uppid" uniquely describes the process owning the file on the calling host. The "uppid" may be generated in any system-dependent fashion. On an X/Open-compliant system it is generally the process ID. On a DOS system it may be generated from the program segment prefix (PSP). The "l_offset" and "l_len" determine which bytes of the file are locked.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct nlm4_lock {
    pub caller_name: Vec<u8>,
    pub fh: Vec<u8>,
    pub oh: Vec<u8>,
    pub svid: i32,
    pub l_offset: u64,
    pub l_len: u64,
}
XDRStruct!(nlm4_lock, caller_name, fh, oh, svid, l_offset, l_len);

/// The nlm_testargs structure defines the information needed to test a lock. The information in this structure is the same as the corresponding fields in the nlm_lockargs structure.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct nlm_testargs {
    pub cookie: Vec<u8>,
    pub exclusive: bool,
    pub alock: nlm4_lock,
}
XDRStruct!(nlm_testargs, cookie, exclusive, alock);

/// This structure is the return value from the NLM_TEST procedure. The other main lock routines return the nlm_res structure.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
#[repr(C)]
pub struct nlm_testres {
    pub cookie: Vec<u8>,
    pub stat: nlm4_stats,
}
XDRStruct!(nlm_testres, cookie, stat);

/// The nlm_lockargs structure defines the information needed to request a lock on a server. The "block" field must be set to true if the client wishes the procedure call to block until the lock can be granted (see NLM_LOCK). A false value will cause the procedure call to return immediately if the lock cannot be granted. The "reclaim" field must only be set to true if the client is attempting to reclaim a lock held by an NLM which has been restarted (due to a server crash, and so on). The "state" field is used with the monitored lock procedure call (NLM_LOCK). It is the state value supplied by the local NSM, see Network Status Monitor Protocol .
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct nlm_lockargs {
    pub cookie: Vec<u8>,
    pub block: bool,
    pub exclusive: bool,
    pub alock: nlm4_lock,
    pub reclaim: bool,
    pub state: i32,
}
XDRStruct!(
    nlm_lockargs,
    cookie,
    block,
    exclusive,
    alock,
    reclaim,
    state
);

/// The nlm_res structure is returned by all of the main lock routines except for NLM_TEST which has a separate return structure defined below. Note that clients must not rely upon the "cookie" being the same as that passed in the corresponding request.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
#[repr(C)]
pub struct nlm_res {
    pub cookie: Vec<u8>,
    pub stat: nlm4_stats,
}
XDRStruct!(nlm_res, cookie, stat);

/// The nlm_cancargs structure defines the information needed to cancel an outstanding lock request. The data in the nlm_cancargs structure must exactly match the corresponding information in the nlm_lockargs structure of the outstanding lock request to be cancelled.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct nlm_cancargs {
    pub cookie: Vec<u8>,
    pub block: bool,
    pub exclusive: bool,
    pub alock: nlm4_lock,
}
XDRStruct!(nlm_cancargs, cookie, block, exclusive, alock);

/// The nlm_unlockargs structure defines the information needed to remove a previously established lock.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
#[repr(C)]
pub struct nlm_unlockargs {
    pub cookie: Vec<u8>,
    pub alock: nlm4_lock,
}
XDRStruct!(nlm_unlockargs, cookie, alock);

pub const IPPROTO_TCP: u32 = 6; /* protocol number for TCP/IP */
pub const IPPROTO_UDP: u32 = 17; /* protocol number for UDP/IP */
pub const PROGRAM: u32 = 100021;
pub const VERSION: u32 = 4;
