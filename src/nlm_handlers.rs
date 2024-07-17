use crate::context::RPCContext;
use crate::nlm;
use crate::nlm::nlm4_stats;
use crate::nlm::nlm_res;
use crate::nlm::nlm_testres;
use crate::rpc::*;
use crate::xdr::*;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::cast::FromPrimitive;
use std::io::{Read, Write};
use tracing::{debug, error};

/*
version NLM4_VERS {
    void NLMPROC4_NULL(void) = 0;
    nlm4_testres NLMPROC4_TEST(nlm4_testargs) = 1;
    nlm4_res NLMPROC4_LOCK(nlm4_lockargs) = 2;
    nlm4_res NLMPROC4_CANCEL(nlm4_cancargs) = 3;
    nlm4_res NLMPROC4_UNLOCK(nlm4_unlockargs) = 4;
    nlm4_res NLMPROC4_GRANTED(nlm4_testargs) = 5;
    void NLMPROC4_TEST_MSG(nlm4_testargs) = 6;
    void NLMPROC4_LOCK_MSG(nlm4_lockargs) = 7;
    void NLMPROC4_CANCEL_MSG(nlm4_cancargs) = 8;
    void NLMPROC4_UNLOCK_MSG(nlm4_unlockargs) = 9;
    void NLMPROC4_GRANTED_MSG(nlm4_testargs) = 10;
    void NLMPROC4_TEST_RES(nlm4_testres) = 11;
    void NLMPROC4_LOCK_RES(nlm4_res) = 12;
    void NLMPROC4_CANCEL_RES(nlm4_res) = 13;
    void NLMPROC4_UNLOCK_RES(nlm4_res) = 14;
    void NLMPROC4_GRANTED_RES(nlm4_res) = 15;
    nlm4_shareres NLMPROC4_SHARE(nlm4_shareargs) = 20;
    nlm4_shareres NLMPROC4_UNSHARE(nlm4_shareargs) = 21;
    nlm4_res NLMPROC4_NM_LOCK(nlm4_lockargs) = 22;
    void NLMPROC4_FREE_ALL(nlm4_notify) = 23;
} = 4;

*/

#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone, Debug, FromPrimitive, ToPrimitive)]
enum NlmProgram {
    NLMPROC4_NULL = 0,
    NLMPROC4_TEST,
    NLMPROC4_LOCK,
    NLMPROC4_CANCEL,
    NLMPROC4_UNLOCK,
    NLMPROC4_GRANTED,
    NLMPROC4_TEST_MSG,
    NLMPROC4_LOCK_MSG,
    NLMPROC4_CANCEL_MSG,
    NLMPROC4_UNLOCK_MSG,
    NLMPROC4_GRANTED_MSG,
    NLMPROC4_TEST_RES,
    NLMPROC4_LOCK_RES,
    NLMPROC4_CANCEL_RES,
    NLMPROC4_UNLOCK_RES,
    NLMPROC4_GRANTED_RES,
    NLMPROC4_SHARE = 20,
    NLMPROC4_UNSHARE,
    NLMPROC4_NM_LOCK,
    NLMPROC4_FREE_ALL,
    INVALID = isize::MAX,
}

pub fn handle_nlm(
    xid: u32,
    call: call_body,
    input: &mut impl Read,
    output: &mut impl Write,
    _context: &RPCContext,
) -> Result<(), anyhow::Error> {
    if call.vers != nlm::VERSION {
        error!(
            "Invalid NLM Version number {} != {}",
            call.vers,
            nlm::VERSION
        );
        prog_mismatch_reply_message(xid, nlm::VERSION).serialize(output)?;
        return Ok(());
    }
    let prog = NlmProgram::from_u32(call.proc).unwrap_or(NlmProgram::INVALID);

    match prog {
        NlmProgram::NLMPROC4_NULL => nlmproc4_null(xid, input, output)?,
        NlmProgram::NLMPROC4_TEST => nlmproc4_test(xid, input, output)?,
        NlmProgram::NLMPROC4_LOCK => nlmproc4_lock(xid, input, output)?,
        NlmProgram::NLMPROC4_CANCEL => nlmproc4_cancel(xid, input, output)?,
        NlmProgram::NLMPROC4_UNLOCK => nlmproc4_unlock(xid, input, output)?,
        _ => {
            proc_unavail_reply_message(xid).serialize(output)?;
        }
    }
    Ok(())
}

pub fn nlmproc4_null(
    xid: u32,
    _: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), anyhow::Error> {
    debug!("nlmproc4_null({:?}) ", xid);
    // build an RPC reply
    let msg = make_success_reply(xid);
    debug!("\t{:?} --> {:?}", xid, msg);
    msg.serialize(output)?;
    Ok(())
}

pub fn nlmproc4_test(
    xid: u32,
    read: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), anyhow::Error> {
    let mut args = nlm::nlm_testargs::default();
    args.deserialize(read)?;
    debug!("nlmproc4_test({:?}, {:?}) ", xid, args);
    make_success_reply(xid).serialize(output)?;
    nlm_testres {
        cookie: args.cookie,
        stat: nlm4_stats::NLM4_ROFS,
    }
    .serialize(output)?;
    Ok(())
}

pub fn nlmproc4_lock(
    xid: u32,
    read: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), anyhow::Error> {
    let mut args = nlm::nlm_lockargs::default();
    args.deserialize(read)?;
    debug!("nlmproc4_lock({:?}, {:?}) ", xid, args);
    make_success_reply(xid).serialize(output)?;
    nlm_res {
        cookie: args.cookie,
        stat: nlm4_stats::NLM4_ROFS,
    }
    .serialize(output)?;
    Ok(())
}

pub fn nlmproc4_cancel(
    xid: u32,
    read: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), anyhow::Error> {
    let mut args = nlm::nlm_cancargs::default();
    args.deserialize(read)?;
    debug!("nlmproc4_cancel({:?}, {:?}) ", xid, args);
    make_success_reply(xid).serialize(output)?;
    nlm_res {
        cookie: args.cookie,
        stat: nlm4_stats::NLM4_ROFS,
    }
    .serialize(output)?;
    Ok(())
}

pub fn nlmproc4_unlock(
    xid: u32,
    read: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), anyhow::Error> {
    let mut args = nlm::nlm_cancargs::default();
    args.deserialize(read)?;
    debug!("nlmproc4_unlock({:?}, {:?}) ", xid, args);
    make_success_reply(xid).serialize(output)?;
    nlm_res {
        cookie: args.cookie,
        stat: nlm4_stats::NLM4_ROFS,
    }
    .serialize(output)?;
    Ok(())
}
