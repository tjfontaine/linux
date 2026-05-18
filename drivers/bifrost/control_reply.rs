// SPDX-License-Identifier: GPL-2.0
// Virtqueue control-buffer reposting and LOAD_PROG completion replies.
//
// Goal item 9 (status truthfulness): every LOAD_PROG command receives
// exactly one response through `complete_load_prog`. Each
// `attach_slot_*` returns a c_int (0 on full success; negative errno
// on failure with all locally-acquired resources released). The
// worker thread routes the highest-severity status into
// `complete_load_prog` — never status=0 when verify/JIT/attach failed.
//
// Wire format of the LOAD_PROG completion event (op=9) carried on the
// guest→host event vq:
//
//     u32  op                       = 9
//     u64  seq                      LOAD_PROG seq from the request trailer
//     i32  status                   0 or negative errno
//     u16  detail_len               UTF-8 byte length (0 if no detail)
//     [u8; detail_len] detail       diagnostic string (missing kfunc name,
//                                   unresolved FENTRY target, etc.)
//
// `detail` is mandatory on the wire (always followed by the u16 length)
// but may be empty. virtio-conduit on the host side parses the trailer
// and forwards the detail into the `D4_KIND_RSP_ERR` body so the host
// CLI can render `bifrost: program N: <label>: <detail>` instead of
// the catch-all "LOAD_PROG failed in guest: status=-N".

use kernel::bindings;
use kernel::prelude::*;

use crate::types::BifrostCmd;
use crate::BifrostGuest;

/// Hard cap on the kernel-side detail string. Bounded well below the
/// event_buf size so a hostile or buggy emitter can't truncate the
/// trailer the host expects.
pub(crate) const LOAD_PROG_STATUS_DETAIL_MAX: usize = 256;

unsafe fn load_prog_seq(cmd: *const BifrostCmd, cmd_len: u32) -> u64 {
    unsafe {
        const CMD_HDR: usize = core::mem::size_of::<BifrostCmd>();
        const SEQ_LEN: usize = core::mem::size_of::<u64>();

        if cmd.is_null() || (cmd_len as usize) < CMD_HDR + SEQ_LEN {
            return 0;
        }
        let cmd_len = cmd_len as usize;
        let declared_seq_off = CMD_HDR.saturating_add((*cmd).len as usize);
        let seq_off = if declared_seq_off + SEQ_LEN <= cmd_len {
            declared_seq_off
        } else {
            cmd_len - SEQ_LEN
        };
        core::ptr::read_unaligned((cmd as *const u8).add(seq_off) as *const u64)
    }
}

pub(crate) unsafe fn send_load_prog_status(
    bg: *mut BifrostGuest,
    seq: u64,
    status: i32,
    detail: &[u8],
) {
    unsafe {
        const OP_LOAD_PROG_STATUS: u32 = 9;
        const HDR_LEN: usize = 4 + 8 + 4 + 2; // op + seq + status + detail_len
        let detail_len = detail.len().min(LOAD_PROG_STATUS_DETAIL_MAX);
        let total_len = HDR_LEN + detail_len;

        let event_buf = (*bg).event_buf as *mut u8;
        core::ptr::copy_nonoverlapping(
            &OP_LOAD_PROG_STATUS as *const u32 as *const u8,
            event_buf,
            4,
        );
        core::ptr::copy_nonoverlapping(&seq as *const u64 as *const u8, event_buf.add(4), 8);
        core::ptr::copy_nonoverlapping(&status as *const i32 as *const u8, event_buf.add(12), 4);
        let detail_len_u16 = detail_len as u16;
        core::ptr::copy_nonoverlapping(
            &detail_len_u16 as *const u16 as *const u8,
            event_buf.add(16),
            2,
        );
        if detail_len > 0 {
            core::ptr::copy_nonoverlapping(detail.as_ptr(), event_buf.add(HDR_LEN), detail_len);
        }

        let mut sg: bindings::scatterlist = core::mem::zeroed();
        bindings::sg_init_one(&mut sg, (*bg).event_buf, total_len as core::ffi::c_uint);
        let add_err = bindings::virtqueue_add_outbuf(
            (*bg).vq_event,
            &mut sg,
            1,
            (*bg).event_buf,
            bindings::GFP_KERNEL,
        );
        if add_err != 0 {
            pr_err!(
                "bifrost_guest: LOAD_PROG status event add failed: {}\n",
                add_err
            );
            return;
        }
        bindings::virtqueue_kick((*bg).vq_event);

        let mut consumed_len: core::ffi::c_uint = 0;
        let mut spins: u32 = 0;
        loop {
            let ret = bindings::virtqueue_get_buf((*bg).vq_event, &mut consumed_len);
            if !ret.is_null() {
                break;
            }
            core::hint::spin_loop();
            spins += 1;
            if spins % 1024 == 0 {
                bindings::__cond_resched();
            }
        }
    }
}

pub(crate) unsafe fn repost_ctrl_buffer(bg: *mut BifrostGuest) {
    unsafe {
        let mut sg_in: bindings::scatterlist = core::mem::zeroed();
        bindings::sg_init_one(&mut sg_in, (*bg).ctrl_buf, 65536);
        bindings::virtqueue_add_inbuf(
            (*bg).vq_ctrl,
            &mut sg_in,
            1,
            (*bg).ctrl_buf,
            bindings::GFP_KERNEL,
        );
        bindings::virtqueue_kick((*bg).vq_ctrl);
    }
}

pub(crate) unsafe fn complete_load_prog(
    bg: *mut BifrostGuest,
    cmd: *const BifrostCmd,
    status: i32,
) {
    unsafe { complete_load_prog_with_detail(bg, cmd, status, b"") }
}

pub(crate) unsafe fn complete_load_prog_with_detail(
    bg: *mut BifrostGuest,
    cmd: *const BifrostCmd,
    status: i32,
    detail: &[u8],
) {
    unsafe {
        // op == 2 → legacy LOAD_PROG; op == 3 → post-cutover
        // DTRACE_SESSION envelope. Both reply with the same
        // `[i32 status][u16 detail_len][detail]` shape on the rsp
        // ring so the host's existing `decode_load_prog_status` path
        // works for either.
        if !cmd.is_null() && ((*cmd).op == 2 || (*cmd).op == 3) {
            let seq = load_prog_seq(cmd, (*bg).cmd_len);
            send_load_prog_status(bg, seq, status, detail);
        }
        repost_ctrl_buffer(bg);
    }
}
