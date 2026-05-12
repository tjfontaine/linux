// SPDX-License-Identifier: GPL-2.0
// Virtqueue control-buffer reposting and LOAD_PROG completion replies.

use kernel::bindings;
use kernel::prelude::*;

use crate::types::BifrostCmd;
use crate::BifrostGuest;

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

pub(crate) unsafe fn send_load_prog_status(bg: *mut BifrostGuest, seq: u64, status: i32) {
    unsafe {
        const OP_LOAD_PROG_STATUS: u32 = 9;
        let event_buf = (*bg).event_buf as *mut u8;
        core::ptr::copy_nonoverlapping(
            &OP_LOAD_PROG_STATUS as *const u32 as *const u8,
            event_buf,
            4,
        );
        core::ptr::copy_nonoverlapping(&seq as *const u64 as *const u8, event_buf.add(4), 8);
        core::ptr::copy_nonoverlapping(&status as *const i32 as *const u8, event_buf.add(12), 4);

        let mut sg: bindings::scatterlist = core::mem::zeroed();
        bindings::sg_init_one(&mut sg, (*bg).event_buf, 16);
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
    unsafe {
        if !cmd.is_null() && (*cmd).op == 2 {
            let seq = load_prog_seq(cmd, (*bg).cmd_len);
            send_load_prog_status(bg, seq, status);
        }
        repost_ctrl_buffer(bg);
    }
}
