// SPDX-License-Identifier: GPL-2.0
// Bounded parser for direct LOAD_PROG command payloads.

use kernel::bindings;
use kernel::ffi::c_int;
use kernel::prelude::*;

use crate::bpf_consts::{BPF_LD_IMM64, BPF_PSEUDO_MAP_FD};
use crate::types::{BifrostCmd, BpfInsn, MapDef};
use crate::wire::{
    PROBE_TYPE_UPROBE, PROBE_TYPE_UPROBE_BY_SYM, PROBE_TYPE_URETPROBE,
    PROBE_TYPE_URETPROBE_BY_SYM, PROBE_TYPE_USDT,
};

pub(crate) unsafe fn validate_load_prog_cmd(cmd: *const BifrostCmd, cmd_len: u32) -> c_int {
    unsafe {
        const CMD_HDR: usize = core::mem::size_of::<BifrostCmd>();
        const FIXED: usize = 4 + 32 + 4;
        const MAP_DEF_SIZE: usize = core::mem::size_of::<MapDef>();
        const INSN_SIZE: usize = core::mem::size_of::<BpfInsn>();

        if cmd.is_null() || (cmd_len as usize) < CMD_HDR {
            return -(bindings::EINVAL as i32);
        }
        let declared = (*cmd).len as usize;
        let avail = (cmd_len as usize).saturating_sub(CMD_HDR);
        if declared > avail || declared < FIXED {
            pr_err!(
                "bifrost_guest: LOAD_PROG invalid length declared={} avail={}\n",
                declared,
                avail
            );
            return -(bindings::EINVAL as i32);
        }

        let base = (cmd as *const u8).add(CMD_HDR);
        let mut off = 0usize;
        let limit = declared;

        let need = |off: usize, n: usize, limit: usize| -> bool {
            off.checked_add(n).map_or(false, |end| end <= limit)
        };
        if !need(off, 4, limit) {
            return -(bindings::EINVAL as i32);
        }
        let num_maps = *(base.add(off) as *const u32) as usize;
        off += 4 + 32;
        if !need(off, 4, limit) {
            return -(bindings::EINVAL as i32);
        }
        let flags = *(base.add(off) as *const u32);
        off += 4;
        let probe_type = (flags & 0xff) as u8;

        match probe_type {
            PROBE_TYPE_UPROBE | PROBE_TYPE_URETPROBE => {
                if !need(off, 4, limit) {
                    return -(bindings::EINVAL as i32);
                }
                let path_len = *(base.add(off) as *const u32) as usize;
                off += 4;
                if path_len > 256 || !need(off, path_len, limit) {
                    return -(bindings::EINVAL as i32);
                }
                off += path_len;
                if !need(off, 8, limit) {
                    return -(bindings::EINVAL as i32);
                }
                off += 8;
            }
            PROBE_TYPE_UPROBE_BY_SYM | PROBE_TYPE_URETPROBE_BY_SYM => {
                if !need(off, 4, limit) {
                    return -(bindings::EINVAL as i32);
                }
                let bn_len = *(base.add(off) as *const u32) as usize;
                off += 4;
                if bn_len == 0 || bn_len > 64 || !need(off, bn_len, limit) {
                    return -(bindings::EINVAL as i32);
                }
                off += bn_len;
                if !need(off, 4, limit) {
                    return -(bindings::EINVAL as i32);
                }
                let sym_len = *(base.add(off) as *const u32) as usize;
                off += 4;
                if sym_len == 0 || sym_len > 256 || !need(off, sym_len, limit) {
                    return -(bindings::EINVAL as i32);
                }
                off += sym_len;
            }
            PROBE_TYPE_USDT => {
                if !need(off, 4, limit) {
                    return -(bindings::EINVAL as i32);
                }
                let bn_len = *(base.add(off) as *const u32) as usize;
                off += 4;
                if bn_len == 0 || bn_len > 64 || !need(off, bn_len, limit) {
                    return -(bindings::EINVAL as i32);
                }
                off += bn_len;
                if !need(off, 4, limit) {
                    return -(bindings::EINVAL as i32);
                }
                let prov_len = *(base.add(off) as *const u32) as usize;
                off += 4;
                if prov_len == 0 || prov_len > 64 || !need(off, prov_len, limit) {
                    return -(bindings::EINVAL as i32);
                }
                off += prov_len;
                if !need(off, 4, limit) {
                    return -(bindings::EINVAL as i32);
                }
                let probe_len = *(base.add(off) as *const u32) as usize;
                off += 4;
                if probe_len == 0 || probe_len > 256 || !need(off, probe_len, limit) {
                    return -(bindings::EINVAL as i32);
                }
                off += probe_len;
            }
            _ => {}
        }

        if num_maps > 8 {
            pr_err!("bifrost_guest: LOAD_PROG num_maps {} exceeds driver cap 8\n", num_maps);
            return -(bindings::EINVAL as i32);
        }
        let map_bytes = match num_maps.checked_mul(MAP_DEF_SIZE) {
            Some(v) => v,
            None => return -(bindings::EINVAL as i32),
        };
        if !need(off, map_bytes, limit) {
            return -(bindings::EINVAL as i32);
        }
        off += map_bytes;

        if !need(off, 4, limit) {
            return -(bindings::EINVAL as i32);
        }
        let num_insns = *(base.add(off) as *const u32) as usize;
        off += 4;
        let insn_bytes = match num_insns.checked_mul(INSN_SIZE) {
            Some(v) => v,
            None => return -(bindings::EINVAL as i32),
        };
        if !need(off, insn_bytes, limit) {
            return -(bindings::EINVAL as i32);
        }

        let insns = base.add(off) as *const BpfInsn;
        let mut idx = 0usize;
        while idx < num_insns {
            let insn = &*insns.add(idx);
            if insn.code == BPF_LD_IMM64 && insn.src_reg() == BPF_PSEUDO_MAP_FD {
                if idx + 1 >= num_insns {
                    pr_err!("bifrost_guest: LOAD_PROG ldimm64 at final insn {}\n", idx);
                    return -(bindings::EINVAL as i32);
                }
                idx += 2;
            } else {
                idx += 1;
            }
        }
        off += insn_bytes;

        if !need(off, 4, limit) {
            return -(bindings::EINVAL as i32);
        }
        let num_relocs = *(base.add(off) as *const u32) as usize;
        off += 4;
        for _ in 0..num_relocs {
            if !need(off, 5, limit) {
                return -(bindings::EINVAL as i32);
            }
            let insn_idx = *(base.add(off) as *const u32) as usize;
            off += 4;
            let name_len = *base.add(off) as usize;
            off += 1;
            if name_len == 0 || name_len >= 256 || !need(off, name_len, limit) {
                return -(bindings::EINVAL as i32);
            }
            if insn_idx >= num_insns {
                return -(bindings::EINVAL as i32);
            }
            off += name_len;
        }
        0
    }
}
