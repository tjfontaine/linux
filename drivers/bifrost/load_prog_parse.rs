// SPDX-License-Identifier: GPL-2.0
// Bounded parser for direct LOAD_PROG command payloads.
//
// The parser is the single source of truth for the LOAD_PROG byte layout.
// It walks the command body, validates every read against the declared
// length, and returns a `LoadProgLayout` containing the offsets, counts,
// and extracted trailer strings the dispatch needs. The dispatch in
// `bifrost.rs` consumes that struct exclusively — no pointer-arithmetic
// re-derivation of trailer boundaries lives in the dispatch path.

use kernel::bindings;
use kernel::ffi::c_int;
use kernel::prelude::*;

use crate::bpf_consts::{BPF_LD_IMM64, BPF_PSEUDO_MAP_FD};
use crate::types::{
    read_u32_le_unaligned, read_u64_le_unaligned, BifrostCmd, BpfInsn, MapDef,
    BPF_INSN_WIRE_SIZE, MAP_DEF_WIRE_SIZE,
};
use crate::wire::{
    PROBE_TYPE_UPROBE, PROBE_TYPE_UPROBE_BY_SYM, PROBE_TYPE_URETPROBE, PROBE_TYPE_URETPROBE_BY_SYM,
    PROBE_TYPE_USDT,
};

/// Caps mirroring the historical inline scratch buffers. Bumping any of
/// these requires bumping the matching field in `LoadProgLayout`.
pub(crate) const UPROBE_PATH_MAX: usize = 256;
pub(crate) const UPROBE_BASENAME_MAX: usize = 64;
pub(crate) const UPROBE_SYMBOL_MAX: usize = 256;
pub(crate) const UPROBE_PROVIDER_MAX: usize = 64;
/// Driver cap on per-program maps; checked here so the dispatch never
/// has to re-check.
pub(crate) const MAX_MAPS_PER_PROG: usize = 8;

/// Validated offsets, lengths, and extracted strings for one LOAD_PROG
/// command body. Every byte offset is relative to `payload_base`, the
/// first byte after `BifrostCmd::data` (i.e. after `op` + `len`).
#[repr(C)]
pub(crate) struct LoadProgLayout {
    pub(crate) num_maps: u32,
    pub(crate) target_name: [u8; 32],
    pub(crate) flags: u32,
    pub(crate) probe_type: u8,

    /// Byte offset of the MapDef array from `payload_base`.
    pub(crate) maps_off: usize,
    /// Byte offset of the `num_insns` u32 from `payload_base`.
    pub(crate) insns_header_off: usize,
    /// Byte offset of the first eBPF instruction from `payload_base`.
    pub(crate) insns_off: usize,
    pub(crate) num_insns: u32,
    /// Byte offset of the `num_relocs` u32 from `payload_base`.
    pub(crate) relocs_off: usize,
    pub(crate) num_relocs: u32,

    /// Uprobe trailer scratch. `*_len = 0` ⇒ field not present in this
    /// probe shape. `uprobe_path_buf` is NUL-padded for callers that
    /// hand it straight to a C-string consumer.
    pub(crate) uprobe_path_buf: [u8; UPROBE_PATH_MAX + 1],
    pub(crate) uprobe_path_len: usize,
    pub(crate) uprobe_basename: [u8; UPROBE_BASENAME_MAX + 1],
    pub(crate) uprobe_basename_len: usize,
    pub(crate) uprobe_symbol: [u8; UPROBE_SYMBOL_MAX + 1],
    pub(crate) uprobe_symbol_len: usize,
    pub(crate) uprobe_provider: [u8; UPROBE_PROVIDER_MAX + 1],
    pub(crate) uprobe_provider_len: usize,
    pub(crate) uprobe_file_offset: u64,
}

impl LoadProgLayout {
    fn zeroed() -> Self {
        Self {
            num_maps: 0,
            target_name: [0; 32],
            flags: 0,
            probe_type: 0,
            maps_off: 0,
            insns_header_off: 0,
            insns_off: 0,
            num_insns: 0,
            relocs_off: 0,
            num_relocs: 0,
            uprobe_path_buf: [0; UPROBE_PATH_MAX + 1],
            uprobe_path_len: 0,
            uprobe_basename: [0; UPROBE_BASENAME_MAX + 1],
            uprobe_basename_len: 0,
            uprobe_symbol: [0; UPROBE_SYMBOL_MAX + 1],
            uprobe_symbol_len: 0,
            uprobe_provider: [0; UPROBE_PROVIDER_MAX + 1],
            uprobe_provider_len: 0,
            uprobe_file_offset: 0,
        }
    }
}

/// Parse and validate a LOAD_PROG command. Returns the parsed layout on
/// success or a negative errno on any malformed input. Every read goes
/// through the local `need()` bound check; every multiplication is
/// `checked_mul`. The parser never allocates and is `no_std`-clean.
pub(crate) unsafe fn parse_load_prog(
    cmd: *const BifrostCmd,
    cmd_len: u32,
) -> Result<LoadProgLayout, c_int> {
    unsafe {
        const CMD_HDR: usize = core::mem::size_of::<BifrostCmd>();
        const FIXED: usize = 4 + 32 + 4;

        if cmd.is_null() || (cmd_len as usize) < CMD_HDR {
            return Err(-(bindings::EINVAL as i32));
        }
        // `BifrostCmd` header is naturally 4-aligned and lives at
        // the start of the kmalloc-backed control buffer; the `len`
        // field load here is the only typed read against `cmd`
        // itself. Everything after the header (the payload) is
        // accessed through `read_u32_le_unaligned` /
        // `read_u64_le_unaligned` / `{MapDef, BpfInsn}::read_le_unaligned`
        // so variable-length string trailers cannot leave a later
        // wide field on an odd offset.
        let declared = (*cmd).len as usize;
        let avail = (cmd_len as usize).saturating_sub(CMD_HDR);
        if declared > avail || declared < FIXED {
            pr_err!(
                "bifrost_guest: LOAD_PROG invalid length declared={} avail={}\n",
                declared,
                avail
            );
            return Err(-(bindings::EINVAL as i32));
        }

        let base = (cmd as *const u8).add(CMD_HDR);
        let limit = declared;
        let need = |off: usize, n: usize| -> bool {
            off.checked_add(n).map_or(false, |end| end <= limit)
        };

        let mut layout = LoadProgLayout::zeroed();

        // num_maps + target_name + flags
        if !need(0, FIXED) {
            return Err(-(bindings::EINVAL as i32));
        }
        layout.num_maps = read_u32_le_unaligned(base);
        core::ptr::copy_nonoverlapping(base.add(4), layout.target_name.as_mut_ptr(), 32);
        layout.flags = read_u32_le_unaligned(base.add(4 + 32));
        layout.probe_type = (layout.flags & 0xff) as u8;

        let mut off = FIXED;

        // Per-probe trailer.
        match layout.probe_type {
            PROBE_TYPE_UPROBE | PROBE_TYPE_URETPROBE => {
                if !need(off, 4) {
                    return Err(-(bindings::EINVAL as i32));
                }
                let path_len = read_u32_le_unaligned(base.add(off)) as usize;
                off += 4;
                if path_len > UPROBE_PATH_MAX || !need(off, path_len) {
                    pr_err!(
                        "bifrost_guest: LOAD_PROG uprobe path_len {} out of range\n",
                        path_len
                    );
                    return Err(-(bindings::EINVAL as i32));
                }
                core::ptr::copy_nonoverlapping(
                    base.add(off),
                    layout.uprobe_path_buf.as_mut_ptr(),
                    path_len,
                );
                layout.uprobe_path_buf[path_len] = 0;
                layout.uprobe_path_len = path_len;
                off += path_len;
                if !need(off, 8) {
                    return Err(-(bindings::EINVAL as i32));
                }
                // `path_len` is attacker-controlled, so this u64 lands
                // on `4+32+4+4+path_len` — odd whenever path_len is
                // odd. The unaligned helper byte-copies through a
                // stack array.
                layout.uprobe_file_offset = read_u64_le_unaligned(base.add(off));
                off += 8;
            }
            PROBE_TYPE_UPROBE_BY_SYM | PROBE_TYPE_URETPROBE_BY_SYM => {
                if !need(off, 4) {
                    return Err(-(bindings::EINVAL as i32));
                }
                let bn_len = read_u32_le_unaligned(base.add(off)) as usize;
                off += 4;
                if bn_len == 0 || bn_len > UPROBE_BASENAME_MAX || !need(off, bn_len) {
                    pr_err!(
                        "bifrost_guest: LOAD_PROG uprobe-by-sym bn_len {} out of range\n",
                        bn_len
                    );
                    return Err(-(bindings::EINVAL as i32));
                }
                core::ptr::copy_nonoverlapping(
                    base.add(off),
                    layout.uprobe_basename.as_mut_ptr(),
                    bn_len,
                );
                layout.uprobe_basename[bn_len] = 0;
                layout.uprobe_basename_len = bn_len;
                off += bn_len;
                if !need(off, 4) {
                    return Err(-(bindings::EINVAL as i32));
                }
                let sym_len = read_u32_le_unaligned(base.add(off)) as usize;
                off += 4;
                if sym_len == 0 || sym_len > UPROBE_SYMBOL_MAX || !need(off, sym_len) {
                    pr_err!(
                        "bifrost_guest: LOAD_PROG uprobe-by-sym sym_len {} out of range\n",
                        sym_len
                    );
                    return Err(-(bindings::EINVAL as i32));
                }
                core::ptr::copy_nonoverlapping(
                    base.add(off),
                    layout.uprobe_symbol.as_mut_ptr(),
                    sym_len,
                );
                layout.uprobe_symbol[sym_len] = 0;
                layout.uprobe_symbol_len = sym_len;
                off += sym_len;
            }
            PROBE_TYPE_USDT => {
                if !need(off, 4) {
                    return Err(-(bindings::EINVAL as i32));
                }
                let bn_len = read_u32_le_unaligned(base.add(off)) as usize;
                off += 4;
                if bn_len == 0 || bn_len > UPROBE_BASENAME_MAX || !need(off, bn_len) {
                    pr_err!(
                        "bifrost_guest: LOAD_PROG usdt bn_len {} out of range\n",
                        bn_len
                    );
                    return Err(-(bindings::EINVAL as i32));
                }
                core::ptr::copy_nonoverlapping(
                    base.add(off),
                    layout.uprobe_basename.as_mut_ptr(),
                    bn_len,
                );
                layout.uprobe_basename[bn_len] = 0;
                layout.uprobe_basename_len = bn_len;
                off += bn_len;
                if !need(off, 4) {
                    return Err(-(bindings::EINVAL as i32));
                }
                let prov_len = read_u32_le_unaligned(base.add(off)) as usize;
                off += 4;
                if prov_len == 0 || prov_len > UPROBE_PROVIDER_MAX || !need(off, prov_len) {
                    pr_err!(
                        "bifrost_guest: LOAD_PROG usdt prov_len {} out of range\n",
                        prov_len
                    );
                    return Err(-(bindings::EINVAL as i32));
                }
                core::ptr::copy_nonoverlapping(
                    base.add(off),
                    layout.uprobe_provider.as_mut_ptr(),
                    prov_len,
                );
                layout.uprobe_provider[prov_len] = 0;
                layout.uprobe_provider_len = prov_len;
                off += prov_len;
                if !need(off, 4) {
                    return Err(-(bindings::EINVAL as i32));
                }
                let probe_len = read_u32_le_unaligned(base.add(off)) as usize;
                off += 4;
                if probe_len == 0 || probe_len > UPROBE_SYMBOL_MAX || !need(off, probe_len) {
                    pr_err!(
                        "bifrost_guest: LOAD_PROG usdt probe_len {} out of range\n",
                        probe_len
                    );
                    return Err(-(bindings::EINVAL as i32));
                }
                core::ptr::copy_nonoverlapping(
                    base.add(off),
                    layout.uprobe_symbol.as_mut_ptr(),
                    probe_len,
                );
                layout.uprobe_symbol[probe_len] = 0;
                layout.uprobe_symbol_len = probe_len;
                off += probe_len;
            }
            _ => {}
        }

        // MapDef array. We only validate length and stash an offset
        // here — dispatch reads MapDef fields via
        // `MapDef::read_le_unaligned` because variable-length string
        // trailers above can leave `maps_off` on an odd byte.
        if (layout.num_maps as usize) > MAX_MAPS_PER_PROG {
            pr_err!(
                "bifrost_guest: LOAD_PROG num_maps {} exceeds driver cap {}\n",
                layout.num_maps,
                MAX_MAPS_PER_PROG
            );
            return Err(-(bindings::EINVAL as i32));
        }
        let map_bytes = match (layout.num_maps as usize).checked_mul(MAP_DEF_WIRE_SIZE) {
            Some(v) => v,
            None => return Err(-(bindings::EINVAL as i32)),
        };
        if !need(off, map_bytes) {
            return Err(-(bindings::EINVAL as i32));
        }
        layout.maps_off = off;
        off += map_bytes;

        // Instruction header + body.
        if !need(off, 4) {
            return Err(-(bindings::EINVAL as i32));
        }
        layout.insns_header_off = off;
        layout.num_insns = read_u32_le_unaligned(base.add(off));
        off += 4;
        let insn_bytes = match (layout.num_insns as usize).checked_mul(BPF_INSN_WIRE_SIZE) {
            Some(v) => v,
            None => return Err(-(bindings::EINVAL as i32)),
        };
        if !need(off, insn_bytes) {
            return Err(-(bindings::EINVAL as i32));
        }
        layout.insns_off = off;

        // LD_IMM64 pseudo-fd insns occupy two slots; the second slot
        // must exist. Walk to catch a truncated trailing pair.
        let insns_base = base.add(off);
        let mut idx = 0usize;
        while idx < layout.num_insns as usize {
            let insn = BpfInsn::read_le_unaligned(insns_base.add(idx * BPF_INSN_WIRE_SIZE));
            if insn.code == BPF_LD_IMM64 && insn.src_reg() == BPF_PSEUDO_MAP_FD {
                if idx + 1 >= layout.num_insns as usize {
                    pr_err!("bifrost_guest: LOAD_PROG ldimm64 at final insn {}\n", idx);
                    return Err(-(bindings::EINVAL as i32));
                }
                idx += 2;
            } else {
                idx += 1;
            }
        }
        off += insn_bytes;

        // Reloc trailer.
        if !need(off, 4) {
            return Err(-(bindings::EINVAL as i32));
        }
        layout.relocs_off = off;
        layout.num_relocs = read_u32_le_unaligned(base.add(off));
        off += 4;
        for _ in 0..layout.num_relocs as usize {
            if !need(off, 5) {
                return Err(-(bindings::EINVAL as i32));
            }
            let insn_idx = read_u32_le_unaligned(base.add(off)) as usize;
            off += 4;
            let name_len = *base.add(off) as usize;
            off += 1;
            if name_len == 0 || name_len >= 256 || !need(off, name_len) {
                return Err(-(bindings::EINVAL as i32));
            }
            if insn_idx >= layout.num_insns as usize {
                return Err(-(bindings::EINVAL as i32));
            }
            off += name_len;
        }

        Ok(layout)
    }
}
