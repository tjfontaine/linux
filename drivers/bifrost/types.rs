// SPDX-License-Identifier: GPL-2.0
// drivers/bifrost/types.rs
//
// Wire-format struct types shared with the host across the
// VQ_CTRL / LOAD_PROG path:
//   - `BifrostCmd`: virtio cmd header (op + len + inline data).
//   - `MapDef`: per-map LOAD_PROG payload entry (20 numeric bytes
//     mirroring the host emit side at
//     `host/bifrost/src/cli/wrapper.rs::MapDecl`, plus a 32-byte
//     name on the host side that's stripped at the libkrun edge).
//   - `BpfInsn`: in-memory eBPF instruction (8 bytes, mirrors
//     `struct bpf_insn` from include/uapi/linux/bpf.h).
//
// All `#[repr(C)]` so the layout is stable and compatible with the
// host's emit code.  Fields are `pub(crate)` so sibling modules
// in this driver can access them without going through getters.

#[repr(C)]
pub(crate) struct BifrostCmd {
    pub(crate) op: u32,
    pub(crate) len: u32,
    pub(crate) data: [u8; 0],
}

/// Map definition received from host in LOAD_PROG payload (20 bytes).
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct MapDef {
    pub(crate) map_type: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) fake_fd: i32,
    /// Bit-packed: low byte = agg_kind (0=count/sum, 1=min, 2=max,
    /// 3=avg). Snapshot worker dispatches the appropriate per-cpu
    /// reduce shim. Other bits reserved.
    pub(crate) flags: u32,
}

/// BPF instruction layout (8 bytes).
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct BpfInsn {
    pub(crate) code: u8,
    /// `dst_reg:4 | src_reg:4`
    pub(crate) regs: u8,
    pub(crate) off: i16,
    pub(crate) imm: i32,
}

impl BpfInsn {
    pub(crate) fn src_reg(&self) -> u8 {
        self.regs >> 4
    }
    pub(crate) fn set_src_reg(&mut self, r: u8) {
        self.regs = (self.regs & 0x0f) | (r << 4);
    }
}
