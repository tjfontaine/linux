// SPDX-License-Identifier: GPL-2.0
// drivers/bifrost/types.rs
//
// Wire-format struct types shared with the host across the
// VQ_CTRL / LOAD_PROG path:
//   - `BifrostCmd`: virtio cmd header (op + len + inline data).
//   - `MapDef`: per-map LOAD_PROG payload entry (24 numeric bytes
//     mirroring the host emit side at
//     `host/bifrost/src/cli/wrapper.rs::MapDecl`, plus a 32-byte
//     name on the host side that's stripped at the libkrun edge).
//   - `BpfInsn`: in-memory eBPF instruction (8 bytes, mirrors
//     `struct bpf_insn` from include/uapi/linux/bpf.h).
//
// All `#[repr(C)]` so the layout is stable and compatible with the
// host's emit code.  Fields are `pub(crate)` so sibling modules
// in this driver can access them without going through getters.
//
// Wire byte order is little-endian throughout (the host CLI emits
// LE and both supported guest architectures are LE). The wire
// payload starts immediately after the 8-byte `BifrostCmd` header
// inside a `kmalloc`-backed control buffer. The 8-byte header is
// 8-aligned, but the variable-length string trailers that follow
// `flags` can land any subsequent fixed-width field on an odd
// offset (e.g. a 13-byte uprobe path leaves the `u64 file_offset`
// at offset 4+32+4+4+13 = 57). The aligned typed reads the
// previous parser used were therefore undefined behavior on the
// kernel-build target. Replace with the `read_le_*` /
// `MapDef::read_le_unaligned` / `BpfInsn::read_le_unaligned`
// helpers below, which copy bytes through a stack array and
// recompose via `from_le_bytes`. They compile to a `memcpy + bswap?`
// pair the JIT collapses, and they are correct for any byte
// alignment.

#[repr(C)]
pub(crate) struct BifrostCmd {
    pub(crate) op: u32,
    pub(crate) len: u32,
    pub(crate) data: [u8; 0],
}

/// Map definition received from host in LOAD_PROG payload (24 bytes).
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

/// On-wire size of [`MapDef`]. Pinned here rather than relying on
/// `size_of::<MapDef>()` so the parser and dispatch sites stay in
/// lockstep with the host emit width if the struct ever gains
/// padding.
pub(crate) const MAP_DEF_WIRE_SIZE: usize = 24;

/// On-wire size of [`BpfInsn`]. Same rationale as
/// [`MAP_DEF_WIRE_SIZE`].
pub(crate) const BPF_INSN_WIRE_SIZE: usize = 8;

impl MapDef {
    /// Decode a [`MapDef`] from a possibly-unaligned wire pointer.
    ///
    /// Caller must guarantee `p..p+MAP_DEF_WIRE_SIZE` is readable.
    /// Bytes are interpreted little-endian regardless of host or
    /// guest endianness.
    #[inline]
    pub(crate) unsafe fn read_le_unaligned(p: *const u8) -> Self {
        let mut buf = [0u8; MAP_DEF_WIRE_SIZE];
        // SAFETY: caller asserts MAP_DEF_WIRE_SIZE bytes are readable.
        unsafe { core::ptr::copy_nonoverlapping(p, buf.as_mut_ptr(), MAP_DEF_WIRE_SIZE) };
        Self {
            map_type: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            key_size: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            value_size: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            max_entries: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            fake_fd: i32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
            flags: u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]),
        }
    }
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

    /// Decode a [`BpfInsn`] from a possibly-unaligned wire pointer.
    ///
    /// Caller must guarantee `p..p+BPF_INSN_WIRE_SIZE` is readable.
    #[inline]
    pub(crate) unsafe fn read_le_unaligned(p: *const u8) -> Self {
        let mut buf = [0u8; BPF_INSN_WIRE_SIZE];
        // SAFETY: caller asserts BPF_INSN_WIRE_SIZE bytes are readable.
        unsafe { core::ptr::copy_nonoverlapping(p, buf.as_mut_ptr(), BPF_INSN_WIRE_SIZE) };
        Self {
            code: buf[0],
            regs: buf[1],
            off: i16::from_le_bytes([buf[2], buf[3]]),
            imm: i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        }
    }

    /// Store a [`BpfInsn`] back through a possibly-unaligned wire
    /// pointer in little-endian byte order.
    ///
    /// Caller must guarantee `p..p+BPF_INSN_WIRE_SIZE` is writable.
    #[inline]
    pub(crate) unsafe fn write_le_unaligned(p: *mut u8, v: BpfInsn) {
        let off_bytes = v.off.to_le_bytes();
        let imm_bytes = v.imm.to_le_bytes();
        let buf = [
            v.code,
            v.regs,
            off_bytes[0],
            off_bytes[1],
            imm_bytes[0],
            imm_bytes[1],
            imm_bytes[2],
            imm_bytes[3],
        ];
        // SAFETY: caller asserts BPF_INSN_WIRE_SIZE bytes are writable.
        unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), p, BPF_INSN_WIRE_SIZE) };
    }
}

/// Read a little-endian `u32` from a possibly-unaligned pointer.
///
/// # Safety
/// `p..p+4` must be readable.
#[inline]
pub(crate) unsafe fn read_u32_le_unaligned(p: *const u8) -> u32 {
    let mut buf = [0u8; 4];
    unsafe { core::ptr::copy_nonoverlapping(p, buf.as_mut_ptr(), 4) };
    u32::from_le_bytes(buf)
}

/// Read a little-endian `u64` from a possibly-unaligned pointer.
///
/// # Safety
/// `p..p+8` must be readable.
#[inline]
pub(crate) unsafe fn read_u64_le_unaligned(p: *const u8) -> u64 {
    let mut buf = [0u8; 8];
    unsafe { core::ptr::copy_nonoverlapping(p, buf.as_mut_ptr(), 8) };
    u64::from_le_bytes(buf)
}
