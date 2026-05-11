// SPDX-License-Identifier: GPL-2.0
// drivers/bifrost/bpf_consts.rs
//
// BPF kernel-API constants used by the bifrost guest driver.
// These mirror values from `include/uapi/linux/bpf.h` and the
// kernel's BPF JIT layer; centralising them here keeps the
// magic-number table in one place and lets the proto-drift lint
// audit them against the host emit path.
//
// Map types come straight from `enum bpf_map_type` in the UAPI
// header.  We list only the variants the guest actually uses;
// extending the set is a one-line addition here plus a bifrost.rs
// import update.
//
// `BPF_LD_IMM64` (0x18) is the multi-insn 64-bit immediate-load
// opcode: the second u64 of the pair carries the upper 32 bits.
// `BPF_PSEUDO_MAP_FD` is the pseudo-fd marker that tells the
// verifier the immediate is a map handle (replaced by the
// real bpf_map* during reloc).

pub(crate) const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub(crate) const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
pub(crate) const BPF_MAP_TYPE_RINGBUF: u32 = 27;

pub(crate) const BPF_LD_IMM64: u8 = 0x18; // BPF_LD | BPF_DW | BPF_IMM
pub(crate) const BPF_PSEUDO_MAP_FD: u8 = 1;
