// SPDX-License-Identifier: GPL-2.0
// drivers/bifrost/shmem_layout.rs
//
// SHMEM region size + sub-region offsets used by the bifrost
// guest driver.  The values are compile-time constants; runtime
// publishing of the offsets/lengths happens via the in-region
// header at SHMEM_HDR_OFF (the host reads what the guest actually
// chose rather than relying on a duplicate set of constants).
//
// Mirror reference on the libkrun host side:
// `third_party/smolvm/libkrun/src/devices/src/virtio/bifrost/
// shmem/state.rs::shmem_hdr` — that submodule defines the byte
// offsets the host uses to read the publish slots, not the
// region layout itself.

/// SHMEM region size: 16 MB. vmalloc-backed so we sidestep the
/// MAX_PAGE_ORDER ceiling (alloc_pages above order=10/11 fails on
/// arm64 default configs). Per-page PFNs are ferried to the host.
pub(crate) const SHMEM_REGION_SIZE: usize = 16 * 1024 * 1024;
pub(crate) const SHMEM_N_PAGES: usize = SHMEM_REGION_SIZE / 4096;
/// Magic value the guest writes at SHMEM offset 0 immediately
/// before sending `SHMEM_INIT` so the host can confirm it sees
/// the same memory. ASCII 'BFSH' interpreted as little-endian.
pub(crate) const SHMEM_MAGIC: u32 = 0x48534642;
/// Layout version stored next to the magic. Bumped whenever the
/// header layout changes incompatibly.
pub(crate) const SHMEM_VERSION: u32 = 3;

/// Phase 3a SHMEM sub-region layout (offsets within the 16 MB
/// region, all 4 KB aligned). Kept in sync with the host's
/// `shmem_hdr` module — host reads the actual chosen offsets and
/// lengths from the in-region header rather than hardcoding.
pub(crate) const SHMEM_HDR_OFF: usize = 0;
pub(crate) const SHMEM_HDR_LEN: usize = 4096;
pub(crate) const SHMEM_RINGBUF_OFF: usize = SHMEM_HDR_LEN;
pub(crate) const SHMEM_RINGBUF_LEN: usize = 6 * 1024 * 1024; // 6 MB events
pub(crate) const SHMEM_BTF_OFF: usize = SHMEM_RINGBUF_OFF + SHMEM_RINGBUF_LEN;
pub(crate) const SHMEM_BTF_CAP: usize = 6 * 1024 * 1024; // 6 MB; vmlinux BTF is ~4.6 MB
pub(crate) const SHMEM_KSYMS_OFF: usize = SHMEM_BTF_OFF + SHMEM_BTF_CAP;
pub(crate) const SHMEM_KSYMS_CAP: usize = 2 * 1024 * 1024; // 2 MB; kallsyms is ~1.5 MB
pub(crate) const SHMEM_VMA_CACHE_OFF: usize = SHMEM_KSYMS_OFF + SHMEM_KSYMS_CAP;
pub(crate) const SHMEM_VMA_CACHE_LEN: usize = SHMEM_REGION_SIZE - SHMEM_VMA_CACHE_OFF;
const _: () = assert!(SHMEM_VMA_CACHE_OFF + SHMEM_VMA_CACHE_LEN == SHMEM_REGION_SIZE);
