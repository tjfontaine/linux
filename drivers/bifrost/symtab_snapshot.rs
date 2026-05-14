// SPDX-License-Identifier: GPL-2.0
// SHMEM side-channel snapshots for user binary symbol tables.

use kernel::bindings;
use kernel::ffi::{c_int, c_void};
use kernel::prelude::*;

use crate::record_writer::RecordWriter;
use crate::wire::{SHMEM_DROP_CLASS_STKSTR, SYM_TABLE_PROBE_MAGIC};

extern "C" {
    /// C helper: pack the ELF function-symbol table of `file` into
    /// `buf` for the host's gustack symbolicator.
    fn bifrost_helper_emit_symtab_for_file(
        file: *mut bindings::file,
        buf: *mut u8,
        buf_size: u32,
        sym_idx_start: u32,
        sym_idx_next: *mut u32,
    ) -> c_int;

    /// W7: class-aware reserve. Symtab pushes attribute drops to
    /// the STKSTR class so the host can see when symbolication
    /// metadata is starving the ring.
    fn bifrost_shmem_reserve_kernel_class(size: u32, class: u32) -> *mut c_void;
}

/// Trampoline used by `bifrost_helper_for_each_vma_file`'s callback hook.
/// Lets the C helper iterate VMAs while the symtab push stays on the Rust
/// side where SHMEM reserve/submit plumbing already lives.
pub(crate) unsafe extern "C" fn push_symtab_snapshot_cb(
    file: *mut bindings::file,
    _ctx: *mut c_void,
) {
    unsafe {
        push_symtab_snapshot(file);
    }
}

/// Push the ELF function-symbol table of `file` to the host as a
/// side-channel record.  Used at uprobe register time so gustack output
/// can symbolicate frames without reading the binary from a host-mirrored
/// rootfs.
unsafe fn push_symtab_snapshot(file: *mut bindings::file) {
    /// Worst-case body size: 64 KB minus room for the SHM record header.
    const MAX_BODY: usize = 64 * 1024 - 256;
    /// Defensive loop cap for very large symtabs or helper bugs.
    const MAX_CHUNKS: usize = 16;

    if file.is_null() {
        return;
    }
    unsafe {
        let mut sym_idx: u32 = 0;
        for chunk in 0..MAX_CHUNKS {
            let rec = bifrost_shmem_reserve_kernel_class(MAX_BODY as u32, SHMEM_DROP_CLASS_STKSTR)
                as *mut u8;
            if rec.is_null() {
                return;
            }

            let mut writer = RecordWriter::new(rec, MAX_BODY);
            writer.write_u32(0);
            writer.write_u32(SYM_TABLE_PROBE_MAGIC);
            writer.write_u64(bindings::ktime_get_mono_fast_ns());
            writer.write_u64(0);
            let body_off = writer.off;
            let body_buf = rec.add(body_off);
            let body_avail = MAX_BODY.saturating_sub(body_off) as u32;

            let mut sym_idx_next: u32 = 0;
            let written = bifrost_helper_emit_symtab_for_file(
                file,
                body_buf,
                body_avail,
                sym_idx,
                &mut sym_idx_next as *mut u32,
            );
            bindings::bifrost_shmem_submit_kernel(rec as *mut c_void);
            if written < 0 {
                pr_err!(
                    "bifrost_guest: emit_symtab_for_file chunk[{}] failed: {}\n",
                    chunk,
                    written
                );
                return;
            }
            if sym_idx_next == 0 {
                return;
            }
            if sym_idx_next <= sym_idx {
                pr_err!(
                    "bifrost_guest: emit_symtab_for_file chunk[{}] no progress (idx={} -> {})\n",
                    chunk,
                    sym_idx,
                    sym_idx_next
                );
                return;
            }
            sym_idx = sym_idx_next;
        }
        pr_err!(
            "bifrost_guest: emit_symtab_for_file hit MAX_CHUNKS ({}) - symtab tail dropped\n",
            MAX_CHUNKS
        );
    }
}
