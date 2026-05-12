// SPDX-License-Identifier: GPL-2.0
// drivers/bifrost/record_writer.rs
//
// Bounds-checked writer for SHMEM record buffers.  Used by
// push_agg_snapshot, push_symtab_snapshot, and the SHMEM
// publish helpers to construct length-prefixed records into
// raw `*mut u8` buffers without overflowing the reserved
// SHMEM_RECORD_MAX_PAYLOAD ceiling.
//
// Every write returns `bool`: `true` on success, `false` if the
// write would have exceeded the limit (in which case the writer
// is left at the same offset so the caller can either retry or
// emit a partial/error record).
//
// `pub(crate)` keeps the type module-private to the bifrost
// driver crate; sibling files (push_*, send_shmem_init, etc.)
// can use it once we extract them.

/// Note: `off` is `pub(crate)` because the existing callers
/// (push_agg_snapshot, push_symtab_snapshot) treat it as both a
/// progress cursor *and* a checkpoint they roll back to on error
/// — see the `writer.off = chk;` rollback pattern in
/// push_agg_snapshot's per-entry loop.  Making it private would
/// require introducing a `Checkpoint` type and `restore()` API.
pub(crate) struct RecordWriter {
    base: *mut u8,
    pub(crate) off: usize,
    limit: usize,
}

impl RecordWriter {
    pub(crate) fn new(base: *mut u8, limit: usize) -> Self {
        Self {
            base,
            off: 0,
            limit,
        }
    }

    pub(crate) fn write_u32(&mut self, val: u32) -> bool {
        if self.off + 4 > self.limit {
            return false;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                &val as *const u32 as *const u8,
                self.base.add(self.off),
                4,
            );
        }
        self.off += 4;
        true
    }

    pub(crate) fn write_i32(&mut self, val: i32) -> bool {
        self.write_u32(val as u32)
    }

    pub(crate) fn write_u64(&mut self, val: u64) -> bool {
        if self.off + 8 > self.limit {
            return false;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                &val as *const u64 as *const u8,
                self.base.add(self.off),
                8,
            );
        }
        self.off += 8;
        true
    }

    /// Write a raw byte slice — used for length-prefixed key bodies
    /// in push_agg_snapshot's variable-width entries.
    pub(crate) fn write_bytes(&mut self, src: &[u8]) -> bool {
        if self.off + src.len() > self.limit {
            return false;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), self.base.add(self.off), src.len());
        }
        self.off += src.len();
        true
    }

    /// Overwrite a u32 at a previously-written offset. Used for
    /// patching count fields after the body length is known.
    pub(crate) fn poke_u32(&mut self, off: usize, val: u32) -> bool {
        if off + 4 > self.limit {
            return false;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(&val as *const u32 as *const u8, self.base.add(off), 4);
        }
        true
    }
}
