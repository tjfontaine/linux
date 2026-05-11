// SPDX-License-Identifier: GPL-2.0
// drivers/bifrost/path_helpers.rs
//
// Path-manipulation helpers used by the bifrost guest driver.
// Initially this is just `path_basename`, extracted from bifrost.rs
// as the first step of the refactor roadmap's Phase 4 file split.
// `no_std` is inherited from the parent crate (drivers/bifrost/
// bifrost.rs), no need to declare it here.
//
// Tests for this module live in the host-side mirror at
// `host/bifrost/tests/path_basename_compat.rs` rather than inline:
// the kernel rust build cannot exercise `#[cfg(test)]` blocks
// (no cargo test under Kbuild), and the `assert_eq!` macro is
// `std`-only.

/// Extract the basename of a NUL-terminated path stored in a byte
/// buffer.  Returns the slice from the byte after the last `/` to the
/// first NUL or end-of-buffer, whichever comes first.  Used by the
/// uprobe path resolver to derive a `task->comm` candidate from a
/// requested binary path.
pub fn path_basename(buf: &[u8]) -> &[u8] {
    let mut end = buf.len();
    let mut last_slash: Option<usize> = None;
    for i in 0..buf.len() {
        if buf[i] == 0 {
            end = i;
            break;
        }
        if buf[i] == b'/' {
            last_slash = Some(i);
        }
    }
    let start = last_slash.map(|i| i + 1).unwrap_or(0);
    &buf[start..end]
}
