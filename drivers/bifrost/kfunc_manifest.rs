// SPDX-License-Identifier: GPL-2.0
// Runtime validation for the Rust/C Bifrost kfunc helper manifest.

use kernel::bindings;
use kernel::prelude::*;

// kfunc manifest expected on the C side.  Each entry is
// (name, canonical_signature_string).  bifrost_helpers.c carries the
// identical list as `BIFROST_KFUNC_MANIFEST`; module init validates
// they match by computing the same djb2 hash on both sides.
//
// Adding a new bifrost_helper_*: append here AND in bifrost_helpers.c.
// Order matters — the hash mixes entries in array order.
//
// Changing a signature: update the sig string in both places.  Module
// init refuses to load on mismatch with a named pr_err so silent
// Rust↔C ABI drift can't ship.
struct KfuncDecl {
    name: &'static [u8],
    sig: &'static [u8],
}

const BIFROST_KFUNC_EXPECTED: &[KfuncDecl] = &[
    KfuncDecl {
        name: b"bifrost_helper_find_task_by_comm",
        sig: b"struct task_struct *(const unsigned char *, unsigned int)",
    },
    KfuncDecl {
        name: b"bifrost_helper_put_task_struct",
        sig: b"void (struct task_struct *)",
    },
    KfuncDecl {
        name: b"bifrost_helper_resolve_symbol",
        sig: b"int (struct file *, const u8 *, u32, u64 *, u64 *)",
    },
    KfuncDecl {
        name: b"bifrost_helper_resolve_usdt",
        sig: b"int (struct file *, const u8 *, u32, const u8 *, u32, u64 *, u64 *)",
    },
    KfuncDecl {
        name: b"bifrost_helper_emit_symtab",
        sig: b"int (struct file *, u8 *, u32, u32, u32 *)",
    },
    KfuncDecl {
        name: b"bifrost_helper_emit_symtab_for_file",
        sig: b"int (struct file *, u8 *, u32, u32, u32 *)",
    },
    KfuncDecl {
        name: b"bifrost_helper_for_each_vma_file",
        sig: b"void (struct task_struct *, void (*)(struct file *, void *), void *)",
    },
];

const BIFROST_KFUNC_EXPECTED_HASH: u32 = bifrost_kfunc_expected_hash();
const BIFROST_KFUNC_EXPECTED_LEN: u32 = BIFROST_KFUNC_EXPECTED.len() as u32;

extern "C" {
    /// Manifest hash exported by bifrost_helpers.c.  Mismatch
    /// vs `BIFROST_KFUNC_EXPECTED_HASH` ⇒ Rust extern decls disagree
    /// with the live C signatures; refuse module load.
    fn bifrost_kfunc_manifest_hash() -> u32;
    /// Number of entries in the C-side manifest.  A length mismatch
    /// surfaces independently of the hash so the diagnostic names
    /// the specific failure mode.
    fn bifrost_kfunc_manifest_len() -> u32;
}

pub(crate) fn validate() -> Result<()> {
    // kfunc manifest validation.  Refuses to load if
    // bifrost_helpers.c's exported manifest disagrees with the
    // Rust extern decls' expected manifest.  Two checks: array
    // length first (clearer diagnostic on add/remove drift),
    // then the djb2 hash (catches signature-string drift).  A
    // clean tree never trips this — scripts/check-kfunc-manifest.sh
    // gates merges on the same comparison at build time — so
    // hitting the runtime check is a hard signal that the C and
    // Rust sides got out of sync via a path that bypassed the
    // lint (e.g., a libkrunfw patch landed without the matching
    // Rust update).
    let c_len = unsafe { bifrost_kfunc_manifest_len() };
    if c_len != BIFROST_KFUNC_EXPECTED_LEN {
        pr_err!(
            "bifrost_guest: kfunc manifest length mismatch (C={}, Rust={}); refusing module load.  bifrost_helpers.c and bifrost.rs disagree on the kfunc surface — re-vendor wire.rs / re-run scripts/check-kfunc-manifest.sh.\n",
            c_len,
            BIFROST_KFUNC_EXPECTED_LEN
        );
        return Err(Error::from_errno(-(bindings::EINVAL as i32)));
    }
    let c_hash = unsafe { bifrost_kfunc_manifest_hash() };
    if c_hash != BIFROST_KFUNC_EXPECTED_HASH {
        pr_err!(
            "bifrost_guest: kfunc manifest hash mismatch (C=0x{:08x}, Rust=0x{:08x}); refusing module load.  A bifrost_helper_* signature in bifrost_helpers.c disagrees with the matching extern decl in bifrost.rs.  Likely cause: signature changed on one side without the other.  Run scripts/check-kfunc-manifest.sh to see which entry drifted.\n",
            c_hash,
            BIFROST_KFUNC_EXPECTED_HASH
        );
        return Err(Error::from_errno(-(bindings::EINVAL as i32)));
    }
    pr_info!(
        "bifrost_guest: kfunc manifest OK ({} entries, hash=0x{:08x})\n",
        c_len,
        c_hash
    );
    Ok(())
}

/// Const-fn djb2 — same algorithm bifrost_helpers.c uses.  `h = 5381;
/// for each byte b: h = (h * 33) + b`, wrapping mod 2^32.  Const-eval
/// means the expected hash is computed at compile time and the runtime
/// check is a single u32 compare.
const fn bifrost_kfunc_djb2_byte(h: u32, b: u8) -> u32 {
    h.wrapping_mul(33).wrapping_add(b as u32)
}

const fn bifrost_kfunc_djb2_bytes(mut h: u32, bytes: &[u8]) -> u32 {
    let mut i = 0;
    while i < bytes.len() {
        h = bifrost_kfunc_djb2_byte(h, bytes[i]);
        i += 1;
    }
    // Trailing NUL — matches the C side which mixes one extra `* 33`
    // after each name and each sig as a field separator.
    h.wrapping_mul(33)
}

const fn bifrost_kfunc_expected_hash() -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < BIFROST_KFUNC_EXPECTED.len() {
        h = bifrost_kfunc_djb2_bytes(h, BIFROST_KFUNC_EXPECTED[i].name);
        h = bifrost_kfunc_djb2_bytes(h, BIFROST_KFUNC_EXPECTED[i].sig);
        i += 1;
    }
    h
}
