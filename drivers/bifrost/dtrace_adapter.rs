// SPDX-License-Identifier: GPL-2.0
//
// Linux KernelAdapter — bridges the no_std lowering crate
// (`crates/bifrost-dtrace-lower`) to the bifrost driver's existing
// kfunc / BPF surface.
//
// ## Source-of-truth pinning
//
// The trait this file implements is owned by
// `crates/bifrost-dtrace-lower/src/adapter.rs` in the root repo. The
// kernel build cannot pull a workspace crate (it runs inside a
// krunvm with only the kernel tree mounted), so until libkrunfw's
// kernel-build orchestration is updated to pass
// `--extern bifrost_dtrace_lower=<rmeta>` to rustc, this file
// **mirrors** the trait surface verbatim and is audited by
// `scripts/check-proto-drift.sh` against the canonical declaration.
//
// Once libkrunfw is updated (planned alongside the
// scripts/check-no-active-bfr7.sh strict-mode flip), this file
// switches to `use bifrost_dtrace_lower::adapter::*;` and drops the
// inline trait mirror.
//
// ## What this file does today
//
// The methods are stubs that return `RejectReason::NotImplemented`.
// They exist so:
//
//   - `bifrost.rs` can already type-check against the planned
//     adapter surface,
//   - the integration shape is visible to anyone reading the driver
//     tree,
//   - the upcoming "wire the real eBPF lowering through" work has a
//     fixed surface to fill in.
//
// The pre-rebuild path (build a BFR7 wrapper on the host, decode in
// load_prog_parse.rs, drive attach/slots/record_writer) keeps working
// until the host migrates fully to DTRACE_SESSION_V1; the strict-mode
// gate `scripts/check-no-active-bfr7.sh --strict` is what flips the
// cutover.

#![allow(dead_code)]
#![allow(unreachable_pub)]

/// Mirrors `bifrost_dtrace_lower::adapter::RejectReason`. Numeric
/// values pinned — `check-proto-drift.sh` enforces equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RejectReason {
    ZeroMatch = 1,
    NoProvider = 2,
    NotImplemented = 3,
    DestructiveDisabled = 4,
    AggKindUnsupported = 5,
    ResourceExhausted = 6,
    LoweringFailed = 7,
}

/// Mirrors `bifrost_dtrace_lower::adapter::ProbeTarget`.
pub struct ProbeTarget<'a> {
    pub provider: &'a str,
    pub module: &'a str,
    pub function: &'a str,
    pub name: &'a str,
}

/// Mirrors `bifrost_dtrace_lower::adapter::EcbStatus`.
pub enum EcbStatus {
    Accepted { attached_id: u64 },
    Rejected(RejectReason),
    ZeroMatch,
}

/// Mirrors `bifrost_dtrace_lower::adapter::SessionEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    Begin,
    End,
}

/// Mirrors `bifrost_dtrace_lower::agg::AggKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AggKind {
    Count = 0x0101,
    Min = 0x0102,
    Max = 0x0103,
    Avg = 0x0104,
    Sum = 0x0105,
    StdDev = 0x0106,
    Quantize = 0x0107,
    LQuantize = 0x0108,
    LLQuantize = 0x0109,
}

/// The Linux adapter.  Holds whatever per-session state the bifrost
/// driver needs to remember between `attach_probe` and
/// `record_action` calls.
///
/// Today: an opaque shell.  Future: slot table handle, BPF prog map,
/// per-ECB attach IDs.
pub struct LinuxAdapter {
    next_attached: u64,
}

impl LinuxAdapter {
    pub const fn new() -> Self {
        Self { next_attached: 0 }
    }

    pub fn provider_supports(&self, provider: &str) -> bool {
        matches!(
            provider,
            "fbt" | "tracepoint" | "uprobe" | "usdt" | "profile" | "bifrost"
        )
    }

    pub fn attach_probe(&mut self, target: ProbeTarget<'_>) -> Result<u64, RejectReason> {
        if !self.provider_supports(target.provider) {
            return Err(RejectReason::NoProvider);
        }
        // Real impl: route to fbt / tracepoint / uprobe / usdt /
        // profile resolution + slot allocation.  Today: stub.
        Err(RejectReason::NotImplemented)
    }

    pub fn bind_predicate(
        &mut self,
        _attached_id: u64,
        _difo_bytes: &[u8],
    ) -> Result<(), RejectReason> {
        Err(RejectReason::NotImplemented)
    }

    pub fn record_action(
        &mut self,
        _attached_id: u64,
        _kind: u32,
        _difo_bytes: &[u8],
    ) -> Result<(), RejectReason> {
        Err(RejectReason::NotImplemented)
    }

    pub fn declare_aggregation(
        &mut self,
        _var_id: u32,
        _kind: AggKind,
        _bucket_count: u32,
    ) -> Result<(), RejectReason> {
        Err(RejectReason::AggKindUnsupported)
    }

    pub fn detach_probe(&mut self, _attached_id: u64) {
        // Real impl: bpf_link_close / kprobe-unregister / uprobe-detach.
    }

    pub fn on_session_event(&mut self, _event: SessionEvent) {
        // Real impl: pre-allocate slot table on Begin; flush
        // aggregations on End.
    }
}
