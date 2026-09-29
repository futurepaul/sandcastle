//! Every limit the core enforces, in one place, with the relationships
//! between them asserted when the crate compiles.

/// Effects one computer may run in one tick. A converging computer needs
/// at most a dozen (a rebase: fetch, quiesce, stop, snapshot, disk, create,
/// launch, probe); past this the tick moves on and the next one continues.
pub const STEPS_PER_TICK_MAX: u32 = 16;

/// A failure's reason, as stored and shown: enough for engine stderr's
/// telling line, never a whole log.
pub const REASON_BYTES_MAX: usize = 512;

/// A new whole stream after this many incrementals, so a restore never
/// replays a long chain.
pub const INCREMENTALS_MAX: u32 = 48;

/// A restore chain's links: one whole stream and its incrementals.
pub const CHAIN_LINKS_MAX: usize = INCREMENTALS_MAX as usize + 1;

/// Snapshots of one disk the node looks at in one observation. A disk
/// holds `snapshots_kept` plus the unshipped few; this is far above both.
pub const SNAPSHOTS_OBSERVED_MAX: usize = 4_096;

/// The most snapshots the node keeps per disk (an operator's setting is
/// checked against this).
pub const SNAPSHOTS_KEPT_MAX: u32 = 1_000;

/// Snapshots destroyed in one prune effect.
pub const PRUNE_BATCH_MAX: usize = 64;

/// Retry backoff: the first retry after this, doubling to the most.
pub const BACKOFF_FIRST_MS: u64 = 2_000;
pub const BACKOFF_MAX_MS: u64 = 60_000;

/// Doublings before the backoff reaches its most (2 s · 2^5 = 64 s).
pub const BACKOFF_DOUBLINGS_MAX: u32 = 5;

/// A snapshot's number, as named (`sc-<seq>-<kind>`), fits here.
pub const SNAPSHOT_SEQ_MAX: u64 = u64::MAX / 2;

/// Generations one computer goes through in its life; far past any real
/// update cadence, and a counter that cannot wrap.
pub const GENERATION_SEQ_MAX: u32 = u32::MAX / 2;

// Design checks: they fail the build, not a node.
const _: () = assert!(STEPS_PER_TICK_MAX >= 12, "a rebase needs about a dozen steps in one tick");
const _: () = assert!(CHAIN_LINKS_MAX == INCREMENTALS_MAX as usize + 1);
const _: () = assert!(BACKOFF_FIRST_MS << BACKOFF_DOUBLINGS_MAX >= BACKOFF_MAX_MS);
const _: () = assert!(BACKOFF_FIRST_MS < BACKOFF_MAX_MS);
const _: () = assert!((SNAPSHOTS_KEPT_MAX as usize) + CHAIN_LINKS_MAX < SNAPSHOTS_OBSERVED_MAX, "an observation holds every snapshot the node keeps");
const _: () = assert!(PRUNE_BATCH_MAX > 0);
