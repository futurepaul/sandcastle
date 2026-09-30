//! What the node sees computers doing (docs/sandcastle-sleep.md, Tiers):
//! requests through their URLs (a computer with one in flight is active
//! now), data a client sends through an open WebSocket, its guest's CPU
//! and network over their floors, a wake. Never the guest's say-so, but
//! for a busy answer, which only keeps it awake.
//!
//! In memory only: the row keeps the last activity the core acted on. A
//! restarted node counts every awake computer active from its start
//! (`executor::Node::new`), and a sleeping one waits for news.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use sandcastle_core::model::{ComputerId, Millis, Seen};

use crate::gates::Sample;

#[derive(Default)]
pub struct Activity {
    seen: Mutex<HashMap<ComputerId, Tracked>>,
}

#[derive(Clone, Copy, Default)]
struct Tracked {
    last: Millis,
    in_flight: u32,
}

impl Activity {
    fn with<T>(&self, f: impl FnOnce(&mut HashMap<ComputerId, Tracked>) -> T) -> T {
        f(&mut self.seen.lock().expect("never poisoned: panics abort"))
    }

    pub fn touch(&self, id: ComputerId, at: Millis) {
        self.with(|m| {
            let s = m.entry(id).or_default();
            s.last = s.last.max(at);
        });
    }

    /// A request through its URL started: active until it ends.
    pub fn begin(&self, id: ComputerId, at: Millis) {
        self.with(|m| {
            let s = m.entry(id).or_default();
            // Bounded by the daemon's connection slots.
            s.in_flight = s.in_flight.checked_add(1).expect("requests in flight are bounded by the node's connections");
            s.last = s.last.max(at);
        });
    }

    /// A request ended (its answer sent, or its client gone). A computer
    /// forgotten meanwhile (deleted) is left forgotten.
    pub fn end(&self, id: ComputerId, at: Millis) {
        self.with(|m| {
            if let Some(s) = m.get_mut(&id) {
                assert!(s.in_flight > 0, "a request ends once, after it began");
                s.in_flight -= 1;
                s.last = s.last.max(at);
            }
        });
    }

    /// What was seen: the newest activity, and whether a request is in
    /// flight.
    pub fn seen(&self, id: ComputerId) -> Seen {
        self.with(|m| m.get(&id).map_or(Seen::NOTHING, |s| Seen { last: Some(s.last), in_flight: s.in_flight > 0 }))
    }

    /// Forgets computers that are gone.
    pub fn retain(&self, ids: &HashSet<ComputerId>) {
        self.with(|m| m.retain(|id, _| ids.contains(id)));
    }
}

/// What counts as a guest being active between two samples, tuned from the
/// capacity report's measured rates.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Floors {
    /// Thousandths of one vCPU.
    pub cpu_permille: u32,
    pub net_bytes_per_s: u64,
}

/// A guest's rates between two samples `ms` apart: CPU in thousandths of
/// one vCPU, network in bytes a second. Counters that went back (a restart)
/// count from zero.
pub fn rates(before: &Sample, after: &Sample, ms: u64) -> (u32, u64) {
    assert!(ms > 0);
    let cpu_ns = after.cpu_ns.saturating_sub(before.cpu_ns);
    let net = (after.net_rx + after.net_tx).saturating_sub(before.net_rx + before.net_tx);
    // ns over ms·1e6 ns is vCPUs; a thousandth of that per ms·1e3.
    let cpu_permille = u32::try_from(cpu_ns / (ms * 1_000)).unwrap_or(u32::MAX);
    let net_per_s = net.saturating_mul(1_000) / ms;
    (cpu_permille, net_per_s)
}

impl Floors {
    pub fn active(&self, (cpu_permille, net_per_s): (u32, u64)) -> bool {
        cpu_permille > self.cpu_permille || net_per_s > self.net_bytes_per_s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> ComputerId {
        ComputerId::from_bytes([n; 8])
    }

    /// Goal: a request in flight is activity however long it runs (a
    /// streamed answer), and its end is activity then.
    #[test]
    fn a_request_in_flight_is_activity_until_it_ends() {
        let a = Activity::default();
        assert_eq!(a.seen(id(1)), Seen::NOTHING, "nothing seen");
        a.begin(id(1), 100);
        a.begin(id(1), 110);
        assert_eq!(a.seen(id(1)), Seen { last: Some(110), in_flight: true });
        a.end(id(1), 200);
        assert!(a.seen(id(1)).in_flight, "one still in flight");
        a.end(id(1), 300);
        assert_eq!(a.seen(id(1)), Seen { last: Some(300), in_flight: false });
        a.touch(id(1), 250);
        assert_eq!(a.seen(id(1)).last, Some(300), "never back");
        a.retain(&HashSet::new());
        assert_eq!(a.seen(id(1)), Seen::NOTHING);
        a.end(id(1), 400);
        assert_eq!(a.seen(id(1)), Seen::NOTHING, "a forgotten computer's request ends quietly");
    }

    #[test]
    fn rates_between_samples() {
        let before = Sample { cpu_ns: 1_000_000_000, net_rx: 1_000, net_tx: 0, ..Sample::default() };
        let after = Sample { cpu_ns: 1_500_000_000, net_rx: 11_000, net_tx: 10_000, ..Sample::default() };
        // Half a vCPU-second over 10 s is 50 thousandths; 20 kB over 10 s.
        assert_eq!(rates(&before, &after, 10_000), (50, 2_000));
        assert_eq!(rates(&after, &before, 10_000), (0, 0), "a restarted guest's counters");
        let floors = Floors { cpu_permille: 50, net_bytes_per_s: 4_096 };
        assert!(!floors.active((50, 2_000)));
        assert!(floors.active((51, 0)));
        assert!(floors.active((0, 4_097)));
    }
}
