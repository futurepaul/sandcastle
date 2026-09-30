//! Runs the executor for every computer, each at its own pace: a batch per
//! computer per tick, at most `BATCHES_AT_ONCE_MAX` at once, never two for
//! one computer, so an hours-long upload or restore of one computer never
//! holds another's (audit item 7). A batch starts from an engine listing
//! taken after its computer's previous batch ended, so it never plans from
//! what that batch changed.
//!
//! Between ticks, a nudged computer (a request waits for it to wake) is
//! stepped at once, from a listing of its own: waking a warm computer
//! takes milliseconds, and the tick's two seconds would dwarf them.
//!
//! The store failing is not something the node can converge around: it
//! crashes the node (systemd restarts it; machines keep running), and a
//! store that does not open on the way back up stops it there.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sandcastle_core::model::{ComputerId, Machine};

use crate::executor::Node;
use crate::gates::{Engine, World};

pub const BATCHES_AT_ONCE_MAX: usize = 32;
/// How often every computer is looked at: an owner's change is acted on
/// within about this long.
pub const TICK: Duration = Duration::from_secs(2);

/// Every machine is measured once in this many ticks (10 s).
pub const SAMPLE_EVERY_TICKS: u32 = 5;

/// Computers to step before the next tick.
#[derive(Default)]
pub struct Nudges {
    ids: Mutex<BTreeSet<ComputerId>>,
    notify: tokio::sync::Notify,
}

impl Nudges {
    pub fn nudge(&self, id: ComputerId) {
        let mut ids = self.ids.lock().expect("never poisoned: panics abort");
        // Bounded by the node's computers: an id is nudged once until taken.
        ids.insert(id);
        drop(ids);
        self.notify.notify_one();
    }

    /// The nudged computers not in a batch now, no longer nudged.
    fn take(&self, busy: &HashSet<ComputerId>) -> Vec<ComputerId> {
        let mut ids = self.ids.lock().expect("never poisoned: panics abort");
        let ready: Vec<ComputerId> = ids.iter().copied().filter(|id| !busy.contains(id)).collect();
        for id in &ready {
            ids.remove(id);
        }
        ready
    }

    fn waiting(&self, id: ComputerId) -> bool {
        self.ids.lock().expect("never poisoned: panics abort").contains(&id)
    }
}

pub async fn run<W: World>(node: Arc<Node<W>>) {
    let busy: Arc<Mutex<HashSet<ComputerId>>> = Arc::new(Mutex::new(HashSet::new()));
    let slots = Arc::new(tokio::sync::Semaphore::new(BATCHES_AT_ONCE_MAX));
    let mut ticks: u32 = 0;
    // Intentionally unbounded: the node's control loop, ended by the
    // process.
    loop {
        let listed = tick(&node, &busy, &slots, None).await;
        if let (true, Some(machines)) = (ticks.is_multiple_of(SAMPLE_EVERY_TICKS), &listed) {
            node.sample(machines).await;
        }
        ticks = ticks.wrapping_add(1);
        let next = tokio::time::Instant::now() + TICK;
        // Nudged computers until the next tick; bounded by the tick.
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(next) => break,
                _ = node.nudges.notify.notified() => {
                    let ready = node.nudges.take(&busy.lock().expect("never poisoned: panics abort"));
                    if !ready.is_empty() {
                        tick(&node, &busy, &slots, Some(&ready)).await;
                    }
                }
            }
        }
    }
}

/// Starts a batch for every computer not in one (or for `only`), from a
/// fresh listing; answers the listing.
async fn tick<W: World>(
    node: &Arc<Node<W>>,
    busy: &Arc<Mutex<HashSet<ComputerId>>>,
    slots: &Arc<tokio::sync::Semaphore>,
    only: Option<&[ComputerId]>,
) -> Option<HashMap<ComputerId, Machine>> {
    let busy_before: HashSet<ComputerId> = busy.lock().expect("never poisoned: panics abort").clone();
    let machines = match node.world.engine().list().await {
        Ok(m) => m,
        Err(f) => {
            eprintln!("schedule: the engine did not list its machines: {:?}: {}", f.error, f.detail);
            return None;
        }
    };
    let in_flight: HashSet<ComputerId> = busy.lock().expect("never poisoned: panics abort").union(&busy_before).copied().collect();
    node.reconcile(&machines, &in_flight).unwrap_or_else(|e| panic!("the store failed reconciling the ledger: {e}"));
    node.make_room(&in_flight).unwrap_or_else(|e| panic!("the store failed making room: {e}"));
    let ids = match only {
        Some(ids) => ids.to_vec(),
        None => node.store.ids().unwrap_or_else(|e| panic!("the store failed listing computers: {e}")),
    };
    for id in ids {
        let mut b = busy.lock().expect("never poisoned: panics abort");
        // Busy now, or busy while the engine was listed: its listing may
        // predate what its last batch did.
        if b.contains(&id) || busy_before.contains(&id) {
            if only.is_some() {
                // Stepped once its batch ends.
                node.nudges.nudge(id);
            }
            continue;
        }
        let Ok(slot) = slots.clone().try_acquire_owned() else { break };
        b.insert(id);
        let machine = machines.get(&id).copied().unwrap_or(Machine::Absent);
        let node = node.clone();
        let busy = busy.clone();
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(e) = node.batch(id, machine).await {
                panic!("the store failed stepping {}: {e}", id.hex());
            }
            busy.lock().expect("never poisoned: panics abort").remove(&id);
            if node.nudges.waiting(id) {
                node.nudges.notify.notify_one();
            }
        });
    }
    Some(machines)
}
