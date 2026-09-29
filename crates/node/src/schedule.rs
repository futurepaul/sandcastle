//! Runs the executor for every computer, each at its own pace: a batch per
//! computer per tick, at most `BATCHES_AT_ONCE_MAX` at once, never two for
//! one computer, so an hours-long upload or restore of one computer never
//! holds another's (audit item 7). A batch starts from an engine listing
//! taken after its computer's previous batch ended, so it never plans from
//! what that batch changed.
//!
//! The store failing is not something the node can converge around: it
//! crashes the node (systemd restarts it; machines keep running), and a
//! store that does not open on the way back up stops it there.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sandcastle_core::model::{ComputerId, Machine};

use crate::executor::Node;
use crate::gates::{Engine, World};

pub const BATCHES_AT_ONCE_MAX: usize = 32;
/// How often every computer is looked at: an owner's change is acted on
/// within about this long.
pub const TICK: Duration = Duration::from_secs(2);

pub async fn run<W: World>(node: Arc<Node<W>>) {
    let busy: Arc<Mutex<HashSet<ComputerId>>> = Arc::new(Mutex::new(HashSet::new()));
    let slots = Arc::new(tokio::sync::Semaphore::new(BATCHES_AT_ONCE_MAX));
    // Intentionally unbounded: the node's control loop, ended by the
    // process.
    loop {
        tick(&node, &busy, &slots).await;
        tokio::time::sleep(TICK).await;
    }
}

async fn tick<W: World>(node: &Arc<Node<W>>, busy: &Arc<Mutex<HashSet<ComputerId>>>, slots: &Arc<tokio::sync::Semaphore>) {
    let busy_before: HashSet<ComputerId> = busy.lock().expect("never poisoned: panics abort").clone();
    let machines = match node.world.engine().list().await {
        Ok(m) => m,
        Err(f) => {
            eprintln!("schedule: the engine did not list its machines: {:?}: {}", f.error, f.detail);
            return;
        }
    };
    let ids = node.store.ids().unwrap_or_else(|e| panic!("the store failed listing computers: {e}"));
    for id in ids {
        {
            let mut b = busy.lock().expect("never poisoned: panics abort");
            // Busy now, or busy while the engine was listed: its listing
            // may predate what its last batch did.
            if b.contains(&id) || busy_before.contains(&id) {
                continue;
            }
            let Ok(slot) = slots.clone().try_acquire_owned() else { return };
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
            });
        }
    }
}
