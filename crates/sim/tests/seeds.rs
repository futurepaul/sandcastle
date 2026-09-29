//! Seeds: each runs the node through a few hundred chosen actions (owners'
//! commands, steps, crashes, faults, the guest, time), checking the
//! invariants after every one, then settles it and checks it converged.
//! `SANDCASTLE_SIM_SEEDS=n` runs more; `SANDCASTLE_SIM_SEED=s` replays one.

fn seeds() -> Vec<u64> {
    if let Ok(one) = std::env::var("SANDCASTLE_SIM_SEED") {
        return vec![one.parse().expect("a seed is a number")];
    }
    let n: u64 = std::env::var("SANDCASTLE_SIM_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(64);
    (1..=n).collect()
}

#[tokio::test(flavor = "current_thread")]
async fn seeds_hold_their_invariants_and_converge() {
    let mut all = sandcastle_sim::Stats::default();
    for seed in seeds() {
        let s = sandcastle_sim::run(seed, 400).await;
        all.created += s.created;
        all.effects += s.effects;
        all.failed_effects += s.failed_effects;
        all.crashes += s.crashes;
        all.served += s.served;
        all.rollbacks += s.rollbacks;
        all.snapshots += s.snapshots;
        all.shipped += s.shipped;
        all.restores_done += s.restores_done;
        all.deleted += s.deleted;
        all.rotations += s.rotations;
        all.withdrawals += s.withdrawals;
        all.wedges += s.wedges;
        all.kills += s.kills;
    }
    println!("{all:?}");
    // The seeds must have done what they claim to test.
    if std::env::var("SANDCASTLE_SIM_SEED").is_err() {
        assert!(all.served > 0 && all.crashes > 0 && all.failed_effects > 0, "{all:?}");
        assert!(all.snapshots > 0 && all.shipped > 0 && all.deleted > 0, "{all:?}");
        assert!(all.rollbacks > 0 && all.restores_done > 0, "{all:?}");
        assert!(all.rotations > 0 && all.withdrawals > 0 && all.wedges > 0 && all.kills > 0, "{all:?}");
    }
}
