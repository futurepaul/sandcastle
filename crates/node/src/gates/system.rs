//! The host's clock and randomness.

use sandcastle_core::model::Millis;

pub struct SystemClock;

impl super::Clock for SystemClock {
    fn now(&self) -> Millis {
        let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("the clock is after 1970");
        u64::try_from(since.as_millis()).expect("milliseconds since 1970 fit u64")
    }
}

pub struct OsRandom;

impl super::Random for OsRandom {
    fn fill(&self, buf: &mut [u8]) {
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(buf);
    }
}
