//! The real world: msb, ZFS, the S3 bucket, the credential source over
//! HTTPS, a TCP prober, the system clock, and the OS's randomness.

use super::msb::Msb;
use super::probe::TcpProber;
use super::s3::Bucket;
use super::source::Https;
use super::system::{OsRandom, SystemClock};
use super::zfs::Zfs;

pub struct Live {
    pub engine: Msb,
    pub disks: Zfs,
    pub objects: Option<Bucket>,
    pub source: Option<Https>,
    pub prober: TcpProber,
    pub clock: SystemClock,
    pub random: OsRandom,
}

impl super::Meter for Live {
    async fn samples(&self) -> super::GateResult<std::collections::HashMap<sandcastle_core::model::ComputerId, super::Sample>> {
        self.engine.metrics().await
    }

    async fn host(&self) -> super::GateResult<super::HostFacts> {
        let memory = super::host::host_memory()?;
        // Off Linux (development) there is no cgroup to read.
        let cgroup = super::host::cgroup_memory().ok();
        let pool = self.disks.pool_space().await?;
        let home = self.engine.home().to_path_buf();
        let engine_disk = super::host::space(&home, &home).await?;
        Ok(super::HostFacts { memory, cgroup, pool, engine_disk })
    }
}

impl super::World for Live {
    type Engine = Msb;
    type Disks = Zfs;
    type Objects = Bucket;
    type Source = Https;
    type Prober = TcpProber;
    type Clock = SystemClock;
    type Random = OsRandom;
    type Meter = Live;

    fn engine(&self) -> &Msb {
        &self.engine
    }

    fn disks(&self) -> &Zfs {
        &self.disks
    }

    fn objects(&self) -> Option<&Bucket> {
        self.objects.as_ref()
    }

    fn source(&self) -> Option<&Https> {
        self.source.as_ref()
    }

    fn prober(&self) -> &TcpProber {
        &self.prober
    }

    fn clock(&self) -> &SystemClock {
        &self.clock
    }

    fn random(&self) -> &OsRandom {
        &self.random
    }

    fn meter(&self) -> &Live {
        self
    }
}
