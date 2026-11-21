# sandcastle on AWS Nitro Sandboxes

A node whose computers run as confidential Nitro Sandboxes: AWS's
Firecracker on an EC2 instance (the "parent") whose memory the parent
cannot read, each sandbox attested by a document its Nitro Security
Module signs. This is the backend the Nitro spike measured (sandcastle
draft PR #18, `docs/nitro-spike.md` there) built into sandcastle's own
engine, one PR at a time. celld reaches it exactly as it reaches the krun
engine: the same `engine.sock`, Cloudflare's container API.

The stack, each a draft PR on `node`:

1. **The guest** (`nitro/guest-boot`): sandcastle's guest boots a Nitro
   Sandbox. Below.
2. **Release assets** (`nitro/release-assets`): the parent's setup, the
   guest kernel and initrd, a measured image.
3. **The runner** (`nitro/firecracker-runner`): `sandcastle-vm` runs
   Firecracker inside its jail.
4. **The engine** (`nitro/engine-backend`): the engine picks krun or Nitro
   per node; images become measured roots.
5. **The bridge** (`nitro/vsock-bridge`): the engine reached from a home
   that runs in a Nitro Sandbox of its own, over the home's vsock.
6. **The sealed scratch disk** (`nitro/sealed-scratch`): a computer's
   writable layer is ciphertext on the parent.
7. **The attested session** (`nitro/attested-session`): a home verifies
   each computer and drives it over a session the parent cannot read or
   use; the parent keeps start, stop and kill.
8. **A guest with no door** (`nitro/home-no-door`): a home's own sandbox
   takes no exec at all and runs only what its measured root names.
9. **Egress inside the boundary** (`nitro/egress-in-session`): a
   computer's connections and lookups go to its home over sessions; the
   parent's proxy sees none of them, and the NIC takes nothing in.

## The guest

What a Nitro Sandbox changes for sandcastle's guest, and why:

- **It boots from an initrd.** Only the kernel, its command line and the
  initrd are measured into the sandbox's PCRs, so the guest's own binary
  must be in the initrd, not on a disk the parent could swap. The kernel's
  rootfs is where `pivot_root` (the workload's start) is refused, so the
  init first moves itself onto a tmpfs of its own and runs again from
  there (`sys::leave_initrd_root`). It tells an initrd by its root's
  filesystem type, not by its own name: krun runs it as `/init` too.
- **Its image is the device the command line names**
  (`sandcastle.image=/dev/dm-N`, once), a dm-verity device the kernel
  makes from `dm-mod.create=` on that same command line. The root hash is
  measured with the command line, so the measured kernel line decides
  which root boots, never the runner's start message. A name that is not
  a device-mapper node is refused, not ignored. With no such word, the
  krun path's `/dev/vdb` is unchanged.
- **Its clock comes from its NSM.** A confidential sandbox boots at 1970,
  with no clock the parent sets (and none it could be trusted to set).
  The NSM signs the time into every attestation document, so the guest
  asks `/dev/nsm` for one with a random nonce and sets its clock from the
  document's `timestamp`, right after its lifecycle hello and before its
  start: before anything checks a certificate. A guest with an NSM that
  cannot give a plausible time fails its boot there, typed, rather than
  later as a TLS error in the workload. The document is read, not
  verified: the guest reads its own NSM, and verifying documents is the
  operator's job (`nsm.rs`).

## Release assets

What a Nitro node runs beside sandcastle's own binaries, each pinned and
each built the same way every time, because each is measured:

- **The parent** (`nitro/parent-ready.sh`): a fresh Amazon Linux 2023
  Graviton instance, launched with enclaves on, to ready: kernel 6.18 at
  6.18.51 or later, the Nitro Enclaves memory pool on its command line,
  Firecracker v1.18.0 checked against its pinned SHA-256, the build tools,
  the slot budget, and `/dev/nitro_enclaves` in a group of its own (a udev
  rule), so a VM's jailed uid opens it as it opens `/dev/kvm` elsewhere.
  It prints the host's facts as JSON. Idempotent: run, reboot when it says
  so, run again.
- **The guest kernel** (`nitro/guest-kernel.sh`): Amazon Linux's 6.18
  tree at a pinned tag, Firecracker v1.18's CI config, and sandcastle's own
  lines (the NSM, dm-verity with `dm-mod.create=`, no modules). The build's
  user, host, time and counter are fixed, so the same source and config
  make the same bytes (the spike built it twice to the same SHA-256).
- **The guest's mke2fs** (`nitro/guest-mke2fs.sh`): e2fsprogs at a pinned
  release (kernel.org's SHA-256), built statically with Alpine's musl
  toolchain in an image pinned by digest. The guest formats its sealed
  scratch disk with it (below).
- **The guest's nft** (`nitro/guest-nft.sh`): libmnl, libnftnl and
  nftables at pinned releases (their tarballs' SHA-256, as downloaded:
  netfilter.org signs with GPG, not checked here), built statically the
  same way. A guest of sessions loads its egress rules with it (below).
- **The initrd**: the engine makes it at open from its `guest` binary,
  that mke2fs and that nft, as it makes the boot disk for libkrun: a newc archive with
  every owner, mode and time fixed (`sandcastle_rootfs::initrd`), so the
  same inputs make the same bytes.

PCR0 measures the kernel, the initrd and the command line; the command
line names the image's verity root hash. So a sandbox's PCR0 is a
function of the release (kernel and guest), the image's root, and the
launch's flags. A node builds an image's root in a build VM, as krun
nodes do, which is not byte-reproducible: two nodes' builds of one image
give two root hashes, each measured. Publishing one PCR0 per image needs a
deterministic build of the root; that is not done here.

## The runner

`sandcastle-vm` boots a Nitro Sandbox when its config carries a `nitro`
section: Firecracker v1.18 as the runner's child, inside the same jail,
in place of libkrun in the runner's own thread. Everything else the runner
does for libkrun it does unchanged, so the engine and its clients see one
VM either way:

- **The jail** binds Firecracker and the kernel from the node's lib dir,
  the initrd from the lib dir or the engine's state (the engine makes it),
  and `/dev/nitro_enclaves` in place of `/dev/kvm`, which a Nitro parent
  has none of. The VM's uid joins the device's group (`nitro_gid`); a node
  with none runs no Nitro Sandbox. libkrun's files are never bound then.
- **The disks** keep their order, so the guest's `wire::disks` hold: the
  first is the image's dm-verity hash tree (`DiskRole::Hashes`, read-only
  and shared) where libkrun has the boot disk, then the image, the scratch
  disk and the data disk.
- **The kernel's line** (`VmConfig::nitro_cmdline`) is spelled out whole,
  because PCR0 and PCR1 measure it: Firecracker's default, `quiet`, the
  verity table over the image with its root hash, the guest told to mount
  that device, then the node's tunings. A build has no root and no table.
- **Firecracker's config** (`firecracker.rs`, the spike's, which described
  its launches to the MiB) is written from the VM's: every DMB size in
  confidential mode, every enclave flag written, no drive the root device,
  the tap with the guest's MAC (the jail makes it a permanent neighbor).
- **The guest's channels:** Firecracker's vsock is a unix socket in the
  run directory. The guest's dial to the host's port 1025 reaches
  `v.sock_1025`, where the runner serves the lifecycle as it does for
  libkrun. `agent.sock`, which the engine's agent client opens, is a relay:
  each connection becomes `CONNECT 1024` on Firecracker's vsock, its `OK`
  read a byte at a time (what follows is the agent's), then a plain
  stream.
- **Control:** a Nitro Sandbox has no pause, so pause and resume answer an
  error; kill ends the runner, its PID namespace's first process, and
  Firecracker with it. The runner ends when Firecracker does, with its
  status.
- **Seccomp:** the runner installs libkrun's allowlist only for libkrun.
  Firecracker installs its own filter on its threads; the runner's own
  threads (lifecycle, relays, forwarder) run unfiltered in the jail. An
  allowlist for them, installed after Firecracker starts, is not done.

## The engine

A node is krun's or Nitro's by its config: `nitro` (`{}` takes every
default) names Firecracker and the kernel in `lib_dir`, the launch's mode
(confidential unless set) and `cpu_overcommit`. The API is unchanged:
celld's `CELLD_CONTAINER_ENGINE=krun:<socket>` reaches it as it reaches a
krun node.

- **At open** it needs `/dev/nitro_enclaves` in a group of its own (not
  root's) instead of `/dev/kvm`, and makes the guest's initrd from its
  `guest` binary instead of the boot disk.
- **Images** are built in a build VM as on krun, the build VM a Nitro
  Sandbox in direct mode (the layers are no secret, and untrusted layers
  are never unpacked on the host). Then the host formats the root's
  dm-verity tree (`veritysetup format`, `sandcastle_rootfs::verity`) and
  keeps its table in the image's record. An image built before the node
  ran Nitro is built again at its next load; a start on one is refused,
  typed.
- **A start** boots the image's measured root: its hash tree first, its
  table on the kernel's line, a vsock CID of the slot's own (3 plus the
  slot), no balloon (a sandbox's memory is the pool's until it stops).
  Memory under 256 MiB or odd is refused before anything is reserved.
- **Snapshots** are refused, and so is a start from one, and a data disk
  (below, "The sealed scratch disk"). The cell's sleep goes on without a
  snapshot when one is refused; a home runs with
  `FRAGMENT_COMPUTER_SNAPSHOTS=off` and asks for none.
- **Capacity:** `memory_mib_max` is the operator's, sized to the pool
  less each sandbox's overheads (2 MiB and 16 MiB a device in confidential
  mode; the spike's line 10).

## The bridge

A home (celld and the cell) may run in a confidential sandbox of its own
on the parent that runs its computers. celld reaches the engine through
`sandcastle-bridge`, one binary in two halves, so celld and the engine are
unchanged:

- **home**, in the home: `engine.sock` and `ports.sock` in `/run/sandcastle`
  (`CELLD_CONTAINER_ENGINE=krun:/run/sandcastle/engine.sock`). Each
  connection becomes a vsock stream to the host: port 5000 the engine's
  API, 5001 `ports.sock`. It listens on its own vsock port 5002 for the
  intercepts and dials celld's intercept socket (`--intercepts`).
- **parent**, beside the home's Firecracker: it listens on the home's
  `<uds>_5000` and `<uds>_5001` (where Firecracker hands the home's dials)
  and dials the engine, and listens at celld's intercept path on the
  parent, where the engine dials it, each connection a `CONNECT 5002` into
  the home.

The API and the intercepts are bytes. `ports.sock` hands a connected
socket over, which no vsock can carry: the parent takes the engine's
socket and relays it on the stream the request came on, after the reply
(framed by its length); the home hands celld one end of a socketpair and
relays the other, saying `transport: "vsock"` as the engine does of its
own unix sockets. Every connection is a relay of its own, at most 1024
live per listener. The intercept path is celld's
`<data dir>/intercepts-<6 hex of sha256(node)>.sock`: run the home's celld
with a fixed `CELLD_NODE` and give both halves that path.

## The sealed scratch disk

A computer's scratch disk (its overlay's writable layer: everything it
writes outside `/data`'s saves) is ciphertext on the parent:

- **The key** is 64 random bytes the guest draws at boot (`getrandom`)
  and hands to the kernel in a dm-crypt table (AES-256-XTS) by
  device-mapper's ioctls, with the flag that wipes the kernel's copies of
  the call's buffers; the guest wipes its own. It is never written to a
  disk, never sent, and dies with the VM. The parent cannot read the
  guest's memory, so it cannot read the key.
- **No key release is needed**, because the scratch disk does not outlive
  the VM: every start makes a new one, and what must outlive it is saved
  through the cell (`DirectoryBackup`). So there is nothing to snapshot
  (a copy would be ciphertext no one can open), and a data disk, which
  outlives its VM by design, is refused on a Nitro node.
- **The format** is the guest's: the parent hands over a sparse file of
  the disk's size and nothing on it; the guest makes ext4 on the mapping
  with the initrd's `mke2fs` (no journal, inode tables left for the
  kernel to zero, so only a few megabytes are written).
- **Which guests seal:** every guest with an NSM, that is every Nitro
  Sandbox; the parent cannot turn it off without changing the guest, and
  so the initrd and PCR0.

## The attested session

A home drives its computers over a session of its own with each, which
the parent carries and can neither read nor use (`crates/session`):

- **The guest's key.** Each guest life makes a Curve25519 key. On a node
  whose engine says `session_required`, the guest's measured kernel line
  carries `sandcastle.session=required` (so dropping it changes PCR0), and
  the guest listens on vsock 1026, which the runner relays (`session.sock`)
  and the engine's API offers as an upgrade.
- **The claim.** When a computer starts, the home half of
  `sandcastle-bridge` holds the start's answer, waits for it to run, and
  attests it: the guest answers its NSM's document for the home's fresh
  nonce, with its key as the document's public key. The home verifies the
  chain to AWS's root, the nonce and the age (`sandcastle-nitro-attest`),
  and the PCR0 against its pins, then runs Noise NK to that key, which
  only that guest holds, and sends the session's secret. The guest is
  claimed for its life: a second claim is refused. A computer that does
  not attest is destroyed and its start fails.
- **The work.** Each exec, and each connection to a computer's port, is a
  connection of its own resumed with Noise NKpsk0 by that secret, the
  agent's protocol inside. The guest's own agent port answers only what
  the parent keeps: ping, a signal to the entrypoint (stop), the memory
  trim; its exec and connect are refused there. Kill is the runner's.
- **Kept across a home restart.** The home keeps each claim's credential
  in its own state directory (0600), so a computer kept running through a
  home restart is still the home's.
- **The pins** are the PCR0s of the images a home runs on its node. Each is
  read once from a computer of the image, as the home's first refusal
  prints it, and written to the pin file by the operator. A node builds an
  image's root itself (not byte-reproducible), so a pin is the node's, and
  that first reading trusts the node (above, "Release assets").

## A guest with no door

A home is a sandbox too, and its guest is sandcastle's. Two kernel-line
words, both measured into PCR0, take the parent's last hands off it:

- **`sandcastle.agent=none`**: the agent's host port takes only ping and a
  signal to the entrypoint (the parent keeps stop and kill), and there is
  no session port. Nothing runs a command in that guest, the parent
  included. Its logs are its only voice.
- **`sandcastle.start=image`**: the guest runs `/etc/sandcastle/start.json`
  (a process: argv, env, cwd, user) read from the image's read-only layer,
  which dm-verity checks, and ignores the entrypoint the parent's start
  message names. What the sandbox runs is then a function of its PCR0, so
  a key released only to that PCR0 (KMS's) is released only to it. An
  image with no such file refuses its boot.

Together they make a production home image: no exec door, its start its
own. A debug image is another one, with another PCR0, so it can never get
the production home's keys. A word for a session and one for no door at
all refuse the boot together.

## Egress inside the boundary

On a node of sessions, a computer's connections and lookups never reach
the parent's egress proxy:

- **The claim** carries the home's configuration: its CA (the one the
  workload trusts for intercepted hosts; the parent's CA in the start
  message is not written) and egress on. The guest says Ready, waits for
  it, and starts its workload only then.
- **The guest catches its own traffic**: nftables in the guest (the
  kernel's inet family, `/nft` from the initrd) redirects every TCP
  connection the workload makes to anywhere but the guest, and every DNS
  query, to the forwarder (`crates/forward`, the runner's own, now
  shared); nothing else leaves, and nothing comes in but on loopback. The
  NIC still exists and carries nothing.
- **Each one is an egress session**: the guest dials the host's vsock port
  1027, names itself by its key, and runs Noise NNpsk0 with the claim's
  secret, so only its home can answer. The runner hands it to the engine
  (`egress-session.sock`), the engine to its `nitro.session_egress` path,
  the bridge's parent half into the home (vsock 5003), all unread.
- **The home decides**: the home half runs the same egress proxy the
  engine runs (`sandcastle_egress`), one per computer, from the policy its
  start named (the home reads the start and the intercepts' changes as it
  forwards them): intercepted hosts to celld's socket in the home, the
  internet from the home, refusals. The CA's key is made once in the
  home's state directory and never leaves it.

## What the parent can still see and do

A confidential sandbox keeps its memory from the parent. Everything that
crosses the sandbox's edge, the parent still holds. As built here, for a
computer:

**It sees:**

1. **A computer's traffic**, on a node of sessions with egress inside the
   boundary (above): ciphertext of egress sessions, not even where each
   goes. Elsewhere, the egress proxy runs in the engine and terminates TLS
   for every intercepted host: on a Fragment node the platform's API, the
   model routes and the saves, in plain text.
2. **Exec and terminals** go over each computer's attested session on a
   node that requires them (above): the parent carries ciphertext. On a
   node that does not, `agent.sock` is relayed in the clear.
3. **Ports.** A home's connection to a computer's port goes over its
   session. With egress inside the boundary the guest takes nothing in on
   its NIC, so the parent's own `ports.sock` reaches no port (`egress.md`).
4. **Disks.** The scratch disk is ciphertext (above, "The sealed scratch
   disk"); the parent sees which blocks are written and when, not what.
   The image is protected for integrity only (dm-verity): its contents are
   public anyway. A Nitro node takes no data disk.
5. **Metadata:** when each computer starts and stops, its size, its DNS
   names, and the timing and size of everything above.

**It can:**

6. **Run commands in a computer** only on a node that does not require
   sessions. On one that does, the guest refuses the parent's exec, and a
   claim the parent makes first leaves the home's attempt refused, so the
   home never puts its data in that VM.
7. **Change what it relays:** answer or alter an intercepted request, or
   an exec's output, or scramble the scratch disk's blocks (XTS has no
   integrity: a changed block reads as garbage, not as the parent's
   choice).
8. **Boot something else in a computer's place**, only where nothing
   checks: a home that requires sessions verifies each computer's
   document and PCR0 before it uses it.
9. **Stop, refuse or slow anything** (availability is never protected).

**What is closed, and what is left:** the attested session closes 6 and
8, and 2 and 7 for exec; egress inside the boundary closes 1 and 3. 4 is
closed for the scratch disk by a key the guest makes and keeps. Left: 5
(metadata: when computers start and stop, their sizes, the timing and size
of their sessions), 7 for scrambled disk blocks, 9, and that a pin is read
from a node's own build.

## Evidence

`docs/nitro-evidence/` holds real runs on a parent. First (an m8g.xlarge,
Amazon Linux 2023, kernel 6.18): celld's engine conformance suite
(`celld dev` with `CELLD_CONTAINER_ENGINE=krun:<engine.sock>`) against
this engine in Nitro mode, every sandbox confidential.

- `conformance-nitro.json`: 25 passed, 0 failed, 0 unsupported: start,
  ports, exec (output, stdin, PTY and resize, kill, abort), signals,
  HTTP and HTTPS intercepts (HTTPS needs the guest's NSM clock), snapshot
  and start from a snapshot.
- `engine-log.txt`: the engine's own lines for that run: the image's
  build VM applying its five layers and ending, then each sandbox's start
  (ready in about 500 ms) and end.

- `egress.md`: egress inside the boundary: a canary the parent's proxy read
  9 times with the parent deciding, 0 times with the home deciding; the
  parent's own port connection refused; the suite through the home.
- `no-door.md`: a guest with no door: the image's own start run in place
  of the parent's, the parent's exec refused, an image without a start
  refused its boot.
- `session.md`: the attested session: an exec over it answered, the
  parent's own exec and claim refused, the suite through a home.
- `sealed-scratch.md`: the sealed scratch disk: a planted string found
  0 times on the parent (8,192 with no seal), and the suite's 23 cases
  that do not snapshot passing on it.
- `home-computers.md`: a home in a Nitro Sandbox of its own, on the same
  parent, running its computers on this engine through the bridge:
  Fragment's Hermes image (arm64) as a measured root, an agent made and
  answering from a browser, its file kept across a restart, two home
  restarts and a wake, and its screen through `ports.sock`.

The run found three bugs, each fixed in the PR that owns it: the guest
rebooted where Nitro's Firecracker ends only on a power-off (the guest),
Firecracker's vsock dropped a host's close so a build's guest waited on
a closed connection (the runner), and a build whose client went away
left its build VM running and the build lock held (the engine).
