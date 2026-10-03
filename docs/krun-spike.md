# The libkrun spike

> Imported from fragment (github.com/futurepaul/fragment, branch
> `krun-spike`, draft PR #103) on 2026-10-02, when the engine moved to
> this repository. It is the record of the spike as run there: "this
> branch", `sandcastle/`, `sandcastled`, msb, and master are fragment's.
> Paths are this repository's. The test node's name and public address
> are redacted (`<node-ip>` in the evidence), and its before and after
> snapshots (`lat6-before.txt`, `lat6-after.txt`) stayed in fragment's
> history.

*Plan, 2026-09-30 (Paul: "can you do this on [the test node] without
disrupting the existing work? new worktrees / branches for everything
until we've proved it. and make sure we follow engineering-style").*
Why: docs/background.md, Why libkrun. The bar: docs/background.md, The
bar (Cloudflare's container capabilities). Paul also sees what this
becomes: a close-to-the-metal alternative to Docker for celld's
container API, so it is built as an engine with Cloudflare's container
semantics, not a sandcastle-only shortcut.

This is a **spike**: a lower-rung diagnostic that proves or disproves one
design on real hardware and records the evidence. It is written to the
engineering style, so what it proves can become the product without a
rewrite. It merges nowhere until Paul decides.

## Problem

sandcastle runs its computers through msb's CLI, and fights it: a
sandbox outlives its entrypoint, ports are fixed at create, interception
only substitutes values, a flushed pause is refused for PID-1 inits,
freed memory never returns, and the VM process runs as the node's user
in the host's namespaces. The question is whether running libkrun
directly, with our own jail, roots, guest agent, and network, gives
Cloudflare's container semantics exactly, at msb's speed or better, and
isolates each VM from the node and from each other.

## Acceptance

The spike is done when `docs/krun-spike.md`'s Results section holds each
of these, measured on the test node (10 samples where cheap, median and
range), with the evidence the driver printed:

1. **Boot.** A busybox guest's boot to its agent ready; the Hermes image
   (`nousresearch/hermes-agent:v2026.9.24`) from its OCI image to serving
   on its port. Compared with msb: Hermes cold 6.0 to 6.2 s.
2. **Pause and resume.** Each, timed; a connection that arrives while
   paused resumes the VM and is served. Compared with msb: 8 ms each.
3. **Exec.** A round trip; a PTY with resize; stdin; kill; the exit code.
   The entrypoint's own exit code, reported, and the VM stopped then.
   Compared with msb: 9 to 20 ms.
4. **Any port.** A connection to a port nobody declared: first byte, and
   throughput over 100 MB; HTTP and a WebSocket through it.
5. **Interception.** From the guest, with no proxy setting: an HTTPS
   request to a named host handed to a handler, which answers it; a
   placeholder substituted with a secret; with the internet off, a name
   that is not intercepted does not resolve; a private address refused.
6. **Memory back.** An idle Hermes' resident memory with the balloon's
   free-page reporting, against msb's 892 to 925 MiB.
7. **Isolation.** From inside a VM process's jail, an escape probe finds
   the node's key, the node's state, `ubuntu`'s home, and another VM's
   disk unreachable, and sees its own uid, not `ubuntu`'s.
8. **Fresh roots.** Two starts from one image see a fresh root each
   time (a file written in the first is gone in the second), and
   `/data` keeps it.
9. **The build is clean.** Every new crate passes `cargo clippy
   --workspace --all-targets --all-features -- -D warnings` and `cargo
   test --workspace --all-features` from `sandcastle/`, on the Mac and
   in CI, with no libkrun installed there.
10. **Nothing else moved on the test node** (the constraints below), shown by the
    other services' start times and datasets before and after.

## Constraints

### Musts

- **Separate everything on the test node:**
  - source and builds under `/home/ubuntu/krun-spike/` (a checkout of
    this branch);
  - libkrun and libkrunfw built at pinned commits into
    `/home/ubuntu/krun-spike/prefix/`, loaded from there by path, never
    installed system-wide (msb's own `libkrunfw.so.5.6.1` is untouched);
  - ZFS under `tank/krun-spike` only, with a 60 GiB quota;
  - VMs under a `krun-spike.slice` with `MemoryMax=8G` and
    `CPUQuota=800%`. The host has 124 GiB and `sandcastled`'s unit may
    take 113 GiB, which leaves 11 GiB; 8 keeps 3 for the host.
  - At most two spike VMs at once: Hermes at 2 vCPU and 4 GiB, test
    guests at 1 vCPU and 512 MiB.
- **Nothing public:** nothing binds a non-loopback address, and the
  firewall is unchanged. The driver runs on the test node itself.
- **The engineering style** (below), from the first commit.
- **Pinned and audited dependencies**, each named in this doc with why.
- **One reset:** `sandcastle-krun-spike reset` removes `tank/krun-spike`'s
  children and any spike VM, mount, or network namespace left behind.
  It is the only cleanup, and it deletes whole explicit roots.
- **Every privileged action is listed here, and there are no others:**
  - `sudo zfs create|set|clone|destroy`, under `tank/krun-spike` only;
  - `sudo systemctl set-property --runtime krun-spike.slice MemoryMax=8G
    CPUQuota=800%` (not kept across a reboot);
  - `sudo systemd-run --slice=krun-spike.slice --scope sandcastle-vm jail
    …`: the jailer, which drops to the VM's own uid before libkrun runs;
  - `apt install` of build-only packages, and only if libkrunfw's kernel
    build needs them (flex, bison, and the like), each named in Results.
  - `rustup target add x86_64-unknown-linux-musl` is `ubuntu`'s own, not
    the system's.

### Must-nots

- Touch `sandcastled` (its unit, binary, state, `tank/sandcastle`,
  `/etc/sandcastle`), msb (`/home/ubuntu/.microsandbox`,
  `/home/ubuntu/.local/bin/msb`), `iroh-relay`, the firewall, or the
  earlier spikes in `/home/ubuntu/spike*`. Restart none of them.
- Stop or change the paused Hermes computer on the test node (another session's).
- Merge to master, deploy anything, or put secrets on the test node. Model calls
  go to a stand-in handler, labeled as one.
- Depend on fragment's crates or on `sandcastle-node` from the new
  crates: they must be able to leave for celld's ecosystem.

### Preferences

- libkrun's newer builder API (`krun_vmm_builder_*`, with a pause and
  resume handle and a balloon) over the 1.x context API, if a pinned
  commit builds and boots.
- TSI networking first: the VMM opens the guest's sockets inside the
  VM's network namespace, so nftables and a transparent redirect apply
  unchanged. virtio-net and a tap in that namespace is the fallback.
- Load libkrun at run time (`dlopen` through `libc`), so nothing links it
  at build time and CI builds without it.
- Keep Linux-only code (namespaces, seccomp, vsock, the guest) behind
  `cfg(target_os = "linux")`, so the workspace still builds and tests on
  the Mac.
- Build libkrunfw from its pinned source. Copying msb's own
  `libkrunfw.so.5.6.1` into the prefix is the fallback if that build
  blocks, labeled as such in Results.

### Escalations (stop and ask Paul)

- No pinned libkrun offers pause, resume, and the balloon together.
- The jail needs more privilege than the one root jailer step: this is
  the production privilege model, and it is Paul's call.
- Any need to touch what the must-nots name, open a port, or pass the
  budget.
- TSI escapes the namespace's rules and interception needs virtio-net and
  a userspace stack: a larger scope.
- libkrunfw's licensing (a GPL kernel inside a shared library) bears on
  shipping it.
- A real model call would need a key on the test node.

## Layout

On fragment's branch `krun-spike` (stacked on `two-substrates`), new
crates in its `sandcastle/` workspace (now this repository's root), none
depending on `sandcastle-node` or fragment:

| Crate | What | Tested on the host |
|---|---|---|
| `sandcastle-wire` (`crates/wire`) | the host's and guest's protocol over vsock: length-prefixed frames, typed messages, every limit a constant | encode and decode, round-trip, oversized and malformed frames refused, a fuzz target |
| `sandcastle-guest` (`crates/guest`) | the guest's init and agent, one static binary (`x86_64-unknown-linux-musl`): mounts, the CA, the entrypoint in a PID namespace as its PID 1 with its exit code reported, exec, port connections, sync and freeze | the mount plan and the exec state machine as pure functions |
| `sandcastle-vm` (`crates/vm`) | the runner: a pure lifecycle (created, booting, ready, paused, stopped) and its validated configuration; the libkrun gate (`dlopen`); the jailer (namespaces, uid and gid maps, the mount namespace, seccomp, the cgroup) | the lifecycle's transitions, valid and invalid; configuration refused at every limit |
| `sandcastle-egress` (`crates/egress`) | the rules (host, glob, `ip:port`, CIDR; 128 entries, as Cloudflare), the nftables rendering, and the intercepting proxy with the node's CA | rule matching at the limits; the proxy on loopback, a handler answering |
| `sandcastle-rootfs` (`crates/rootfs`) | an OCI image pulled and unpacked once per digest (whiteouts applied), made an ext4 image (`mke2fs -d`), written to a zvol | manifest and layer parsing; whiteouts; digests checked twice (on download and before use) |
| `sandcastle-krun-spike` (`crates/krun-spike`) | the driver: each scenario below, its evidence as JSON, and `reset` | none: it is the spike |

### Dependencies (to audit before adding)

- libkrun and libkrunfw from `github.com/containers`, at pinned commits,
  built on the test node. Recorded: the commits, their licenses, and the API used.
- Rust, already in the workspace: `tokio`, `hyper`, `rustls`,
  `tokio-rustls`, `rcgen`, `serde`, `serde_json`, `sha2`, `thiserror`.
- New, each audited: `libc` (namespaces, `dlopen`, seccomp's `prctl`);
  a `tar` reader and gzip and zstd decoders for layers. An OCI registry
  client is written over hyper (tokens, manifests, blobs), not pulled in.
- On the test node's host: `mke2fs` (e2fsprogs 1.47.0), `nft`, `zfs`. Present.

## Phases

Each phase ends with its tests green and its numbers recorded before the
next begins.

1. **Pin, build, boot.**
   - libkrun and libkrunfw at chosen commits, built into the prefix.
   - `sandcastle-wire` and the runner's pure lifecycle, with their tests.
   - A busybox root made an ext4 zvol, cloned per start.
   - `sandcastle-guest` as init says it is ready over vsock.
   - *Evidence:* boot to ready (10); a fresh root each start (acceptance
     8, the root half).
2. **The jail.**
   - The root jailer creates a user namespace mapping a per-VM uid from
     `ubuntu`'s subordinate range (100000 to 165535), keeps the `kvm`
     group, makes a mount namespace holding only `/dev/kvm`, the VM's
     disks, and the libraries, a network namespace, and the cgroup; then
     drops privileges and applies seccomp before libkrun starts.
   - The escape probe runs in the same jail in place of the VM.
   - *Evidence:* acceptance 7. *Tests:* the jail's plan (maps, mounts,
     rules) as pure data, refused when it would leak.
3. **Exec and exit.**
   - The agent's exec: streams, PTY and resize, stdin, kill, exit codes.
   - The entrypoint supervised as the PID namespace's PID 1: its code
     reported, the VM stopped.
   - *Evidence:* acceptance 3. *Tests:* frames valid and invalid, a
     repeated request id refused, an unknown process, a closed stream,
     the limit on processes at once.
4. **Any port.**
   - A connection over vsock to the guest's `127.0.0.1:<port>`; HTTP and
     a WebSocket through it.
   - *Evidence:* acceptance 4.
5. **The network and interception.**
   - TSI in the VM's namespace: nftables for public-only egress (the
     node's own addresses denied) and redirection of 80 and 443 to the
     proxy, in the same namespace, jailed with it.
   - The proxy matches the rules, substitutes a placeholder or calls the
     handler (a stand-in on a unix socket, labeled as the stand-in for
     celld's callback).
   - With the internet off, DNS answers only for intercepted names.
   - *Evidence:* acceptance 5. *Tests:* the matcher at every boundary;
     the rendering of rules; the proxy against a loopback handler.
6. **Hermes.**
   - The real image pulled, unpacked, and made a root; a `/data` zvol;
     s6's `/init` under the guest's init.
   - Its port served through phase 4's path.
   - Pause and resume, and a connection waking a paused VM.
   - The balloon's reporting on, and its resident memory idle.
   - *Evidence:* acceptance 1 (Hermes), 2, 6, and 8 (`/data` kept).
7. **Crash and reset.**
   - `kill -9` of a VM mid-run leaves no process, mount, or network
     namespace behind once reset runs, and `/data` is intact.
   - The driver's `reset` restores the test node to its before state.
   - *Evidence:* acceptance 10.

## Evaluation

- **Host tests** (CI and the Mac): every pure piece above, each mutation
  with a valid and an invalid path, frames round-tripped, limits
  exercised at the edge and one past it, and a fuzz target for the frame
  decoder.
- **The driver on the test node**: each scenario prints JSON evidence (samples,
  median, range, versions, commits) that goes into Results as is.
- **Honesty:** the stand-in handler is named as one, and no number from
  a harness is reported as the product's.

## How the engineering style applies here

- **Limits, named and asserted:** a frame (1 MiB), processes per VM
  (64), port connections per VM (256), intercept rules (128), boot
  (60 s), a paused VM's resume (1 s), each an asserted bound or a typed
  refusal; loops over bounded sources say so.
- **Typed errors** per crate (`thiserror`), matched by callers; no
  `anyhow` outside the driver.
- **Assertions stay on in release** (the workspace's profile already
  aborts on panic and checks overflow). About two a function: what it
  assumes on entry, what it produces on exit. Paired where data crosses
  (a frame checked when written and again when read; an image digest
  checked on download and again before use).
- **No recursion; iterative, bounded state machines** (the lifecycle,
  the exec session, the proxy's connection).
- **Pure core, narrow gates:** the lifecycle, the jail's plan, the rules,
  and the mount plan are pure and host-tested; KVM, ZFS, and the network
  come in through gates.
- **Names:** nouns, units last (`boot_ms_max`, `frame_bytes_max`).
- **Comments say why; tests say how** (a preamble: goal, then method).
- **clippy with warnings denied**, from the first commit.
- **Hard cuts:** nothing here keeps msb's shape for compatibility; if the
  spike holds, the engine replaces msb's gate behind sandcastle's engine
  trait, with msb kept only as an alternate engine until parity.
- **Debt:** anything the spike skips on purpose gets a ledger entry
  before it could ship.

## What two other libkrun sandboxes taught (Paul's gut check)

Read before phase 1 (2026-10-01): smolvm (smol-machines/smolvm @ 9f446ae,
v1.22.0) and NVIDIA OpenShell (@ 2935e973, its `openshell-driver-vm`).

- **Neither uses upstream libkrun's pause, resume, or balloon.** smolvm
  carries a fork 230 commits ahead (and 197 behind) for exactly those;
  OpenShell has none of them. Upstream master gained them on 2026-09-11 (the
  builder API), unreleased: pinned here at master.
- **OpenShell boots what this spike boots**: a read-only bootstrap ext4,
  a per-sandbox sparse overlay disk, a read-only image disk, all
  virtio-blk; and it unpacks OCI images inside a VM ("image-prep"), because
  a host cannot be trusted to make Linux ext4 ownership right. Both are
  this spike's choices too (below).
- **TSI is where smolvm hurts**: idle keep-alive connections dropped after
  about six minutes, a guest-kernel NULL dereference in TSI's setsockopt,
  half-close bugs, and TSI's own egress filter not enforced. OpenShell
  dropped TSI and gvproxy for no NIC at all and a seccomp-notify broker in
  the guest. So phase 5 starts with virtio-net on a tap inside the VM
  process's network namespace (kernel TCP, the namespace's nftables), not
  TSI, reversing the plan's preference on this evidence.
- **Neither jails its VMM by default.** smolvm's hardening (a per-VM uid,
  cgroup, Landlock, a seccomp allowlist) is opt-in by environment
  variable; OpenShell's VMM runs unjailed. The jail here is the default.
- **Copied**: the guest dials out to say ready (no polling); the vsock
  listener is bound before ready is said; the exit code travels over vsock
  (libkrun's own path needs a virtio-fs root); fake addresses from
  198.18.0.0/15 for intercepted names (OpenShell's DNS), for phase 5;
  dropping the guest's page cache on idle so free-page reporting returns
  it (smolvm's reclaim pulse), for phase 6.
- **Not copied**: a bash PID 1 (OpenShell), forking from a tokio process
  (OpenShell's launcher), environment on argv, a 32 MiB frame (smolvm; 1
  MiB here), crun inside the guest (smolvm).

## Results

### Deviations from the plan, and why

1. **Roots are overlays, not ZFS clones.** The image is one read-only ext4
   disk shared by every VM of that image; each start gets a fresh sparse
   scratch ext4 (4.6 ms to make 4 GiB, median) as the overlay's upper
   layer. Cloudflare's semantics exactly, no ZFS needed for roots (the
   engine runs on any Linux host), and no `sudo zfs` at all: the spike's
   ZFS dataset was never created. `/data` is its own disk (a file here; a
   zvol in sandcastle, as today).
2. **Images are unpacked inside a build VM.** The test node's `mke2fs` cannot read
   a tarball (no libarchive), and unpacking as `ubuntu` would own every
   file by uid 1000; in a VM the guest is root, so owners, modes, and
   whiteouts are exact, and a hostile layer reaches only that VM's target
   disk. The host only downloads and checks digests (on download, and
   again before each use).
3. **The guest ends the VM by rebooting.** x86 without ACPI cannot power
   off ("Power off not available: System halted instead"); libkrun's
   `reboot=k` turns the reset into the VMM's exit.
4. **Phase 1 ran unjailed, as `ubuntu`, with no privilege at all** (one
   test VM at a time, 512 MiB); the jail and the slice come with phase 2.
5. **Build-only packages installed** (needrestart suspended, nothing
   upgraded, no service restarted): `python3-pyelftools flex bison
   libelf-dev bc`, which pulled `m4 zlib1g-dev libzstd-dev`.
6. **ubuntu's own toolchain** gained the `x86_64-unknown-linux-musl`
   target and `clippy`.
7. **The jail is Firecracker's model, not a user namespace.** The VM
   process runs as a plain uid of its own, 300000 + slot (outside every
   subordinate range, so no user namespace on the host maps it), in new
   PID, mount, network, IPC, and UTS namespaces. A user namespace would add
   kernel surface and buy nothing a dropped uid does not.
8. **Two more privileged actions, for reset.**
   - `sudo systemctl stop krun-spike.slice` stops only the spike's own
     scopes.
   - `sudo sandcastle-vm restore --settings jail.json` hands back to
     `ubuntu` any file under the spike's `vms/` and `data/` that a VM uid
     still owns. It never follows a link and touches only owners in the VM
     range.

   A jailer that `systemctl stop` killed before the fix below left its run
   directory owned by uid 300000, which is why `restore` exists. The jailer
   now takes SIGTERM, SIGINT, and SIGHUP synchronously: it kills its VM and
   hands the files back itself.
9. **The network is a tap, not TSI**, on smolvm's evidence (above): the
   guest has a real NIC (virtio-net), so the kernel's own TCP runs on both
   sides.
10. **The intercepting proxy runs on the node, outside the jail**, not
    "jailed with" the VM as the plan said. It holds the CA's key and the
    secrets it substitutes, which must stay out of reach of an escape
    from the VMM. Inside the jail is only a forwarder (the runner's
    threads), which decides nothing.

### Phase 1: pin, build, boot (2026-10-01)

- **libkrun** `b63baa1895c60d58b731fdebb9180ba266292848` (master, Apache-2.0;
  the builder API with `krun_vmm_handle_pause/resume` and a balloon that
  offers free-page reporting, which `MADV_DONTNEED`s reported pages), built
  with `--features ffi,blk,net` in 14 s. **libkrunfw**
  `f6a710faaa8cfe3b67a4bcdadb082c2183a914f1` (5.6.2, Linux 6.12.109,
  LGPL-2.1 with a GPL-2.0 kernel), built from source in about two minutes.
  Both in `/home/ubuntu/krun-spike/prefix/lib`, loaded by path; msb's
  `libkrunfw.so.5.6.1` untouched.
- **The guest**: `sandcastle-guest`, 1.4 MB, static (musl), the boot disk's
  `/init`. The boot disk is 16 MiB, made in 6 ms.
- **busybox:1.37.0** pulled (one layer, 2.2 MB) in 428 ms and made a disk by
  a build VM in 195 ms, its boot included (442 entries; one device node
  skipped).
- **Boot to ready, busybox, 1 vCPU, 512 MiB, n = 10** (the driver's clock,
  from spawning the runner to the guest's ready on the lifecycle channel):
  **median 107.0 ms, range 103.8 to 109.8**. Of that, the guest kernel's
  own clock reads 55.5 ms (53 to 58) at ready: about 50 ms is the runner
  (loading libkrun and libkrunfw, building the VMM: 5.7 ms) and libkrun
  starting the kernel. The first agent round trip after ready: median 2.1
  ms. msb's Hermes cold start is 6.0 to 6.2 s; Hermes's own number comes
  in phase 6.
- **Fresh roots (acceptance 8)**: a first start wrote `/marker` and
  `/data/marker`; a second start from the same image and data disk saw
  `root-fresh` and `kept`. Pass.

### Phase 2: the jail (2026-10-01)

The jailer (`sandcastle-vm jail`, run as `sudo -n systemd-run --scope
--slice=krun-spike.slice`) plans the jail as pure data (refused when it
would leak: a writable mount outside the spike's root, a shared disk
writable, a uid of root's or the node's, a device not on the list), then:

- makes the VM's run directory and writable disks the VM uid's;
- forks a child into new PID, mount, network, IPC, and UTS namespaces;
- builds a tmpfs root holding only:
  - the VM's disks (shared ones read-only);
  - its run directory;
  - the runner, libkrun, and libkrunfw (read-only);
  - the C library's directories (read-only);
  - `/dev/kvm`, `/dev/null`, and `/dev/urandom`;
- pivots into that root and remounts it read-only;
- empties the capability bounding and ambient sets;
- drops to the VM uid, keeping only the `kvm` group;
- sets no-new-privileges and `RLIMIT_CORE` 0;
- installs a seccomp filter (namespaces, mounts, tracing, BPF, keys,
  modules, io_uring, `clone3` answered ENOSYS so `clone`'s flags can be
  filtered);
- execs the runner.

The parent stays root only to wait, then hands the files back to
`ubuntu`. The slice: `MemoryMax=8G`, `CPUQuota=800%`.

- **Escape probe (acceptance 7): pass.** In the jail, as uid 300000 with
  groups `994` (kvm) only:
  - Capabilities: effective and bounding sets both empty;
    no-new-privileges set; seccomp mode 2.
  - Processes: it sees only itself (`/proc` holds PID 1).
  - Root: `config.json dev disks krun lib lib64 proc usr vm`, read-only
    (a write gets EROFS).
  - Not found (ENOENT): `/etc/sandcastle/node.key`, `/etc/sandcastle`,
    `/var/lib/sandcastle`, `/home/ubuntu`, its `.ssh` and `.microsandbox`,
    the spike's own directory, and a second jailed VM's disk.
  - Network: the node's own `:22` and `:443`, and 1.1.1.1, are
    unreachable; `127.0.0.1:3340` (iroh-relay on the host's loopback)
    and `127.0.0.53:53` are refused, since this is the jail's own
    loopback.
  - Refused with EPERM: `mount`, `unshare(CLONE_NEWUSER)`, `ptrace`,
    `setuid(0)`, `chroot`, `bpf`. `clone3` gets ENOSYS.
  - Writes refused: opening libkrun or the boot disk for writing.
  - `/dev/kvm` opens.
- **Boot to ready, jailed, n = 10: median 128.7 ms, range 122.9 to 132.1**
  (unjailed 107.0). The runner's own clock is unchanged (107.3 ms); the
  jail costs about 22 ms, most of it `sudo` and `systemd-run`.
- **Fresh roots, jailed: pass.** Afterwards the VMs' files are `ubuntu`'s
  again.
- **Nothing else moved:**
  - `sandcastled` (PID 932627, up since 18:56:58) and `iroh-relay` (PID
    921147, since 18:41:01) are unchanged, with no restarts.
  - The other session's `msb machine` is untouched.
  - ZFS still has only `tank/sandcastle`, and the nft ruleset's hash is
    unchanged.
  - No spike scope is left.

### Phase 3: exec and exit (2026-10-01, jailed)

Every check passes:

- stdout and stderr arrive separately, with an exit code of 3;
- stdin reaches `cat`;
- 10 MB of stdout arrives whole;
- a PTY reports `24 80`, is resized, then reports `50 120`;
- `SIGKILL` gives the exit signal 9;
- a missing binary is refused ("No such file or directory");
- the 65th process at once is refused ("64 processes at once"), and the
  slots come back once those connections drop;
- an entrypoint that runs `exit 7` is reported as code 7.

Numbers:

- **Exec round trip** (`/bin/true`, from request to its exit, n = 20):
  **median 4.0 ms**, range 1.8 to 4.1. msb: 9 to 20 ms.
- **Kill to exit:** 2.1 ms.
- **The entrypoint's exit to the runner gone:** 20 ms. The VM stops as a
  container does.

### Phase 4: any port (2026-10-01, jailed)

No port is declared anywhere: each connection asks the agent for
`127.0.0.1:<port>` inside the guest.

- **HTTP** to `jmalloc/echo-server:v0.3.7` on an undeclared port (9123):
  the whole request, connection included, takes a **median 4.0 ms**
  (n = 10).
- **A WebSocket through it**: `101 Switching Protocols`, the server's
  greeting, and an echo in 0.2 ms.
- **First byte from a server already listening: 2.7 ms.** Later samples
  read 25 ms, but that is busybox `nc` restarting between connections plus
  the driver's 20 ms retry, not the path.
- **Throughput over 100 MB** is bound by the guest's CPU and libkrun's
  vsock path:

  | vCPUs | `nc` | exec's stdout (no TCP) |
  |---|---|---|
  | 1 | 155 MiB/s | 117 MiB/s |
  | 2 | 197 MiB/s | 217 MiB/s |

  This is enough for web apps and model streams, not for bulk data.
  Larger copy buffers in the agent changed it by 2%.

### Phase 5: the network and interception (2026-10-01, jailed)

**How it is built.** The jailer gives the VM process's network namespace
a tap (10.0.2.2/24, owned by the VM uid) and its own nftables:

- every TCP connection arriving on the tap is redirected to the runner's
  forwarder on `:15001`, and DNS on `:53` to `:15353`;
- the input chain drops everything else;
- the forward chain drops everything.

The namespace has no other interface and no route out. The host's
firewall and its namespace are unchanged.

The forwarder reads `SO_ORIGINAL_DST` and hands each connection or query
over the run directory's unix socket to the node's proxy
(`sandcastle-egress`). The proxy decides:

- **Names** get fake addresses from 198.18.0.0/15, as OpenShell's do, so
  the rules decide by name and the guest never learns a real address.
- **Intercepted hosts** are TLS-terminated with a leaf the node's CA mints
  per name, then sent to the handler or have their placeholders
  substituted.
- **Everything else** is spliced to the real destination after the
  rules, which are Cloudflare's: 128 entries; hosts, globs, addresses,
  `ip:port`, and ranges; private addresses and the node's own refused.

The guest itself has no proxy setting: a static address, a default route,
`/etc/resolv.conf`, and the CA at Cloudflare's path,
`/etc/cloudflare/certs/cloudflare-containers-ca.crt`.

**Acceptance 5: pass.** From `curlimages/curl:8.22.0`:

- **An intercepted HTTPS request handed to a handler, which answers it.**
  `POST https://model.example.com/v1/chat/completions` reached the
  stand-in (labeled "the spike's stand-in for celld's callback route")
  with the method, path, host, scheme, and the request's own
  `Authorization` intact. The request took 2.7 ms median (n = 5, curl's
  `time_total` inside the guest).
- **A placeholder substituted with a value.** `Authorization: Bearer
  SC_PLACEHOLDER_TEST_0001` to `https://httpbin.org/headers` reached
  httpbin.org, over real TLS, as `Bearer sk-test-not-a-real-secret` (a
  labeled test string).
- **Everything else spliced with its real TLS.** `https://example.com/`
  answered 200, with curl verifying example.com's own certificate.
- **Private addresses refused.** `10.0.0.1`, `169.254.169.254` (cloud
  metadata), and the node's own `<node-ip>:22` and `:443` each got
  an empty reply: the forwarder accepted, and the proxy closed.
- **With the internet off:**
  - `nslookup example.com` gets NXDOMAIN;
  - `nslookup model.example.com` gets 198.18.0.1;
  - the handler still answers;
  - `https://1.1.1.1/` by address is refused.
- **A bug the run found:** a connection by name was judged by its fake
  address, which is not public. It is now judged by name, and the real
  address the proxy resolves is checked instead (`Compiled::reachable`).
  The tests cover both.

### Escalation: pause and resume on Linux (decided: no warm tier)

*Paul, 2026-10-01: "I think we're fine without warm... that's parity with
cloudflare anyway."* An idle VM stops and a wake is a cold start. What
comes next is docs/krun-engine.md.

**Finding.** At the pinned libkrun (b63baa18), `krun_vmm_handle_pause`
and `krun_vmm_handle_resume` answer `FeatureDisabled` on Linux:

- The handle's path to the VMM (`VmCtl` to `Vmm::pause`) is compiled for
  macOS (HVF) only, though the header promises pause and resume.
- The Linux vCPU loop already has `Pause` and `Resume` events, and a
  signal that kicks a vCPU out of `KVM_RUN` (Firecracker's, inherited).
  Only the wiring is missing.
- smolvm's fork wires it on Linux, with `KVM_KVMCLOCK_CTRL` so a resumed
  guest's watchdogs do not fire.

The balloon is there on Linux. So the plan's escalation ("no pinned
libkrun offers pause, resume, and the balloon together") holds, and
pause stopped here. Nothing else depends on it, so the other phases went
on.

The options:

1. **A small libkrun patch, upstreamed** (recommended): wire `VmCtl` on
   Linux.
   - `Vmm::pause` sends `Pause` to each vCPU and kicks it out of
     `KVM_RUN`.
   - `resume` sends `Resume` and calls `KVM_KVMCLOCK_CTRL`.
   - Roughly 150 lines with tests, carried as one patch on the pinned
     commit until it merges.
   - This is a real VM pause: memory stays put and the guest's clock is
     told. That is the warm tier msb gave (8 ms).
2. **The cgroup freezer on the VM's own scope** (`systemctl freeze`): no
   libkrun change.
   - The guest is not told it was frozen, so it sees its clock jump.
   - It needs one more root action per pause.
   - An interim, at most.
3. **No warm tier on libkrun until upstream has one.** A cold start to
   serving is 4.4 s here, against msb's 6.0 to 6.2.

Blocked by this, and so not measured: pause and resume times, and a
connection waking a paused VM (acceptance 2). The client's wake path
(`connect_waking`: resume, then connect) is written and waits on it.

### Phase 6: Hermes (2026-10-01, jailed)

`nousresearch/hermes-agent:v2026.9.24` ran as sandcastle runs it on msb:

- its image's s6 `/init /opt/hermes/docker/main-wrapper.sh gateway run`
  is the entrypoint, and inside the workload's PID namespace PID 1 is
  `s6-svscan`;
- its dashboard is on 9119, its health path `/api/auth/providers`;
- `/opt/data` is its own disk (ext4 with a journal);
- 2 vCPUs, 4 GiB, and the balloon;
- a NIC behind the egress proxy: the internet on, model hosts
  intercepted to the stand-in, no model key on the node.

The dashboard's basic-auth values are labeled test strings.

- **The image:** 42 layers, 968 MB compressed, pulled in 14.7 s. A build
  VM unpacked its 107,405 entries in 14.3 s (the largest layer, 404 MB,
  in 4.6 s).
- **Boot to serving (acceptance 1)**, the driver's clock from spawning
  the jailer to the first answer from `/api/auth/providers` over the agent:
  - **median 4.37 s, range 4.26 to 4.45** (n = 9, each a fresh root with
    `/opt/data` already initialized, as msb's cold wake of an existing
    computer has);
  - the first boot, which initialized `/opt/data`, 4.48 s;
  - the guest itself is ready at 224 ms; the rest is Hermes starting;
  - msb: 6.0 to 6.2 s.
- **Exec into Hermes:** 4.0 ms median. A health GET through the port
  path: 4.4 ms median.
- **`/opt/data` kept, the root fresh (acceptance 8, the data half).**
  After a restart, a file written to `/opt/data` was there and one
  written to `/` was not. Pass.
- **Memory (acceptance 6).** Hermes ran serving and then idle, with a
  reclaim at 90 s: the agent's `Reclaim` drops the guest's page cache and
  compacts, smolvm's idea. Measured: the VM process's resident memory
  (its cgroup's charge is within 2 to 9%).

  | Hermes, idle | 0 s | 30 to 90 s | after a reclaim (5 to 45 s on) |
  |---|---|---|---|
  | msb (earlier, no reclaim) | | 892 to 925 MiB | |
  | no balloon (the control) | 634 | 915 | **916** |
  | balloon, the kernel's default reporting (2 MiB blocks) | 633 | 906 | **674** |
  | balloon, `page_reporting.page_reporting_order=0` (4 KiB) | 633 | 844 to 858 | **604** |

  Hermes kept serving after every reclaim (200). Free-page reporting
  alone barely moves an idle Hermes (906 against 915). With a reclaim it
  returns about 300 MiB, a third of msb's figure: 604 against 892 to 925.

  The guest then holds about 470 MB. The rest is the guest kernel's and
  the VMM's own memory, and free pages too scattered to report.

  So the engine should reclaim on idle (the node's idle timer calls it
  before a computer sleeps), and run its guests at reporting order 0.
  The kernel arguments are validated: plain `key=value` only, never a
  root or an init.

### Phase 7: crash and reset (2026-10-01, jailed)

- **A VM ended at once mid-write.** The guest was writing to `/data` in
  a loop, and the runner was ended with `_exit`, as a crash would.
  - It was gone in 32 ms.
  - No VM process, no scope, and no file owned by a VM uid were left,
    because the jailer handed them back.
  - A 64 MiB file written and synced before the crash read back on the
    next start with the same SHA-256. `/data` is ext4 with a journal.
- **The jailer itself killed outright.** `sudo systemctl kill
  --signal=KILL` on its scope (systemd exits 1, "Failed to send signal
  SIGKILL to auxiliary processes", about the runner in its own PID
  namespace) left:
  - its run directory and data disk owned by the VM uid;
  - **no VM process**, since the runner now has `PR_SET_PDEATHSIG(SIGKILL)`.

  The first run, before that was added, showed a runner outliving its
  jailer; reset stopped it, and this run proves the fix. `reset` (stop
  the slice, restore, remove) handed 11 entries back and left nothing:
  no processes, no scopes, no files owned by a VM uid, no run directories.
- **Nothing else moved (acceptance 10).** Compare the node's before and
  after snapshots (`lat6-before.txt` with `lat6-after.txt`, kept in
  fragment's history, not here):
  - `sandcastled` (PID 932627, up since 18:56:58) and `iroh-relay` (PID
    921147, since 18:41:01) have zero restarts each.
  - The other session's `msb machine` (PID 1028699) and its paused
    computer are untouched.
  - Listening sockets are the same, and the nftables and iptables hashes
    are the same. There is no named network namespace.
  - ZFS gained two snapshots of the other session's computer
    (`@sc-8-auto`, `@sc-9-pause`), taken by `sandcastled` itself; the
    spike never ran `zfs`.
  - What remains of the spike is `/home/ubuntu/krun-spike` (sources, the
    prefix, binaries, and 3.8 GB of cached images and blobs that `reset
    --all` removes), and an empty `krun.slice`: systemd made it as the
    parent of `krun-spike.slice`, and it is gone at the next reboot.

### Acceptance

| # | What | Result |
|---|---|---|
| 1 | Boot | busybox **107 ms** (jailed 124 to 129); Hermes to serving **4.37 s** (msb 6.0 to 6.2) |
| 2 | Pause and resume, a wake on connection | **Blocked: escalated** (libkrun pauses on macOS only) |
| 3 | Exec | **4.0 ms** round trip (msb 9 to 20); PTY, resize, stdin, kill, codes, limits; the entrypoint's exit stops the VM |
| 4 | Any port | HTTP and WebSocket undeclared; first byte 2.7 ms; about 200 MiB/s on 2 vCPUs |
| 5 | Interception | Handler, substitution, splice, refusals, the internet off: all pass, with no proxy setting |
| 6 | Memory back | Idle Hermes **604 MiB** after a reclaim at 4 KiB reporting (msb 892 to 925) |
| 7 | Isolation | The escape probe reaches nothing; its own uid, no capabilities, seccomp |
| 8 | Fresh roots | Pass (busybox and Hermes), `/data` and `/opt/data` kept |
| 9 | The build | clippy `-D warnings` and every test, whole workspace, on the Mac and on Linux; CI on the draft pull request |
| 10 | Nothing else moved | Pass |

### What would ship differently (the ledger, if this goes on)

- **Pause and resume**, per the escalation.
- **The seccomp filter is a denylist.** An allowlist built from what
  libkrun actually calls is stronger: smolvm's approach, with
  seccompiler.
- **The forwarder runs as threads in the runner**, inside the VMM's own
  jail. A small process of its own in the same jail would keep it apart
  from libkrun.
- **The jailer runs through `sudo` and `systemd-run`**, costing about 22
  ms a start. sandcastled would run it directly, as a root helper it owns
  (the privilege model is Paul's call either way).
- **Image builds skip xattrs**, so file capabilities are lost, and skip
  device nodes. zstd layers are decoded as one frame.
- **The runner's exit status is libkrun's, not the entrypoint's.** The
  entrypoint's code travels over the lifecycle channel, which is what
  the node reads.
- **Throughput through a guest port is vsock-bound** (about 200 MiB/s on
  2 vCPUs). Enough for web and model traffic. A bulk path would want
  virtio-net ingress.
- **The handler is a stand-in.** celld's callback route
  (docs/background.md, The bar) is the real one.
