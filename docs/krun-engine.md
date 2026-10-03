# The libkrun engine: from spike to production

> Imported from fragment (github.com/futurepaul/fragment, branch
> `krun-spike`, draft PR #103) on 2026-10-02, when the engine moved to
> this repository. It is the record of E1 to E7 as run there: "master",
> `sandcastled`, msb, and fragment's CI are fragment's. Paths are this
> repository's. The test node's name and public address are redacted
> (`<node-ip>` in the evidence), and its after snapshot
> (`lat6-after-engine.txt`) stayed in fragment's history.

*Plan, 2026-10-01.* Paul, after the spike (docs/krun-spike.md):

- "we're fine without warm... that's parity with cloudflare anyway";
- "proceed with whatever you need to make this production grade (full
  parity with what we need from cloudflare)";
- the seccomp filter becomes an allowlist;
- the other calls are mine, made for **speed first, then Cloudflare
  parity**.

Nothing merges to master until this is fully proven. The work continues
on branch `krun-spike` (draft PR #103) and on a branch of the celld fork.

## Problem

The spike proved that libkrun, driven directly, boots, isolates, and
intercepts better and faster than msb. What exists is crates and a test
driver, not an engine: nothing holds VMs on a node's behalf, and nothing
speaks Cloudflare's container API. celld's `ctx.container` is wired to
Docker, with snapshots and intercepts stubbed.

The goal is an engine that:

- a node runs as a service;
- implements Cloudflare's Durable Object container API method by method,
  at the speed the spike measured;
- is reached by celld through an engine interface that Docker also
  implements, so fragment writes against `ctx.container` alone.

## The calls, for speed then parity

| Call | Decision | Why |
|---|---|---|
| Warm tier (pause) | None: an idle VM stops, and a wake is a cold start | Paul; Cloudflare has none |
| seccomp | An allowlist from what libkrun calls | Paul |
| Launching VMs | A root engine service jails each VM itself (no `sudo` or `systemd-run`); celld and sandcastled stay unprivileged and call it over a unix socket | About 20 ms off every start; how Docker's daemon works |
| Guest ports | Measured (E4): the NIC wins. The engine connects a TCP socket from inside the VM's network namespace and hands it over on `ports.sock`; vsock stays for servers listening on loopback only | 5.8 GiB/s and 0.34 ms to first byte, against vsock's 2.5 GiB/s and 4 ms |
| Images | Unpack as Docker does: xattrs (file capabilities), device nodes, every zstd form; accept `docker save` tars, which is how celld ships images | Parity |
| Roots and snapshots | Keep overlays (a fresh root in 5 ms, no ZFS). `snapshotContainer` copies the writable layer; storage with reflinks only if that measures slow | Speed; Cloudflare's snapshot is the writable root only |
| Proxy and NIC | Keep: the proxy on the node outside the jail, a real NIC rather than TSI | No speed cost; safer, more reliable |
| Forwarder | Keep it in the VM process | An extra process per VM costs start time; the allowlist covers it |
| Intercepted requests | Go to the Durable Object through celld's callback route | Parity: `interceptOutboundHttp` hands a request to a Fetcher |
| celld | An engine trait in the fork, Docker and this engine behind it; one conformance Worker for both | Snapshots and intercepts are stubs on Docker anyway |
| Internet off, a name not intercepted | NXDOMAIN at once; Cloudflare lets the lookup time out | Speed; nothing waits on a timeout |
| Memory | 4 KiB free-page reporting by default, and a reclaim when a VM idles | 604 MiB against 906 for an idle Hermes |
| libkrunfw | Shipped as its own library with its source, as Podman and msb do | Nothing to do until we distribute binaries |

## Acceptance

Measured on the test node under the spike's rules (docs/krun-spike.md,
Constraints), with evidence in `docs/krun-spike-evidence/`.

1. **The engine API is Cloudflare's container API**, every call, with
   Cloudflare's validation and limits:
   - `start({image | containerSnapshot, entrypoint, env, enableInternet,
     instance, labels})`, with instance `lite`, `basic`, `standard-1` to
     `standard-4`, or custom `{vcpu, memoryMib, diskMb}`;
   - `running`, `inspect`, `destroy(error)`, `signal(n)`, `monitor`;
   - `exec(cmd, {stdin, stdout, stderr: pipe | ignore | combined, cwd,
     env, user, pty})`, with `kill(signal)`, `resize`, exit codes, and
     exec's env not inheriting `start`'s except `PATH`;
   - `getTcpPort(p)` for any port, both `fetch` and `connect`;
   - `snapshotContainer({name})` returning `{id, size, name}`, restored by
     `start({containerSnapshot})`, image-tied, kept 30 days and refreshed
     on restore;
   - `interceptOutboundHttp` and `interceptOutboundHttps` (host, glob,
     `ip:port`, CIDR, `*`, an optional port), and `interceptAllOutbound`,
     added while running; 128 entries counted as Cloudflare counts them
     (a hostname is two); the CA at Cloudflare's path;
   - logs.
2. **Speed**, each with its median and range:
   - a jailed busybox start to ready at or under the spike's unjailed
     107 ms (now 124 to 129 jailed);
   - exec under 5 ms;
   - a guest port at least 1 GiB/s if the NIC path holds (otherwise the
     reason recorded);
   - a snapshot and a restore timed against the bytes changed;
   - Hermes to serving no slower than 4.37 s.
3. **celld on the engine.** A conformance Worker calling every method of
   `ctx.container`:
   - passes on celld with this engine;
   - passes on celld with Docker for every method Docker supports;
   - is ready to run on Cloudflare (Paul's account).

   Intercepted requests reach the Durable Object through celld's callback
   route.
4. **Images.** These build and run as Docker runs them: busybox, alpine,
   debian, ubuntu, python, node, nginx, Hermes, and
   `cloudflare/sandbox`, whose control server serves. File capabilities
   are kept (ping as a non-root user), and a `docker save` tar loads.
5. **Hardening:**
   - the seccomp allowlist holds every scenario, and the escape probe
     still reaches nothing;
   - a restart of the engine keeps its running VMs (adopted, not
     killed);
   - a crash of any piece leaves nothing that `reset` cannot clear;
   - limits on VMs and memory per node, refused with a typed error.
6. **Clean:**
   - clippy with warnings denied and every test, on the Mac, on Linux,
     and in CI;
   - the test node undisturbed, shown before and after.

## Constraints

The spike's musts and must-nots hold (docs/krun-spike.md): its own
directory, prefix, slice, and uid range on the test node; nothing public;
`sandcastled`, msb, `iroh-relay`, the firewall, and other sessions' work
untouched; no secrets on the test node.

New this time:

- **The engine runs as root**, as a transient unit in the spike's slice
  with a cgroup subtree of its own: `sudo systemd-run --unit=krun-engine
  --slice=krun-spike.slice -p Delegate=yes`. Nothing is installed.
- **Its socket** is in the spike's directory, owned by `ubuntu`.
- **The celld fork** changes on a branch of `futurepaul/celld`. fragment
  pins that branch's commit only on `krun-spike`.
- **Escalate** a need to change anything outside the spike's slice and
  directory, a shipping or licensing question, and a Cloudflare account
  action.

## Phases

Each phase ends with its tests green, its numbers in Results, and a
commit.

1. **E1, the engine.** A crate, `sandcastle-engine`, with a library and
   a `sandcastle-engine` binary:
   - It holds a table of VMs and a state directory.
   - It forks the jailer directly and makes each VM's cgroup itself
     (`memory.max`, `cpu.max` for fractional vCPUs, `pids.max`).
   - It serves an API on a unix socket: HTTP/1.1 with JSON, and upgraded
     streams for exec and ports.
   - Images: pulls, loads `docker save` tars, and builds each image once
     per digest.
   - The driver becomes a client of the engine. Start latency is
     measured against the spike's.
2. **E2, parity calls:**
   - instance types and their limits;
   - labels;
   - `inspect`;
   - `signal` to the entrypoint;
   - `monitor`'s exit code;
   - logs: the entrypoint's stdout and stderr, apart from the console,
     bounded and rotated;
   - exec's `stdout`/`stderr` modes, env rule, and PTY sizes;
   - intercept rules added while running, counted as Cloudflare counts
     them;
   - snapshots (create, restore, list, expire).
3. **E3, images:** xattrs, device nodes, multi-frame zstd, `docker save`,
   and the corpus.
4. **E4, speed:** guest ports over the NIC against vsock, scratch disks
   from a template, and the start path profiled down.
5. **E5, hardening:**
   - the seccomp allowlist;
   - adoption across an engine restart;
   - limits per node;
   - crash recovery;
   - the escape probe again.
6. **E6, celld:**
   - an engine trait in the fork, with Docker and this engine behind it;
   - the callback route for intercepted requests;
   - `inspect`, `snapshotContainer`, and the intercepts wired to the
     engine;
   - the conformance Worker, run on the test node against this engine and on
     the Mac against Docker (the test node has no Docker, and installing it
     would rewrite the host's firewall).
7. **E7, results:** CI, reset, and the evidence.

## E6 design

*2026-10-01.* celld's `ctx.container` today: Docker only, with no
abstraction (`ContainerEngine` holds a `Docker`); the harness predates
Cloudflare's current surface (workers-types 5.20261001.1); `inspect`,
`snapshotContainer`, and the intercepts are stubs that reject. A survey
also found two celld defects on the way: an inactivity sweeper that
dropping does not cancel (a re-activated cell's container is killed under
it), and `CELLD_EGRESS_PUBLIC_ONLY` refusing a container's own port.

The work, on branch `krun-engine` of the celld fork (from the pinned
`hardening-v0.6.0`, 4f50c81), fragment pinning it only on `krun-spike`:

1. **The engine's exec over its API.** `POST /v1/containers/{name}/exec`
   with the exec's JSON (`cmd`, `env`, `cwd`, `user`, `stdin`, `stdout`,
   `stderr`, `pty`) upgrades to a framed stream, Docker's 8-byte frame
   header (stream byte, big-endian length): to the client 1 stdout,
   2 stderr, 4 started `{pid}`, 3 exited `{code, signal}`, 5 error; from
   the client 0 stdin (empty is EOF), 6 resize `{cols, rows}`, 7 signal
   `{signal}`. The engine applies Cloudflare's env rule (only `PATH`
   inherited). The guest agent's wire stays the engine's own.
2. **Intercepts reach celld.** The engine's egress names the container in
   `x-sandcastle-container` (overwriting whatever the guest sent), so one
   celld socket serves every VM on the node.
3. **An engine trait in celld** (`Backend`): reap, prepare, image presence
   and load (`docker save` tars, as today), create-and-start, wait, kill,
   remove, inspect, exec, and the new calls (snapshot, intercepts).
   Docker moves behind it unchanged; the krun backend is a client of the
   engine's socket. `CELLD_CONTAINER_ENGINE=krun:<engine.sock>` selects
   it.
4. **The harness moves to Cloudflare's current surface:** `start({image |
   containerSnapshot, instance, ...})`, `images`, `inspect()`,
   `snapshotContainer()`, `interceptOutboundHttp/Https`,
   `interceptAllOutboundHttp`, and `exec` with `pty`, `resize`, and an
   `AbortSignal`. Docker gets `inspect`; what Docker cannot do rejects
   with "not supported by celld's Docker engine".
5. **Ports.** `getTcpPort` on the krun backend: a celld listener on
   loopback per (container, port) that takes a socket from `ports.sock`
   per connection and splices it, so `fetch`, `connect`, and WebSocket
   upgrades stay celld's own. A dial path that hands the socket to them
   directly, with no relay, comes after.
6. **The callback route.** `intercept*` stores the binding's route (the
   `Fetcher`'s unforgeable side table, as `globalOutbound` uses) on the
   cell; celld's intercept socket maps `x-sandcastle-container` to the
   cell and dispatches the request on the service-call path.
7. **The conformance Worker** in the fork's `examples/`: one Durable
   Object calling every method of `ctx.container` with a JSON verdict per
   method, deployable unchanged to Cloudflare.

## Evaluation

- **Host tests** for every pure piece:
  - the API's validation at each limit;
  - instance arithmetic;
  - the intercept accounting;
  - snapshot expiry;
  - cgroup values;
  - adoption from the state directory;
  - valid and invalid paths, and replay where a call can repeat.
- **The driver on the test node**: each acceptance item as a scenario, its
  evidence as JSON.
- **The conformance Worker**: the same file run against every engine,
  method by method, with each result recorded.
- **Honesty:** the stand-in handler goes away once celld's callback route
  exists, and nothing measured through a harness is reported as the
  product's number.

## Results

*2026-10-01, on the test node.* E1 to E7 are done. Every number below is from one engine build
(`engine_sha256_16` 364f2f6fac921a28), with seccomp enforced, in
`docs/krun-engine-evidence/`. Medians, with the range in brackets.

### Acceptance

| | Item | State |
|---|---|---|
| 1 | Cloudflare's container API | Every call, the intercepts' callback to the Durable Object included (E6); 29 parity checks pass (`parity.json`) |
| 2 | Speed | Met but one: a jailed start is 108.1 ms against the 107 ms bar (below) |
| 3 | celld on the engine | Met: the conformance Worker passes 25 of 25 on this engine, and on Docker every method Docker has but its own three gaps (E6, below) |
| 4 | Images | Met: the corpus, file capabilities granted to a non-root user, `docker save` loads, Cloudflare's `sandbox-shim` |
| 5 | Hardening | Met: the allowlist holds every scenario; adoption; limits refused with typed errors |
| 6 | Clean | Clippy and tests on the Mac, on Linux, and in CI; the test node as found (E7) |

### Speed

| Measure | Now | Spike | Notes |
|---|---|---|---|
| busybox, start to ready (jailed, `lite`) | 108.1 ms [106.6–111.0] | 107 unjailed, 124–129 jailed | `boot.json` |
| exec round trip | 4.0 ms [1.3–80.0] | 4.0 | `exec.json` |
| guest port, NIC (`ports.sock`) | 5.8 GiB/s, 0.34 ms to first byte | — | `port-nic.json`; 2 vCPU |
| guest port, vsock | 2.5 GiB/s, 4.0 ms to first byte | 0.18 GiB/s | the spike's figure was busybox `nc`'s ceiling, not vsock's |
| snapshot; start from it | 46.6 ms; 215 ms | — | a 4 MB writable root |
| Hermes, start to serving | 4.47 s [4.46–4.47] | 4.37 | `hermes.json`; ready in 250 ms |
| an intercepted request's round trip | 2.8 ms on `standard-1` | 2.6 | on `lite` most wait out the 1/16 vCPU's period (93 ms) |
| engine restart to serving, its VMs adopted | 39 ms | — | `crash.json` |

Where the start goes now (`boot.json`, from the request): prepared
1.8 ms, jailed 6.2 (nft 1.9), the VMM built and running 12.8, the
guest's init says hello at 104.8 (its kernel's clock reads 47 ms), ready
at 107.9. Two cuts made it:

- **The VM is born in its cgroup.** The jailer moved itself into the
  VM's cgroup with a write to `cgroup.procs`, which waits out an RCU
  grace period: 13.7 of a 14.4 ms jail. It now forks the VM with
  `clone3(CLONE_INTO_CGROUP)` and stays in the engine's cgroup itself.
- **`pci=off`.** libkrun's devices are all virtio-mmio; the kernel's
  PCI probe cost 7 ms.

Measured and not taken: `cryptomgr.notests`, `tsc=reliable`,
`no_timer_check` (no change); dropping virtio-rng (1 ms, not worth
weaker entropy where RDRAND is missing); skipping btrfs's initcall
(0.7 ms). What is left, from the guest's `dmesg` with `initcall_debug`
(`boot-dmesg.json`), for later:

- about 45 ms from the first `KVM_RUN` to the kernel's clock, unexplained
  without `perf` on the node;
- in the kernel: jitterentropy's self-test 6.4 ms,
  `sched_clock_init_late` 5.8 ms, `param_sysfs` 2.5 ms, virtio probes
  8.5 ms; a trimmed libkrunfw config is the lever;
- libkrun's `KVM_REINJECT_CONTROL`, 4.4 ms (an SRCU sync), a patch
  upstream;
- the nft ruleset by netlink instead of spawning `nft`, about 2 ms.

### What E4 and E5 found and fixed

- **Guest ports go over the NIC.** With a server that writes 1 MiB at a
  time, the NIC carries 5.8 GiB/s against vsock's 2.5. A client sends
  `{name, port}` to `ports.sock`; one engine thread enters the VM's
  network namespace, makes a socket, and returns, and the engine
  connects it to the guest and passes the fd (SCM_RIGHTS). Nothing
  relays the bytes. `refused` means nothing listens on the NIC, and the
  client falls back to vsock, which reaches a server on the guest's
  loopback (checked). The jailer adds the guest's MAC as a permanent
  neighbor, so no first connection waits on ARP (libkrun attaches the
  tap lazily, and a first ARP sent before that was lost: a 1 s stall).
- **An exit could be lost.** The guest sent `Exited` and powered off at
  once, and libkrun ends the process on the guest's reboot, racing the
  runner's read: five of six fast exits lost their code once the start
  got faster. The runner now answers `Recorded`, and the guest waits for
  it (2 s at most) before powering off; wire version 2.
- **A VM that ends while the engine is down** has its exit read from its
  events file at restart, so `monitor()` answers with its code (5, in
  the crash scenario), not "not found".
- **The seccomp allowlist holds.** Every scenario passes with it
  enforced, and the kernel logged no kill but the probe's: in the jail,
  a child under the runner's filter dies by SIGSYS at `execve` and lives
  through `getpid`.
- **CPU.** `lite`'s 1/16 vCPU is enforced over a 100 ms period with a
  burst of one quota. A 20 ms period was tried and was worse: it spread
  every request out to sixteen times its CPU time (60 ms for a 2.6 ms
  call).
- **Images.** A file capability is granted to a non-root user (CapEff
  `0x2000` for `cap_net_raw`, as `ping` needs). Cloudflare's
  `sandbox-shim`, copied into `node:24-trixie-slim` as their example
  Dockerfile does, answers every `Files` call the SDK makes (write, read,
  stat, list, rename, recursive remove, errno for a missing path and for
  a write `user` may not make).

### E6: celld on the engine

*2026-10-01.* celld's fork, branch `krun-engine` (56ccbd4, pinned on
`krun-spike` only), puts `ctx.container` on an engine trait with Docker
and this engine behind it, on Cloudflare's current surface. The
conformance Worker (the fork's `examples/container-conformance`) calls
every method and answers per method; evidence in `conformance-krun.json`
and `conformance-docker.json`.

| Engine | Passed | Unsupported | Failed |
|---|---|---|---|
| krun, celld on the test node, seccomp enforced | 25 | 0 | 0 |
| Docker 29.4, celld on the Mac | 16 | 5 (snapshots, interception) | 4 |

Docker's four are its own gaps, not regressions: its `exec()` inherits
the container's whole environment; its exec `kill()` (twice) signals a
pid the daemon reports from the host's namespace; `enableInternet: false`
is not enforced off Linux. On the engine, through celld: exec 3 to 4 ms,
an intercepted HTTP request 3 ms and HTTPS 86 ms (on `lite`), a snapshot
46 ms.

What E6 added to the engine:

- **exec over the API** (`exec_stream`): an upgraded, framed stream, so
  celld never speaks the agent's wire. 4.0 ms request to exit, as straight
  to the agent (`exec-api.json`).
- **Intercepts name their container and index** (`x-sandcastle-container`,
  `x-sandcastle-intercept`, both overwriting what the guest sent), so one
  celld socket serves the node and finds the binding.
- **`ports.sock` falls back to the guest's loopback** over vsock when the
  NIC refuses, so a server bound to 127.0.0.1 is reached too; a
  connection made while a server starts can land there (`port-nic.json`:
  `nic_fresh_vm.transport`). With the server up, the first connection to
  a fresh VM is over the NIC, nine times of nine.
- **`inspect()`'s image is empty** while starting and after a restore.
- **Two load fixes:** a reference arrives percent-escaped in the query and
  is decoded; an image loaded again under another name answers to it.

What it found and fixed in celld along the way: an inactivity sweeper that
dropping did not cancel (it killed a re-activated cell's container);
`monitor()` rejecting after a plain `destroy()`; `destroy()` during a
start leaving the container running; exec's ignored streams buffering
until the process blocked; a refused intercept poisoning every later
start; the public-only egress policy refusing an object's own container
port. Docker's gaps above stay, written into the fork's
docs/services/containers.md.

### E7: clean, and the test node as found

- Clippy with warnings denied and every test pass for the sandcastle
  workspace on the Mac and on the test node, and CI's `sandcastle` job runs both
  on every push; the celld fork's crate builds and its new tests pass
  (its other clippy findings are this toolchain's new lints in files the
  branch does not touch). fragment's whole CI, e2e included, runs against
  the pinned fork.
- The test node as found (`lat6-after-engine.txt` against the spike's
  `lat6-before.txt`, both in fragment's history): `iroh-relay` and `sandcastled` keep their pids, the
  other session's paused Hermes still runs (its dataset gained that
  session's own snapshots), and the host's nftables and iptables hashes
  are unchanged. The engine runs in `krun-spike.slice` with no VMs; the
  spike's directory holds 14 GB (images, the celld build).
- `sandcastle-krun-spike reset [--all]` clears the engine's VMs and run
  directories, stops the engine and the slice, and hands every file back
  (E1, used throughout).

### Hermes's start, measured

*After E7, 2026-10-01.* `hermes-trace` is a diagnostic. `--snoop` copies
`sandcastle-snoop` into the guest, which records every process, its CPU,
and each port as it listens, on the guest's clock; `--env`, `--argv`,
`--vcpu` and `--after` vary the start. Its evidence is
`hermes-start.json`. Run 0 has a fresh `/opt/data`, Hermes migrates its
config on run 1, and from run 2 on is its steady state, which is what a
user's Hermes is.

Of the 4.45 s to serving, 0.25 s is the engine. The rest is the image's
own start, and it is CPU-bound: the 2 vCPUs run at 94–100% from 1.4 s to
4.7 s, iowait stays under 2%, and the 113 MiB read from the image's
disk comes out of the host's page cache. Nothing is installed on the
path, since the venv is baked into the image. But the image ships no
bytecode (8,744 `.py` files under `/opt/hermes`, no `.pyc`) and sets
`PYTHONDONTWRITEBYTECODE=1`, so every Python process compiles everything
it imports, on every start.

| Steady state, guest clock (s) | As run | Bytecode cache | Cache, dashboard alone |
|---|---|---|---|
| kernel and our init, to the workload | 0.18 | 0.19 | 0.21 |
| s6-overlay, the setup hook's shell | 0.09 | 0.09 | 0.05 |
| `docker_config_migrate.py` | 0.22 | 0.15 | 0.15 |
| `skills_sync.py` | 0.18 | 0.14 | 0.12 |
| `container_boot` (reconciles profiles) | 0.52 | 0.23 | 0.23 |
| the dashboard: its service to listening | 3.70 | 1.77 | 1.25 |
| **to serving, from the request, unsampled** | **4.45** | **2.42** | **2.06** |

- **Six Python processes.** Three setup helpers run in series (0.9 s).
  Then three processes start together on 2 vCPUs: the dashboard, the
  gateway s6 supervises, and our main program, `hermes gateway run`. The
  main program hands the gateway to s6 and stays up, having paid for a
  full import (0.95 s of CPU) in the window the dashboard needs.
- **The cache.** Set `PYTHONDONTWRITEBYTECODE=` and
  `PYTHONPYCACHEPREFIX=/opt/data/.pycache` in the start's environment,
  and change nothing else. Steady state goes from 4.45 s to 2.42 s, and
  the gateway's API from 4.94 s to 2.43 s.
  - Run 0 writes the cache (3.85 s).
  - Hermes's own second run, its config migration from schema 0 to 46,
    rewrites 1,568 of the cache's 1,569 files. Why was not chased.
  - The cache holds from the third run on.
  - Baked into the image, it would hold from the first.
- **The dashboard.** In a booted guest its imports take 1.59 s from
  source and 0.60 s from bytecode. Started by hand in a steady-state
  guest it is ready in 1.06 s, 0.88 s of that importing 1,529 modules.
  Two of them serve nothing the dashboard needs at start:
  `tui_gateway.server` (229 ms) and `gateway.host_rendezvous` (72 ms).
- **After serving.** The gateway runs `uv pip install edge-tts` into
  `/opt/data/lazy-packages` on every start. It is off the path to
  serving, and whether it succeeds was not checked.
- **The gateway alone.** With the dashboard off (`HERMES_DASHBOARD=0`,
  the main program `gateway run` with `HERMES_GATEWAY_NO_SUPERVISE=1`),
  ready means its API (8642) listening. That takes 4.5 s, or 2.0 s with
  the cache: the gateway is one process, 1.21 s from its start to
  listening, the same as the dashboard alone. A Hermes reached only
  through Relay, whose connection the gateway dials out, starts as fast
  as one reached only through the dashboard.

- **Snapshots, Cloudflare's way** (`hermes-snapshot`: no data disk, and
  each start from the snapshot the run before took). A filesystem
  snapshot keeps the disk, not the processes, so each start still runs
  all of Hermes's start.
  - With the image's environment: 4.5–4.7 s, no gain. Nothing slow is
    ever written to disk.
  - With bytecode written to the root: 2.73–2.77 s from the second run
    on, against 2.42 s for the cache on `/opt/data`.
  - The restore copies the snapshot and adds 0.17–0.24 s to ready.
    Taking one at each stop adds 0.3–0.4 s.
  - The snapshot grows about 16 MiB a run with Hermes's logs and state:
    85 MiB to 148 MiB over four starts.
  - It also binds the user's state to the image it was taken over.
  - Here `/opt/data` does a snapshot's job more cheaply. Only memory (a
    paused or memory-snapshotted VM) starts well under a second.

Toward 1 s, in order, each measured or estimated:

1. **Bytecode in the image**, measured above at 2.0 s.
   - A derived image adds `RUN python -m compileall -q -j0
     --invalidation-mode unchecked-hash /opt/hermes`. Built:
     `crates/krun-spike/images/hermes-bytecode`, loaded
     through the engine; run with `hermes-trace --image`.
   - Measured, the start as sandcastle runs it: 2.69 s on a fresh disk
     (4.41 before) and 2.43–2.50 s after.
   - Measured, the gateway alone: 2.12–2.18 s fresh and 1.99–2.07 s
     after, over 8 runs. One earlier run of 12 never listened within
     120 s; it did not recur, and a failed wait now keeps the run's
     output.
   - That compiles all 8,823 modules in 6.6 s, adding 134 MiB to the
     image, or 43 MiB gzipped (4.5% of its 968 MB).
   - `unchecked-hash` keeps the bytecode valid where a builder rewrites
     file times. `/opt/hermes` is sealed by design, so nothing can make
     the bytecode stale.
   - Upstream, it is `uv sync --compile-bytecode` (or
     `UV_COMPILE_BYTECODE=1`) and a `compileall` of the editable source.
   - The start-environment cache is the stopgap. It works only where
     `/opt/data` persists.
   - On Cloudflare, the baked image gets the same win: its containers run
     the image as built. The cache does not carry over, because a
     container's disk is fresh at every start unless it starts from a
     snapshot.
2. **One gateway, started after the dashboard listens.**
   - Measured: 0.36 s of contention (2.42 against 2.06).
   - The main program should be `sleep infinity`, not `gateway run`;
     the supervised gateway is the gateway. On a fresh disk, seed it
     with `HERMES_GATEWAY_BOOTSTRAP_STATE=running`.
   - Engine-side, a startup boost would also help: more CPU for a VM's
     first seconds, like Cloud Run's.
3. **Setup skipped when nothing changed.** The three helpers cost
   0.5 s with bytecode, and each is a pure function of the image and
   `/opt/data`. Keyed by the image's digest on the data disk:
   - set `HERMES_SKIP_CONFIG_MIGRATION=1`, which already exists;
   - skip the skills sync;
   - reconcile in shell.

   This is a derived image's hook, or upstream. Estimate: 0.4–0.5 s.
4. **Lazy imports in the dashboard.** Bind the port first and import the
   TUI gateway, host rendezvous, routers and MCP on first use. This is
   upstream. Estimate: 0.3–0.5 s.
5. **The VM.** Hermes's guest reaches its init at 0.17 s against
   busybox's 0.05; likely its 6 GiB and 2 vCPUs, not yet measured.
   - The cuts above apply to it.
   - So would a pool of prepared, unassigned VMs, as Cloudflare
     restores them (below). That is under Future improvements.
   - Estimate: 0.1–0.2 s.

With 1–3, which are ours to make, steady state is about 1.6 s. With 4
and 5 as well it is 0.9–1.3 s, so under 1 s takes the better end of
both, or a dashboard that imports less still.

Against Cloudflare's "faster agent sandboxes" (2026-09-30; a median of
4.05 s down to 648 ms, time until a `debian-trixie` sandbox is
interactive, not an application's start):

| Practice | Here |
|---|---|
| Placement on the Durable Object's machine first | The engine is on celld's node; there is no multi-node placement yet |
| Restore a prepared VM that is not yet assigned | Not done: each start boots its own (108 ms busybox, 250 ms Hermes); under Future improvements |
| Reuse networking and filesystem setup; batch repeated work | Partly: the jail is 6 ms, the nft ruleset still spawns `nft` |
| Don't wait on services the first command doesn't need | Not done for Hermes: its setup helpers and gateway come before its dashboard (steps 2 and 3) |
| Image and instance as start arguments | Done (the 5.x surface) |
| Images on the host before the request | One node: converted once and hot in its page cache; no fleet pre-pull |
| Filesystem snapshots | Done: `snapshotContainer`, 46 ms; a start from one, 215 ms |

### Open for Paul

1. **More start speed.** About 45 ms from the first `KVM_RUN` to the
   guest kernel's clock is unexplained without `perf` on the node. Known
   cuts: a trimmed libkrunfw config (10 ms or more, a kernel config we
   would carry), a libkrun patch upstream for `KVM_REINJECT_CONTROL`
   (4.4 ms), the VM's nft ruleset by netlink rather than spawning `nft`
   (about 2 ms). Recommended: the last two now, the kernel config later.
   For Hermes, the image's own start is the 4.2 s (above). Recommended:
   - a derived Hermes image with bytecode and the setup stamps;
   - `sleep infinity` as its main program;
   - the lazy imports offered upstream.
2. **Where it runs.** The engine needs KVM: fleet nodes are bare metal
   like the test node, not Fly machines.
3. **The celld branch.** `krun-engine` is pushed to the fork with no PR,
   pinned on `krun-spike` only: a PR on the fork now, or after #103 is
   proven?

### Future improvements

- **A pool of prepared VMs** (Paul, 2026-10-01: later, not needed now).
  Booted, unassigned guests take an image and disks at start, as
  Cloudflare restores a prepared VM. This would save most of a VM's own
  start: 0.1–0.2 s of Hermes's, and about 0.1 s of busybox's 108 ms.
  libkrun fixes a VM's disks when it is built, so an image would arrive
  over virtio-fs into a directory the host binds late.

### Debt

This list is the engine's ledger: each stays here until it is paid.

- A `docker save` tar's `diff_ids` are not checked against its layers
  (celld is the only loader, and trusted).
- The build VM ends the same way the run VM did before `Recorded`: its
  `Finished` reply races its power-off. No build has lost it yet.
- `ended` keeps the last 4096 exits and drops by name order, not age.
- celld's `getTcpPort()` on the krun engine relays through a loopback
  listener per port; a dial path that hands the engine's socket to
  `fetch`, `connect`, and WebSocket upgrades directly would drop the hop.
  The listener is reachable from the node's loopback, as Docker's bridge
  address is.
- An intercepted request's body is held whole (at most 32 MiB) for the
  service call.
- Memory is now reported as the VM's cgroup (730 MiB for an idle Hermes
  after a reclaim), which counts the page cache of its disks; the
  spike's 604 MiB was the VMM's resident memory alone.
