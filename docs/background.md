# Background: why libkrun, and the bar

> Condensed on 2026-10-02 from two fragment docs on its branch
> `krun-spike`: `docs/sandcastle-on-libkrun.md` (an investigation) and
> `docs/containers-on-celld.md` (an audit), both of 2026-09-30. Kept here
> is why the engine exists and the bar it is held to. Their plans for
> sandcastled, msb, and the celld fork's own changes and security
> findings stayed with fragment, and the msb-era control plane was cut.

## Why libkrun

sandcastle, fragment's self-hosted computers, first ran its microVMs
through microsandbox's `msb` CLI, and fought it:

1. **The CLI is the boundary.** Every engine call is a subprocess, parsed
   from text or JSON, across msb versions.
2. **A sandbox outlives its entrypoint.** `msb create` keeps the VM up
   whatever the entrypoint does, and `msb wait` reports no exit code.
3. **Ports** are set at create, and `msb modify` cannot add one; the host
   has no route to a guest's address.
4. **Interception** substitutes a secret's value and cannot hand a
   request to code.
5. **Pause.** A flushed pause is refused for an image whose init takes
   PID 1.
6. **Memory.** A guest's freed memory is never returned: a warm Hermes
   held about 900 MiB.
7. **Isolation.** The VM process (the libkrun VMM) ran as the node's user,
   with no seccomp, in the host's user, mount, network, and PID
   namespaces. libkrun's own security model says the guest and the VMM
   share one security context and the host must isolate the VMM, so a
   guest that escaped into its VMM was the node's user.

Most of these are msb's product choices (a sandbox as a long-lived thing
you exec into, substitution as the swap, a CLI as the API), not limits of
libkrun. libkrun's C API (a builder) gives directly:

- vCPUs and memory, and libkrunfw's bundled kernel as the payload;
- virtio-blk disks, virtio-fs, virtio-net (a tap, among others), vsock,
  consoles, a balloon with free-page reporting, rng;
- a handle usable from another thread (pause and resume are wired on
  macOS only at the pinned commit: docs/krun-spike.md, Escalation);
- `krun_vmm_run`, which takes over its process: one process per VM;
- TSI as an alternative to a NIC (not used here: docs/krun-spike.md,
  smolvm's evidence).

It has no memory snapshot, and Cloudflare has none either.

What the engine builds on it, as built (docs/krun-spike.md, Deviations,
and docs/krun-engine.md):

| Piece | What |
|---|---|
| The runner and its jail | `sandcastle-vm`, one process per VM: its own uid outside every subordinate range, new PID, mount, network, IPC, and UTS namespaces, a tmpfs root holding only its disks and libraries, no capabilities, a seccomp allowlist, and a cgroup the engine makes |
| Roots | an OCI image unpacked once per digest, inside a build VM, into a read-only ext4 disk; each start a fresh sparse scratch overlay (Cloudflare's semantics); snapshots copy the writable layer |
| The guest's init and agent | `sandcastle-guest`, one static binary: mounts, the CA at Cloudflare's path, the entrypoint as its PID namespace's PID 1 with its exit code reported; over vsock, exec (streams, a PTY and its resize, kill), any guest port, image builds |
| The network | a tap in the VM's network namespace, its own nftables redirecting every connection to a forwarder that hands it to the node's proxy, outside the jail: Cloudflare's rules, fake addresses for names, TLS intercepted with the node's CA, each match handed to a handler or a placeholder substituted |
| Memory back | the balloon at 4 KiB free-page reporting, and a reclaim on idle |
| Logs | the entrypoint's stdout and stderr, bounded and rotated |

## The bar: Cloudflare's container API

The audit's finding: upstream celld (v0.6.0) already had `ctx.container`,
on a local Docker or Podman engine. So the seam is Cloudflare's own API,
and a computer written against `ctx.container` alone runs:

- **on Cloudflare**, natively;
- **on celld with Docker or Podman**: development and CI, on a laptop;
- **on celld with this engine**: self-hosted, on microVMs.

Decided (Paul, 2026-09-30):

- Upstream celld is assumed to converge on Cloudflare's advertised
  feature set; the fork carries what that does not cover yet.
- The engine is the operator's choice (Docker or microVMs), not a fork of
  the code.
- **The bar is Cloudflare's capabilities.** How far the self-hosted side
  goes is as far as Cloudflare does.

The API, method by method: what Cloudflare defines, what celld v0.6.0
had, and what this engine does (docs/krun-engine.md, Acceptance).

| Cloudflare | celld v0.6.0 | This engine |
|---|---|---|
| `running`, `monitor()` (resolves at exit 0, rejects with `exitCode`) | Docker's `/wait` | the entrypoint is the guest's supervised PID 1; its exit and code are the container's, and the VM stops then |
| `start({image \| containerSnapshot, entrypoint, env, enableInternet, labels})` | had, but no snapshots | a fresh root each start, the image's entrypoint or an override, env, labels, the internet on or off |
| `start({instance})`: `lite`, `basic`, `standard-1` to `-4`, or `{vcpu, memoryMib, diskMb}` | sizes from config only | each start's size, refused where Cloudflare refuses (1 to 4 vCPU, at most 12 GiB and 20 GB, at least 3 GiB per vCPU), enforced by the VM's cgroup |
| `images` | none | pulled from a registry, or loaded from `docker save` tars (how celld ships them) |
| `destroy(error?)`, `signal(n)` | had | the same |
| `exec(cmd, {stdin, stdout, stderr, cwd, env, user, pty})`, `kill`, `resize` | Docker exec | an upgraded, framed stream (Docker's 8-byte frame header); exec's env inherits only `PATH` from `start`'s |
| `getTcpPort(p).fetch()`, `.connect()`, WebSockets | by the container's bridge address | any port, undeclared: a socket made inside the VM's network namespace and passed over `ports.sock`, or vsock to a server on the guest's loopback |
| `inspect()` | a stub | the image and labels |
| `snapshotContainer({name})`, `start({containerSnapshot})` | stubs | the writable root copied, `{id, size, name}`, image-tied, kept 30 days and refreshed on restore |
| `interceptOutboundHttp/Https`, `interceptAllOutbound*` | stubs | host, glob, `ip:port`, CIDR, `*`; 128 entries counted as Cloudflare counts them; added while running; with the internet off, DNS answers only intercepted names; each match goes to celld's callback route, named by `x-sandcastle-container` and `x-sandcastle-intercept` |

**Conformance.** One Durable Object (the celld fork's
`examples/container-conformance`) calls every method of `ctx.container`
and answers per method. The same file runs against every engine, so each
difference is a bug on the self-hosted side or a named, documented
divergence. On this engine it passes 25 of 25 (docs/krun-engine.md, E6).

**Docker is not a microVM.** Its containers share the host's kernel. It
is for development and for people who trust each other; strangers'
computers run on Cloudflare or on microVMs.
