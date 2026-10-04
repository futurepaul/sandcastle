# sandcastle

Cloudflare's container API on libkrun microVMs. A Durable Object's
`ctx.container` (`start`, `exec`, `getTcpPort`, `monitor`, `signal`,
`destroy`, `inspect`, the outbound intercepts, `snapshotContainer`) is
answered call for call, with Cloudflare's validation and limits, by an
engine that boots each container as its own microVM on
[libkrun](https://github.com/containers/libkrun). Each VM is jailed: its
own uid, its own namespaces, a seccomp allowlist, and a cgroup holding its
instance size.

The engine is driven by celld (a self-hosted Workers runtime) on its
fork's branch `krun-engine`
([futurepaul/celld](https://github.com/futurepaul/celld), commit
`56ccbd4`), whose `ctx.container` calls this engine over a unix socket
in place of Docker. Code written against `ctx.container` alone runs on
Cloudflare, on celld with Docker, and on celld with this engine.

## Status

**Spike-proven, not production.** Measured on one bare-metal x86_64
Linux/KVM test node, 2026-10-01, with seccomp enforced
(docs/krun-engine.md, Results; the evidence is in `docs/`):

| | |
|---|---|
| busybox, start to ready (jailed) | 108 ms median |
| exec round trip | 4.0 ms |
| a guest port over the NIC | 5.8 GiB/s, 0.34 ms to first byte |
| a snapshot; a start from it | 46.6 ms; 215 ms |
| Hermes (`nousresearch/hermes-agent:v2026.9.24`) to serving | 4.47 s, 250 ms of it the engine |
| celld's conformance Worker, every method of `ctx.container` | 25 of 25 |

What is not done: one node only (no placement across machines), no warm
(paused) tier, as on Cloudflare; libkrunfw is not yet distributed with
binaries (a licensing question: a GPL kernel inside an LGPL library); and
the debt in docs/krun-engine.md, Debt. The driver
(`crates/krun-spike`) is a lower-rung diagnostic, not the product.

## Where it fits

[fragment](https://github.com/futurepaul/fragment) is fragments and
computers. Its v1 runs on Cloudflare, where computers are Cloudflare
Containers. Its self-hosted lane returns once that product works: celld
for cells and sandcastle for computers, both speaking Cloudflare's APIs,
so the same fragment runs on either. This repository is the computers
half.

It was fragment's `sandcastle/` workspace (draft PR #103, branch
`krun-spike`) and keeps that history. When it moved here, its msb-era
control plane (`sandcastled`, the msb gate, iroh and the web client, the
simulator, its e2e and CLI) was cut, as fragment decided (its
`docs/cloudflare-v1.md`, decision 33).

## Layout

| Crate | What |
|---|---|
| `crates/wire` | the host's and the guest's protocol over vsock: length-prefixed frames, typed messages, every limit a constant |
| `crates/vm` | `sandcastle-vm`: one microVM per process; its validated configuration, a pure lifecycle, the libkrun gate (`dlopen`), the runner, its jail, and a client |
| `crates/guest` | `sandcastle-guest`: the guest's init and agent, one static binary (`<arch>-unknown-linux-musl`) |
| `crates/rootfs` | OCI images: references, manifests, a registry client with every digest checked on download and again before use, and the ext4 disks a VM boots |
| `crates/egress` | a VM's egress: Cloudflare's rules (128 entries), fake addresses for names, a resolver, and the node-side proxy that intercepts TLS with the node's CA |
| `crates/engine` | `sandcastle-engine`: the root service holding the node's VMs, serving Cloudflare's API on a unix socket |
| `crates/krun-spike` | `sandcastle-krun-spike`: the driver, each scenario's evidence as JSON, and `reset` |

The engine's API is HTTP/1.1 with JSON on `engine.sock` in its state
directory (`/v1/containers/{name}/start`, `exec` as an upgraded framed
stream, `signal`, `wait`, `destroy`, `logs`, `intercepts`, `snapshots`,
`/v1/images/pull` and `load`), and `ports.sock` hands out a connected
socket to any guest port. Names follow Cloudflare's (camelCase), so a
caller passes `ctx.container`'s options through unchanged
(`crates/engine/src/api.rs`).

## Build and test

Rust stable (1.98 tested), on Linux or macOS:

```sh
cargo build --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Nothing links libkrun at build time (it is loaded with `dlopen`), and no
test needs KVM. The Linux-only pieces (the jail, seccomp, vsock, cgroups,
the engine's service, the guest, the driver's scenarios) are behind
`cfg(target_os = "linux")`, so on macOS the workspace builds and tests
its pure pieces; Linux compiles and tests the rest. CI
(`.github/workflows/ci.yml`) runs all three on `ubuntu-latest` and
`ubuntu-24.04-arm`.

## Running it on a KVM host

The engine needs:

- Linux on x86_64 or aarch64 with `/dev/kvm` and `/dev/vhost-vsock`,
  `mke2fs`, and `nft` (aarch64, as on a Mac's Linux VM with nested
  virtualization: docs/mac.md). A node runs images of its own
  architecture (`linux/amd64` or `linux/arm64`);
- libkrun `b63baa1895c60d58b731fdebb9180ba266292848` (built with
  `--features ffi,blk,net`) and libkrunfw
  `f6a710faaa8cfe3b67a4bcdadb082c2183a914f1` (5.6.2), built into a prefix
  and loaded from there by path, never installed system-wide;
- the guest built static:
  `cargo build --release -p sandcastle-guest --target x86_64-unknown-linux-musl`
  (`aarch64-unknown-linux-musl` on arm64);
- root for the engine itself, which jails each VM. It runs as a
  transient unit with a delegated cgroup subtree, for example
  `sudo systemd-run --unit=krun-engine --slice=krun-spike.slice -p Delegate=yes sandcastle-engine serve --config engine.json`;
  its clients (celld, the driver) stay unprivileged and call its socket.

The driver keeps everything under one root, `KRUN_SPIKE_ROOT` (binaries
in `bin/`, libkrun in `prefix/lib/`, the engine's state in `e/`), and
prints each scenario's evidence as JSON:

```sh
sandcastle-krun-spike boot --n 10
sandcastle-krun-spike parity
KRUN_SPIKE_NODE_IP=<the node's public address> sandcastle-krun-spike probe
sandcastle-krun-spike reset [--all]
```

Its scenarios are `boot`, `fresh-root`, `exec`, `exec-api`, `port`,
`port-nic`, `egress`, `parity`, `fidelity`, `corpus`, `probe`, `crash`,
`dmesg`, `hermes`, `hermes-memory`, `hermes-trace`, `hermes-snapshot`,
`census`, `pull`, and `reset`; `probe` and `egress` check that a guest cannot reach the node's
own `:22` and `:443`, at `KRUN_SPIKE_NODE_IP`. How each was run, and the
rules the spike kept on a shared node, are in docs/krun-spike.md.

## Docs

- `docs/background.md`: why libkrun rather than msb, and the bar
  (Cloudflare's container API, method by method).
- `docs/krun-spike.md`: the spike, its constraints, phases, and results,
  with `docs/krun-spike-evidence/`.
- `docs/krun-engine.md`: from spike to engine (E1 to E7), the results,
  what is open, and the debt, with `docs/krun-engine-evidence/`.

## License

MIT (`LICENSE`), as fragment. libkrun is Apache-2.0; libkrunfw is
LGPL-2.1 with a GPL-2.0 kernel. Neither is vendored here.
