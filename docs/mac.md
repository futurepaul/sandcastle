# sandcastle on a Mac: a runner in a Linux VM

*Written 2026-10-04 for fragment's self-hosted lane: Paul's Mac as a
second runner beside the Linux box at 192.168.50.7.* The aarch64 port
(branch `arm64`) is proven under emulation (Evidence, below). It has
not yet run on a Mac.

sandcastle needs Linux and `/dev/kvm`. On an Apple silicon Mac it runs
inside an aarch64 Linux VM with nested virtualization, so KVM works in
that VM:

```
Mac (macOS 15+, M3 or later)
└── Lima VM "sandcastle": Debian 13 arm64, vz, nestedVirtualization
    ├── /dev/kvm
    ├── sandcastle-engine   root, systemd unit; each container a jailed libkrun microVM
    └── sandcastle-node     your user; dials wss://fragment.home.arpa/api/nodes/uplink
                            (the box's platform), and serves the engine's API over it
```

The node dials out, so nothing on the Mac listens. Its containers run
**linux/arm64 images** only: a node pulls and loads its own
architecture's image.

## 1. Check the Mac

```sh
sysctl -n machdep.cpu.brand_string   # Apple M3, M3 Pro, M4 ... (M1 or M2: see the end)
sw_vers -productVersion              # 15.0 or later
```

Both are needed: Virtualization.framework offers nested virtualization
on M3 and later, from macOS 15.

## 2. The Linux VM

```sh
brew install lima
limactl --version     # 2.0 or later (nestedVirtualization came in 1.1); written against 2.2.1
```

Save this as `sandcastle.yaml`. The image is pinned by date and digest
(the SHA512 in that directory's `SHA512SUMS`; the same pin as Lima's own
`debian-13` template):

```yaml
minimumLimaVersion: "2.0.0"
vmType: vz
nestedVirtualization: true
# Leave macOS room: adjust to the laptop (engine.json's memory_mib_max
# below is what the VMs may hold together).
cpus: 6
memory: "12GiB"
disk: "64GiB"
images:
  - location: "https://cloud.debian.org/images/cloud/trixie/20261001-2618/debian-13-genericcloud-arm64-20261001-2618.qcow2"
    arch: "aarch64"
    digest: "sha512:d8470b8c6c38fead046c794b5800a5a7b96672d5bcf543cc230ceb0c4b8ace05ed341a0c8928045422243fde26b2f1f2f58e99244c65709ffda2e3d4b674dd5a"
# Nothing of the Mac's is shared in: a guest that escaped its microVM
# and its jail would find only this VM.
mounts: []
containerd:
  system: false
  user: false
```

```sh
limactl start --name=sandcastle ./sandcastle.yaml
limactl shell sandcastle
```

Everything from here runs inside the VM (`limactl shell sandcastle`)
unless it says "on the Mac".

## 3. Check /dev/kvm

```sh
ls -l /dev/kvm                 # crw-rw---- 1 root kvm 10, 232 ...
sudo dmesg | grep -i kvm       # kvm [1]: VHE mode initialized successfully
```

No `/dev/kvm`, or `kvm [1]: HYP mode not available`, means the VM booted
without nested virtualization: check step 1, then (on the Mac)
`limactl stop sandcastle`, `limactl edit sandcastle --set
'.nestedVirtualization=true'`, and start it again. Lima refuses the
setting outright on a Mac that cannot do it.

## 4. Packages

```sh
sudo apt-get update
sudo apt-get install -y build-essential git curl ca-certificates e2fsprogs nftables openssl
echo vhost_vsock | sudo tee /etc/modules-load.d/vhost_vsock.conf
sudo modprobe vhost_vsock
```

## 5. Build the binaries and get the libraries

All in the VM, natively (aarch64). Rust, pinned (rustup-init 1.29.1 and
its published SHA-256; the toolchain the box uses, 1.99.0):

```sh
curl -fsSLo /tmp/rustup-init https://static.rust-lang.org/rustup/archive/1.29.1/aarch64-unknown-linux-gnu/rustup-init
echo "15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433  /tmp/rustup-init" | sha256sum -c
chmod +x /tmp/rustup-init
/tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain 1.99.0 --target aarch64-unknown-linux-musl
. ~/.cargo/env
```

sandcastle (the engine, runner, node and driver, glibc; the guest,
static musl):

```sh
git clone -b arm64 https://github.com/futurepaul/sandcastle ~/src/sandcastle
cd ~/src/sandcastle
cargo build --release --locked -p sandcastle-engine -p sandcastle-vm -p sandcastle-node -p sandcastle-krun-spike
cargo build --release --locked -p sandcastle-guest --target aarch64-unknown-linux-musl
```

libkrun, at the commit the box runs:

```sh
git clone https://github.com/containers/libkrun ~/src/libkrun
cd ~/src/libkrun && git checkout b63baa1895c60d58b731fdebb9180ba266292848
cargo build --release --locked -p libkrun --features ffi,blk,net
```

libkrunfw 5.6.2 (the guest's kernel, Linux 6.12.109), upstream's own
aarch64 release build, checked against GitHub's published digest. Its
tag, `v5.6.2` (`f14ac64c`), is three commits before the README's
`f6a710fa`, which adds only an x86 config change and three virtio-gpu
patches (sandcastle has no GPU); nothing was released from it. It needs no versioned glibc symbols, so any aarch64
distribution loads it:

```sh
curl -fsSLo /tmp/libkrunfw-aarch64.tgz https://github.com/libkrun/libkrunfw/releases/download/v5.6.2/libkrunfw-aarch64.tgz
echo "dea7905a167eee17d482200ea2fe15871aceb293b0674ac825ed7ae69759399f  /tmp/libkrunfw-aarch64.tgz" | sha256sum -c
mkdir -p ~/src/libkrunfw && tar -xzf /tmp/libkrunfw-aarch64.tgz -C ~/src/libkrunfw
```

Or build it from source instead (about 20 minutes; the Makefile fetches
the kernel with no checksum, so seed it first):

```sh
sudo apt-get install -y bc bison flex libelf-dev elfutils python3-pyelftools cpio xz-utils patch
git clone https://github.com/libkrun/libkrunfw ~/src/libkrunfw-src && cd ~/src/libkrunfw-src && git checkout v5.6.2
mkdir -p tarballs && curl -fL -o tarballs/linux-6.12.109.tar.xz https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.109.tar.xz
echo "5484e552a334e15019f4aeba89e5b58f04651cf2f4e24e04de9f152f1c38e3fa  tarballs/linux-6.12.109.tar.xz" | sha256sum -c
make -j"$(nproc)" && make PREFIX="$HOME/src/libkrunfw/usr" install
```

Install them where the engine loads them, root-owned:

```sh
sudo install -d -m 0755 /opt/sandcastle/bin /opt/sandcastle/lib /etc/sandcastle
sudo install -m 0755 ~/src/sandcastle/target/release/{sandcastle-engine,sandcastle-vm,sandcastle-node,sandcastle-krun-spike} /opt/sandcastle/bin/
sudo install -m 0755 ~/src/sandcastle/target/aarch64-unknown-linux-musl/release/sandcastle-guest /opt/sandcastle/bin/
sudo install -m 0755 ~/src/libkrun/target/release/libkrun.so /opt/sandcastle/lib/libkrun.so
sudo install -m 0755 "$(find ~/src/libkrunfw -name 'libkrunfw.so.5.*' -type f | head -1)" /opt/sandcastle/lib/libkrunfw.so.5
```

**Or cross-build on the box** (x86_64) and copy `bin/` and `lib/` over:
zig 0.16.0 (`zig-x86_64-linux-0.16.0.tar.xz`, SHA-256
`70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00`)
and `cargo install cargo-zigbuild --version =0.23.4 --locked`, then
`cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.36 -p …`
(glibc 2.36 or later), `--target aarch64-unknown-linux-musl` for the
guest, and the same for libkrun. The Evidence below used both ways.

## 6. The engine, a systemd unit

`/etc/sandcastle/engine.json` (your user is the engine's client; on
Lima its uid is your Mac's, e.g. 501):

```sh
sudo tee /etc/sandcastle/engine.json >/dev/null <<EOF
{
  "state_dir": "/var/lib/sandcastle",
  "lib_dir": "/opt/sandcastle/lib",
  "runner": "/opt/sandcastle/bin/sandcastle-vm",
  "guest": "/opt/sandcastle/bin/sandcastle-guest",
  "client_uid": $(id -u),
  "client_gid": $(id -g),
  "uid_base": 300000,
  "vms_max": 16,
  "memory_mib_max": 8192,
  "kernel_args": ["page_reporting.page_reporting_order=0"],
  "pull": true
}
EOF
```

`system_libs` is left out: the default for arm64 is Debian's,
`/usr/lib/aarch64-linux-gnu` and the loader `/usr/lib/ld-linux-aarch64.so.1`.

`/etc/systemd/system/sandcastle-engine.service`:

```ini
[Unit]
Description=sandcastle engine
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/sandcastle/bin/sandcastle-engine serve --config /etc/sandcastle/engine.json
Slice=sandcastle.slice
Delegate=yes
LimitNOFILE=524288
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sandcastle-engine
journalctl -u sandcastle-engine -n 5    # ... serving on /var/lib/sandcastle/engine.sock and /var/lib/sandcastle/ports.sock
```

A first VM, through the driver (it finds the engine at `$KRUN_SPIKE_ROOT/e`):

```sh
mkdir -p ~/spike && ln -sfn /var/lib/sandcastle ~/spike/e
export KRUN_SPIKE_ROOT=~/spike
/opt/sandcastle/bin/sandcastle-krun-spike pull busybox:1.37.0
/opt/sandcastle/bin/sandcastle-krun-spike boot --n 5     # start_to_ready_ms
/opt/sandcastle/bin/sandcastle-krun-spike exec --n 5     # "pass": true
```

## 7. The node, dialing the box

**Pair it** (experimental; docs/node.md, Pairing): the box must let its
people bring their own machines (fragment's `FRAGMENT_BYOC=on`;
docs/self-host-lan.md, step 7), and `sandcastle-node` must have `pair`:
step 5's binaries, built from the branch `node`, have it (and `arm64`).
The CA is still copied in first (below, "The CA"). Then, in the VM, as
your user:

```sh
sudo install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" /etc/sandcastle-node
/opt/sandcastle/bin/sandcastle-node pair https://fragment.home.arpa --config /etc/sandcastle-node/node.json --name mac \
  --ca-file /etc/sandcastle/home-ca.pem \
  --engine /var/lib/sandcastle/engine.sock --ports /var/lib/sandcastle/ports.sock --egress /run/sandcastle-node/egress.sock
```

It prints a link and a code. Open the link (the iPhone or the Mac),
signed in, check the code, and approve; tick "Run my new computers on it"
for a person whose first computer should start here (a person's first
computer starts as they pick a username, before settings). It ends having written
`/etc/sandcastle-node/node.json` and `node.secret` (0600): no secret is
copied by hand, and the box needs no row for it. Then use
`/etc/sandcastle-node/node.json` in the unit below, and skip "The secret"
and the hand-written config. The node runs only the computers you choose
for it in the platform's settings.

**Or by hand**, as a node of the box's own list: four things come from
the box (fragment's LAN mode, its docs/self-host-lan.md):

| | Here | Where it comes from |
|---|---|---|
| The uplink | `wss://fragment.home.arpa/api/nodes/uplink` | the platform's base, `https://fragment.home.arpa` |
| The node's id | `mac-1` | the platform's list of nodes (`uplink:mac-1`) |
| The node's secret | a file, at least 32 bytes | made once, held by both sides |
| The LAN's CA | `home-ca.pem` (public) | the CA on the box |

**The name.** `getent hosts fragment.home.arpa` should print
192.168.50.7. Lima's resolver asks the Mac's, so it does once the Mac
uses the box's DNS. Until then:
`echo '192.168.50.7 fragment.home.arpa' | sudo tee -a /etc/hosts`.

**The CA** is a certificate, not a secret. Fetch it on the Mac from the
box's root page, and check its fingerprint against the one the box's
banner printed:

```sh
curl -so home-ca.pem http://192.168.50.7/ca/ca.pem
openssl x509 -in home-ca.pem -noout -fingerprint -sha256
```

Copy it in (`limactl copy home-ca.pem sandcastle:/tmp/home-ca.pem`), then
trust it for the system's tools and give it to the node:

```sh
sudo install -m 0644 /tmp/home-ca.pem /usr/local/share/ca-certificates/fragment-home.crt
sudo update-ca-certificates
sudo install -m 0644 /tmp/home-ca.pem /etc/sandcastle/home-ca.pem
curl -sS -o /dev/null -w '%{http_code}\n' https://fragment.home.arpa/    # a status, not a certificate error
```

**The secret** stays a file end to end: never echoed, pasted, or put on
a command line. If the box made it (at `<box path>`), copy it file to
file. On the Mac:

```sh
(umask 077; scp paul@192.168.50.7:<box path> ./mac-1.secret)
limactl copy ./mac-1.secret sandcastle:/tmp/node.secret && rm ./mac-1.secret
```

In the VM:

```sh
sudo install -m 0600 -o "$(id -un)" -g "$(id -gn)" /tmp/node.secret /etc/sandcastle/node.secret && rm /tmp/node.secret
```

(Or make it here, `(umask 077; openssl rand -hex 32 > /tmp/node.secret)`,
install it the same way, and copy it to the box the other way round.)

`/etc/sandcastle/node.json`, with no `listen`: the node only dials.
`ca_file` covers both the uplink and the intercepts it sends to the
platform:

```json
{
  "engine": "/var/lib/sandcastle/engine.sock",
  "ports": "/var/lib/sandcastle/ports.sock",
  "egress": "/run/sandcastle-node/egress.sock",
  "secret_file": "/etc/sandcastle/node.secret",
  "platform": "https://fragment.home.arpa",
  "ca_file": "/etc/sandcastle/home-ca.pem",
  "uplink": { "url": "wss://fragment.home.arpa/api/nodes/uplink", "id": "mac-1" }
}
```

`/etc/systemd/system/sandcastle-node.service`, as your user (a paired
node's config is `/etc/sandcastle-node/node.json`; write it
with `sudo tee` so `$(id -un)` is filled in, or type the name):

```ini
[Unit]
Description=sandcastle node (dials fragment's uplink)
After=sandcastle-engine.service network-online.target
Wants=sandcastle-engine.service network-online.target

[Service]
User=<you>
Group=<you>
RuntimeDirectory=sandcastle-node
ExecStart=/opt/sandcastle/bin/sandcastle-node serve --config /etc/sandcastle/node.json
NoNewPrivileges=yes
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sandcastle-node
journalctl -u sandcastle-node -f
```

## 8. What working looks like

- `/dev/kvm` exists, and `dmesg` says KVM initialized (step 3).
- `journalctl -u sandcastle-engine`: `serving on /var/lib/sandcastle/engine.sock and /var/lib/sandcastle/ports.sock`.
- The driver's `boot` reports `start_to_ready_ms`, and `exec` says
  `"pass": true` (step 6).
- `journalctl -u sandcastle-node`:
  `sandcastle-node: serving over the uplink to wss://fragment.home.arpa/api/nodes/uplink as mac-1, intercepts on /run/sandcastle-node/egress.sock to https://fragment.home.arpa`,
  then `sandcastle-node: uplink: connected to wss://fragment.home.arpa/api/nodes/uplink as mac-1`.
  A wrong secret or id shows as `uplink: the platform refused the dial:
  401 …; dialing again in …`, its waits doubling up to a minute; an
  untrusted CA as `uplink: dialing: …` with the certificate error.
- On the box, a computer placed on `mac-1` wakes: the node's journal
  logs each call (`uplink: #<n> POST /v1/containers/…/start 201`), and
  `sudo ls /var/lib/sandcastle/vms` in the VM shows its run directory.

After an update: rebuild, `sudo install` as in step 5, then `sudo
systemctl restart sandcastle-engine sandcastle-node`. A restarted engine
adopts the VMs still running.

## On an M1 or M2

There is no nested virtualization, so the VM has no `/dev/kvm` and the
engine cannot run there. The alternative is a native macOS engine on
libkrun's Hypervisor.framework backend, which needs a new jail (macOS
has no namespaces, seccomp, cgroups or nftables): a port, not a setting.
Until then such a Mac is not a runner.

## Evidence (2026-10-04)

Without a Mac: on the box (x86_64), qemu 11.1.1 (Arch's package,
unprivileged) emulated an aarch64 machine with EL2 (`-machine
virt,virtualization=on,gic-version=3 -cpu max`, TCG). Its guest, the same
Debian 13 image, booted at EL2 ("kvm [1]: VHE mode initialized
successfully", kernel 6.12.111) and had `/dev/kvm`. Inside it, the
binaries cross-built with zig, libkrun b63baa1 and libkrunfw 5.6.2 above:

| | |
|---|---|
| The workspace's tests, built for aarch64 and run there | all pass (16 test binaries); CI runs them on GitHub's arm64 runner too |
| `sandcastle-vm run`, unjailed, an entrypoint that exits 7 | ready in 1.9 to 2.5 s; `exited` with code 7; the VM ends (PSCI reset) |
| The engine as the unit above, jailed, seccomp enforced: `boot --n 5` | start to ready 2.1 s median |
| `exec`, `fresh-root`, `crash`, `exec-api`, `egress` | pass |
| `pull busybox:1.37.0` (the arm64 manifest, unpacked by a build VM) | 5.8 s |
| A snapshot, and a start from it | 2.8 s and 2.3 s; the snapshot's file is there |
| seccomp in audit mode across those, with auditd | no call outside the allowlist |
| Step 5 as written, natively in that guest (rustup, sandcastle, libkrun, libkrunfw's release) | 13 min under emulation; its binaries boot (1.8 s median) and pass `exec`, enforced |
| The units in steps 6 and 7 as written | the engine serves; the node starts, and with no `fragment.home.arpa` to resolve says `uplink: dialing: …` and backs off |

These are emulation's numbers: TCG ran this guest about 16 times slower
than the box. On the x86 node a busybox start is 108 ms; an M3's, under
nested virtualization, is not yet measured.

Found on the way, and fixed on `arm64`:

- The seccomp filter admitted only x86_64's ABI and named x86-only calls.
- The jail required `/lib64`, which Debian's arm64 does not have, and
  could not bind its loader, a file beside the multiarch directory.
- Pulls and loads asked for `linux/amd64` whatever the host.
- `pci=off` went to every kernel; arm64's libkrunfw has no PCI, so it
  reached our init's environment instead.

## Open

- **arm64 images.** fragment's stub and Hermes images are built
  `--platform linux/amd64`. The Mac needs `linux/arm64` builds. The
  stub's bases (`rust:1.99-alpine`, `busybox:1.37-musl`) and Hermes'
  upstream (`nousresearch/hermes-agent`) publish arm64, but our Hermes
  Dockerfile downloads litestream's `linux-x86_64` tarball by checksum,
  so it needs the arm64 one per `TARGETARCH`. Placement across nodes
  must send a computer only to a node of its image's architecture.
- **A real Mac.** Nested KVM under Apple's hypervisor (its vGIC and
  timers) and the real timings are unmeasured.
- **The port scenario** timed out on its echo server under emulation:
  at the lite instance's 1/16 vCPU, the Go server took more than the
  driver's 10 s to listen. Started by hand, it listened. This is the
  emulator's slowness, not the port.
