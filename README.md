# sandcastle

Self-hosted computers: a microVM made from an OCI image, with a durable
disk, one service, and one locked-down URL. It is fragment-next's answer
to "Fly Sprites, but ours" (the research, the decisions, and the plan are
in `../docs/sandbox.md`). It depends on nothing in fragment-next, so it can
move to Finite unchanged.

The contract is thin on purpose. A node knows **public keys, grants, and
computers**. It knows nothing of people, organizations, agents, billing,
or what runs inside a computer:

- Every API call is NIP-98 signed (`Authorization: Nostr <event>`, kind
  27235, `u`, `method`, `payload`, a random `nonce`); the signer is the
  principal. A replay cache refuses an event seen before inside the skew
  window.
- **Grants** are rows the node owns, written only by keys configured as
  grantors (`--grantor`): Finite's Core, fragment's platform, or a
  person's own key on their own machine. A grant caps how many computers a
  key holds and how large each may be. Revoking it stops the key's
  computers.
- **A computer belongs to the key that created it.** Anyone else gets the
  same 404 as a missing name.
- **Credentials come from a platform.** A computer's spec may name a
  `credentials_url`; the node asks it, signed with its own key, which the
  platform lists. The values reach the engine's credential swap and never
  the guest (Credentials, below).

## Layout

The node is built to the engineering style's shape: a pure core, gates
to the world, and a deterministic simulation of the whole node
(`../docs/sandcastle-rewrite.md`).

| Crate | What |
|---|---|
| `crates/proto` | The wire contract: `ComputerSpec`, `ComputerView`, `GrantSpec`, `Ticket`, `ApiError`, a credential source's `CredentialsAsk` and `Credentials`, and every limit, validated before anything is stored |
| `crates/nip98` | NIP-98: verify (the node), sign (clients, the `sign` feature) |
| `crates/core` | The node's decisions as pure functions: each computer a state machine in its row; `plan` (what to do next), `apply` and `note` (the row after it), `learn` (what the batch now knows), and `check` (invariants and tripwires, on in release) |
| `crates/node` | The machinery: the store (SQLite, typed columns), the API's mutations as commands (each in one transaction), the gates (`msb`, ZFS, S3, the credential source, the prober, the clock, randomness), the executor, the scheduler, the seal, the manifest |
| `crates/sim` | A deterministic simulation: the real core, store, and executor against a simulated world with faults, crashes at every step, wedged guests, and hung machines; invariants after every action, convergence after settling |
| `crates/sandcastled` | The daemon, a thin layer: `serve` (the config, the signed API, a computer's URL, the listener) and `reset` |
| `crates/cli` | `sandcastle`: signs calls with a key file and prints the answer |
| `crates/e2e` | `sandcastle-e2e`: the real engine end to end on a KVM host, with JSON evidence |

## The API

`https://api.<domain>/v1/…`, NIP-98 on everything but `GET /v1/health`
(which also answers the node's own public key, `node_key`, when it has
one).

| Call | Who | What |
|---|---|---|
| `PUT /v1/grants/{pubkey}` | a grantor | `{computers_max, vcpus_max, memory_mib_max, data_gib_max}` |
| `GET /v1/grants/{pubkey}` | that key, or a grantor | |
| `DELETE /v1/grants/{pubkey}` | a grantor | revoke; the key's computers stop |
| `PUT /v1/computers/{name}` | a key with a grant | create (201), the same spec again (200), or an update (200): the image, the service, `url_auth`, and `credentials_url` can change; storage and size are fixed (409). A `credentials_url` outside the node's listed origins is 400 |
| `GET /v1/computers[/{name}]` | the owner | desired and observed state, `pending` (true until the node has acted on the latest spec and desired state: poll until false), a `rollback` if any, the URL; env values read `(set)` |
| `GET /v1/computers/{name}/snapshots` | the owner | the node's snapshots of the durable disk, oldest first |
| `GET /v1/backups` | a key | its backups in the node's bucket, its deleted computers' included |
| `PUT /v1/computers/{name}?restore=<computer id>@<snapshot>` | a key with a grant | create a computer whose disk starts from that backup: the key's own, whole back to a full stream, same size and mount |
| `POST /v1/computers/{name}/start` \| `/stop` | the owner | stop stays stopped |
| `DELETE /v1/computers/{name}` | the owner | 202; the computer reads `desired: deleted` until its machine and disk are gone, then 404 |
| `POST /v1/computers/{name}/tickets` | the owner | a single-use link, good for 60 s, that opens the computer's URL in a browser |
| `POST /v1/computers/{name}/wake` | the owner, or a grantor | 202; a sleeping computer wakes (written to its row), an awake one stays awake an idle time from now: a scheduler's call before a job it fires |
| `POST /v1/computers/{name}/sleep` | the owner, or a grantor | `{"tier": "warm" \| "cold"}`: a serving computer sleeps now rather than when next idle; only ever colder; any request wakes it |

A computer's spec:

```json
{
  "image": "nousresearch/hermes-agent:v2026.9.24",
  "vcpus": 2, "memory_mib": 4096,
  "storage": "data", "data_gib": 10, "data_path": "/opt/data",
  "service": {
    "argv": ["/opt/hermes/docker/entrypoint-dispatch.sh", "serve", "--host", "0.0.0.0", "--port", "9119"],
    "port": 9119,
    "health_path": "/api/auth/providers",
    "env": {"HERMES_DASHBOARD_BASIC_AUTH_USERNAME": "…", "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD": "…", "HERMES_DASHBOARD_BASIC_AUTH_SECRET": "…"}
  },
  "url_auth": "owner",
  "credentials_url": "https://fragment.club/api/sandcastle/credentials"
}
```

Each field in brief:

- **`storage`** is one of three:
  - `data`: the image is the system and `data_path` is a durable disk.
  - `ephemeral`: nothing survives.
  - `pet`: the whole machine is durable. Refused until built.
- **`service`** is the one process the node launches on every boot. The node keeps its definition, so nothing in the guest can change or revive it.
- **`service.init`** (`{argv, stop}`, with `argv` empty) runs the service under the image's own init instead: the engine hands it PID 1 (`msb --init`), and it starts and supervises what the image means to run; the node launches nothing, still probes health, restarts a machine whose service stays silent past the grace, and stops it with `stop` (the machine then powers off by itself). The service's `env` reaches the init at boot, valued in msb's environment, never its command line. Hermes runs this way, as its image means to, with its gateway (and cron) under s6:

  ```json
  "service": {
    "argv": [],
    "init": {"argv": ["/init", "/opt/hermes/docker/main-wrapper.sh", "gateway", "run"], "stop": ["/run/s6/basedir/bin/halt"]},
    "port": 9119, "health_path": "/api/auth/providers",
    "env": {"HERMES_DASHBOARD": "1", "HERMES_DASHBOARD_PORT": "9119", "HERMES_DASHBOARD_BASIC_AUTH_USERNAME": "…", "…": "…"}
  }
  ```
- **`env`** holds the service's own settings. It reaches the guest through an exec's stdin into a root-only file, never a command line.
- **`service.busy`** (`{path, field}`) is how the node asks the service whether it is working before it puts the computer to sleep: a GET of `path` through its port, busy when the JSON's top-level `field` is true or above zero, and when the answer says nothing (no answer, not JSON, no such field). Hermes: `{"path": "/api/status", "field": "active_agents"}`.
- **Outbound credentials** come from `credentials_url`, never `env` (below).

## Credentials

A computer's service spends credentials outbound (a model key, say)
without ever holding one:

1. **The node asks.** At every create and start, it POSTs a
   `CredentialsAsk` (`{computer, id, node, owner}`: the owner is the key
   that made the computer) to the spec's `credentials_url`, NIP-98 signed
   over the body with **the node's own key** (`--node-key-file`). It asks
   only origins its operator lists (`--credentials-origin`), and a platform
   answers only nodes it lists.
2. **The platform answers** `{credentials: [{name, value, hosts,
   placeholder?}]}`, or refuses. A name ends in `_KEY`, `_TOKEN`, or
   `_SECRET` (so no name is one the engine or its host reads), and may not
   shadow a service variable. A placeholder, if named, is what the service
   sees: shaped like the real thing for services that check (Hermes takes
   an OpenRouter key only if it starts `sk-or-`); without one, msb's own
   (`$MSB_<NAME>`).
3. **The engine swaps.** The node hands msb the names, hosts, and
   placeholders in a secret config (a 0600 file with no value in it,
   removed after the create), and each value in msb's own environment,
   never a command line. The guest's CA trusts msb's interception, and
   the service's env holds the placeholder; msb replaces it with the value
   only in requests to the credential's hosts.
4. **It stays current.** Every `--credentials-every-s` (900) the node asks
   again. A new value is swapped in live (`msb modify`), and the guest sees
   nothing change. New names, hosts, or placeholders restart the machine.
   A platform that is down keeps what a machine holds, and holds a new
   generation back without stopping the old one or rolling back. A
   platform that **refuses** (a 4xx: the owner's key revoked, say) has the
   values withdrawn, live, until it answers again. The row records what
   each machine holds as its shape and a digest, never a value, so a
   restarted daemon knows without asking; the values themselves live in
   the machine's msb process.

A value lives in the node's memory for one engine call, and in msb's
host process for the machine's life. It never reaches the store, a view,
a log, the guest, its disk, a snapshot, or a backup.

On fragment the credential is the computer's own token for the
platform's model route (`OPENAI_API_KEY`, for the platform's host), so
its model calls are paid and counted there. Hermes then runs its bare
custom provider: `HERMES_INFERENCE_PROVIDER=custom`, and both
`CUSTOM_BASE_URL` and `OPENAI_BASE_URL` at the route (the first picks the
endpoint; Hermes sends `OPENAI_API_KEY` only where the second points).

Limits:

- Only credentials that travel in headers to known hosts. Not a token in
  a URL path, a client that pins certificates, or a signing key.
- A response can echo a value back into the guest.
- A refusal takes effect at the next refetch, so up to
  `--credentials-every-s`.

## What happens

The API records what callers want, in one transaction per call. The node
converges to it at its own pace: every 2 s the scheduler lists the
engine's machines once and runs a batch for each computer, at most 32 at
once and never two for one computer, so an hours-long upload of one
never holds another. A batch is up to 16 steps, each three calls the
simulator can crash between: plan (read the row, ask the core), perform
the effect through its gate within its deadline (or observe), and record
the outcome against the row as it is now. Backoff, the snapshot
schedule, what is owed, and every open upload are columns in the row, so
a restart resumes rather than starts over.

- **Create.** An idle microVM is made from the image, with the service port published on `127.0.0.1` only. For `data` storage it gets the computer's durable disk, a ZFS volume the node made and owns (not the engine's). Then the service is launched.
- **Snapshots** (`sc-<n>-<auto|stop|rebase>`, numbered in the row) of the durable disk are taken only when something was written since the last one:
  - every `--snapshot-every-s` (300 s by default) while serving, after the guest syncs (a sync that fails is logged and the snapshot taken anyway: crash-consistent, which SQLite in WAL mode recovers from);
  - after a stop: owed in the row before the stop, so a crash between the two still takes it;
  - before a machine is replaced (a rebase, or a crashed machine): from what the disk shows, so nothing written is ever replaced unsnapshotted.

  The node keeps the newest `--snapshots-kept` (24 by default), plus the last one shipped.
- **Serving** means the service answered its health path through that port. It is not the engine's say-so.
- **Update.** When the image or service changes (a new *generation*), the node fetches its credentials first (a source that is down leaves the old machine serving), then:
  1. stops the service gracefully and syncs the guest,
  2. stops the machine,
  3. snapshots the disk,
  4. recreates the machine on the same disk,
  5. relaunches the service.
- **Rollback.** A new generation is rolled back only for its own fault: the engine refusing to make or launch it (no such image, a bad argv), or its service not answering within `--startup-grace-s` (120 s by default). The node goes back to the last generation that served, keeping the data (never rewound). A view's `rollback` names the failed and running images and the reason; `start` retries it, and a new spec replaces it. An engine that timed out or could not run is the node's fault: a backoff, never a rollback.
- **Failures** back off in the row: 2 s, doubling to 60 s.
- **Nothing waits forever.** A guest that will not quiesce is stopped with its machine after one failed try; a machine that will not power off is killed (`msb stop -f`) after one failed stop; a guest that will not take a launch is restarted. The simulator's wedged guests and hung machines hold every one of these.
- **Daemon restart.** A restarted daemon picks running machines up where they are, without relaunching anything; the launch script refuses to start a second copy. A daemon that crashes (the store failing, an assertion) is restarted by systemd; its machines keep running.

The router is the node's one listener: TLS on 443, then by Host.

- **`api.<domain>`** is the API.
- **`<name>.<domain>`** is a computer. For `url_auth: owner`, the router admits only a browser holding its `__Host-sandcastle` session:
  - That session comes from redeeming a ticket, once.
  - The cookie is stripped before the service sees the request, as is anything a client claims about where it came from (`Forwarded`, `X-Forwarded-*`, `X-Real-IP`).
  - The service's own login (Hermes') is the second gate.
- WebSockets pass through; each holds a connection slot of its own, for at most a day.

## Budgets

A node keeps inside a reserve its operator chose, so it never runs the
host out of memory or disk (`../docs/sandcastle-sleep.md`):

- **Memory.** A machine that may run commits its whole allocation plus
  the engine's overhead (`--machine-overhead-mib`, 64) in a ledger that
  never passes `--reserve-memory-gib`. The core asks for room before it
  makes or starts a machine; without room a computer waits (its status
  says so), with no fault and no backoff. A rebase or a restart keeps its
  room; a stop for good releases it. A restarted node adopts the machines
  it finds running. The kernel holds the same line: the node refuses to
  start unless its unit's `MemoryMax=` (which caps its machines too,
  under `KillMode=process`) is at least the reserve
  (`--allow-uncapped-memory` for development).
- **Disk.** A computer's disk is a ZFS volume with its size reserved (not
  sparse). A computer is made only if its disk and its snapshots'
  headroom (`--snapshot-headroom-pct`, 25) fit `--reserve-disk-gib`
  beside every other's; a ZFS quota on the parent holds the same line.
- **The engine's disk.** Each machine is made with a writable layer of
  `--layer-gib` (4, msb's default; `msb --root-disk`), and a computer is
  made only if every layer fits `--reserve-engine-disk-gib`.

**Measured, and tuned from it.** The node samples every machine every
10 s (`msb metrics`: resident memory, guest memory, CPU, network, its
layer). `GET /v1/node` (grantors; `sandcastle node --memory-mib
--data-gib`) reports the reserve and costs, what is committed and what
is measured, each machine's memory (p50, p95, max over an hour) and
layer, what more fits of a size, and warnings when the host no longer
holds the reserve: no `MemoryMax=` or one below it, other processes'
memory, no ZFS quota or one below it, a pool or engine disk too small.

**Choosing the reserve.** `sandcastled setup --zfs-parent … --msb-home
…` reads the host, asks how much of it computers may have (suggesting
some), and prints what that holds for a computer size (running at once,
paused, and in all, and what bounds it) and the quota and unit settings
that make ZFS and the kernel hold it. It changes nothing. On
finite-lat-6 (124 GiB, a 1.7 TB pool), for 4 GiB / 10 GiB Hermes
computers: 27 running at once, about 118 paused (a paused Hermes under
s6 holds about 900 MiB: measured, `--warm-resident-mib`), 71 in all with
4 GiB layers (bound by the engine's disk; 120 with 1 GiB layers, bound
by disk).

## Sleep

A computer its owner wants running is awake, warm, or cold, as the node
chooses (`../docs/sandcastle-sleep.md`, Tiers):

| | Its machine | Its memory | A request waits |
|---|---|---|---|
| **awake** | running | its whole allocation, in the ledger | nothing |
| **warm** | paused (`msb pause --guest-flush required`) | what it measured resident when it paused | a resume: milliseconds |
| **cold** | stopped, its disk and layer kept | nothing | a boot: seconds |

- **Idle** (`--idle-after-s`, 30; 0 turns sleep off): no activity for
  that long, and its service not busy, puts a serving computer warm.
  Activity is what the node sees: a request through its URL (for as
  long as it is in flight: a long stream is never idle), data a client
  sends through an open WebSocket (not its pings or pongs: a quiet
  dashboard keeps nothing awake; any byte of another upgrade), its
  guest's CPU or network over the floors between samples
  (`--activity-cpu-permille`, 50; `--activity-net-bytes-per-s`, 4096;
  tuned from the report's measured rates), and a wake.
- **Warm** for `--cold-after-s` (86400) goes cold: the machine is
  resumed, its service stopped cleanly, the machine stopped, and the
  snapshot after a stop taken. A computer whose machine would not pause
  (a guest that cannot flush) goes cold instead of warm.
- **Room**: a wake asks the ledger for the machine's whole allocation;
  with none, the least recently active warm computers go cold until
  there is, and the woken one waits. A warm computer holds only what it
  measured, since a frozen machine cannot grow.
- **A request** to a sleeping computer is held, its computer stepped at
  once rather than at the next tick, and forwarded when it serves
  (`WAKE_DEADLINE`, 60 s, then 503). The request counts as activity
  before the router reads the computer's row, and the node pauses a
  machine only after a fresh look at its activity, so a request that
  arrives while a sleep is decided wakes the computer instead of meeting
  a frozen one.
- **While asleep**: what it wrote before it slept is snapshotted once
  its guest has flushed (`sc-<n>-pause`), and shipped; no credential
  rotation (a paused machine takes no exec); a stop or a deletion
  resumes it first, so its service stops gracefully.
- **The view** says `warm` or `cold`, and is not pending: sleep is the
  node's to choose. An owner's new generation or start wakes it.
- **Cron** inside a sleeping guest does not run: its ticker is frozen.
  The cron provider (phase 5 step 4) wakes it.

## Backups

With `--backup-bucket`, each computer's batch ships its snapshots off the host, oldest first, as duties after its lifecycle (so a prune never races a ship):

- **Streams.** The first is a whole `zfs send -c`, then incrementals from the last one shipped. After 48 incrementals, or when the last shipped snapshot was pruned, the next goes whole again.
- **Sealing.** Every object is sealed before it leaves (`seal.rs`): AES-256-GCM in 1 MiB chunks with the STREAM construction, and a per-object key from HKDF of the node's backup key, bound to the object's path. The bucket can neither read an object, nor alter it, reorder it, truncate it, or swap it for another without the restore failing.
- **Layout.** Objects are uploaded in parts (`--backup-part-mib`, 16) under `nodes/<node>/computers/<computer id>/`. An open upload is a column in the row: after a crash it is finished from part 1, or aborted, never dropped.
- **Manifest.** Each computer has a sealed manifest there, naming its owner and its chain. So a node that lost its state still authorizes and replays a restore from the bucket alone.
- **The key.** It is a file (`--backup-key-file`, 64 hex). **The operator keeps a copy apart from the node**: without it, no backup opens.
- **Credentials.** The bucket's key (`--backup-credentials`, an env file) should reach that bucket alone.

A restore (`?restore=` on create):

1. The node reads the manifest.
2. It checks the owner is the signer and the chain is whole.
3. It replays the chain into the new computer's empty disk, each object opened as it streams and fed to `zfs receive`.
4. Only then does it boot the machine.

A restore cut short resumes: a disk holding a prefix of the chain gets
the rest, and anything else is destroyed and replayed from the start. It
is done only when the target snapshot is on the disk.

## Running a node

The node needs:

- Linux with `/dev/kvm`, or macOS on Apple Silicon (not yet tried).
- microsandbox `msb` 0.7.4, the exact version.
- A wildcard certificate for `*.<domain>`.

The test node, `finite-lat-6`, runs under systemd with no capabilities at
all. systemd binds 443 and hands the daemon the socket (`sd_listen_fds`).

`/etc/systemd/system/sandcastled.socket`:

```ini
[Socket]
ListenStream=0.0.0.0:443
Accept=no

[Install]
WantedBy=sockets.target
```

`/etc/systemd/system/sandcastled.service`:

```ini
[Unit]
Requires=sandcastled.socket
After=network-online.target sandcastled.socket

[Service]
User=ubuntu
SupplementaryGroups=kvm
Environment=HOME=/home/ubuntu
ExecStart=/home/ubuntu/sandcastle/target/release/sandcastled serve --state-dir /var/lib/sandcastle \
  --domain sandcastle.fragment.club --tls-cert /etc/sandcastle/le-cert.pem --tls-key /etc/sandcastle/le-key.pem \
  --grantor <hex> --msb /home/ubuntu/.local/bin/msb --msb-home /home/ubuntu \
  --guest-deny <the node's IPv4> --guest-deny <the node's IPv6 /64> --zfs-parent tank/sandcastle \
  --node-name lat-6 --backup-bucket sandcastle-backups --backup-credentials /etc/sandcastle/backups.env \
  --backup-key-file /etc/sandcastle/backup.key \
  --node-key-file /etc/sandcastle/node.key --credentials-origin https://fragment.club \
  --reserve-memory-gib 112 --reserve-disk-gib 1500 --reserve-engine-disk-gib 300
MemoryMax=113G
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=true
KillMode=process
Restart=on-failure
```

**`KillMode=process`:** stopping the daemon never stops a computer.

**Starting over** (a test node): `sandcastled reset` takes the same
`--state-dir`, `--msb`, `--msb-home`, `--zfs-parent`, `--node-name`, and
bucket flags, and `--confirm <node name>`. It kills and removes the
node's machines, aborts the uploads its state names, deletes its objects
under `nodes/<node>/`, destroys its disks, and removes its state. Stop the
daemon first. Run twice, it is the same as once.

**No capabilities, deliberately.** An earlier unit gave the daemon
`CAP_NET_BIND_SERVICE`. Every VM process inherited it, and Linux then
denied an unprivileged `msb stop` the `/proc` access it needs.

**`--guest-deny`** keeps computers off the node's own addresses (its sshd,
its router). The engine's public-only egress already refuses private
ranges, link-local metadata, and the host's loopback.

The host's firewall admits 22 and 443 and nothing else.

**Disks** are ZFS volumes under `--zfs-parent`. The node is unprivileged, so the host is set up once:

1. A pool, and the parent dataset (`zfs create -o mountpoint=none tank/sandcastle`).
2. Delegation to the daemon's user: `zfs allow -u <user> create,destroy,mount,snapshot,send,receive,rollback,clone,promote,hold,release,volsize,volmode,refreservation,compression,userprop tank/sandcastle`. ZFS asks for `mount` even for volumes, which are never mounted on the host.
3. A udev rule giving that user the device nodes of those volumes and no others:

```
KERNEL=="zd*", SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", PROGRAM="/lib/udev/zvol_id $devnode", RESULT=="tank/sandcastle/*", OWNER="<user>", GROUP="<user>", MODE="0600"
```

A disk is formatted (ext4) only when `blkid` finds nothing on it at all, and a ZFS user property (`sandcastle:formatted`) records it once done. A blkid error is never read as "empty".

**The node's own key** (`--node-key-file`) is made on the node and never
leaves it: `sandcastle keygen --out /etc/sandcastle/node.key` (0600, the
daemon's user). The platform lists its public key, which `sandcastle
health` shows (`node_key`); fragment's is `FRAGMENT_SANDCASTLE_NODES`.

## The client

```sh
cargo build -p sandcastle
sandcastle keygen --out ~/.sandcastle/key      # prints the public key
export SANDCASTLE_API=https://api.sandcastle.fragment.club SANDCASTLE_KEY_FILE=~/.sandcastle/key
sandcastle health
sandcastle grant <pubkey> --computers 3 --vcpus 4 --memory-mib 8192 --data-gib 20   # as a grantor
sandcastle put hermes --spec hermes.json
sandcastle get hermes
sandcastle ticket hermes                       # open the link in a browser
sandcastle snapshots hermes
sandcastle backups
sandcastle put copy --spec hermes.json --restore <computer id>@<snapshot>
```

Two flags cover a node without public DNS or a public certificate:

- `--ca-file` trusts a private CA.
- `--connect <ip:443>` skips DNS; the TLS name and the signed URL stay the API's.

## Checks

`cargo clippy --workspace --all-targets --all-features -- -D warnings` and
`cargo test --workspace --all-features`: 103 tests, in CI (the
`sandcastle` job).

- **The core** (`crates/core/tests/paths.rs`): each path a computer
  takes, step by step: create, serve, rebase, rollback (and never for a
  node fault), stop and start, delete in order, restore (resumed after a
  crash), snapshots owed across a crash, shipping and pruning, credentials
  (rotate, withdraw, a new shape), and the liveness rules (a wedged
  guest, a hung machine, a restart through its own failures).
- **The node** (`crates/node`): the store's schema and caps, every
  command valid, invalid, and replayed, and a restart that reads back
  every field and no value; the seal, SigV4, the manifest; the gates'
  parsing and bounds (msb's list, arguments that hold no owner syntax, a
  credential only in msb's environment, ZFS listings read whole or
  refused, a program's output past its cap refused).
- **The simulator** (`crates/sim/tests/seeds.rs`): 64 seeds by default
  (`SANDCASTLE_SIM_SEEDS=n` runs more; `SANDCASTLE_SIM_SEED=s` replays
  one, and a failing seed prints its last gate calls), each 400 actions
  (owners' commands, steps, crashes after an effect or between steps,
  gate faults and lost replies, guest writes, wedges, hangs, crashed
  machines, the credential source's moods, time), invariants after every
  one, then convergence. 1024 seeds pass. It found five defects the
  hand-written tests had not (`../docs/sandcastle-rewrite.md`).
- **The daemon** (`crates/sandcastled`): the router over real TLS on the
  simulator's world: auth (valid, invalid, replay), a computer's whole
  life through the proxy and a tunnel, a restore through the API, and a
  restart that keeps state, sessions, and the replay cache.
- **The real engine** (`crates/e2e`, by hand: it needs the KVM host):

  ```sh
  cargo run --release -p sandcastle-e2e -- \
    --keys-dir ~/.config/finite-next/secrets/sandcastle-test \
    --evidence target/e2e/sandcastle-e2e.json \
    [--hermes --hermes-owner-key ~/.config/finite-next/secrets/fragment-club-e2e-key]
  ```

  Sections `auth`, `life`, `crash`, `backup`, `hermes`, `cleanup`
  (`--only` picks some): 62 checks in about 100 s on `finite-lat-6`,
  among them the daemon SIGKILLed mid-rebase and mid-restore by a watcher
  on the host, and a model call from a Hermes guest through the swap with
  the computer's own token (a few cents). It reaches a computer the
  node's certificate does not name with the API's TLS name and the
  computer's Host header.
