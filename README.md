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

## Layout

| Crate | What |
|---|---|
| `crates/proto` | The wire contract: `ComputerSpec`, `ComputerView`, `GrantSpec`, `Ticket`, `ApiError`, and every limit, validated before anything is stored |
| `crates/nip98` | NIP-98: verify (the node), sign (clients, the `sign` feature) |
| `crates/sandcastled` | The node: the store (SQLite), the engine gate (`msb`), the supervisor, the API, the proxy, the router |
| `crates/cli` | `sandcastle`: signs calls with a key file and prints the answer |

## The API

`https://api.<domain>/v1/…`, NIP-98 on everything but `GET /v1/health`.

| Call | Who | What |
|---|---|---|
| `PUT /v1/grants/{pubkey}` | a grantor | `{computers_max, vcpus_max, memory_mib_max, data_gib_max}` |
| `GET /v1/grants/{pubkey}` | that key, or a grantor | |
| `DELETE /v1/grants/{pubkey}` | a grantor | revoke; the key's computers stop |
| `PUT /v1/computers/{name}` | a key with a grant | create (201), the same spec again (200), or an update (200): the image, the service, and `url_auth` can change; storage and size are fixed (409) |
| `GET /v1/computers[/{name}]` | the owner | desired and observed state, the URL; env values read `(set)` |
| `POST /v1/computers/{name}/start` \| `/stop` | the owner | stop stays stopped |
| `DELETE /v1/computers/{name}` | the owner | 202; the computer reads `desired: deleted` until its machine and disk are gone, then 404 |
| `POST /v1/computers/{name}/tickets` | the owner | a single-use link, good for 60 s, that opens the computer's URL in a browser |

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
  "url_auth": "owner"
}
```

Each field in brief:

- **`storage`** is one of three:
  - `data`: the image is the system and `data_path` is a durable disk.
  - `ephemeral`: nothing survives.
  - `pet`: the whole machine is durable. Refused until built.
- **`service`** is the one process the node launches on every boot. The node keeps its definition, so nothing in the guest can change or revive it.
- **`env`** holds the service's own settings. It reaches the guest through an exec's stdin into a root-only file, never a command line.
- **Outbound credentials** go through the credential source, which is not built yet. They never go in `env`.

## What happens

The API records what callers want. The supervisor converges the engine to
it every 2 s, from the node's own state:

- **Create.** An idle microVM is made from the image, with the data disk and the service port published on `127.0.0.1` only. Then the service is launched.
- **Serving** means the service answered its health path through that port. It is not the engine's say-so.
- **Update.** When the image or service changes (a new *generation*), the node:
  1. stops the service gracefully,
  2. syncs the guest,
  3. stops the machine cleanly,
  4. recreates it on the same disk,
  5. relaunches the service.
- **Rollback.** A new generation that fails (its create or launch errs, or its service does not answer within `--startup-grace-s`, 120 s by default) is marked failed. The node goes back to the last spec that served, keeping the data (never rewound). A view's `rollback` field names the failed and running images and the reason. `start` retries it, and a new spec replaces it. The good spec failing is an ordinary failure, so the node never flips between the two.
- **Daemon restart.** A restarted daemon re-adopts running machines without relaunching anything. The launch script refuses to start a second copy.
- **Failures** back off: five in a row, then 60 s alone.

The router is the node's one listener: TLS on 443, then by Host.

- **`api.<domain>`** is the API.
- **`<name>.<domain>`** is a computer. For `url_auth: owner`, the router admits only a browser holding its `__Host-sandcastle` session:
  - That session comes from redeeming a ticket, once.
  - The cookie is stripped before the service sees the request.
  - The service's own login (Hermes') is the second gate.
- WebSockets pass through.

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
ExecStart=/home/ubuntu/sandcastle/target/release/sandcastled --state-dir /var/lib/sandcastle \
  --domain sandcastle.fragment.club --tls-cert /etc/sandcastle/le-cert.pem --tls-key /etc/sandcastle/le-key.pem \
  --grantor <hex> --msb /home/ubuntu/.local/bin/msb --msb-home /home/ubuntu \
  --guest-deny <the node's IPv4> --guest-deny <the node's IPv6 /64>
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=true
KillMode=process
Restart=on-failure
```

**`KillMode=process`:** stopping the daemon never stops a computer.

**No capabilities, deliberately.** An earlier unit gave the daemon
`CAP_NET_BIND_SERVICE`. Every VM process inherited it, and Linux then
denied an unprivileged `msb stop` the `/proc` access it needs.

**`--guest-deny`** keeps computers off the node's own addresses (its sshd,
its router). The engine's public-only egress already refuses private
ranges, link-local metadata, and the host's loopback.

The host's firewall admits 22 and 443 and nothing else.

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
```

Two flags cover a node without public DNS or a public certificate:

- `--ca-file` trusts a private CA.
- `--connect <ip:443>` skips DNS; the TLS name and the signed URL stay the API's.

## Checks

`cargo clippy --workspace --all-targets --all-features -- -D warnings` and
`cargo test --workspace --all-features`: 35 tests.

The node's tests run the real router, TLS, HTTP, store, and supervisor
against a fake engine whose services are live sockets. They cover:

- valid, invalid, and replayed calls;
- idempotent create, conflicts, and ownership;
- a whole life, from create to delete, including a ticket, the cookie
  strip, an upgrade, a rebase, and stop/start;
- rollback, and backoff when there is nothing to roll back to;
- a restart that re-adopts.

The real engine is proven by hand on `finite-lat-6`
(`../docs/sandbox.md`, Phases 1 and 2 on the real engine). That is not
yet a Rust e2e: see the debt ledger.
