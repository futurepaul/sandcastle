# A node on the network

*Proposed 2026-10-03, for fragment's self-hosted lane (fragment's
`docs/self-host.md`, seam 2, on its branch `selfhost`).*

The engine serves Cloudflare's container API on unix sockets, to a
client on the same box (celld, the driver). A **node** is the engine
with a platform somewhere else: fragment's cell on Cloudflare, on celld
on another box, or under `wrangler dev` on this one. The platform drives
the node's containers through `NodeContainer` (fragment's
`cell/node.mjs`). That is Cloudflare's `ctx.container`, method for
method, over this API. So the code that drives a container doesn't
change with where the container runs.

`sandcastle-node` is a second process beside the engine:

- **It is unprivileged.** The engine stays root and reachable only on its
  sockets. The node runs as the engine's client user, holds the node's
  secret, and is the only thing on the network.
- **It checks every call's signature.**
- **It hands each intercepted request to the platform,** signed.

## The API

The API is the engine's routes (`crates/engine/src/linux/server.rs`) on
`listen`. Every call is signed (Auth, below). Most calls pass to
`engine.sock` unchanged:

```
GET    /v1/health                          the engine's, and {"node": {version, isolation, arch}}
GET    /v1/containers[/{name}]             list, inspect
POST   /v1/containers/{name}/start         see below
POST   /v1/containers/{name}/destroy|signal|snapshots
GET    /v1/containers/{name}/wait|logs
PUT    /v1/containers/{name}/intercepts
GET    /v1/snapshots;  DELETE /v1/snapshots/{id}
GET    /v1/images;     POST /v1/images/pull
```

Three calls work differently from the engine's:

- **`start`.** The node sets `handler` to its own egress socket,
  whatever the platform sent. A platform never names a path on the
  node.
- **`exec` is a WebSocket** (`GET /v1/containers/{name}/exec`, with
  `Upgrade: websocket`), because a Worker's `fetch` can upgrade to
  nothing else.
  - The first message is the exec's JSON (`ExecRequest`).
  - After that, each binary message is exactly one of the engine's frames
    (`exec_stream`), in both directions.
  - From the platform, only stdin, resize and signal frames are accepted,
    and each is checked whole.
- **`ANY /v1/containers/{name}/ports/{port}/{path}` is a guest port,**
  HTTP and WebSocket alike.
  - The node takes a connected socket from `ports.sock` and speaks HTTP
    over it.
  - It bridges a 101 both ways.
  - The guest sees the host of the URL the platform was asked for, which
    the platform passes in `x-sandcastle-url`.

Image loads (`docker save` tars) stay on the engine's own socket. An
operator loads images on the node; a platform only names them.

## Intercepts

Every container the node starts names the node's egress socket as its
handler. The engine's egress proxy sends each intercepted request there,
with `x-sandcastle-container`, `-intercept`, `-host` and `-scheme` set.
These overwrite anything the guest sent under those names. The node
then:

1. reads the request whole, up to 32 MiB, the engine's own bound;
2. signs it;
3. sends it to `<platform>/api/nodes/egress`, with its path in
   `x-sandcastle-path`;
4. streams the platform's answer back to the guest.

A WebSocket's upgrade (`connection: upgrade`, `upgrade: websocket`) has
no body. The node signs it over the empty body and sends it on with its
`connection` and `upgrade` headers; these are the only hop headers that
pass. On the platform's 101, the node answers the engine with the same
101 and joins the two connections both ways. Any other answer passes back
as it is. The stub's bridge needs this for its keepalive and for
`/f/<f>/__live`.

On the platform, the computer's object checks the signature again. It
refuses an intercept that names any container but its own, and gives the
request to the binding its container set for that index. Intercepts are
only ever appended while a container runs, so an index is stable.

### WebSockets through the engine's proxy

The engine's egress proxy carries the guest's half (`crates/egress`,
`ws.rs`). A guest's upgrade to an intercepted host, `ws://` or `wss://`
through the proxy's TLS, goes where its request would: to the handler
(the node), or for a substitute to the real host with its placeholders
replaced. On the answer's 101 the proxy answers the guest's 101 and
joins the two connections. Any other answer passes back as one. A 101 to
anything but a WebSocket's upgrade is a 502.

The proxy reads each frame's head as it passes. Payloads stream through,
and each way holds one 16 KiB read. It ends both sides, and sends each a
close frame where one fits between frames (masked toward the platform,
whose client it is):

| | Limit | Close |
|---|---|---|
| A frame's payload | 32 MiB, an intercepted body's bound | 1009 |
| A message, its frames together | 32 MiB | 1009 |
| A control frame | 125 bytes, never fragmented | 1002 |
| RFC 6455's framing broken: a reserved opcode, a continuation with no message, a client's frame unmasked, a server's masked | | 1002 |
| Nothing either way | 1 hour (`IDLE`) | 1001 |
| A side done (its stream ended, or close frames both ways) | 10 s (`CLOSE_WAIT`) for the other | 1001 |

`IDLE` is long because a computer's keepalive is silent by design while
it is held. Ending one costs little: the computer's object holds it awake
20 minutes after a close, and the bridge dials again at once.

- Each joined WebSocket holds one of the forwarder's 256 connections a VM
  may have (`FORWARDS_MAX`), so they are bounded with the rest.
- Each end is a decision in the proxy's log: `WebSocket closed`,
  `WebSocket idle 3600000 ms (1001)`, `WebSocket refused from the guest:
  a frame of … bytes, past … (1009)`.
- A WebSocket to a host that is not intercepted is spliced as bytes, as
  before: no headers set, no limits. The rules refuse what they refused.
- An engine restart ends every WebSocket through it; its guests dial
  again.

**Evidence (2026-10-04).**

1. **Host tests,** `cargo test -p sandcastle-egress`: 25 in the crate
   and 4 in `tests/websocket.rs`, under 1 s together.
   - The gate: frames pass byte for byte however the reads split them,
     in every head form; limits at their edges; each malformed head; the
     proxy's own close frames, each way.
   - The join, over in-memory pipes: idle, a refusal, a side done while
     the other lingers, and a clean close.
   - Through the proxy, with a stand-in platform on the handler's socket
     and a guest's client (tokio-tungstenite) that dials the proxy as the
     forwarder does:
     - `ws://` and `wss://` (a client that trusts only the node's CA),
       the four headers set; text, and 700,000 bytes of binary, echoed; a
       close from the guest and one from the platform, each clean; a
       second socket after the first;
     - a 403 passes back as an answer, its body intact; a 101 to a plain
       `GET` is a 502;
     - not intercepted, with the internet off: NXDOMAIN, and an
       unassigned fake address and a public one refused. Allowed by a
       rule: spliced untouched, no headers set, and a frame past the
       limit passes;
     - a substitute's WebSocket goes on to the real host, its placeholder
       replaced and its frames held to the limits;
     - a frame at the limit passes. One byte past it, from the guest or
       from the platform, closes both sides with 1009. A client's frame
       unmasked closes both with 1002. Traffic keeps a socket open past
       the idle limit, and quiet ends it with 1001.
   - After each socket, the proxy's count of joined WebSockets is 0
     again.
2. **curl 8.22,** the version in `curlimages/curl:8.22.0`, ran on the
   host through the same proxy, with a TCP stand-in for the forwarder
   (not kept). `ws://` and `wss://` got the platform's hello, and
   `-T -`'s message came back echoed.
3. **On a jailed engine:** `sandcastle-krun-spike egress` (Acceptance 5)
   now opens one of each from the curl image too, through the stand-in
   handler, which answers WebSockets:

   ```sh
   printf sandcastle-ws-up | curl -sS -m 3 -T - \
     --cacert /etc/cloudflare/certs/cloudflare-containers-ca.crt wss://model.example.com/ws
   ```

   Its checks are `ws_through_intercept`, `wss_through_intercept`, and
   `off_wss_through_intercept` (the internet off). Not yet run: it needs
   the engine built from this change, as root.

**Found on the way:**

- **An address intercept could take down the engine.** An HTTP
  `ip:port`, range, or `*` intercept matched by a connection to an
  address has no name, and the proxy took one with `expect`. That was a
  panic, and with `panic = "abort"` the whole engine went down, every VM
  with it, from inside a guest. The address is now the host. Sandcastle's
  `main` has the same bug; its fix is a PR of its own.
- **A substitute went on to port 80 or 443,** whatever port the guest
  dialed. It now goes to that port.
- **The join's watch missed a side's end.** It took its deadline once and
  slept, so a side that ended meanwhile waited out `IDLE` instead of
  `CLOSE_WAIT`. The join test hung in 2 runs of 5. A side's end now wakes
  the watch.
- **TLS that ends without `close_notify`.** tokio-tungstenite drops its
  stream without one, which rustls reports as an error. In a join it is
  an end like any other: the close frames say whether it was clean.
- **curl keeps a WebSocket open after the platform's close** (8.22, with
  `-T -`), and ends only at `-m`, with 28. So the checks read its output,
  not its exit code.

## Auth

Calls are signed with HMAC-SHA256 under the node's secret (at least 32
bytes, a file on each side), in the header
`x-sandcastle-auth: t=<unix seconds>,sig=<hex>`. A timestamp more than
60 s from the receiver's clock is refused.

- **A call** signs
  `sandcastle-node-v1\n{method}\n{path and query}\n{t}\n{sha256(body)}`.
- **A guest port** signs `UNSIGNED-PAYLOAD` in the body's place, because
  its body streams. The platform has already checked who may use the
  port; the node only learns that the platform sent the request.
- **An intercept** signs
  `sandcastle-egress-v1\n{method}\n{container}\n{intercept}\n{scheme}\n{host}\n{path}\n{t}\n{sha256(body)}`.

**Debt:**

- A call's signature replayed inside its window verifies. Fixing this
  needs a nonce cache (the node's and the object's), like the one the
  uplink's dial already has (The uplink, The dial).
- A guest port's body is not signed.
- Both matter only where the network itself is not trusted, and that is
  where TLS goes (Reachability).

## Reachability

The protocol is HTTP. Getting from the platform to the node is the
network's job:

| Where the node is | How the platform reaches it |
|---|---|
| The platform's own box | `listen` on loopback |
| A LAN or an intranet | a private address, with TLS from the operator's CA in front (`ca_file` covers the node's calls back) |
| A datacenter | a public address, with TLS in front |
| Behind NAT, or a network that allows only outbound HTTPS | the uplink: the node dials a WebSocket out to the platform, which serves this same API over it (The uplink) |

## The uplink

*Phase S7 of fragment's self-hosted lane.* A node the platform cannot
reach (behind NAT, or in a network whose only way out is HTTPS on 443)
dials the platform instead. It opens one WebSocket to
`<platform>/api/nodes/uplink` (`wss` in production, `ws` in dev), and the
platform serves this same API over it. Nothing above the transport
changes:

- The platform's calls are the same requests, signed as before (Auth).
- The node answers each one with its own router (`server::route`),
  exec and guest-port WebSockets included.
- Intercepts still go out as HTTPS requests to `/api/nodes/egress`
  (below, "Intercepts stay off the uplink").

On the platform, one `Node` Durable Object per node id holds the socket.
`NodeContainer`'s calls reach it through the object's `fetch`, in place
of a `fetch` to the node's URL. `FRAGMENT_NODE_URL=uplink:<id>` chooses
this transport.

### Configuration

```json
{
  "engine": "/run/sandcastle/engine.sock",
  "ports": "/run/sandcastle/ports.sock",
  "egress": "/run/sandcastle-node/egress.sock",
  "secret_file": "/etc/sandcastle/node.secret",
  "platform": "https://fragment.example",
  "uplink": { "url": "wss://fragment.example/api/nodes/uplink", "id": "office-1" }
}
```

`listen` is optional once there is an `uplink`; a node may do both. On
the platform, `FRAGMENT_NODE_URL=uplink:office-1` and the same secret.

### The dial

The node's upgrade request carries three headers:

- `x-sandcastle-node: <id>` (1 to 64 of `a-z`, `0-9` and `-`);
- `x-sandcastle-nonce: <32 hex>`, fresh for each dial;
- `x-sandcastle-auth: t=<unix seconds>,sig=<hex>`, over
  `sandcastle-uplink-v1\n{id}\n{nonce}\n{t}`.

The platform refuses the dial unless:

- the id is the node it is configured with;
- the timestamp is inside the 60 s window;
- the nonce is one it has not seen inside the window. The object keeps
  the nonces of the last window, at most `DIALS_PER_WINDOW` of them, and
  refuses a dial past that.

A connection lives for hours, so a signature on its first request is not
enough: the node must also know the platform is real before it serves
anything. So the platform's first frame is `hello`, `t=…,sig=…` over
`sandcastle-uplink-hello-v1\n{id}\n{nonce}\n{t}`. It signs the node's own
nonce, so a hello recorded from another dial answers no other. The node
serves nothing before a good hello, and gives up on the dial after
`HELLO_WAIT`.

A newer dial replaces the older connection. The platform sends the new
connection's hello before anything else touches it, then ends the older
connection's streams (below, "Keepalive and reconnecting", for the calls
it asks again).

### Frames

Each WebSocket binary message carries one or more whole frames, each
big-endian:

```
kind u8 | flags u8 | stream u32 | length u32 | payload (length bytes)
```

A sender batches the frames it has ready together, up to
`MESSAGE_BYTES_MAX` (one frame's most) and `FRAMES_PER_MESSAGE_MAX` (64)
a message. So a call with a small body (`open`, `data`, `end`) is one
message, not three. This matters because a platform cannot set
TCP_NODELAY (a Worker cannot, and workerd does not). Its TCP holds a small
write back until the one before is acknowledged (Nagle's algorithm), so
with one frame a message every call with a body waited out the node's
delayed acknowledgement: 41.9 ms a call, against 0.6 ms batched (below,
Evidence). A message that ends inside a frame, or holds more than the
limits allow, is refused whole.

| kind | stream | way | payload |
|---|---|---|---|
| 1 `hello` | 0 | platform → node | `t=…,sig=…` (The dial) |
| 2 `ping` | 0 | both | at most 8 bytes |
| 3 `pong` | 0 | both | the ping's payload |
| 4 `open` | n | platform → node | the request's head: JSON `{method, path, headers}` |
| 5 `head` | n | node → platform | the answer's head: JSON `{status, headers}` |
| 6 `data` | n | both | body bytes, 1 to `DATA_BYTES_MAX` |
| 7 `end` | n | both | none: that way's body is done |
| 8 `reset` | n | both | why, UTF-8: the stream is over, both ways |
| 9 `window` | n | both | u32: more bytes the other side may send |
| 10 `ws-message` | n | both | a fragment of one message; flags `FIN` (its last) and `BINARY` |
| 11 `ws-close` | n | both | u16 code and a reason, or nothing |

A stream is one HTTP exchange. The platform picks its id (never 0, never
one in flight) and sends `open`, its body as `data`, then `end`. The node
answers `head`, its body as `data`, then `end`. A `101` head makes the
stream a WebSocket: `ws-message` and `ws-close` both ways, until each side
has sent its `ws-close`. Either side may `reset` at any time. Frames for
a stream that is over are dropped, because the other side may have sent
them before it learned. Any other frame out of order, such as `data`
before `head`, a second `head`, `data` after `end`, `ws-message` before a
`101`, or an `open` for a stream in flight, resets that stream. A frame
that does not decode ends the connection.

**Flow control.** Each way of each stream starts with a window of
`WINDOW_BYTES` that its `data` may fill. The receiver sends `window` as
its reader takes the bytes. A sender past its window is a protocol error,
so neither side ever holds more than a window of a stream's body. A
WebSocket cannot push back on a Worker (`send` never waits), so
`ws-message`s are not windowed. Each side bounds what it holds for a
stream instead (`STREAM_BUFFERED_BYTES_MAX`), and resets a stream whose
reader falls that far behind.

**Limits** (`uplink::frame`, mirrored in the cell's `uplink.mjs`):

| | |
|---|---|
| A frame's payload | 256 KiB (`FRAME_PAYLOAD_BYTES_MAX`); `data` at most 64 KiB |
| A message | its frames, at most 256 KiB and 10 bytes in all, and 64 of them |
| A head (`open`, `head`) | 64 KiB, at most 100 headers |
| A WebSocket message, reassembled | 4 MiB (an exec frame is at most 1 MiB and 8 bytes) |
| Streams in flight on a connection | 128 |
| A stream's window | 256 KiB |
| Bytes held for one stream | 4 MiB |
| Bytes held for a connection | 32 MiB (the platform's end is a Durable Object, with 128 MB) |

### Keepalive and reconnecting

- The node pings every `PING_EVERY` (20 s), and the platform answers each
  ping. Hearing nothing for `SILENT_MAX` (60 s) ends the connection.
  Proxies that close idle sockets, and Cloudflare's 100 s, never see one
  idle.
- The node dials again after `RECONNECT_MIN` (1 s), doubling to
  `RECONNECT_MAX` (60 s), each wait with up to half again of jitter. A
  connection that lived `STABLE_AFTER` (30 s) starts the waits over.
- A dial has `DIAL_WAIT` (15 s), the TCP and TLS connections and the
  upgrade included.
- The node sets TCP_NODELAY on its side, and re-arms TCP_QUICKACK after
  every read: it acknowledges at once whatever a platform that Nagles
  sends it. Behind a relay that Nagles toward the node, a 2 MiB upload
  took 53–66 ms with it and 610–650 ms without (Evidence).
- When a connection drops, a call the node had not yet answered, and that
  is safe to ask again (a `GET` that is not an upgrade: `wait`, inspect,
  a guest's page), waits up to `AGAIN_WAIT_MS` (30 s) for the node's next
  dial and is asked again there. So the platform's `monitor()`, a `wait`
  that lasts as long as the container, outlives a reconnect. Any other
  call in flight fails with a 502 that says why, as a direct call fails
  when its connection drops.
- A call made while no uplink is open waits `UPLINK_WAIT_MS` (5 s) for
  one, then answers 503. A platform that is down for long pushes the
  node's waits toward `RECONNECT_MAX`. A computer that wakes meanwhile
  then fails its start, as it would against an unreachable node on
  `listen`, and its owner wakes it again (Evidence).

### Intercepts stay off the uplink

Intercepts go node to platform, and the node can always open a
connection to the platform: it already holds one. So the uplink adds no
reach for them. Through the uplink, every computer's egress would pass
through one object. That covers model calls that stream for minutes, and
backups of up to 32 MiB. They go to the router instead, which spreads
them across the computers' own objects. They should move onto the uplink
only if a network allows a node a single connection. What they need
instead is a pool of connections that the node reuses, in place of one
connection per request.

### Evidence (2026-10-03)

Nothing here needs root: the engine is the **fake engine**
(`crates/fake-engine`), a lower-rung test double with no VMs. Its exec
echoes stdin, its guest ports are a local HTTP and WebSocket echo
server handed over on `ports.sock`, and its own route makes a guest's
request through the container's intercepts.

1. **Host tests,** `cargo test -p sandcastle-node --lib` (14):
   - the codec: round trips, batches, truncated and oversized messages,
     malformed frames, and heads;
   - each side's order: data before a head, a second head, data after
     its end, a replayed open, WebSocket frames before a 101, and
     fragments;
   - the dial and the hello: another node's, another nonce's, stale, a
     replay refused by the book, and a hello from another dial.
2. **In process,** `cargo test -p sandcastle-node --test uplink`, about
   3 s. The node's uplink runs against a stand-in platform
   (`tests/uplink.rs`) and the fake engine. It covers:
   - health, and an unsigned call (401);
   - start, inspect and intercepts;
   - exec with stdin and stdout: 393,238 bytes echoed byte for byte,
     one message longer than a frame;
   - a guest port: 3,000,000 bytes down and 2 MiB up, each many windows
     long; and its WebSocket, with text and a 700,000-byte message;
   - a guest's request through an intercept to `/api/nodes/egress` and
     back;
   - 128 `wait`s in flight, with the 129th refused as busy, and a reset
     freeing a place;
   - destroy, which answers every `wait`;
   - the platform dropping the connection: the node dials again with a
     new nonce, and the old dial, replayed, is refused (401);
   - a hello recorded from another dial: the node hangs up and answers
     nothing.
3. **The real thing.** fragment's dev stack (`wrangler dev`) with
   `FRAGMENT_NODE_URL=uplink:dev-node`. The node and the fake engine run
   in a network namespace with loopback alone; their only way out is a
   unix-socket bridge to the platform's port:

   ```sh
   R=target/uplink   # in fragment-uplink: the node's secret (mode 600), node.json, logs
   FRAGMENT_NODE_URL=uplink:dev-node FRAGMENT_NODE_SECRET_FILE=$R/node.secret \
     FRAGMENT_NODE_IMAGES='{"stub":"docker.io/library/stub:fake"}' cargo xtask dev --port 8890
   socat UNIX-LISTEN:$R/platform.sock,fork,mode=600 TCP:127.0.0.1:8890,nodelay
   unshare -rn sh -c "ip link set lo up
     socat TCP-LISTEN:8890,bind=127.0.0.1,fork,reuseaddr,nodelay UNIX-CONNECT:$R/platform.sock &
     sandcastle-fake-engine --dir $R/ns/engine &
     exec sandcastle-node serve --config $R/ns/node.json"   # an uplink, no listen
   ```

   Inside the namespace, `ip -brief addr` shows `lo` alone, and `ss -ltn`
   shows the bridge's `127.0.0.1:8890` and the fake guest's loopback
   port. The node listens nowhere, and the host's LAN address is
   unreachable. The platform was driven as the shell drives it, signed
   in through the WorkOS fake:
   - `POST /api/computers`, `…/wake`, `…/ports/8080/ticket` and
     `…/sleep`;
   - a guest port through the computer's own origin;
   - the guest's request through the fake engine's own route.

   The final run (release builds; wall-clock times at the client):

   | What | Through the uplink |
   |---|---|
   | Wake: start and four intercepts | 46 ms; each call 0.1 to 0.25 ms at the node |
   | A guest port's page, through the ticket | 200 in 11 ms |
   | 3 MB down and 2 MiB up through a guest port | 47 ms and 63 ms, intact (on `listen`: 12 ms and about 6 ms) |
   | A guest port's WebSocket | 101 in 13 ms; text echoed; 700,000 bytes echoed intact (29 ms); close 1000 |
   | The guest's request through `api.fragment.internal` | 200, the computer's view, in 12 ms |
   | The node restarted while the computer was awake | it dialed again in 53 ms. The `wait` was asked again and answered when the sleep ended the container. The computer stayed awake |
   | The platform restarted | the node dialed again by itself. The computer's new object inspected its container (200), adopted it, and armed its intercepts again |
   | Sleep | 2.1 s: the backup's exec (2.0 s, the double's idle bound), signal 15, then `wait` 200 |

**Found on the way.** Each is fixed here unless it says otherwise.

- **Nagle.** With one frame a message, every call with a body waited for
  a delayed acknowledgement, about 40 ms. Batching took a wake from
  290 ms to 46 ms (above, Frames).
- **The relays.** socat without `nodelay` slowed 2 MiB up to 1.3 s and
  3 MB down to 0.29 s. With `nodelay` they take 57 to 64 ms and 42 to
  50 ms, the same as with the node on the host, dialing workerd
  directly. Behind a relay that Nagles toward the node, TCP_QUICKACK
  makes a 2 MiB upload 53 to 66 ms, against 610 to 650 ms without it.
- **curl's `Expect: 100-continue`.** curl waits 1 s for an answer before
  it sends a body past 1 MiB, on `listen` and the uplink alike. The
  numbers above send an empty `Expect:`.
- **A dropped uplink failed the computer's `wait`.** The computer would
  then never have heard its container exit. Fixed by asking again.
- **fragment's `entry.mjs` reported to routes the cell does not have.**
  It reported `container/exited` and `container/tab`, but the cell's
  routes are `computer/exited` and `computer/tab`. So every guest port's
  WebSocket answered 500, and no exit was ever reported. Master has the
  same bug; the fix is on fragment's branch, to cherry-pick.
- **A long platform outage fails a computer's wake.** It pushes the
  node's backoff toward a minute. A computer that wakes meanwhile fails
  its start (`wont_wake`), as it would against an unreachable node, and
  its owner wakes it again.

**Not shown in the stack: exec's stdin.** The platform's only exec with
stdin is the Sandbox SDK's backup and restore. Its `sandbox-shim` speaks
first, and the SDK writes stdin only after the shim's answer, which no
double gives. So in the stack, the exec's WebSocket, its JSON and its
exit went through the uplink, and the SDK refused the double's empty
output ("truncated control data"). Stdin echoed back is shown in process
(rung 2). S2's checks on a real engine, which runs as root, are still
Paul's to run.

## Test doubles

Two engines stand in for the real one where it cannot run. Neither is
ever a node's engine.

- **The fake engine** (`crates/fake-engine`) runs nothing: containers
  are records and exec echoes (The uplink, Evidence).
- **The Docker double** (`crates/docker-engine`,
  `sandcastle-docker-engine`) serves the engine's API on the same two
  sockets and runs each container in Docker, through the `docker` CLI.
  It gives Docker's isolation only, with no VMs. It is for a node in front
  of a real image on a box with Docker but without KVM or root, such as
  fragment's self-hosted lane.

What the double fakes, and how:

- **Start** is `docker run --init --pull never`. The container is named
  `sandcastle-<8 hex of the dir>-<name, ':' as '-'>` and labelled
  `sandcastle.double=<dir>`. Three mounts go in: `<dir>/c/<run>` at
  `/.sandcastle`, the relay at `/.sandcastle-relay`, and the double's CA
  where Cloudflare's containers find theirs. The start answers once the
  relay is up. A container that exits during its start still starts, and
  `wait` reports the exit. A missing image is a 404.
- **Intercepts** take exact hosts on 80 (http) and 443 (https) only.
  A glob, `*`, an address, another port or a substitute is a 400. Each
  host goes into the container's `/etc/hosts` as 127.0.0.1. There the
  relay (`sandcastle-docker-relay`, static, std only) listens on loopback.
  It joins each connection to the container's `http.sock` or
  `https.sock`, which the double serves on the host. The double terminates
  HTTPS with its CA, for the name the guest's TLS asks for. It then hands
  each request to the handler with the egress proxy's four
  `x-sandcastle-*` headers, streaming both bodies. A WebSocket's upgrade
  goes the same way: on the handler's 101 the double answers the guest's
  101 and joins the two connections. A host stays in
  `/etc/hosts` after its intercept is gone, and then answers 502. Nothing
  else is intercepted: the container's network is Docker's, and open.
- **The relay** also has `ws-probe <host> <path> <message>`, a guest's
  WebSocket client for the tests, since busybox has none.
- **Exec** is `docker exec`, with the relay in front
  (`exec [--combined] <pidfile> <cmd…>`). So a signal frame reaches the
  process, through the image's `kill`; without `kill`, the docker client
  is ended instead. A combined stderr keeps its order. The process sees
  the container's whole env, where the engine gives it only `PATH`.
  A pty is a 400.
- **Ports.** `ports.sock` connects over TCP to the container's address on
  Docker's bridge and hands the socket over as `nic`. A port bound only to
  the guest's loopback is refused.
- **Wait** is `docker wait`. A code of 128+n after the double sent
  signal n is reported as signal n. **Destroy** is `docker rm -f`.
  **Snapshots** are `docker commit` to `sandcastle-double-snapshot:<id>`.
  **Logs** are `docker logs --tail 1000`. **Images** are the box's own,
  and a pull is a 400.
- **Not applied:** CPU and memory limits, `enableInternet: false`, allow
  and deny lists, and data disks (a 400). Each start logs what it skips.
  The start's env is on docker's command line, so other users on the box
  can read it.
- **Its own end** (SIGTERM or SIGINT) removes every container and
  snapshot labelled for its dir. Its start removes whatever a double on
  the same dir left behind.

```sh
cargo build --release -p sandcastle-docker-relay --target x86_64-unknown-linux-musl
# for arm64 from x86: CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld … --target aarch64-unknown-linux-musl
cargo build --release -p sandcastle-docker-engine
sandcastle-docker-engine --dir <dir> --relay $PWD/target/x86_64-unknown-linux-musl/release/sandcastle-docker-relay
```

It runs as a user in the `docker` group. The node's config names
`<dir>/engine.sock` and `<dir>/ports.sock`. `<dir>` must be short, so
that `<dir>/c/<run>/https.sock` fits a unix socket's 107 bytes; this is
checked at start.

**Evidence (2026-10-04),** all with `fragment-stub:s2`:

1. **Host tests,** `cargo test -p sandcastle-docker-engine -p
   sandcastle-docker-relay` (21): names, each docker call's argv,
   `/etc/hosts` lines, what routes and where, exits and signals, and the
   relay's command lines and its copy with half-close.
2. **`tests/docker.rs`** (ignored: it needs Docker,
   `SANDCASTLE_DOCKER_TEST_IMAGE` and the static relay), about 2.7 s. A
   start takes 150 to 210 ms. A guest's `wget` reaches the handler with the
   four headers, and HTTPS through the container's loopback is terminated
   with the CA. A host no longer intercepted gets a 502. 393,238 bytes of
   stdin echo intact in about 22 ms. Also covered: stderr apart, combined,
   or ignored; exit codes; cwd and user; signal 15 to an exec; a guest
   port and a refused one; a snapshot restored; signal, destroy, and
   `wait`; an entrypoint that exits at once; a missing image; and the
   double's end leaving nothing.
3. **`tests/node.rs`** (ignored, the same needs), about 1.5 s.
   `sandcastle-node`'s own servers, wired as its `main.rs` wires them,
   stand in front of the double. A stand-in platform checks the node's
   signatures. A signed start takes 160 ms. Exec runs over the node's
   WebSocket: a guest's `POST` goes through `api.fragment.internal` to
   `/api/nodes/egress`, signed by the node, and 393,238 bytes of stdin
   echo. A guest's WebSocket (`ws-probe`) goes through the intercept, the
   double and the node. The platform echoes it, and the round trip takes
   about 20 ms. `health` says `isolation: "docker"` and the node's arch.
   A guest port answers. The stub's own entrypoint boots, and its
   screen on 6080 answers through the node. The bridge's first
   `GET /api/computer` came before its intercept was armed and failed; it
   tried again 1.5 s later and reached the platform. Signal 15 ends it
   with code 0.

**Found on the way:**

- **busybox wget cannot finish an HTTPS handshake here.** Its TLS takes
  one handshake message per record. rustls 0.23 sends TLS 1.2's server
  flight as one record. So the handshake fails against the double, and
  against the engine's egress proxy too, which uses the same rustls. The
  test drives a rustls client through `nc` in the container instead.
- **No WebSocket crossed an intercept.** The bridge opens WebSockets to
  `api.fragment.internal` (`/api/computer/keepalive`, `/f/<f>/__live`).
  The double and the node's egress now carry them (Intercepts, above),
  and so does the engine's egress proxy, with limits (Intercepts,
  WebSockets through the engine's proxy).
- **A `wait` after the end blocked for good.** tokio's
  `watch::Sender::send` stores nothing while no receiver is subscribed.
  So a `wait` asked after a container ended never answered. Both doubles
  now use `send_replace`; the fake engine has a test for it.
- **The node's `health` said `isolation: "microvm"` whatever its
  engine.** It now reports the engine's `isolation` when its health names
  one (the double's is `docker`), and the node's `arch`.

## Pairing

*Experimental; fragment's docs/self-host.md, seam 2, "Bring your own
computer".* A person starts sandcastle on a machine of theirs and pairs it
with their account on a platform that lets its people bring their own
computers (fragment's `FRAGMENT_BYOC=on`). It is then a node for their
computers alone, dialing in over the uplink like any node the platform
cannot reach. A platform with it off refuses the pairing, saying why.

```sh
sandcastle-node pair https://fragment.home.arpa --config /etc/sandcastle-node/node.json \
  [--name mac] [--ca-file /etc/sandcastle/home-ca.pem] [--secret-file <path>] \
  [--engine <engine.sock> --ports <ports.sock> --egress <egress.sock>]
```

It is a device authorization (RFC 8628's shape; `src/pair.rs`):

1. The node asks to be paired, `POST <platform>/api/nodes/pair` with its
   name (`--name`, else the machine's) and architecture. It holds nothing
   yet, so the call is unsigned.
2. The platform answers a code for a person to compare (`BCDF-GHJK`), the
   link they approve it at, and a device code that only the node holds.
   The node prints the link and the code, never the device code.
3. It polls `POST <platform>/api/nodes/pair/poll` as often as the
   platform says, and slower when told `slow_down`, until the code
   expires (ten minutes).
4. The person opens the link where they are signed in, checks the code,
   and approves. The platform names the node (`paired-<16 hex>`, never the
   node's choice) and mints its secret. The node's next poll takes both,
   once: a poll replayed after finds nothing.
5. The node writes its secret to its secret's file, 0600, replacing it
   whole (a file beside it, then a rename). It writes its config the same
   way: `platform`, `uplink` (`wss://<platform>/api/nodes/uplink` for
   https, `ws` for http) as the id it was given, `secret_file`, and
   `ca_file` for a private CA (it covers the pairing's calls too). An
   existing config keeps its engine's sockets, its `listen` and its CA. A
   first config takes the three sockets from the flags and puts the
   secret beside itself.
6. `sandcastle-node serve --config <path>` dials as that id.

The secret is never printed and never on a command line. Run it as the
node's user, in a directory of the node's own (`/etc/sandcastle-node`,
not root's `/etc/sandcastle`, where the engine's config lives).

**Revoked** by its owner (in the platform's settings), the node's uplink
is closed (4003), and each later dial is refused: `uplink: the platform
refused the dial: 403 … node_revoked`. It keeps dialing, backing off to
a minute. Pair the machine again to use it again (a new id and secret).

**Evidence (2026-10-05).** `cargo test -p sandcastle-node --lib pair` (5:
its arguments, the uplink from the platform, the config it writes, the
answers, a file written whole) and `--test pair` (3, in process against a
stand-in platform: a pairing through `pending` and `slow_down` to its
files, paired again keeping the sockets; five refusals that write
nothing: BYOC off, an expired code, a replayed poll, an answer naming no
node's id, a secret too short; and a lost poll asked again, three in a
row ending it). fragment's e2e `pairing` section runs the real `pair` in
front of the Docker double, on celld and on wrangler dev (fragment's
docs/self-host.md, Status).

A poll that found no answer (the connection failed, or a gateway's 5xx)
is asked again, up to three in a row. If the platform had answered it
(the approval, its secret) and the answer was lost on the way, the next
poll finds the pairing spent: the node says so, and its owner revokes
that node in settings and pairs again. The calls are sent in origin
form, as the intercepts are (wrangler dev refuses an absolute URI).

## Computers on the real engine

*2026-10-05.* fragment's e2e put its computers on one node in front of
the real engine on an x86_64 box (`FRAGMENT_E2E_NODES=real`). The
computers and chat sections pass on the Docker double. On the engine
they gave 165 passed and 10 failed. Each failure went back to one of two
causes, both fixed here. After the fixes the same sections passed, 175
of 175, in four runs.

- **A computer woke with an empty `/data`.** The workload's root is an
  overlay of two filesystems, the image's disk and the scratch disk.
  - Without `xino`, a directory has the overlay's `st_dev`, and a file
    has its layer's.
  - The Sandbox SDK's backup shim stays on one filesystem. So it backed
    up `/data`'s directories and none of its files.
  - The bridge then woke without its state and answered every turn
    again.

  The guest now mounts the overlay with `xino=on` (`mounts::overlay`).
  Before, `stat` in a guest gave 25 for directories and 26 and 27 for
  files; after, 25 for all. A backup through an intercept to a stand-in
  gateway then held `bridge/state.json`, and a restore into a fresh
  container gave it back.
- **Every intercepted request waited about 40 ms.** The runner's
  forwarder wrote the proxy's answer to the guest's TCP connection piece
  by piece. Nagle's algorithm held each piece after the first for the
  guest's delayed ACK.
  - The bridge's posts came 48 ms apart.
  - The e2e checks that race them failed ("its turn starts and ends on
    work").

  The forwarder now sets `TCP_NODELAY`, as the double's relay always
  did, and so do the proxy's substitute connection and the node's
  connection to the platform. Posts now come 11 ms apart.

The double never showed either: overlay2's layers share a filesystem,
and its relay set `TCP_NODELAY` from the start.

**Not a fault: the keepalive opens and closes every few hundred ms.**
The bridge holds it only while a turn runs, and the scripted turns are
short. Its own log says `keepalive.held` and `keepalive.dropped` each
time, and the double shows the same.

**Not reproduced: three starts that took no exec.** In one earlier
run, three starts in a row each took no exec for 120 s, and a start
half a minute later was fine.
- The VMs had booted: the runner fails a boot at 60 s, and these lived
  120 s, until the platform destroyed them.
- Since then, nine e2e runs and 20 restart cycles on the engine have not
  shown it. Each cycle ends a container with a signal or a kill, then
  starts it again at once.

Two changes make it diagnosable if it comes back:

- an exec's start is bounded at 10 s (`EXEC_START_WAIT`). Before, an
  agent that never answered held the call forever;
- the engine logs each container's start, ready and end, and each exec
  that fails to open, by name.

## Isolation

`health` reports `isolation: "microvm"`: the engine's VMs, each jailed.
An engine whose own health names its isolation is reported as such
instead; the Docker double's is `docker`. A node without KVM would report
something weaker, and the platform's policy decides what it may run
there. `arch` is the node's machine (`x86_64`, `aarch64`), so a platform
can check that a node is what it is listed as.

## Not done

- **The uplink through a forward proxy.** The node dials TCP to the
  platform's host. An HTTP `CONNECT` proxy (`HTTPS_PROXY`), the usual
  corporate path out, is not spoken yet.
- **Some calls in flight do not survive a reconnect.** An exec, a guest
  port's WebSocket, and a write (start, destroy) cannot be asked again,
  so they fail with a 502. Only reads are asked again, `wait` among them.
- **One connection per node.** All of a node's calls pass through its one
  `Node` object, which bounds its throughput. A node with many busy
  computers would dial several uplinks (`<id>/<n>`), with computers
  spread over them.
- **More than one platform per node, and names fenced per platform.**
- **The engine's sizes are Cloudflare's** (at most 4 vCPU and 12 GiB).
  A node's own ceiling, for bigger machines than Containers offer, is
  configuration still to add.
