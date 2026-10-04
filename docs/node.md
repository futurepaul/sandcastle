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
GET    /v1/health                          the engine's, and {"node": {version, isolation}}
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

On the platform, the computer's object checks the signature again. It
refuses an intercept that names any container but its own, and gives the
request to the binding its container set for that index. Intercepts are
only ever appended while a container runs, so an index is stable.

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

- A signature replayed inside its window verifies. Fixing this needs a
  nonce cache (the node's and the object's).
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

A newer dial replaces the older connection; the older connection's
streams are reset.

### Frames

Each WebSocket binary message is exactly one frame, big-endian:

```
kind u8 | flags u8 | stream u32 | length u32 | payload (length bytes)
```

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
- Calls in flight when a connection drops fail, as they would if a direct
  connection dropped.

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

## Isolation

`health` reports `isolation: "microvm"`: the engine's VMs, each jailed.
A node without KVM would report something weaker, and the platform's
policy decides what it may run there.

## Not done

- **The uplink through a forward proxy.** The node dials TCP to the
  platform's host. An HTTP `CONNECT` proxy (`HTTPS_PROXY`), the usual
  corporate path out, is not spoken yet.
- **The uplink's calls in flight survive no reconnect.** A `wait` (the
  platform's `monitor()`) that fails because the connection dropped is
  reported as the container's exit. The computer then recovers through
  its lifecycle. A wait that is asked again after a reconnect, before it
  reports anything, is next.
- **One connection per node.** All of a node's calls pass through its one
  `Node` object, which bounds its throughput. A node with many busy
  computers would dial several uplinks (`<id>/<n>`), with computers
  spread over them.
- **More than one platform per node, and names fenced per platform.**
- **The engine's sizes are Cloudflare's** (at most 4 vCPU and 12 GiB).
  A node's own ceiling, for bigger machines than Containers offer, is
  configuration still to add.
