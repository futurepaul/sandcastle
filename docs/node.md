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
| Behind NAT, or a proxy that allows only outbound HTTPS | the uplink (not built): the node dials a WebSocket out to the platform, which serves this same API over it |

## Isolation

`health` reports `isolation: "microvm"`: the engine's VMs, each jailed.
A node without KVM would report something weaker, and the platform's
policy decides what it may run there.

## Not done

- **The uplink.** It is the only shape that reaches a node behind NAT or
  behind a corporate proxy.
- **More than one platform per node, and names fenced per platform.**
- **The engine's sizes are Cloudflare's** (at most 4 vCPU and 12 GiB).
  A node's own ceiling, for bigger machines than Containers offer, is
  configuration still to add.
