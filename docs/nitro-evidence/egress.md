# Egress inside the boundary, one run

The engine of `nitro/egress-in-session` on a parent (an m8g.xlarge, Amazon
Linux 2023), confidential sandboxes, `"nitro": {"session_required": true,
"session_egress": <the home's path>}`; a home on the parent itself (the
bridge's home half, `--sessions --pins --up --egress`). The guest's
release: kernel `6a2bedef2f69105e72d3a0aadc996e6f1340425dc4e3337f5398ba37dfd3c1c4`
(nftables' inet family, redirect, dummy added), nft
`5aa5f759666f72df6090421a1a1a5155a05d5ed00c063821b447d6605c5571e7`
(nftables 1.1.1, static). The suite's image on this node then attests with
PCR0 `fb3b28b7b451b3ac3b8434afcb259c9b46cb2ac5c8ecd870b264203848afdc7bab87a97ccb9026f88bc14cd376d31ec6`.

## The canary

A computer made a canary from a seed in its start (the parent sees the
seed, not the canary: SHA-256 of it) and asked an intercepted host
(`http://canary.internal/<canary>`) for it three times; the intercepts'
handler, a unix-socket HTTP server standing for celld's, recorded each
path. Meanwhile `strace` read every `read`, `write`, `recv*` and `send*`
of every thread of the parent's engine.

| | The parent decides (sessions off) | The home decides (egress inside the boundary) |
|---|---|---|
| The computer's three requests | 200, 200, 200 | 200, 200, 200 |
| The handler got the canary | 3 times | 3 times |
| **The parent's engine saw it, in plain text** | **9 syscalls** (of 4,089) | **0** (of 4,793) |

The runner's threads were traced too, but strace did not attach to the
jailed runner in either run, so its counts claim nothing.

## The NIC

| | Result |
|---|---|
| A home's connection to the computer's port 8080 (over the session) | `HTTP/1.0 200 OK` |
| The parent's own, at the engine's `ports.sock` (the NIC, then the agent) | refused: "the guest did not accept on 8080 within 5s" |

Before this, the parent's own reached the port over the NIC (`session.md`).

## celld's conformance through the home

`conformance-nitro-egress.json`: **23 passed, 2 failed, 0 unsupported**, the
2 the snapshot cases a Nitro node refuses by design. The intercept cases
now run through the home's own egress: `interceptOutboundHttp` 15 ms,
`interceptOutboundHttps` 13 ms (the workload trusting the home's CA, from
the claim), `interceptAllOutboundHttp` 10 ms.
