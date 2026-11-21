# A Fragment home on Nitro

> **This branch merges nowhere until the owner decides.** It builds on the
> Nitro spike ([nitro-spike.md](nitro-spike.md)) and is phase 1 of "the
> real thing": a Fragment deployment people use from a browser, with the
> platform and each agent's computer inside confidential Nitro sandboxes.

## In plain words

A **home** is one organisation's Fragment, inside one confidential Nitro
sandbox of its own. It runs celld with fragment's real cell, its sign-in,
its files and its secrets. The parent EC2 instance boots it and carries its
bytes, but cannot read its memory. Its computers (lane A's work) are
sibling sandboxes on the same parent.

A person reaches the home from a browser over public HTTPS. The parent
forwards port 443 to the home untouched. The home ends TLS itself, with
certificates it gets itself from Let's Encrypt (TLS-ALPN-01), so the parent
carries ciphertext.

People sign in with their own passkeys, checked by the home's identity
door, so nobody else can sign in as them, the home's operators included.
A first passkey comes only with a one-time invite. A later one needs the
account's own passkey, or one of its recovery codes.

The home's secrets come to it sealed: KMS releases their key only to the
home's own image, measured by its PCR0. Its local disk is encrypted with a
key KMS releases the same way. Its durable state is in an S3 bucket, and
only the home holds the bucket's credentials.

## What runs in the home

| Piece | What it is | Where its state is |
|---|---|---|
| celld | The node (the fork's `selfhost` line), running the cell's release build, on loopback behind Caddy | The fleet bucket (S3); its work files on the encrypted disk |
| The cell | fragment master's release build. The home deploys it to the bucket at boot whenever its release changed | The bucket |
| The identity door | fragment's `crates/identity-door` in its passkey mode, at `<platform>/__door`, playing WorkOS's endpoints to the cell | The encrypted disk (accounts, public keys, hashes) |
| macrofiche | The fragments' git, the code-store contract, at `<platform>/__git` (the CLI and computers reach it there) | The encrypted disk |
| OpenBao | celld's secrets backend, in memory (`-dev`), seeded from the sealed bundle at each boot; its root token is revoked once the cell's is minted | Memory |
| Caddy | The front door: TLS ended here, its certificates got by TLS-ALPN-01 (the platform's at the start, a fragment's on its first visit, once `nitro-home-guest ask` says the cell holds that name) | The encrypted disk |

## A boot

The parent's launcher (`nitro-home up`, a systemd service) boots the
sandbox with:

- sandcastle's guest as init;
- the home's root under dm-verity, with its root hash and the home's KMS
  key id on the measured command line;
- a fresh scratch disk for the overlay;
- the home's data disk.

The workload (`host/entry.sh`) then:

1. sets the clock from the NSM;
2. prints an attestation document, whose PCR0 the key policy names;
3. opens the sealed bundle: its key comes from KMS over TLS the guest ends
   (`nitro-key wake`), and its files go to a tmpfs;
4. opens the data disk with dm-crypt, under a key from KMS. On the first
   boot `nitro-key new` makes it and writes its wrapped form to the disk's
   first block; later boots use `nitro-key wake`;
5. seeds OpenBao, then starts macrofiche, the door and the certificate
   check;
6. deploys the release to the bucket when it changed, then starts celld;
7. starts Caddy last, once what it lets in is ready behind it.

Any service that exits takes the home down, and the systemd service
starts it again. A stop is graceful: celld goes first, so its last writes
reach the bucket, then the rest, and the disk is closed last.

## Secrets

`nitro-home-seal` makes the bundle (`src/sealed.rs`) on the operator's
machine. It seals every file of a directory with AES-256-GCM under a fresh
key K, and K goes to KMS's `Encrypt` under the home's key. The parent hands
the home the bundle as it came.

The key's policy:

- The project's administrators may manage the key and `Encrypt`, never
  `Decrypt` or `GenerateDataKey`.
- The parent's role may `Decrypt` and `GenerateDataKey` only for a
  recipient document whose PCR0 is the home image's. KMS then answers only
  inside an envelope to the document's key. `nitro-key` takes that answer
  only from KMS's own TLS, which ends in the guest.

The bundle holds:

- the cell's store secrets: the host secret, the code store's key, the
  door client's secret and the model key;
- the door's own secret;
- the fleet bucket's credentials, for an IAM user whose policy names that
  bucket alone, so the parent's role cannot reach it.

`cargo xtask home render` (fragment, `nitro/home-release`) writes what the
image carries and what the bundle seals, apart. Nothing in the image is
secret.

## The release rule

A new image has a new PCR0, and the key releases nothing to it until the
policy names that PCR0. `host/pin-pcr0.sh` does that on the operator's
machine:

1. it boots the image once;
2. it verifies the home's own attestation document down to AWS's pinned
   root (`nitro-verify`);
3. it puts the document's PCR0 into the policy, keeping the one before
   beside it, for a rollback.

## Network

The home's NIC is a tap with plain NAT on the parent (`src/net.rs`):

- Every private, shared, link-local and loopback range is refused,
  including the parent's metadata service, its VPC and its own addresses.
- Inbound, only the conf's ports (443) are forwarded, untouched, from the
  parent's own addresses.

The home is our own measured code, so it takes no egress proxy. Its
traffic is KMS, S3, the model API and Let's Encrypt, all over TLS the home
ends, plus DNS.

### Certificates and CAA

Caddy in the home holds one ACME account, at Let's Encrypt's production
directory. Its key and the certificates live in Caddy's storage on the
encrypted disk (`/var/lib/fragment-home/caddy`), so the parent never sees
the key. The DNS then names that account as the only one that may be
issued certificates for the home's names (RFC 8659, and RFC 8657 for
`accounturi`), on the platform's name alone:

```
nitro.<zone>  CAA 0 issue     "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/<n>"
nitro.<zone>  CAA 0 issuewild ";"
```

A fragment's name (`<app>.nitro.<zone>`) holds no CAA of its own, so a CA
climbs to the platform's name and finds these. Every other CA refuses
(each must check CAA), Let's Encrypt refuses every other account, and no
CA may issue a wildcard, which the home never takes.

Proved on 2026-11-21, with the records in place:

- a fragment deployed from the CLI under a new name got its certificate on
  its first visit, in 4.2 s (Let's Encrypt, issued for that name alone);
- another account (a new one, on Let's Encrypt's staging directory, by
  DNS-01) asking for a name under the platform's was refused:
  `urn:ietf:params:acme:error:caa`, "CAA record for nitro.<zone> prevents
  issuance".

The home's account URI is the `location` in
`/var/lib/fragment-home/caddy/acme/acme-v02.api.letsencrypt.org-directory/users/default/default.json`
(the account key beside it never leaves the home).

**If the home ever gets a new ACME account** (its disk remade, the home
moved, the key rotated), change the `issue` record **before** that home
needs a certificate:

1. Start the new home. Caddy registers its new account at its first order,
   which the CAA record refuses: nothing is issued yet.
2. Read the new account's URI from that `default.json`.
3. Replace the `accounturi` in the `issue` record (a DNS change, so the
   owner's), keeping the TTL at 300 s.
4. After the TTL, restart the home or wait for Caddy's retry. It then gets
   its certificates.

Caddy renews a certificate when a third of its life is left (about 30 of
90 days), always with the same account, so renewal needs no change to the
record. Losing the key by accident means losing the disk, and so the
certificates with it: the front door then has none until step 3 is done.
For a planned move, let both accounts be named for a while: two `issue`
records, one for each `accounturi`, then the old one removed.

## Computers

Lane A's engine (sandcastle's Nitro backend) runs on the parent.
`sandcastle-bridge` carries its sockets over vsock (ports 5000 to 5002 on
the home's CID), and celld reaches the engine as it reaches the krun engine
(`CELLD_CONTAINER_ENGINE=krun:/run/sandcastle/engine.sock`). With no engine
(`HOME_ENGINE=none`), fragments and apps work, and a computer is refused,
typed.

## Phase 1's acceptance

| # | What | Result |
|---|---|---|
| 1 | From a browser: sign in, make an agent, chat, a real reply | **Pass.** A passkey sign-in; the agent made from the shell; its greeting and replies from GLM-5.3 Flash through the platform's model route |
| 2 | The agent's computer is a confidential sandbox from our image; its terminal works | **Pass.** Lane A's engine starts it from our Hermes image's measured root (arm64, Hermes v0.23.2). In the chat, the agent's terminal answers `aarch64`, `/dev/nsm` present, 2 CPUs, 5,924 MiB. Its screen (the desktop, through the engine's ports over the bridge) shows |
| 3 | The agent sleeps and wakes with its data; the home restarts and everything is still there | **Pass.** A file the agent wrote survived a computer restart (save, new VM, restore) and a restart of the home (new VM, restore). The home restart lost the last minute of the computer's changes (below) |
| 4 | A fragment app deploys from the CLI and loads | **Pass** (below) |
| 5 | Numbers | Below |
| 6 | What the parent can still see or do | Below |

## Results (2026-11-21, one run each)

The home's own rows ran on one `m8g.xlarge` parent, and the computers' on
the same parent resized to `m8g.2xlarge` (pool 22 GiB). The home is a
2-vCPU, 4 GiB confidential sandbox (`cpu_overcommit` off); a computer is
2 vCPU, 6 GiB, the cell's own size. The browser was headless Chrome on the
operator's machine, reaching the home over the public internet, with a CDP
virtual authenticator (CTAP2, user verification).

| What | Result |
|---|---|
| Launch to the guest's ready | 0.72 s |
| Secrets opened (two KMS round trips through `nitro-key`) | 0.95 to 1.1 s after launch |
| The encrypted disk mounted | 1.2 to 1.7 s |
| OpenBao seeded | 2.3 to 3.4 s |
| celld serving: a warm restart, release unchanged | 3.2 s |
| celld serving: the release changed (deployed first) | 5.7 to 6.4 s; the deploy itself 1.4 to 2.0 s |
| **Launch to the front door answering with a valid certificate:** a warm restart | **3.4 s** |
| Launch to the front door answering: a first boot, its certificate got by TLS-ALPN-01 | 10.8 s |
| `systemctl restart`, to the platform answering again, seen from the operator's machine | 12.9 s (the graceful stop is 5 s of it) |
| The parent rebooted, to the home serving again by itself | about 31 s |
| A passkey enrolled from an invite, then a sign-in to the platform with it | both pass; the account and its passkey kept across door and home restarts |
| `fragment login` approved at `/cli` by that session; `fragment init <app> --template todo` | logged in; deployed in 6.0 s |
| The app's first visit, its certificate got on demand | 4.6 s; a made-up subdomain gets no certificate |
| A todo item written, the home restarted, the item read back | **there**, the CLI's key still valid, the person still signed in |
| A recovery code on a new device; the same code again | a new passkey; then refused |
| A second device added, proved by the first; the first lost; sign-out and sign-in | signed in by the second device alone |
| An invite for an email that has an account | refused |
| KMS refused an image the policy did not name | refused, then released once its own PCR0 was pinned |
| A canary written in the home, searched for in the disk files on the parent | data disk **0**; tmpfs 0; the control written to the plain scratch layer: 4,096 |
| **An agent's first start** (the cell's `start` event, fresh path) | ready at 141 ms in the cell's clock, Hermes heard at 2.6 s, its first turn begun at 3.8 s; lane A's engine reports the VM itself ready 1.3 s after its launch. The greeting then took "8 s, 3 steps" |
| **The first reply, cold:** from the agent's start to its greeting | about 12 s (3.8 s to its first turn, then 8 s of work) |
| **A warm reply:** from sending to the reply on the page | **4.1 s** ("worked for 2 to 3 s") |
| **A wake:** the computer asleep, a message sent, to the reply on the page | **8.1 s**. The cell's `start` event: VM up 1.0 s, data restored from its save (2.7 MB) at 1.3 s, Hermes heard at 1.75 s, its turn begun at 2.9 s |
| Settings → Restart computer (save, new VM, restore) | Awake again in 5.1 s; the file kept |
| The home restarted with the computer awake | the platform answering in 11.0 s; the next message woke a new VM ("up 0 min") with the file, 7.1 s from send to reply |
| The same, since its stop keeps the computers (celld's `containers=keep`, lane A's) | the platform answering in 10.7 s; a file written 6 s before the restart read back by the **same VM** (its boot time unchanged, "up 7 min"), 18 s from send to reply, the cell's wake and its adoption of the computer included |

## What the parent can still see or do

Each item is with the design PR that closes it
([nitro-spike.md](nitro-spike.md), "Design").

| # | What | Closed by |
|---|---|---|
| 1 | **It can run any command in the home** (sandcastle's guest agent takes exec over vsock), and it picks the workload's entrypoint and environment, which PCR0 does not measure. Either way it can have the measured image fetch the home's secrets and hand them out. This is the largest hole: everything below matters only once it is closed | PR 6, the attested control channel. The entrypoint also has to come from the measured command line, with no exec except on that channel |
| 2 | **Whoever ships a new home image can ship one that skips the passkey check**, or anything else: the project's administrators can name any PCR0 in the key's policy (`kms:Put*`), and AWS can too | PR 10, a release rule we cannot change alone |
| 3 | **It can roll back or swap the home's data disk** (an older copy, or another home's under the same key). It cannot read it: AES-XTS under a key from KMS. The encryption is not authenticated, so it can also corrupt blocks | PR 9 (rollback), with dm-integrity |
| 4 | **The fleet bucket is unsealed.** The parent's role has no access, and the home's traffic to S3 is TLS the home ends. But whoever holds AWS administration, or the home's IAM key, reads every object, and can roll the bucket back | The sealed fleet bucket (phase 2) |
| 5 | ~~It could get a certificate for the home's names~~ (TLS-ALPN-01 validates whoever answers on the address the DNS names, and the parent holds that address) | **Closed** 2026-11-21: CAA records name the home's own ACME account (`accounturi`, RFC 8657), whose key never leaves the home, and forbid wildcards. Another account was refused ("Certificates and CAA") |
| 6 | It sees traffic metadata: clients' addresses, the names they ask for (SNI, so the fragments' names), sizes and timing, and the names the home resolves | Inherent to the parent carrying the bytes; DNS over TLS would hide the last |
| 7 | It sees the home's log lines: the boot's steps, celld's warnings, the attestation document. The door's, macrofiche's and celld's full logs stay on the encrypted disk | Keep the parent's view to the boot's steps |
| 8 | It sees phase 1's invite link (`fragment-identity-door invite`, run over its own exec), and could use it first | Invites made and handed over on the attested channel (PR 6), to the owner alone |
| 9 | It can stop, kill, refuse, delay or throttle the home: availability, never content | Inherent |
| 10 | The scratch disk (the overlay's upper layer) is plain on the parent. The home writes nothing secret there (the canary above), but a future change could | PR 7, the scratch disk sealed |

**The computers' side** (lane A's engine; nitro-spike.md's leaks):

| # | What | Closed by |
|---|---|---|
| 11 | **The engine's egress proxy on the parent reads every intercepted request in plaintext**: the computer's calls to the platform (its turns, its chats' records, the model route) and its saves and restores (`backups.sandbox.internal`, the whole of its `/data`). It then relays them to the home over vsock | PR 8, egress and its intercepts inside the boundary (TLS to the home, ended in the home) |
| 12 | **The engine can run any command in a computer** (exec over vsock), and picks its image and environment | PR 6, the attested control channel |
| 13 | The computer's scratch disk is plain on the parent; its `/data` lives in its saves in the bucket, unsealed | PR 7 (scratch), and FPAC's sealed disk in place of the saves (PR 5) |
| 14 | ~~A home restart reaps its computers without a final save~~ | **Closed** 2026-11-21: the home's stop asks celld to keep its computers running (`POST /shutdown?handoff=preserve&containers=keep`, lane A's celld change), and the next start adopts them. A turn in flight at the stop still loses its model call: its retries fail until its cell is adopted, which waits for the cell to be touched |

Outside the parent:

- the operator's machine saw every secret it sealed;
- OpenRouter sees the agents' prompts (the model route);
- an email in an invite is the invite's word, not verified;
- whoever can change the zone's DNS (its DNS host's account, or a token
  for the zone) can change the CAA records and get certificates for the
  home's names by DNS-01;
- **the hosted platform that adds private agents (preview, so Finite) can
  start new accounts at the home, and never get into an existing one.**
  Its admin asks the home's door, signed with the one key the door trusts
  (`passkeys.inviter`), for an invite for its signed-in operator's own
  email. The door makes one only for an email with no account there, and
  answers "sign in" for any other; every later passkey on an account needs
  one of its own (fragment#1449, and the platform's side on master). So
  whoever holds that key, or runs that platform, can start an account in
  any email's name that has none yet, and make its first passkey from the
  invite before its person does.

## Not verified

- The computer's idle sleep (the seat's) was not waited for: the wakes
  above follow a computer restart, a home restart and a reap.
- A second computer; a computer's own disk past its saves (FPAC's sealed
  disk is not in this path).
- Adding a second passkey through its page's one button. Chrome attaches
  every virtual authenticator to the ceremony, and one holding an excluded
  credential refuses the whole `create()`. So the step ran end to end
  through the door's own endpoints instead, as the page calls them: proved
  by the first device's passkey, the first device removed, the new passkey
  made on a second device. Signing out and in with the second device alone
  then worked.
- One run each; no load, no density, no x86 parent.
- The home's ACME account is Let's Encrypt's production. Its rate limits
  were not hit (50 a week for a registered domain): six certificates were
  issued for the zone's names today, the five the home holds and the
  unused DNS-01 wildcard from before the CAA records.
- A renewal under the CAA records (none is due for about 60 days), and
  any CA other than Let's Encrypt refusing.
