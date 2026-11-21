#!/bin/bash
# The home's workload (docs/nitro-home.md, "A boot"), run by sandcastle's
# guest as the PID namespace's first process. Each step says "home:
# <step>" on stdout, which the parent's launcher times as it arrives.
#
#   1. The clock from the NSM (the hypervisor's signed time; a
#      confidential guest boots at 1970, and every TLS check needs it).
#   2. An attestation document, printed: its PCR0 is what the home's KMS
#      key releases to (docs/nitro-home.md, "The release rule").
#   3. The sealed bundle ($HOME_SEALED) opened: its key from KMS over TLS
#      ended here (nitro-key), its files on a tmpfs, never on a disk.
#   4. The data disk (/dev/vdd) opened: dm-crypt under a key from KMS, its
#      wrapped form in the disk's first block; a new disk gets a new key
#      and a filesystem.
#   5. OpenBao in memory, seeded from the bundle: the node's secrets
#      backend, its token for celld minted fresh, its root token revoked.
#   6. macrofiche, the identity door (people's own passkeys), and the
#      front door's certificate check.
#   7. celld: the release deployed to the fleet bucket when it changed,
#      then the node, on loopback.
#   8. Caddy, the front door on 443 (which the parent forwards untouched):
#      TLS ended here, with certificates it gets itself by TLS-ALPN-01.
#
# Settings, none secret, from the launcher's conf: HOME_BUCKET (s3://…),
# HOME_REGION, HOME_PLATFORM (the platform's host), HOME_SUFFIX (the
# fragments'), HOME_ENGINE (none, or bridge: the parent's container
# engine through sandcastle-bridge).
#
# Any service that exits takes the home down (the parent's service starts
# it again); SIGTERM stops it gracefully: celld first (its last data
# durable in the bucket, its computers kept running for the next start),
# then the rest, the disk closed last.
set -euo pipefail
say() { echo "home: $*"; }
# ms since t0, set once the clock is (before it, the clock reads 1970)
ms_since() { echo $(( (10#$(date +%s%N) - 10#$1) / 1000000 )); }
die() { say "failed: $*"; exit 1; }
R=/opt/fragment-home/release
S=/run/fragment-home/secrets
STATE=/var/lib/fragment-home
: "${HOME_BUCKET:?}" "${HOME_REGION:?}" "${HOME_PLATFORM:?}" "${HOME_SUFFIX:?}"
HOME_ENGINE=${HOME_ENGINE:-none}
umask 077

say started
say "time $(/usr/local/bin/nitro-key settime)"
t0=$(date +%s%N)
# celld holds a file per resident cell: room for many fragments
ulimit -n 65536
# Nothing secret is written to the root: its upper layer is the plain
# scratch disk on the parent. Secrets and temporary files go to tmpfs; the
# home's state (its certificates among it) to its encrypted disk.
mkdir -p /run/fragment-home /var/lib/fragment-home
mountpoint -q /run/fragment-home || mount -t tmpfs -o mode=0700,size=64m tmpfs /run/fragment-home
mountpoint -q /tmp || mount -t tmpfs -o mode=1777,size=1g tmpfs /tmp
mkdir -p /run/fragment-home/celld

# 2. what the parent can check this home is: its document, for its PCR0
nonce=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
say "attestation nonce=$nonce document=$(/usr/local/bin/nitro-key attest --nonce "$nonce")"

# 3. the bundle
wrapped=$(/usr/local/bin/nitro-home-guest wrapped)
/usr/local/bin/nitro-key wake --wrapped "$wrapped" --out /run/fragment-home/bundle.key > /run/fragment-home/bundle.json || die "the bundle's key: KMS released nothing (is this image's PCR0 the key policy's?)"
/usr/local/bin/nitro-home-guest open --key-file /run/fragment-home/bundle.key --out "$S" > /dev/null
unset HOME_SEALED wrapped
say "secrets opened"

# 4. the data disk: block 0 holds "nitro-home-disk v1 <wrapped key>",
# the rest is dm-crypt (AES-XTS) under the key KMS releases for it
DISK=/dev/vdd
header=$(dd if=$DISK bs=4096 count=1 status=none | tr -d '\000')
case "$header" in
    "nitro-home-disk v1 "*)
        /usr/local/bin/nitro-key wake --wrapped "${header#nitro-home-disk v1 }" --out /run/fragment-home/disk.key > /run/fragment-home/disk.json || die "the data disk's key"
        new=0 ;;
    "")
        /usr/local/bin/nitro-key new --out /run/fragment-home/disk.key > /run/fragment-home/disk.json || die "a new data disk's key"
        w=$(sed -n 's/.*"wrapped":"\([^"]*\)".*/\1/p' /run/fragment-home/disk.json)
        [ -n "$w" ] || die "KMS gave no wrapped key for the new disk"
        printf 'nitro-home-disk v1 %s' "$w" | dd of=$DISK bs=4096 count=1 conv=sync,notrunc,fsync status=none
        new=1 ;;
    *) die "the data disk's first block is not a home's" ;;
esac
sectors=$(( $(blockdev --getsz $DISK) - 8 ))
dmsetup create --noudevsync home --table "0 $sectors crypt aes-xts-plain64 $(cat /run/fragment-home/disk.key) 0 $DISK 8"
rm -f /run/fragment-home/disk.key
dmsetup mknodes home
if ! dumpe2fs -h /dev/mapper/home > /dev/null 2>&1; then
    [ "$new" = 1 ] || say "the data disk opened to no filesystem: making one (its key is the disk's own, so this disk held nothing of this home's)"
    mkfs.ext4 -q -E lazy_itable_init=1,lazy_journal_init=1 -L home /dev/mapper/home
fi
mount -o noatime /dev/mapper/home $STATE
mkdir -p $STATE/celld $STATE/macrofiche $STATE/door $STATE/caddy $STATE/log
LOG=$STATE/log
say "disk mounted (new=$new)"

pids=()
stop_all() {
    # celld first: its handoff makes the last write durable in the bucket.
    # With an engine, it is asked to keep its computers running for the
    # next start of this home, which adopts them (celld's
    # `containers=keep`); SIGTERM, which reaps them, only if that fails.
    if [ -n "${celld_pid:-}" ]; then
        if [ "${engine:-none}" != none ] && curl -sf -m 5 -X POST 'http://127.0.0.1:8081/shutdown?handoff=preserve&containers=keep' > /dev/null; then
            say "celld stopping, its computers kept"
        else
            kill -TERM "$celld_pid" 2>/dev/null || true
        fi
        wait "$celld_pid" 2>/dev/null || true
    fi
    for p in "${pids[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
    for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
    [ -n "${bao_pid:-}" ] && kill -TERM "$bao_pid" 2>/dev/null || true
    sync
    umount $STATE 2>/dev/null || true
    dmsetup remove home 2>/dev/null || true
}
trap 'say stopping; stop_all; say stopped; exit 0' TERM INT

# 5. OpenBao, in memory: the node's secrets backend (celld reads the
# Secrets Store's bindings from it), seeded from the bundle at each boot
cat $R/hosts >> /etc/hosts
root=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
BAO_DEV_ROOT_TOKEN_ID=$root /usr/local/bin/bao server -dev -dev-listen-address=127.0.0.1:8200 -dev-no-store-token > $LOG/bao.log 2>&1 &
bao_pid=$!
export BAO_ADDR=http://127.0.0.1:8200
for _ in $(seq 100); do curl -sf $BAO_ADDR/v1/sys/health > /dev/null && break; sleep 0.1; done
export BAO_TOKEN=$root
for f in "$S"/store/*; do
    /usr/local/bin/bao kv put -mount=secret "$(basename "$f")" value=@"$f" > /dev/null
done
printf 'path "secret/data/*" { capabilities = ["read"] }\n' | /usr/local/bin/bao policy write fragment-cell - > /dev/null
/usr/local/bin/bao token create -policy=fragment-cell -no-default-policy -orphan -period=720h -field=token > /run/fragment-home/celld/openbao.token
/usr/local/bin/bao token revoke -self > /dev/null
unset BAO_TOKEN root
say "openbao seeded ($(ls "$S"/store | wc -l) secrets)"

# 6. the services beside celld
/usr/local/bin/macrofiche serve --config $R/macrofiche.json > $LOG/macrofiche.out 2> $LOG/macrofiche.log &
pids+=($!)
/usr/local/bin/fragment-identity-door --config $R/door.json 2> $LOG/door.log &
pids+=($!)
/usr/local/bin/nitro-home-guest ask --listen 127.0.0.1:8805 --platform "$HOME_PLATFORM" --suffix "$HOME_SUFFIX" --cell 127.0.0.1:8080 2> $LOG/ask.log &
pids+=($!)

# the parent's container engine (sandcastle's, its Nitro backend), over
# vsock: sandcastle-bridge's home half serves the engine's sockets here and
# relays the engine's intercepts to celld (docs/nitro-home.md, "Computers")
engine=none
case "$HOME_ENGINE" in
    none) ;;
    bridge)
        mkdir -p /run/sandcastle $STATE/sessions
        # each computer is reached over its attested session alone (lane
        # A's PR 6), claimed at its start against the PCR0s pinned here:
        # one a line, kept on the encrypted disk, so a new image's pin is
        # no reimage. A first boot pins nothing that starts: the bridge's
        # log names the PCR0 it refused, and the operator pins it.
        [ -f $STATE/pins ] || printf '%s\n' "# the PCR0 of each computer image this home runs, one a line" "$(printf '0%.0s' $(seq 96))" > $STATE/pins
        # celld's intercept socket, as celld names it for CELLD_NODE=home
        # (`intercepts-` and the first 6 hex of the node's SHA-256)
        /usr/local/bin/sandcastle-bridge home --intercepts $STATE/celld/intercepts-$(printf %s home | sha256sum | cut -c1-6).sock --sessions $STATE/sessions --pins $STATE/pins > $LOG/bridge.log 2>&1 &
        pids+=($!)
        for _ in $(seq 100); do [ -S /run/sandcastle/engine.sock ] && break; sleep 0.05; done
        engine=krun:/run/sandcastle/engine.sock ;;
    *) die "HOME_ENGINE is none or bridge" ;;
esac

# 7. celld: the release deployed when it changed, then the node
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
AWS_ACCESS_KEY_ID=$(cat "$S/aws/access-key-id")
AWS_SECRET_ACCESS_KEY=$(cat "$S/aws/secret-access-key")
export AWS_REGION=$HOME_REGION CELLD_BUCKET=$HOME_BUCKET
release=$(cat $R/release-id)
if [ "$(cat $STATE/deployed 2>/dev/null || true)" != "$release" ]; then
    d0=$(date +%s%N)
    ( cd $STATE && CELLD_ESBUILD=/usr/local/bin/esbuild CELLD_CONTAINER_ENGINE=$engine /usr/local/bin/celld deploy $R/cell/wrangler.home.jsonc --bucket "$HOME_BUCKET" --region "$HOME_REGION" ) > $LOG/deploy.log 2>&1 || { tail -c 2000 $LOG/deploy.log; die "celld deploy"; }
    echo "$release" > $STATE/deployed
    say "deployed $release in $(ms_since "$d0") ms"
fi
CELLD_WATCH=$STATE/celld CELLD_NODE=home CELLD_SECRETS_FILE=$R/celld-secrets.json CELLD_CONTAINER_ENGINE=$engine \
CELLD_TRUST_FORWARDED_HEADERS=1 CELLD_DURABILITY=bucket CELLD_SHUTDOWN_TOTAL_MS=5000 \
CELLD_FACET_MAX_BYTES=20971520 CELLD_DYNAMIC_LOCKDOWN=1 CELLD_MAX_CELL_REQUESTS=512 \
    /usr/local/bin/celld --no-control-plane --listen 127.0.0.1:8080 --internal-listen 127.0.0.1:8081 --region "$HOME_REGION" \
    > >(tee -a $LOG/celld.log | grep --line-buffered -E " (WARN|ERROR) |listening|panicked") 2>&1 &
celld_pid=$!
# celld's whole log, the cell's lines among them, stays on the home's
# disk; the parent sees its warnings and errors
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
for _ in $(seq 600); do curl -sf http://127.0.0.1:8080/.well-known/celld/health > /dev/null && break; sleep 0.05; done
curl -sf http://127.0.0.1:8080/.well-known/celld/health > /dev/null || die "celld never answered its health"
say "celld serving in $(ms_since "$t0") ms from the clock"

# 8. the front door, last: what it lets in is ready behind it
XDG_DATA_HOME=$STATE/caddy XDG_CONFIG_HOME=$STATE/caddy /usr/local/bin/caddy run --config $R/Caddyfile --adapter caddyfile > $LOG/caddy.out 2>&1 &
pids+=($!)
for _ in $(seq 600); do curl -s -o /dev/null --resolve "$HOME_PLATFORM:443:127.0.0.1" "https://$HOME_PLATFORM/" && break; sleep 0.1; done
if curl -sf -o /dev/null --resolve "$HOME_PLATFORM:443:127.0.0.1" "https://$HOME_PLATFORM/"; then
    say "serving in $(ms_since "$t0") ms from the clock (TLS here, its certificate valid)"
else
    say "the front door has no valid certificate yet (see its log); serving behind it"
fi

# a service that exits takes the home down
set +e
wait -n "$celld_pid" "${pids[@]}"
code=$?
say "a service exited ($code): stopping"
stop_all
exit 1
