#!/usr/bin/env bash
# Builds every arm64 program of the home's image (docs/nitro-home.md,
# "The image") on the parent, as its build user, each from a pinned source:
#
#   ./home-build.sh <fragment tree> <sandcastle tree>
#
# Out, under $OUT (~/home-build/out): bin/ (celld, the identity door,
# macrofiche and its git, the guest's helpers, OpenBao, Caddy, esbuild),
# the guest kernel and initrd, and build.json naming each input's pin and
# each output's SHA-256. Run after parent-ready.sh. One program at a time:
# the parent's memory outside the sandbox pool is small.
#
# Shell, not Rust, for the reason parent-ready.sh gives: each step is a
# clone, a cargo build or a checked download.
set -euo pipefail

fragment=$(realpath "$1")
sandcastle=$(realpath "$2")
OUT=${OUT:-$HOME/home-build/out}
SRC=${SRC:-$HOME/home-build/src}
here=$(dirname "$(realpath "$0")")

# The pins. celld: the fork's selfhost line (fragment's docs/self-host.md)
# with two drafts merged (branch nitro/home-celld): nitro/preloaded-images
# (a deploy saves no image named by its content key) and lane A's
# nitro/keep-computers (a restart that asks keeps the computers running);
# macrofiche: its main; fragment: the tree given (its sha recorded).
CELLD_REPO=https://github.com/futurepaul/celld
CELLD_SHA=2a159279faef1e48de01f73662f757426b9490df
MACROFICHE_REPO=https://github.com/futurepaul/macrofiche
MACROFICHE_SHA=a18dc98e9e3abbec769344772edd72e933c396d6
# sandcastle-bridge, the home's half of the container engine's vsock bridge
# (lane A's, sandcastle's nitro/attested-session line: each computer
# reached over its attested session), for the image's glibc.
BRIDGE_REPO=https://github.com/futurepaul/sandcastle
BRIDGE_SHA=5dcb0f3
OPENBAO_VERSION=2.7.2
# openbao_2.7.2_linux_arm64.tar.gz in the release's checksums.txt, as
# fragment's crates/devstack/src/openbao_release.rs pins it.
OPENBAO_SHA256=5b97bf816fa820e5e521abec1db19c6161fcca2f666cf4a84e335089c0e83edd
CADDY_VERSION=2.11.9
# caddy_2.11.9_linux_arm64.tar.gz in the release's caddy_2.11.9_checksums.txt
# (SHA-512), read 2026-11-21.
CADDY_SHA512=9e5e76d7888542924de2c25353ae87c5f77e2a22c5b1198633cae13688922282e05383d142599205c88d8d80eee5e967d291214d7abce4835329a191b20dd6e0
ESBUILD_VERSION=0.28.1
# npm's dist.integrity for @esbuild/linux-arm64@0.28.1: the esbuild
# worker-build uses, for `celld deploy`.
ESBUILD_SHA512=yHs+0uc8+nvEAfAfxrWQKK5peSNzBc4PegcMO0EJ2hT71uA7vB8Ihg2e77R2P7SG5uYjPbHlLLmve4LLLRCf0g==

say() { echo "home-build: $*" >&2; }
mkdir -p "$OUT/bin" "$SRC" "$OUT/dl"

# fetch URL FILE SHA256: a download, refused unless it hashes as pinned.
fetch() {
    curl -sSfL --max-time 600 -o "$2.part" "$1"
    echo "$3  $2.part" | sha256sum -c --quiet - || { rm -f "$2.part"; say "$1: not the pinned SHA-256"; exit 1; }
    mv "$2.part" "$2"
}

# clone REPO SHA DIR
clone() {
    if [ ! -d "$3/.git" ]; then git clone -q "$1" "$3"; fi
    git -C "$3" fetch -q origin
    git -C "$3" checkout -q --detach "$2"
}

# The kernel builds to the same bytes from the same inputs, so one built
# from this script's lines already is kept.
kout="$HOME/nitro/home-kernel/out"
want=$(sha256sum "$here/kernel.config" | cut -d' ' -f1)
if [ -f "$kout/Image" ] && grep -q "\"extra_config_sha256\": \"$want\"" "$kout/kernel.json" 2>/dev/null; then
    say "the guest kernel: kept (its lines unchanged)"
else
    say "the guest kernel, with the home's lines"
    OUT="$HOME/nitro/home-kernel" EXTRA_CONFIG="$here/kernel.config" "$sandcastle/crates/nitro-spike/host/guest-kernel.sh" > /dev/null
fi
cp "$HOME/nitro/home-kernel/out/Image" "$OUT/Image"
cp "$HOME/nitro/home-kernel/out/kernel.json" "$OUT/kernel.json"

say "sandcastle's guest (static, the initrd's init) and the home's helpers"
( cd "$sandcastle" && cargo build -q --release --locked --target aarch64-unknown-linux-musl -p sandcastle-guest )
( cd "$sandcastle" && cargo build -q --release --locked -p sandcastle-nitro-spike -p sandcastle-nitro-home -p sandcastle-nitro-key )
"$sandcastle/target/release/sandcastle-nitro-spike" initrd --init "$sandcastle/target/aarch64-unknown-linux-musl/release/sandcastle-guest" --out "$OUT/guest.initrd" > /dev/null
for b in nitro-key nitro-home-guest; do cp "$sandcastle/target/release/$b" "$OUT/bin/"; done
cp "$sandcastle/target/release/nitro-home" "$OUT/nitro-home"

say "celld $CELLD_SHA"
clone "$CELLD_REPO" "$CELLD_SHA" "$SRC/celld"
# its V8 is pinned per target: aarch64's by the fork's own config file
# (its docs/v8.md)
( cd "$SRC/celld" && cargo --config .cargo/aarch64-unknown-linux-gnu.toml build -q --release --locked -p celld )
cp "$SRC/celld/target/release/celld" "$OUT/bin/celld"

say "macrofiche $MACROFICHE_SHA and its git"
clone "$MACROFICHE_REPO" "$MACROFICHE_SHA" "$SRC/macrofiche"
( cd "$SRC/macrofiche" && cargo xtask engine > /dev/null && cargo build -q --release --locked -p macrofiche )
cp "$SRC/macrofiche/target/release/macrofiche" "$OUT/bin/macrofiche"
rm -rf "$OUT/git" && cp -a "$SRC/macrofiche/target/engine/git-2.55.0" "$OUT/git"

say "sandcastle-bridge $BRIDGE_SHA"
clone "$BRIDGE_REPO" "$BRIDGE_SHA" "$SRC/sandcastle-bridge"
( cd "$SRC/sandcastle-bridge" && cargo build -q --release --locked -p sandcastle-engine --bin sandcastle-bridge )
cp "$SRC/sandcastle-bridge/target/release/sandcastle-bridge" "$OUT/bin/sandcastle-bridge"

say "the identity door, from fragment's tree"
( cd "$fragment" && cargo build -q --release --locked -p fragment-identity-door )
cp "$fragment/target/release/fragment-identity-door" "$OUT/bin/fragment-identity-door"

say "OpenBao $OPENBAO_VERSION, Caddy $CADDY_VERSION, esbuild $ESBUILD_VERSION"
fetch "https://github.com/openbao/openbao/releases/download/v$OPENBAO_VERSION/openbao_${OPENBAO_VERSION}_linux_arm64.tar.gz" "$OUT/dl/openbao.tgz" "$OPENBAO_SHA256"
tar -xzf "$OUT/dl/openbao.tgz" -C "$OUT/bin" bao
curl -sSfL --max-time 600 -o "$OUT/dl/caddy.tgz.part" "https://github.com/caddyserver/caddy/releases/download/v$CADDY_VERSION/caddy_${CADDY_VERSION}_linux_arm64.tar.gz"
echo "$CADDY_SHA512  $OUT/dl/caddy.tgz.part" | sha512sum -c --quiet - || { say "caddy: not the pinned SHA-512"; exit 1; }
mv "$OUT/dl/caddy.tgz.part" "$OUT/dl/caddy.tgz"
tar -xzf "$OUT/dl/caddy.tgz" -C "$OUT/bin" caddy
rm -f "$OUT/bin/tailscale" "$OUT/bin/tailscaled"
curl -sSfL --max-time 300 -o "$OUT/dl/esbuild.tgz" "https://registry.npmjs.org/@esbuild/linux-arm64/-/linux-arm64-$ESBUILD_VERSION.tgz"
got=$(openssl dgst -sha512 -binary "$OUT/dl/esbuild.tgz" | base64 -w0)
[ "sha512-$got" = "sha512-$ESBUILD_SHA512" ] || { say "esbuild: not the pinned SHA-512"; exit 1; }
tar -xzf "$OUT/dl/esbuild.tgz" -C "$OUT/bin" --strip-components=2 package/bin/esbuild

fragment_sha=$(cat "$fragment/.source-sha" 2>/dev/null || git -C "$fragment" rev-parse HEAD)
sandcastle_sha=$(git -C "$sandcastle" rev-parse HEAD 2>/dev/null || echo unknown)
python3 -I - "$OUT" "$CELLD_SHA" "$MACROFICHE_SHA" "$fragment_sha" "$sandcastle_sha" "$OPENBAO_VERSION" "$CADDY_VERSION" "$ESBUILD_VERSION" > "$OUT/build.json" <<'PY'
import hashlib, json, os, sys
out, celld, macrofiche, fragment, sandcastle, bao, ts, esb = sys.argv[1:9]
def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()
files = {}
for name in sorted(os.listdir(os.path.join(out, "bin"))):
    files["bin/" + name] = sha(os.path.join(out, "bin", name))
for name in ("Image", "guest.initrd", "nitro-home"):
    files[name] = sha(os.path.join(out, name))
print(json.dumps({"pins": {"celld": celld, "macrofiche": macrofiche, "fragment": fragment, "sandcastle": sandcastle, "openbao": bao, "caddy": ts, "esbuild": esb, "git": "2.55.0 (macrofiche's xtask engine)"}, "kernel": json.load(open(os.path.join(out, "kernel.json"))), "sha256": files}, indent=1))
PY
say "done: $OUT/build.json"
