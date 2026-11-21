#!/usr/bin/env bash
# Builds the static mke2fs a Nitro guest formats its sealed scratch disk
# with (docs/nitro.md, "Release assets"), on the parent, as the build user
# (it needs Docker):
#
#   ./guest-mke2fs.sh            # writes ~/nitro/guest-mke2fs/out/
#
# Why it exists: a sealed scratch disk is encrypted by a key the guest
# makes at boot (dm-crypt), so the parent cannot format it, and the guest
# boots from an initrd that holds only its own binary. This mke2fs goes
# into that initrd, so the initrd's measurement (PCR0, PCR1) covers it.
#
# What goes in, each pinned: e2fsprogs' release tarball, by the SHA-256
# kernel.org publishes for it, and Alpine's musl toolchain in an image
# pinned by digest. It links statically and is stripped.
#
# Out: `mke2fs` and `mke2fs.json` with every input's pin and its SHA-256.
#
# Shell, not Rust, for the reason parent-ready.sh gives.
set -euo pipefail
E2FS=1.47.4
E2FS_SHA256=fd5bf388cbdbe006a3d3b318d983b2948382440acc85a87f1e7d108653e8db0b
ALPINE=alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
OUT=${OUT:-$HOME/nitro/guest-mke2fs}
tarball=e2fsprogs-$E2FS.tar.xz
mkdir -p "$OUT/out"
cd "$OUT"
if [ ! -f "$tarball" ]; then
    curl -sSfL -o "$tarball.part" "https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v$E2FS/$tarball"
    mv "$tarball.part" "$tarball"
fi
echo "$E2FS_SHA256  $tarball" | sha256sum -c --quiet -
# The build is the container's; SOURCE_DATE_EPOCH fixes what e2fsprogs
# would otherwise stamp with the build's time.
docker run --rm -e "E2FS=$E2FS" -e SOURCE_DATE_EPOCH=0 -v "$OUT:/w" -w /w "$ALPINE" sh -euc '
    apk add --no-cache build-base linux-headers > /dev/null
    rm -rf src && mkdir src && tar -xJf "e2fsprogs-$E2FS.tar.xz" -C src --strip-components=1
    cd src
    ./configure --quiet --disable-nls --disable-fuse2fs --disable-shared --enable-static LDFLAGS=-static > /dev/null
    make -s -j"$(nproc)" libs > /dev/null
    make -s -C misc mke2fs > /dev/null
    strip -o /w/out/mke2fs misc/mke2fs
    chown "$(stat -c %u:%g /w)" /w/out/mke2fs
    rm -rf /w/src
'
file out/mke2fs | grep -qE 'statically linked|static-pie linked' || { echo "guest-mke2fs: not statically linked" >&2; exit 1; }
sum=$(sha256sum out/mke2fs | cut -d' ' -f1)
version=$(out/mke2fs -V 2>&1 | head -1)
python3 -I - "$E2FS" "$E2FS_SHA256" "$ALPINE" "$sum" "$version" > out/mke2fs.json <<'PY'
import json, sys
e2fs, e2fs_sha, alpine, sha, version = sys.argv[1:6]
print(json.dumps({"source": "e2fsprogs " + e2fs, "source_sha256": e2fs_sha, "toolchain": alpine, "static": True, "version": version, "sha256": sha}, indent=1))
PY
cat out/mke2fs.json
