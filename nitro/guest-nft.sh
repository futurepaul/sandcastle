#!/usr/bin/env bash
# Builds the static nft a Nitro guest loads its egress rules with
# (docs/nitro.md, "Egress inside the boundary"), on the parent, as the build
# user (it needs Docker):
#
#   ./guest-nft.sh               # writes ~/nitro/guest-nft/out/
#
# Why: on a node whose computers take their work over attested sessions,
# a guest catches its own workload's connections and lookups (nftables in
# the guest) and carries each to its home over a session, so they never
# reach the parent's proxy. The guest boots from an initrd that holds only
# its own binaries; this nft goes into it, measured with it.
#
# What goes in, each pinned by the SHA-256 of its release tarball as
# downloaded (netfilter.org signs releases with GPG; that signature is not
# checked here): libmnl, libnftnl and nftables, built statically with
# Alpine's musl toolchain in an image pinned by digest, mini-gmp, no CLI,
# no JSON, no documentation.
#
# Shell, not Rust, for the reason parent-ready.sh gives.
set -euo pipefail
ALPINE=alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
SOURCES=(
    "https://www.netfilter.org/pub/libmnl/libmnl-1.0.5.tar.bz2 274b9b919ef3152bfb3da3a13c950dd60d6e2bcd54230ffeca298d03b40d0525"
    "https://www.netfilter.org/pub/libnftnl/libnftnl-1.2.8.tar.xz 37fea5d6b5c9b08de7920d298de3cdc942e7ae64b1a3e8b880b2d390ae67ad95"
    "https://www.netfilter.org/pub/nftables/nftables-1.1.1.tar.xz 6358830f3a64f31e39b0ad421d7dadcd240b72343ded48d8ef13b8faf204865a"
)
OUT=${OUT:-$HOME/nitro/guest-nft}
mkdir -p "$OUT/out"
cd "$OUT"
for s in "${SOURCES[@]}"; do
    url=${s% *}; sum=${s#* }; f=$(basename "$url")
    if [ ! -f "$f" ]; then
        curl -sSfL -o "$f.part" "$url"
        mv "$f.part" "$f"
    fi
    echo "$sum  $f" | sha256sum -c --quiet -
done
docker run --rm -e SOURCE_DATE_EPOCH=0 -v "$OUT:/w" -w /w "$ALPINE" sh -euc '
    apk add --no-cache build-base linux-headers pkgconf bison flex > /dev/null
    rm -rf src prefix && mkdir -p src prefix
    for t in libmnl-1.0.5.tar.bz2 libnftnl-1.2.8.tar.xz nftables-1.1.1.tar.xz; do tar -xf "$t" -C src; done
    export PKG_CONFIG_PATH=/w/prefix/lib/pkgconfig
    (cd src/libmnl-1.0.5 && ./configure --quiet --prefix=/w/prefix --enable-static --disable-shared > /dev/null && make -s -j"$(nproc)" install > /dev/null)
    (cd src/libnftnl-1.2.8 && ./configure --quiet --prefix=/w/prefix --enable-static --disable-shared > /dev/null && make -s -j"$(nproc)" install > /dev/null)
    (cd src/nftables-1.1.1 && ./configure --quiet --prefix=/w/prefix --enable-static --disable-shared --with-mini-gmp --without-cli --without-json --without-xtables --disable-man-doc > /dev/null && make -s -j"$(nproc)" LDFLAGS=-all-static > /dev/null)
    strip -o /w/out/nft src/nftables-1.1.1/src/nft
    chown "$(stat -c %u:%g /w)" /w/out/nft
    rm -rf /w/src /w/prefix
'
file out/nft | grep -qE 'statically linked|static-pie linked' || { echo "guest-nft: not statically linked" >&2; exit 1; }
sum=$(sha256sum out/nft | cut -d' ' -f1)
python3 -I - "$ALPINE" "$sum" > out/nft.json <<'PY'
import json, sys
alpine, sha = sys.argv[1:3]
print(json.dumps({"sources": ["libmnl 1.0.5", "libnftnl 1.2.8", "nftables 1.1.1"], "toolchain": alpine, "static": True, "sha256": sha}, indent=1))
PY
cat out/nft.json
