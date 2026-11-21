#!/usr/bin/env bash
# The home's measured root (docs/nitro-home.md, "The image"), on the
# parent, as root:
#
#   sudo ./home-image.sh <home-build out> <release dir> <out prefix>
#
# The root is Debian's slim base, pinned by digest, the packages of the
# Dockerfile beside this script, home-build.sh's programs, and the release
# (`cargo xtask home render`'s: the cell's build and every config, no
# secret in it). It is flattened by `docker export` and written by the
# spike's verity-image.sh as a raw ext4 disk with its dm-verity tree, so
# the root hash on the measured command line names every byte of it.
# Out: <prefix>.ext4, <prefix>.verity, <prefix>.json (verity-image.sh's)
# and <prefix>.config.json (the image's OCI config, its Env).
#
# Shell, for the reason parent-ready.sh gives.
set -euo pipefail

build=$(realpath "$1")
release=$(realpath "$2")
out=$3
here=$(dirname "$(realpath "$0")")
spike=$(realpath "$here/../../nitro-spike/host")
# debian:trixie-slim for arm64, pinned by its digest at the first build
# (written beside the out prefix, and reused).
BASE_REF=debian:trixie-slim
[ "$(id -u)" = 0 ] || { echo "home-image: run as root" >&2; exit 1; }
[ -f "$release/release-id" ] || { echo "home-image: $release is no home release (cargo xtask home render)" >&2; exit 1; }
[ -f "$build/build.json" ] || { echo "home-image: $build is no home build (home-build.sh)" >&2; exit 1; }

digest_file="$out.base-digest"
if [ ! -s "$digest_file" ]; then
    docker pull -q --platform linux/arm64 "$BASE_REF" > /dev/null
    docker image inspect "$BASE_REF" --format '{{index .RepoDigests 0}}' > "$digest_file"
fi
base=$(cat "$digest_file")

ctx=$(mktemp -d /var/tmp/home-image.XXXXXX)
root=$(mktemp -d /var/tmp/home-root.XXXXXX)
empty=$(mktemp -d /var/tmp/home-extra.XXXXXX)
trap 'rm -rf "$ctx" "$root" "$empty"' EXIT
cp -a "$build/bin" "$ctx/bin"
cp -a "$build/git" "$ctx/git"
cp -a "$release" "$ctx/release"
cp "$here/entry.sh" "$here/Dockerfile" "$ctx/"
docker build -q --platform linux/arm64 --build-arg "BASE=$base" -t nitro-home-root "$ctx" > /dev/null
cid=$(docker create --platform linux/arm64 nitro-home-root)
docker export "$cid" | tar -x -C "$root" --numeric-owner
docker rm "$cid" > /dev/null
docker image inspect nitro-home-root --format '{{json .Config}}' > "$out.config.json"
"$spike/verity-image.sh" "$root" "$empty" "$out" > /dev/null
python3 -I - "$out.json" "$base" "$(cat "$release/release-id")" "$build/build.json" <<'PY'
import json, sys
path, base, release, build = sys.argv[1:5]
d = json.load(open(path))
d["base"] = base
d["release_id"] = release.strip()
d["build"] = json.load(open(build))["sha256"]
json.dump(d, open(path, "w"), indent=1)
print(json.dumps({k: d[k] for k in ("image", "root_hash", "image_mib", "files_bytes", "release_id")}))
PY
