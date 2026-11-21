#!/usr/bin/env bash
# Builds a Nitro node's guest kernel (docs/nitro.md, "Release assets"),
# on the parent, as the build user:
#
#   ./guest-kernel.sh            # writes ~/nitro/guest-kernel/out/
#
# What goes in, each pinned:
#  - Amazon Linux's kernel source at the tag below. Its 6.18 tree already
#    carries the DMB virtio patches confidential mode needs (Firecracker
#    v1.18's CI builds its own 6.18 guests from these tags with no patch of
#    its own: resources/rebuild.sh, get_tag).
#  - Firecracker v1.18's microVM CI config for 6.18 and its EFI fragment:
#    ACPI, virtio-pci, vsock, an EFI-stub image.
#  - sandcastle's own lines, last, so they win: the NSM driver
#    (attestation and the guest's clock, /dev/nsm), dm-verity and
#    `dm-mod.create=` (the root's verity table, root hash included, on the
#    measured command line), loop and FUSE (FPAC's disks), writes to a mounted
#    block device allowed (FPAC's daemon holds its loop device open for
#    writing while ext4 is mounted on it; Firecracker's CI config turns this
#    off), dm-crypt with AES-XTS (the sealed scratch disk: a key the guest
#    makes at boot and never shows; the CPU's AES instructions for it),
#    nftables' redirect and a dummy device (the guest catches its own
#    workload's connections for egress inside the boundary), and
#    nothing built as a module, since the guest boots from an initrd with
#    no module tree.
#
# Reproducible: the build's user, host, time and counter are fixed (the
# time is the source commit's own), and LOCALVERSION is set empty, so the
# same source and config build the same bytes on any machine, and a
# measurement of the image can be recomputed by anyone who builds it.
#
# Out: the image (arm64 `Image` or x86 `bzImage`), its `.config`, and
# `kernel.json` with every input's pin and the image's SHA-256. The
# image, its initrd and its command line are what PCR0 and PCR1 measure.
#
# Shell, not Rust, for the reason parent-ready.sh gives.
set -euo pipefail

AL_TAG=kernel6.18-6.18.62-127.179.amzn2023
FC_REF=firecracker-v1.18
OUT=${OUT:-$HOME/nitro/guest-kernel}
ARCH=$(uname -m)
case "$ARCH" in
    aarch64) target=Image; image=arch/arm64/boot/Image ;;
    x86_64) target=bzImage; image=arch/x86/boot/bzImage ;;
    *) echo "guest-kernel: unsupported architecture $ARCH" >&2; exit 1 ;;
esac

mkdir -p "$OUT/out"
cd "$OUT"
if [ ! -d linux ]; then
    git clone -q --depth 1 --branch "$AL_TAG" https://github.com/amazonlinux/linux linux
fi
git -C linux checkout -q "$AL_TAG"
commit=$(git -C linux rev-parse HEAD)

fc_raw=https://raw.githubusercontent.com/firecracker-microvm/firecracker/$FC_REF/resources/guest_configs
curl -sSfL -o fc-microvm.config "$fc_raw/microvm-kernel-ci-$ARCH-6.18.config"
curl -sSfL -o fc-efi.config "$fc_raw/efi.config"

cat > spike.config <<'EOF'
CONFIG_NSM=y
CONFIG_MD=y
CONFIG_BLK_DEV_DM=y
CONFIG_DM_VERITY=y
CONFIG_DM_INIT=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_BLK_DEV_WRITE_MOUNTED=y
CONFIG_FUSE_FS=y
CONFIG_EXT4_FS=y
CONFIG_OVERLAY_FS=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
CONFIG_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS=y
CONFIG_HOTPLUG_PCI_PCIE=y
CONFIG_EFI_STUB=y
CONFIG_ACPI=y
CONFIG_DEVTMPFS=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_DM_CRYPT=y
CONFIG_CRYPTO_XTS=y
CONFIG_CRYPTO_AES=y
CONFIG_NFT_REDIR=y
CONFIG_NF_TABLES_INET=y
CONFIG_NF_TABLES_IPV6=y
CONFIG_DUMMY=y
CONFIG_MODULES=n
EOF
# The CPU's AES for dm-crypt, by architecture (a symbol of another one
# would be dropped, and the check below refuses a dropped line).
case "$ARCH" in
    aarch64) echo CONFIG_CRYPTO_AES_ARM64_CE_BLK=y >> spike.config ;;
    x86_64) echo CONFIG_CRYPTO_AES_NI_INTEL=y >> spike.config ;;
esac

cd linux
export KBUILD_BUILD_USER=builder KBUILD_BUILD_HOST=sandcastle KBUILD_BUILD_VERSION=1 LOCALVERSION=
KBUILD_BUILD_TIMESTAMP=$(git log -1 --format=%cd --date=format:'%Y-%m-%d %H:%M:%S UTC' "$AL_TAG")
export KBUILD_BUILD_TIMESTAMP
make -s distclean
# Later files override earlier ones; olddefconfig settles the rest.
awk 1 ../fc-microvm.config ../fc-efi.config ../spike.config > .config
make -s olddefconfig
# The spike's lines must have survived olddefconfig (a missing
# dependency silently drops a symbol).
missing=()
while IFS= read -r line; do
    case "$line" in
        CONFIG_*=y) grep -qx -- "$line" .config || missing+=("$line") ;;
    esac
done < ../spike.config
[ ${#missing[@]} -eq 0 ] || { echo "guest-kernel: dropped by olddefconfig: ${missing[*]}" >&2; exit 1; }
make -s -j"$(nproc)" "$target"
cp "$image" "../out/$target"
cp .config ../out/config
sum=$(sha256sum "../out/$target" | cut -d' ' -f1)
release=$(cat include/config/kernel.release)
cd ..
python3 -I - "$AL_TAG" "$commit" "$FC_REF" "$target" "$sum" "$release" \
    "$(sha256sum fc-microvm.config | cut -d' ' -f1)" "$(sha256sum spike.config | cut -d' ' -f1)" > out/kernel.json <<'PY'
import json, sys
tag, commit, fc_ref, target, sha, release, fc_cfg, spike_cfg = sys.argv[1:9]
print(json.dumps({"source": "github.com/amazonlinux/linux", "tag": tag, "commit": commit, "firecracker_config": fc_ref, "firecracker_config_sha256": fc_cfg, "spike_config_sha256": spike_cfg, "image": target, "image_sha256": sha, "release": release, "kbuild": {"user": "builder", "host": "sandcastle", "version": "1", "timestamp": "the tag's commit date"}}, indent=1))
PY
cat out/kernel.json
