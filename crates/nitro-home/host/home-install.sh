#!/usr/bin/env bash
# Installs a home on its parent (docs/nitro-home.md), as root:
#
#   sudo ./home-install.sh <home-build out> <release dir> <sealed bundle> <launcher conf>
#
# The image is made (home-image.sh) under /var/lib/nitro-home/image, the
# bundle and the conf copied beside it (owner-only), the launcher and its
# systemd unit installed. It does not start the home: `systemctl start
# nitro-home` does, and a changed image changes the home's PCR0, which its
# KMS key's policy must name before the home can open its secrets.
set -euo pipefail

build=$(realpath "$1")
release=$(realpath "$2")
sealed=$(realpath "$3")
conf=$(realpath "$4")
here=$(dirname "$(realpath "$0")")
[ "$(id -u)" = 0 ] || { echo "home-install: run as root" >&2; exit 1; }
install -d -m 0700 /var/lib/nitro-home /var/lib/nitro-home/image /etc/nitro-home
"$here/home-image.sh" "$build" "$release" /var/lib/nitro-home/image/home
install -m 0600 "$sealed" /var/lib/nitro-home/sealed.json
install -m 0600 "$conf" /etc/nitro-home/home.json
install -m 0644 "$build/Image" /var/lib/nitro-home/image/Image
install -m 0644 "$build/guest.initrd" /var/lib/nitro-home/image/guest.initrd
install -m 0755 "$build/nitro-home" /usr/local/bin/nitro-home
install -m 0644 "$here/nitro-home.service" /etc/systemd/system/nitro-home.service
systemctl daemon-reload
echo "home-install: installed; start it with: systemctl start nitro-home"
