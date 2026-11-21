# The home's root (docs/nitro-home.md, "The image"): Debian's slim base,
# pinned by digest, with the few packages the home's services use, and
# every program of its own built on the parent from a pinned source
# (home-build.sh). Flattened by `docker export` and made a dm-verity disk
# (home-image.sh), so PCR0 names every byte of it.
#
#   (Caddy, the front door, is a program of home-build.sh's)
#   dmsetup      the data disk's encryption (dm-crypt, its key from KMS)
#   e2fsprogs    the data disk's filesystem, made on the first boot
#   socat        a debugging relay over vsock
#   curl         the entrypoint's health checks
ARG BASE
FROM ${BASE}
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates dmsetup e2fsprogs socat curl procps iproute2 zlib1g libexpat1 libpcre2-8-0 && \
    rm -rf /var/lib/apt/lists/* /etc/nginx/sites-enabled/* && \
    mkdir -p /var/lib/fragment-home /run/fragment-home
COPY bin/ /usr/local/bin/
COPY git/ /opt/macrofiche/git-2.55.0/
COPY release/ /opt/fragment-home/release/
COPY entry.sh /opt/fragment-home/entry.sh
RUN chmod 0600 /opt/fragment-home/release/celld-secrets.json && chmod 0755 /opt/fragment-home/entry.sh
