# Issue #18 [P3-1] — one image for all five authoritative NSD servers (root/TLD/auth).
#
# No widely-trusted official NSD image exists, so we build from a pinned Alpine and install
# NSD from its package repo. This is the cleanest reproducibility story (CLAUDE.md §2): the
# base is pinned by multi-arch manifest digest (works on the M4/arm64 host and x86 CI), and
# NSD's version is fixed by the Alpine 3.20 repo snapshot. Zone files and the per-server
# nsd.conf are bind-mounted at run time (see docker-compose.dns.yml), so the same image serves
# every role — only the mounted config differs.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache nsd bind-tools \
    && mkdir -p /zones /etc/nsd

# NSD needs a writable state dir even with database disabled.
RUN mkdir -p /var/db/nsd && chown -R nsd:nsd /var/db/nsd

EXPOSE 53/udp 53/tcp

# -d: run in the foreground (do not daemonize) so Docker owns the process.
CMD ["nsd", "-d", "-c", "/etc/nsd/nsd.conf"]
