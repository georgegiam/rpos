# Issue #19 [P3-2] — Unbound recursive resolver image.
#
# Built from a pinned Alpine (same reproducibility story as the #18 NSD image, same digest)
# with Unbound + bind-tools from the Alpine 3.20 repo snapshot. Config + root hints are baked
# in (they are tiny and version-controlled). `-d` runs Unbound in the foreground so Docker
# owns the process.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache unbound bind-tools

COPY unbound.conf /etc/unbound/unbound.conf
COPY root.hints   /etc/unbound/root.hints

EXPOSE 53/udp 53/tcp

CMD ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
