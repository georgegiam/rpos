# Issue #20 [P3-3] — the netem helper image.
#
# A throwaway image that netem.sh runs INSIDE each target container's network namespace
# (`docker run --net=container:<id> --cap-add=NET_ADMIN`). This is why NONE of the real images
# (the #19 node/unbound images or the #18 NSD tier) need iproute2, iputils, or NET_ADMIN — the
# tooling and the capability live here instead, so those committed images stay byte-identical
# (CLAUDE.md §2: new code in new files; the #18 tier is not edited).
#
# Base pinned by the SAME multi-arch manifest digest as the #18/Unbound Alpine images
# (reproducibility, CLAUDE.md §2). iproute2 -> `tc`; iputils -> `ping` (for the verify step).
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache iproute2 iputils

# The container never runs on its own; netem.sh always overrides this with an explicit command.
CMD ["sh"]
