# testbed/netem-helper/

The **netem helper image** (`rpos-netem:latest`) used by [`../netem.sh`](../netem.sh) (issue
#20, P3-3).

## Why a helper image (and not baking `tc` into the real images)

`tc netem` needs the `iproute2` toolchain and the `NET_ADMIN` capability. Rather than add those
to every real image and grant the capability in compose, `netem.sh` runs **this** image inside
a target container's network namespace:

```
docker run --rm --net=container:<target> --cap-add=NET_ADMIN rpos-netem tc ...
```

Sharing the target's netns means the `tc` qdisc/filters land on that container's `eth0` exactly
as if run inside it — but the capability and the tooling live only here. Consequences:

- the #19 `node`/`unbound` images and the **#18 DNS tier are not edited** (CLAUDE.md §2: new
  code in new files; the benchmarked/committed images stay identical);
- no `cap_add:` is added to any service in the compose files;
- the whole feature is removable by `./netem.sh clear` — nothing persists in the real images.

`iputils` (`ping`) is included so `netem.sh verify` can measure RTT from inside a container's
netns too.

## Build

Built on demand by `netem.sh` if missing. Manual build:

```bash
docker build -t rpos-netem:latest testbed/netem-helper
```

The base is pinned to the same Alpine manifest digest as the #18/Unbound images
(reproducibility, CLAUDE.md §2).
