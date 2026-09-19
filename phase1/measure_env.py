"""Part 1-2: record the machine (CPU/RAM/disk/SHA acceleration) and the measured
sequential single-core SHA-256 chain rate. Standalone; writes results/env.csv and
results/chainrate.csv. Builds and runs ./chainrate if it is present.

The chain rate is the security-critical constant: it is how fast BOTH the honest prover
and a cheater can compute the dependent hash chain h_i = H(h_{i-1} || pk || i). SHA-256 is
hardware-accelerated on this CPU (ARMv8 FEAT_SHA256, the analogue of x86 SHA-NI), so this
is close to the fastest a single core can go.
"""
import csv, os, platform, subprocess, statistics
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = HERE / "results"; RES.mkdir(exist_ok=True)

def sysctl(name):
    try:
        return subprocess.check_output(["sysctl", "-n", name], text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""

def gib(x):
    try: return f"{int(x)/2**30:.1f}"
    except Exception: return ""

env = {
    "platform": platform.platform(),
    "machine": platform.machine(),
    "cpu_brand": sysctl("machdep.cpu.brand_string"),
    "hw_model": sysctl("hw.model"),
    "physical_cores": sysctl("hw.physicalcpu"),
    "logical_cores": sysctl("hw.logicalcpu"),
    "ram_GiB": gib(sysctl("hw.memsize")),
    "hw_sha256_accel": sysctl("hw.optional.arm.FEAT_SHA256") or "unknown",
    "hw_sha512_accel": sysctl("hw.optional.arm.FEAT_SHA512") or "unknown",
    "python": platform.python_version(),
}
with open(RES / "env.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["key", "value"])
    for k, v in env.items(): w.writerow([k, v])
print("=== environment ===")
for k, v in env.items(): print(f"  {k:18s} {v}")

# --- sequential chain rate via the C benchmark ---
exe = HERE / "chainrate"
rows = []
if exe.exists():
    print("\n=== chainrate (MH/s, one core, real dependent chain) ===")
    subprocess.run([str(exe), "5000000"], stdout=subprocess.DEVNULL)  # warm-up
    for run in range(1, 6):
        out = subprocess.check_output([str(exe), "50000000"], text=True).strip()
        mhs = float(out); rows.append(mhs)
        print(f"  run {run}: {mhs:.3f} MH/s")
    med = statistics.median(rows)
    print(f"  median: {med:.3f} MH/s   ({med*1e6:,.0f} hashes/s)")
    with open(RES / "chainrate.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["run", "MH_per_s"])
        for i, r in enumerate(rows, 1): w.writerow([i, f"{r:.3f}"])
        w.writerow(["median", f"{med:.3f}"])
        w.writerow(["hashes_per_s_median", f"{med*1e6:.0f}"])
else:
    print("\n(chainrate binary not built; see build command at top of chainrate.c)")
print("\nGPU: no discrete GPU / hashcat on this machine (Apple M4 integrated GPU only). "
      "Not measured. Note: the v2 chain is strictly sequential, so GPU parallelism does "
      "not help a cheater recompute a chain segment; only single-core speed matters there.")
