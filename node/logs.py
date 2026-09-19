"""CSV logging helpers. Every measurable event lands in a CSV under node/results/."""
import csv
import os
from datetime import datetime, timezone

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def _path(name: str) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    return os.path.join(RESULTS_DIR, name)


def append_row(filename: str, header: list[str], row: list) -> None:
    """Append one row to results/<filename>, writing the header first if the file is new."""
    path = _path(filename)
    new = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(header)
        w.writerow(row)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
