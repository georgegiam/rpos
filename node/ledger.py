"""Sub-issue #13 — chunk ledger (Algorithm 3).

A coordinated update to a chunk is a two-phase commit across that chunk's replica set:
  * PROPOSE / PRE-COMMIT: the proposer asks every replica to tentatively lock the chunk for
    this proposal id; a replica votes no if it is already locked for a different proposal.
  * COMMIT: on a majority of yes votes, the proposer tells every replica to apply the value
    and append it to a hash-chained log (each entry hashes the previous), giving a tamper-
    evident per-node history.

TTL refresh: a record whose TTL has expired is re-resolved and pushed through the same
ledger path (action "ttl_refresh"), so refreshes are coordinated exactly like any update.
Only chunks written *through the ledger* are TTL-tracked (expiry/domain are recorded on
commit); records written by the query fallback's store_chunk (issue #12) bypass the ledger
and so are not refreshed here. Unifying the two write paths is a Phase 2 integration
concern (issue #16) and is intentionally out of scope for this sub-issue.

Every update is logged to node/results/updates.csv as timestamp, domain, action, outcome.
Builds on QueryMixin (replica_set, upstream resolver, store). In-process transport only.
"""
import hashlib
import time

from node.dns_interface import canonical
from node.ids import chunk_id
from node.logs import append_row, now_iso
from node.net import Network
from node.query import QueryMixin, _decode, _encode

UPDATES_CSV = "updates.csv"
UPDATES_HEADER = ["timestamp", "domain", "action", "outcome"]
GENESIS = "00" * 32


def _entry_hash(prev_hex: str, seq: int, domain: str, action: str, value: str) -> str:
    payload = f"{seq}|{domain}|{action}|{value}".encode()
    return hashlib.sha256(bytes.fromhex(prev_hex) + payload).hexdigest()


class LedgerMixin(QueryMixin):
    def __init__(self, pk: bytes, net: Network, **kwargs):
        super().__init__(pk, net, **kwargs)
        self.ledger: list[dict] = []                 # hash-chained committed entries
        self.pending: dict[int, str] = {}            # cid -> proposal id currently locked
        self.expiry: dict[int, float] = {}           # cid -> monotonic expiry
        self.chunk_domain: dict[int, str] = {}       # cid -> domain (for TTL refresh)
        self.register("ledger_precommit", self._h_precommit)
        self.register("ledger_commit", self._h_commit)
        self.register("ledger_abort", self._h_abort)

    # ---------- RPC handlers (replica side) ----------
    async def _h_precommit(self, src, pid: str, cid: int, domain: str):
        locked = self.pending.get(cid)
        if locked is not None and locked != pid:
            return False                              # already locked for another proposal
        self.pending[cid] = pid
        return True

    async def _h_commit(self, src, pid: str, cid: int, domain: str, value: str, action: str):
        if self.pending.get(cid) not in (pid, None):
            return False
        self._append_entry(domain, action, value)
        self.store[cid] = value
        try:
            _ip, ttl = _decode(value)
            self.expiry[cid] = time.monotonic() + ttl
        except ValueError:
            pass
        self.chunk_domain[cid] = canonical(domain)
        self.pending.pop(cid, None)
        return True

    async def _h_abort(self, src, pid: str, cid: int):
        if self.pending.get(cid) == pid:
            self.pending.pop(cid, None)
        return True

    # ---------- hash-chained log ----------
    def _append_entry(self, domain: str, action: str, value: str) -> dict:
        seq = len(self.ledger)
        prev = self.ledger[-1]["hash"] if self.ledger else GENESIS
        h = _entry_hash(prev, seq, canonical(domain), action, value)
        entry = {"seq": seq, "prev": prev, "domain": canonical(domain),
                 "action": action, "value": value, "hash": h}
        self.ledger.append(entry)
        return entry

    def verify_chain(self) -> bool:
        prev = GENESIS
        for i, e in enumerate(self.ledger):
            if e["seq"] != i or e["prev"] != prev:
                return False
            if e["hash"] != _entry_hash(prev, i, e["domain"], e["action"], e["value"]):
                return False
            prev = e["hash"]
        return True

    # ---------- proposer side ----------
    async def propose_update(self, domain: str, value: str, action: str = "update") -> bool:
        cid = chunk_id(domain)
        replicas, _hops = await self.replica_set(cid)
        majority = len(replicas) // 2 + 1
        seed = f"{domain}|{value}|{action}|{time.time_ns()}|{self.node_id}"
        pid = hashlib.sha256(seed.encode()).hexdigest()[:16]

        # phase 1: pre-commit
        yes = 0
        for nid in replicas:
            try:
                if await self.call(nid, "ledger_precommit", pid, cid, domain, timeout=2.0):
                    yes += 1
            except Exception:
                pass
        if yes < majority:
            for nid in replicas:
                try:
                    await self.call(nid, "ledger_abort", pid, cid, timeout=2.0)
                except Exception:
                    pass
            self._log_update(domain, action, "aborted")
            return False

        # phase 2: commit
        commits = 0
        for nid in replicas:
            try:
                if await self.call(nid, "ledger_commit", pid, cid, domain, value, action, timeout=2.0):
                    commits += 1
            except Exception:
                pass
        outcome = "committed" if commits >= majority else "partial"
        self._log_update(domain, action, outcome)
        return outcome == "committed"

    # ---------- TTL refresh ----------
    async def refresh_expired(self) -> list[tuple[str, bool]]:
        """Re-resolve and re-commit any expired chunk for which this node is the primary.

        Scans only ledger-committed chunks (self.expiry); chunks written via the query
        fallback are not tracked here — see the module docstring and issue #16.
        """
        out: list[tuple[str, bool]] = []
        now = time.monotonic()
        for cid, exp in list(self.expiry.items()):
            if exp > now:
                continue
            domain = self.chunk_domain.get(cid)
            if domain is None or self.upstream is None:
                continue
            primary, _ = await self.find_successor(cid)
            if primary != self.node_id:               # only the primary refreshes
                continue
            ip, ttl, _steps = await self.upstream.resolve(domain)
            if ip is None:
                continue
            ok = await self.propose_update(domain, _encode(ip, ttl), action="ttl_refresh")
            out.append((domain, ok))
        return out

    def _log_update(self, domain: str, action: str, outcome: str) -> None:
        append_row(UPDATES_CSV, UPDATES_HEADER, [now_iso(), canonical(domain), action, outcome])


class LedgerNode(LedgerMixin):
    """Concrete node = Chord + storage + DNS + query + ledger."""
    pass
