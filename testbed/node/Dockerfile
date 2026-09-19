# Issue #19 [P3-2] — the resolver-node image.
#
# BUILD CONTEXT IS THE REPO ROOT (see docker-compose.yml: build.context: ..), because the
# node imports the v3 PoSpace scheme from phase1/ by RELATIVE PATH: node/pospace_admission.py
# computes  dirname(dirname(__file__))/phase1  and puts it on sys.path. phase1/ is not a
# package (no __init__.py) and uses bare sibling imports, so the node/ <-> phase1/ sibling
# layout MUST be preserved inside the image. We copy only node/ and phase1/ (not the whole
# repo) to keep the image lean and to leave rpos.py, results, and the tranco CSVs out.
#
# Base pinned by manifest digest for reproducibility (CLAUDE.md §2), matching the #18 pattern.
FROM python:3.11-slim@sha256:da047cb8f9d1d98e5c070f5300ba9f7274e33b8fc0e5be5ed88740aed1b95ba9

WORKDIR /app

# Install deps first for layer caching.
COPY testbed/node/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Preserve the sibling layout: /app/node and /app/phase1 (so the phase1 sys.path trick lands
# on /app/phase1 and `python -m node.run_node` finds the node package).
COPY node/   ./node/
COPY phase1/ ./phase1/

# PYTHONPATH=/app so `python -m node.run_node` imports the node package; unbuffered so the
# container logs (plot-built line, heartbeats) stream to `docker logs` in real time.
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

# Bare TCP liveness port (see node/run_node.py); NOT a Chord/DNS port.
EXPOSE 9910

CMD ["python", "-m", "node.run_node"]
