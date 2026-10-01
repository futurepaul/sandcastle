# Hermes with its bytecode compiled in (docs/krun-engine.md, "Hermes's
# start, measured"): upstream ships no .pyc and sets
# PYTHONDONTWRITEBYTECODE=1, so every start compiled what it imported.
# unchecked-hash: /opt/hermes is sealed, so nothing can make a .pyc stale,
# and a builder that rewrites file times cannot invalidate them.
FROM nousresearch/hermes-agent:v2026.9.24@sha256:fca358f12efd65bfaaca05884166f15c0e2788375ca30d77061ac1ebc96452b7
RUN /opt/hermes/.venv/bin/python -m compileall -q -j0 --invalidation-mode unchecked-hash /opt/hermes
