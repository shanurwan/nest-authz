# Contributing

NEST AuthZ is a small security-sensitive research library. Keep changes scoped,
make security semantics explicit in an ADR, and add adversarial tests for each
new or changed invariant.

## Development environment

Use a dedicated virtual environment. Do not rely on a shared Anaconda
environment: unrelated packages can constrain `cryptography` or `pyOpenSSL` in
ways that do not reflect this project.

```bash
python -m venv .venv
# POSIX: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

For the optional Nanda Town integration, also install a compatible checkout or
release:

```bash
python -m pip install -e ../nandatown
python -m pip install -e ".[dev]"
```

## Required checks

```bash
python -m unittest discover -s tests -v
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m coverage run -m unittest discover -s tests
python -m coverage report
python -m build
python -m twine check dist/*
python scripts/check_release_artifacts.py dist
python scripts/security_source_scan.py
git diff --check
```

Run `python benchmarks/benchmark_v1.py` only as informational evidence; do not
turn local latency into a brittle CI threshold.

## Change discipline

- Preserve dependency direction: integrations depend on the core, never the
  reverse.
- Do not read ambient time, randomness, environment, files, databases, or the
  network from semantic core modules.
- Do not use Python `hash()`, `repr()`, or mutable insertion order as persistent
  security identity.
- Version canonical schema changes explicitly and update golden/cross-process
  tests.
- Do not weaken a fail-closed result to make an integration convenient.
- Never commit operational private keys, credentials, databases, build output,
  or caches.

No commit, tag, publication, or release should occur until the author reviews
the complete diff and release evidence.
