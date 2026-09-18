# NEST AuthZ

Deterministic Authorization Control Plane for Autonomous Agents

NEST AuthZ provides continuous, policy-driven authorization for
agent actions with delegated authority, human approval, deterministic
replay, and verifiable decision receipts.

Status: Experimental / Research Prototype

Integration target: Nanda Town / NEST

## Development

Install the package in editable mode before running the tests. The tests import
the installed package and do not modify `sys.path`:

```text
python -m pip install --editable .
python -m unittest discover -s tests -v
```

The optional deterministic Nanda Town integration is documented in
[`docs/nandatown-demo.md`](docs/nandatown-demo.md).


Build with codex (gpt-5.6-sol xhigh )
