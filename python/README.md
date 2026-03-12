# TIBET Cortex (Python)

**Zero-trust AI knowledge processing. Data that protects itself.**

Python client for the TIBET Cortex framework. For production use with memory-level security guarantees (mlock, zeroize), use the [Rust crates](https://crates.io/crates/cortex-core).

## Install

```bash
pip install tibet-cortex
```

## Quick Start

### JIS — Multi-Dimensional Access Control

```python
from cortex import JisClaim, JisPolicy, JisGate

# Partner in strategy, EU, clearance 3
claim = JisClaim(
    actor="partner@mckinsey.com",
    clearance=3,
    role="partner",
    department="strategy",
    geo=["NL", "DE"],
)

# M&A document policy
policy = JisPolicy(
    min_clearance=3,
    allowed_roles=["partner"],
    allowed_departments=["strategy"],
    allowed_geos=["NL", "DE", "FR"],
)

verdict = JisGate.evaluate(claim, policy)
print(f"Access: {verdict.allowed}")  # True

# Intern tries same document
intern = JisClaim(actor="intern@mckinsey.com", clearance=1, role="intern")
verdict = JisGate.evaluate(intern, policy)
print(f"Access: {verdict.allowed}")  # False
print(f"Reasons: {[d.reason.value for d in verdict.denials]}")
# ['clearance_too_low', 'role_not_allowed', 'department_not_allowed', 'geo_restricted']
```

### Envelope — JIS-Gated Data

```python
from cortex import Envelope, EnvelopeBlock

env = Envelope(id="doc_001")
env.add_block(EnvelopeBlock.new_embedding(b"vector data"))
env.add_block(EnvelopeBlock.new_content(b"M&A strategy for client X", jis_level=3))

# Everyone can search (embedding is JIS 0)
assert env.embedding() is not None

# Only clearance 3+ can read content
assert env.content(accessor_jis_level=1) is None
assert env.content(accessor_jis_level=3) is not None
```

### Airlock — Controlled Processing

```python
from cortex import Airlock

airlock = Airlock()

result, session = airlock.process(
    data=b"sensitive document",
    actor="analyst@company.com",
    jis_level=2,
    callback=lambda plaintext: len(plaintext),
)

print(f"Result: {result}")
print(f"Duration: {session.duration_ms:.2f}ms")
print(f"Actor: {session.actor}")
```

### Audit — Blackbox-met-Window

```python
from cortex import AuditTrail

trail = AuditTrail(".cortex/audit.json")
trail.record_session(session, query_hash="sha256:abc", response_hash="sha256:def")

stats = trail.stats()
print(f"Queries: {stats['total_queries']}")
print(f"Chain intact: {stats['chain_intact']}")
```

## Architecture

```
STORE     TBZ envelopes + JIS levels
GATE      Multi-dimensional JIS claims (role × dept × time × geo)
AIRLOCK   Zero plaintext lifetime (mlock + zeroize in Rust)
AUDIT     Blackbox-met-window trail (WHO/WHEN, not WHAT)
TIBET     Immutable provenance chain
```

## Links

- [Rust crates (crates.io)](https://crates.io/crates/cortex-core)
- [GitHub](https://github.com/jaspertvdm/tibet-cortex)
- [TBZ — Authenticated compression](https://pypi.org/project/tbz/)

## License

MIT OR Apache-2.0
