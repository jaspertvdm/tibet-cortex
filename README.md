# TIBET Cortex

**Zero-trust AI knowledge processing. Data that protects itself.**

After [CVE-2026-0866](https://nvd.nist.gov/vuln/detail/CVE-2026-0866) (Zombie ZIP) showed that 50 out of 51 AV engines can be fooled by header manipulation, and [McKinsey's Lilli breach](https://www.all-about-security.de/ki-agent-knackt-mckinseys-interne-chatbot-plattform-lilli-in-zwei-stunden-sql-injection-legte-millionen-datensaetze-offen/) exposed 46.5 million chat messages through a single SQL injection, one thing is clear: **the data itself must be the security boundary, not the application around it.**

TIBET Cortex is a Rust framework for building AI knowledge systems where every document chunk protects itself — cryptographically, at every layer, in every state.

## Architecture

```
┌─────────────────────────────────────────────┐
│              TIBET Cortex                    │
│                                              │
│  STORE     TBZ envelopes + JIS levels        │
│            Embedding JIS 0 (searchable)      │
│            Content JIS N (encrypted)         │
│                                              │
│  GATE      Multi-dimensional JIS claims      │
│            role × department × time × geo    │
│                                              │
│  AIRLOCK   Zero plaintext lifetime           │
│            mlock + zeroize + scope-bound     │
│                                              │
│  AUDIT     Blackbox-met-window               │
│            See WHO/WHEN/HOW MUCH, not WHAT   │
│            Immutable TIBET provenance chain   │
│                                              │
│  VAULT     Time-locked audit trails          │
│            Dead man's switch for compliance   │
└─────────────────────────────────────────────┘
```

## The Problem

Every RAG stack today:

```
User Query → Embedding → Vector Search → ALL docs → LLM → Response
```

No layer between "found" and "allowed to read." One SQL injection, one IDOR, one misconfigured endpoint — and your entire knowledge base is exposed.

## The Solution

TIBET Cortex separates **search** from **access**:

- **Embeddings** are JIS level 0 — always searchable
- **Content** is JIS level N — cryptographically gated
- **Processing** happens inside an Airlock — zero plaintext lifetime
- **Every operation** generates a TIBET audit token

```
SQL injection dumps the DB?
→ You get encrypted TBZ envelopes. Unreadable.

Memory dump during processing?
→ Airlock wiped. mlock'd memory zeroed.

Audit trail tampered?
→ TIBET chain broken. Immediately detectable.

System prompt modified?
→ Integrity hash fails. Execution refused.
```

## Crates

| Crate | Description |
|-------|-------------|
| `cortex-core` | TBZ envelopes, TIBET tokens, Ed25519 crypto, zeroizing buffers |
| `cortex-airlock` | mlock'd memory, scope-bound processing, auto-wipe |
| `cortex-jis` | Multi-dimensional claims: clearance × role × dept × time × geo |
| `cortex-store` | sled-backed JIS-gated vector storage |
| `cortex-audit` | Blackbox-met-window audit trails, TIBET chain verification |
| `cortex-cli` | Command-line interface |

## Install

```bash
cargo install cortex-cli
```

## Usage

```bash
# Ingest a document at JIS level 2 (confidential)
cortex ingest ./strategy.pdf --jis-level 2 --source strategy-db

# Query with your identity claim
cortex query "M&A targets" --clearance 3 --role partner --department strategy

# Verify audit chain integrity
cortex verify

# View audit statistics (blackbox-met-window)
cortex audit
cortex audit --full

# Show architecture
cortex info
```

## JIS — Multi-Dimensional Access Control

JIS is not a single number. It's a multi-dimensional identity claim:

```rust
let claim = JisClaim::new("partner@mckinsey.com", 3)
    .with_role("partner")
    .with_department("strategy")
    .with_geo(vec!["NL".into(), "DE".into()]);

let policy = JisPolicy::clearance(3)
    .with_roles(vec!["partner".into()])
    .with_departments(vec!["strategy".into()])
    .with_geos(vec!["NL".into(), "DE".into(), "FR".into()]);

// All dimensions must match
assert!(JisGate::is_allowed(&claim, &policy));
```

An intern in the US sees different data than a partner in the EU — from the same query, on the same system.

## Airlock — Zero Plaintext Lifetime

```rust
let airlock = Airlock::with_defaults();

let (result, audit) = airlock.process(
    encrypted_content,
    "analyst@company.com",
    2,  // JIS level
    |plaintext| {
        // This closure is the ONLY place plaintext exists
        // Memory is mlock'd (never swapped to disk)
        Ok(process(plaintext))
    },
)?;
// After closure: all plaintext memory zeroized
// audit token generated for the trail
```

## Blackbox-met-Window Audit

The auditor sees:
- **WHO** accessed data
- **WHEN** it was accessed
- **HOW MUCH** data was touched (chunks accessed/denied)
- **WHAT JIS level** was used

The auditor does **NOT** see:
- The actual content
- The query itself (only its hash)

Unless they have matching JIS credentials to resolve the hashes.

## Part of the TIBET Ecosystem

- [TBZ](https://github.com/jaspertvdm/tbz) — Block-level authenticated compression
- [TIBET](https://github.com/jaspertvdm/tibet-spec) — Trust & Identity Blockchain for Ethical Transactions
- [OomLlama](https://pypi.org/project/oomllama/) — Rust-native LLM inference engine

## License

MIT OR Apache-2.0
