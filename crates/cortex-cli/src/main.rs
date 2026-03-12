use anyhow::Result;
use clap::{Parser, Subcommand};
use cortex_core::crypto::ContentHash;
use cortex_jis::JisClaim;
use cortex_store::CortexStore;
use cortex_audit::AuditTrail;

#[derive(Parser)]
#[command(
    name = "cortex",
    about = "TIBET Cortex — Zero-trust AI knowledge processing",
    long_about = "JIS-gated vector storage, Airlock-protected inference, TIBET-audited provenance.\nData that protects itself.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Ingest a document into the Cortex store
    #[command(alias = "i")]
    Ingest {
        /// Path to the document
        path: String,
        /// JIS level (0=public, 1=internal, 2=confidential, 3=restricted)
        #[arg(short, long, default_value = "0")]
        jis_level: u8,
        /// Source identifier
        #[arg(short, long)]
        source: Option<String>,
    },

    /// Query the store with JIS-gated access
    #[command(alias = "q")]
    Query {
        /// Search term
        query: String,
        /// Your clearance level
        #[arg(short = 'c', long, default_value = "0")]
        clearance: u8,
        /// Your role
        #[arg(short, long)]
        role: Option<String>,
        /// Your department
        #[arg(short, long)]
        department: Option<String>,
    },

    /// Show audit trail statistics
    #[command(alias = "a")]
    Audit {
        /// Show full chain
        #[arg(short, long)]
        full: bool,
    },

    /// Verify audit chain integrity
    #[command(alias = "v")]
    Verify,

    /// Show Cortex info and architecture
    Info,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Ingest { path, jis_level, source } => {
            let store = CortexStore::open(".cortex/store")?;
            let content = std::fs::read(&path)?;
            let id = format!("doc_{}", ContentHash::compute(&content));

            // Simple embedding: hash of content (real impl would use an embedding model)
            let embedding = ContentHash::compute(&content).as_str().as_bytes().to_vec();

            let hash = store.ingest(
                &id,
                embedding,
                content,
                jis_level,
                source.as_deref(),
            )?;

            println!("TIBET Cortex — Document ingested");
            println!();
            println!("  ID:        {id}");
            println!("  Source:    {path}");
            println!("  JIS level: {jis_level}");
            println!("  Hash:      {hash}");
            println!("  Store:     .cortex/store");
            println!();
            println!("  Document is now JIS-gated. Access requires clearance >= {jis_level}.");

            Ok(())
        }

        Commands::Query { query, clearance, role, department } => {
            println!("TIBET Cortex — JIS-gated query");
            println!();

            let mut claim = JisClaim::new("cli-user", clearance);
            if let Some(ref r) = role {
                claim = claim.with_role(r.as_str());
            }
            if let Some(ref d) = department {
                claim = claim.with_department(d.as_str());
            }
            let _claim = claim; // Used when vector search is implemented

            println!("  Claim:     clearance={clearance}, role={}, dept={}",
                role.as_deref().unwrap_or("any"),
                department.as_deref().unwrap_or("any"),
            );
            println!("  Query:     {query}");
            println!("  Query hash: {}", ContentHash::compute(query.as_bytes()));
            println!();
            println!("  (Vector search not yet implemented — store + JIS gate operational)");

            Ok(())
        }

        Commands::Audit { full } => {
            let trail = AuditTrail::open(".cortex/audit")?;
            let stats = trail.stats()?;

            println!("TIBET Cortex — Audit Trail");
            println!();
            println!("  Total queries:     {}", stats.total_queries);
            println!("  Chunks accessed:   {}", stats.total_chunks_accessed);
            println!("  Chunks denied:     {}", stats.total_chunks_denied);
            println!("  Unique actors:     {}", stats.unique_actors);
            println!("  Chain intact:      {}", if stats.chain_intact { "YES" } else { "BROKEN" });

            if let Some(first) = stats.first_entry {
                println!("  First entry:       {first}");
            }
            if let Some(last) = stats.last_entry {
                println!("  Last entry:        {last}");
            }

            if full {
                println!();
                println!("  Chain ({} tokens):", trail.chain_len());
                for token in &trail.chain().chain {
                    println!("    {} | {} | JIS {} | accessed={} denied={}",
                        &token.token_id,
                        &token.eromheen.actor,
                        token.eromheen.jis_level,
                        token.eromheen.chunks_accessed,
                        token.eromheen.chunks_denied,
                    );
                }
            }

            Ok(())
        }

        Commands::Verify => {
            let trail = AuditTrail::open(".cortex/audit")?;
            let intact = trail.verify_chain();

            println!("TIBET Cortex — Chain Verification");
            println!();
            println!("  Chain length: {} tokens", trail.chain_len());
            if intact {
                println!("  Status:       ALL TOKENS VERIFIED");
                println!("  Integrity:    INTACT");
            } else {
                println!("  Status:       CHAIN BROKEN");
                println!("  Integrity:    COMPROMISED");
            }

            Ok(())
        }

        Commands::Info => {
            println!("TIBET Cortex v{}", env!("CARGO_PKG_VERSION"));
            println!();
            println!("  Zero-trust AI knowledge processing.");
            println!("  Data that protects itself.");
            println!();
            println!("  Architecture:");
            println!("  ┌─────────────────────────────────────┐");
            println!("  │  STORE    TBZ envelopes + JIS levels │");
            println!("  │  GATE     Multi-dimensional JIS      │");
            println!("  │  AIRLOCK  Zero plaintext lifetime    │");
            println!("  │  AUDIT    Blackbox-met-window trail  │");
            println!("  │  TIBET    Immutable provenance chain │");
            println!("  └─────────────────────────────────────┘");
            println!();
            println!("  https://github.com/jaspertvdm/tibet-cortex");

            Ok(())
        }
    }
}
